"""Append-only durable persistence for issuer/revocation accumulator state.

``RevocationAccumulatorService`` keeps its state in memory. None of it
survives a process restart, so a restarted issuer would lose the accumulator
(and every holder's witness lineage) and could not continue its signed
announcement chain.

This module persists that state as an append-only log, which
``DurableRevocationAccumulatorService.open`` replays after a restart. The
log has three parts, all JSON documents (the recovery contract):

* ``header``  — written once: ``{"version", "accumulatorId", "maxEpochLag"}``
* ``signers`` — one record per announcement signer, in rotation order:
  ``{"keyId", "publicKey", "fromEpoch"}`` (public material only)
* ``epochs``  — one record per epoch: ``{"epoch", "operation",
  "announcement"}``. ``operation`` is the mutation that produced the epoch
  (``{"type": "genesis"}`` at epoch 0); ``announcement`` is the
  issuer-SIGNED announcement, verbatim (re-signing on reload would change
  ``announcedAt`` and break the hash chain).

Each mutation appends exactly one epoch record. Its size depends on the
changed leaves and the announcement, never on the length of the history.
Leaves, the credential index, the revoked set and the delta snapshots are
not stored: recovery derives them by replaying the operations and checks
every replayed root against the signed announcement of its epoch.

A store never rewrites or deletes a log record. The single exception is the
migration of a legacy ``zkc:revocation-accumulator-state:v2`` document: after
the durable service has verified the document, ``replace_legacy_state``
swaps it for the equivalent log in one transaction.

Stdlib-only (``sqlite3`` + ``json``). The signing key is NOT persisted (it is
supplied at recovery, exactly as at construction): secret material never
enters the store.
"""

from __future__ import annotations

import json
import sqlite3
from threading import RLock

from zkc_issuer.accumulator import _locked

__all__ = [
    "AccumulatorStateStore",
    "InMemoryAccumulatorStateStore",
    "SQLiteAccumulatorStateStore",
    "AccumulatorStoreError",
]


class AccumulatorStoreError(RuntimeError):
    """A durable accumulator-store failure (fail closed)."""


def _dump(document: dict) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def _load(text: str):
    try:
        return json.loads(text)
    except ValueError as exc:
        raise AccumulatorStoreError("corrupt accumulator log record") from exc


def _epoch_number(record) -> int:
    epoch = record.get("epoch") if isinstance(record, dict) else None
    if type(epoch) is not int or epoch < 0:
        raise AccumulatorStoreError("epoch record has no valid epoch number")
    return epoch


class AccumulatorStateStore:
    """Interface a durable revocation service persists its log through.

    Every write is atomic: a write that returns is durable, and a failed
    write leaves the stored log unchanged. Services publish only after a
    successful write. ``load_log`` returns ``None`` for a store without a
    log, else ``{"header": dict, "signers": [dict, …], "epochs": [dict, …]}``
    with signers in append order and epochs in epoch order.
    """

    def load_log(self):
        raise NotImplementedError

    def create_log(self, header: dict, signer: dict, genesis: dict) -> None:
        """Write the header, first signer and epoch-0 record together.

        Refuses a store that already holds a log or a legacy document.
        """
        raise NotImplementedError

    def append_epoch(self, record: dict) -> None:
        """Append one epoch record; its epoch must be exactly head + 1."""
        raise NotImplementedError

    def append_signer(self, record: dict) -> None:
        """Append one announcement signer record."""
        raise NotImplementedError

    def load_legacy_state(self):
        """Return a legacy v2 state document, or ``None``."""
        raise NotImplementedError

    def replace_legacy_state(self, header: dict, signers: list, epochs: list) -> None:
        """Atomically write a verified log and remove the legacy document."""
        raise NotImplementedError

    def exists(self) -> bool:
        return self.load_log() is not None or self.load_legacy_state() is not None


class InMemoryAccumulatorStateStore(AccumulatorStateStore):
    """Non-durable reference store (round-trips the log in process, e.g. tests).

    Records are kept as JSON text, so callers cannot mutate persisted state
    in place and record sizes match what a durable store writes.
    """

    def __init__(self):
        self._lock = RLock()
        self._header = None
        self._signers: list = []
        self._epochs: list = []
        self._legacy = None

    @_locked
    def load_log(self):
        if self._header is None:
            if self._signers or self._epochs:
                raise AccumulatorStoreError("accumulator log records exist without a header")
            return None
        return {
            "header": _load(self._header),
            "signers": [_load(text) for text in self._signers],
            "epochs": [_load(text) for text in self._epochs],
        }

    @_locked
    def create_log(self, header: dict, signer: dict, genesis: dict) -> None:
        if self._header is not None or self._signers or self._epochs or self._legacy is not None:
            raise AccumulatorStoreError("accumulator store already holds state")
        if _epoch_number(genesis) != 0:
            raise AccumulatorStoreError("the first epoch record must be epoch 0")
        self._header, self._signers, self._epochs = _dump(header), [_dump(signer)], [_dump(genesis)]

    @_locked
    def append_epoch(self, record: dict) -> None:
        if self._header is None:
            raise AccumulatorStoreError("accumulator log does not exist")
        if _epoch_number(record) != len(self._epochs):
            raise AccumulatorStoreError("epoch record does not extend the log head")
        self._epochs.append(_dump(record))

    @_locked
    def append_signer(self, record: dict) -> None:
        if self._header is None:
            raise AccumulatorStoreError("accumulator log does not exist")
        self._signers.append(_dump(record))

    @_locked
    def load_legacy_state(self):
        return None if self._legacy is None else _load(self._legacy)

    @_locked
    def replace_legacy_state(self, header: dict, signers: list, epochs: list) -> None:
        if self._legacy is None:
            raise AccumulatorStoreError("no legacy accumulator state to replace")
        if self._header is not None or self._signers or self._epochs:
            raise AccumulatorStoreError("accumulator store already holds a log")
        if [_epoch_number(record) for record in epochs] != list(range(len(epochs))):
            raise AccumulatorStoreError("migrated epoch records are not contiguous")
        self._header = _dump(header)
        self._signers = [_dump(record) for record in signers]
        self._epochs = [_dump(record) for record in epochs]
        self._legacy = None


_APPEND_ONLY = " BEGIN SELECT RAISE(ABORT, 'accumulator log records are append-only'); END"

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS accumulator_log_header ("
    " accumulator_id TEXT PRIMARY KEY, document TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS accumulator_signers ("
    " accumulator_id TEXT NOT NULL, sequence INTEGER NOT NULL,"
    " document TEXT NOT NULL, PRIMARY KEY(accumulator_id, sequence))",
    "CREATE TABLE IF NOT EXISTS accumulator_epochs ("
    " accumulator_id TEXT NOT NULL, epoch INTEGER NOT NULL,"
    " document TEXT NOT NULL, PRIMARY KEY(accumulator_id, epoch))",
    "CREATE TRIGGER IF NOT EXISTS accumulator_log_header_no_update"
    " BEFORE UPDATE ON accumulator_log_header" + _APPEND_ONLY,
    "CREATE TRIGGER IF NOT EXISTS accumulator_log_header_no_delete"
    " BEFORE DELETE ON accumulator_log_header" + _APPEND_ONLY,
    "CREATE TRIGGER IF NOT EXISTS accumulator_signers_no_update"
    " BEFORE UPDATE ON accumulator_signers" + _APPEND_ONLY,
    "CREATE TRIGGER IF NOT EXISTS accumulator_signers_no_delete"
    " BEFORE DELETE ON accumulator_signers" + _APPEND_ONLY,
    "CREATE TRIGGER IF NOT EXISTS accumulator_epochs_no_update"
    " BEFORE UPDATE ON accumulator_epochs" + _APPEND_ONLY,
    "CREATE TRIGGER IF NOT EXISTS accumulator_epochs_no_delete"
    " BEFORE DELETE ON accumulator_epochs" + _APPEND_ONLY,
)


class SQLiteAccumulatorStateStore(AccumulatorStateStore):
    """Durable SQLite-backed append-only accumulator log.

    Each write is one ``BEGIN IMMEDIATE`` transaction (WAL +
    ``synchronous=FULL``), so a returned write has been flushed. Triggers
    reject UPDATE and DELETE on log records. The accumulator id namespaces
    the rows, so one DB file can hold several accumulators. A connection
    lock serializes transactions and reads across HTTP worker threads.
    Services sharing a store must share one accumulator instance; this is
    not a multi-writer CAS. Explicit ``check_same_thread=True`` opts into
    SQLite thread confinement.
    """

    def __init__(self, path, accumulator_id: str, check_same_thread: bool = False):
        self._lock = RLock()
        self._path = str(path)
        self._accumulator_id = accumulator_id
        try:
            self._conn = sqlite3.connect(self._path, check_same_thread=check_same_thread)
        except sqlite3.Error as exc:
            raise AccumulatorStoreError(
                f"could not open accumulator store: {type(exc).__name__}"
            ) from exc
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            for statement in _SCHEMA:
                self._conn.execute(statement)
            self._conn.commit()
        except sqlite3.Error as exc:
            raise AccumulatorStoreError(
                f"could not initialize accumulator store: {type(exc).__name__}"
            ) from exc

    def _write(self, action: str, body) -> None:
        try:
            with self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                body()
        except sqlite3.Error as exc:
            raise AccumulatorStoreError(
                f"could not {action}: {type(exc).__name__}"
            ) from exc

    def _read(self, action: str, query: str, parameters=()):
        try:
            return self._conn.execute(query, parameters).fetchall()
        except sqlite3.Error as exc:
            raise AccumulatorStoreError(
                f"could not {action}: {type(exc).__name__}"
            ) from exc

    def _log_rows(self) -> tuple:
        key = (self._accumulator_id,)
        header = self._read(
            "read accumulator log",
            "SELECT document FROM accumulator_log_header WHERE accumulator_id = ?",
            key,
        )
        signers = self._read(
            "read accumulator log",
            "SELECT document FROM accumulator_signers WHERE accumulator_id = ? "
            "ORDER BY sequence",
            key,
        )
        epochs = self._read(
            "read accumulator log",
            "SELECT epoch, document FROM accumulator_epochs WHERE accumulator_id = ? "
            "ORDER BY epoch",
            key,
        )
        return header, signers, epochs

    # The v2 format kept one JSON document per accumulator in
    # ``accumulator_state`` and rewrote it on every mutation. It is read only
    # for migration; new stores never create that table.
    def _legacy_row(self):
        if not self._read(
            "read accumulator store schema",
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'accumulator_state'",
        ):
            return None
        rows = self._read(
            "read legacy accumulator state",
            "SELECT document FROM accumulator_state WHERE accumulator_id = ?",
            (self._accumulator_id,),
        )
        return rows[0] if rows else None

    @_locked
    def load_log(self):
        header, signers, epochs = self._log_rows()
        if not header:
            if signers or epochs:
                raise AccumulatorStoreError("accumulator log records exist without a header")
            return None
        return {
            "header": _load(header[0]["document"]),
            "signers": [_load(row["document"]) for row in signers],
            "epochs": [_load(row["document"]) for row in epochs],
        }

    def _insert_log(self, header: dict, signers: list, epochs: list) -> None:
        existing = self._log_rows()
        if any(existing):
            raise AccumulatorStoreError("accumulator store already holds a log")
        key = self._accumulator_id
        self._conn.execute(
            "INSERT INTO accumulator_log_header(accumulator_id, document) VALUES(?, ?)",
            (key, _dump(header)),
        )
        for sequence, record in enumerate(signers):
            self._conn.execute(
                "INSERT INTO accumulator_signers(accumulator_id, sequence, document) "
                "VALUES(?, ?, ?)",
                (key, sequence, _dump(record)),
            )
        for position, record in enumerate(epochs):
            if _epoch_number(record) != position:
                raise AccumulatorStoreError("epoch records are not contiguous")
            self._conn.execute(
                "INSERT INTO accumulator_epochs(accumulator_id, epoch, document) "
                "VALUES(?, ?, ?)",
                (key, position, _dump(record)),
            )

    @_locked
    def create_log(self, header: dict, signer: dict, genesis: dict) -> None:
        def body():
            if self._legacy_row() is not None:
                raise AccumulatorStoreError("accumulator store holds legacy state")
            self._insert_log(header, [signer], [genesis])

        self._write("create accumulator log", body)

    @_locked
    def append_epoch(self, record: dict) -> None:
        epoch = _epoch_number(record)
        document = _dump(record)

        def body():
            row = self._conn.execute(
                "SELECT COUNT(*) AS count, MAX(epoch) AS head FROM accumulator_epochs "
                "WHERE accumulator_id = ?",
                (self._accumulator_id,),
            ).fetchone()
            if row["count"] == 0:
                raise AccumulatorStoreError("accumulator log does not exist")
            if epoch != row["head"] + 1:
                raise AccumulatorStoreError("epoch record does not extend the log head")
            self._conn.execute(
                "INSERT INTO accumulator_epochs(accumulator_id, epoch, document) "
                "VALUES(?, ?, ?)",
                (self._accumulator_id, epoch, document),
            )

        self._write("persist accumulator epoch", body)

    @_locked
    def append_signer(self, record: dict) -> None:
        document = _dump(record)

        def body():
            row = self._conn.execute(
                "SELECT COUNT(*) AS count, MAX(sequence) AS head FROM accumulator_signers "
                "WHERE accumulator_id = ?",
                (self._accumulator_id,),
            ).fetchone()
            if row["count"] == 0:
                raise AccumulatorStoreError("accumulator log does not exist")
            self._conn.execute(
                "INSERT INTO accumulator_signers(accumulator_id, sequence, document) "
                "VALUES(?, ?, ?)",
                (self._accumulator_id, row["head"] + 1, document),
            )

        self._write("persist accumulator signer", body)

    @_locked
    def load_legacy_state(self):
        row = self._legacy_row()
        return None if row is None else _load(row["document"])

    @_locked
    def replace_legacy_state(self, header: dict, signers: list, epochs: list) -> None:
        def body():
            if self._legacy_row() is None:
                raise AccumulatorStoreError("no legacy accumulator state to replace")
            self._insert_log(header, signers, epochs)
            self._conn.execute(
                "DELETE FROM accumulator_state WHERE accumulator_id = ?",
                (self._accumulator_id,),
            )

        self._write("migrate legacy accumulator state", body)

    @_locked
    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
