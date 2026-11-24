"""Durable issuance/renewal ledger for the reference issuer adapter.

The adapter keeps one private record per issued credential: the trusted
session that owns its lineage, the provider identity, the verified claims and
expiry, the holder commitment and the rebind window. Renewal and rebind
attestation need these records, so a restart that loses them strands every
pre-restart credential. A durable accumulator alone does not keep them.

``IssuanceLedgerStore`` persists the ledger as one JSON document. The adapter
writes it ahead of every accumulator mutation, so the document can be
reconciled with the accumulator after a crash:

* a ``pending`` record whose credential the accumulator knows was committed
  (the crash happened after the mutation) and is promoted;
* a ``pending`` record the accumulator does not know never took effect and is
  dropped;
* a ``committed`` record the accumulator does not know, or an accumulator
  credential with no record, means the two stores diverged (for example one was
  restored from an older backup). Restore fails closed.

Document format ``zkc:issuer-ledger:v1``::

    {"version": "zkc:issuer-ledger:v1", "issuerId": str, "accumulatorId": str,
     "records": [{"credentialId": "0x..", "state": "pending"|"committed",
                  "schemaId": str, "issuedAt": int, "renewedFrom": "0x.."|null,
                  "sessionIdentity": str, "providerRef": str,
                  "providerExpiresAt": int,
                  "credential": {"claims": {...}, "expiresAt": int,
                                 optional "attributeLayoutId": "0x.."},
                  "holderCommitment": "0x..", "rebindWindow": [int, int]}]}

Records are ordered by issuance. The document holds provider identities and
verified claims but no signing key or holder secret; protect it like the
issuer's other private provider data. This module does not coordinate several
writers: one adapter process owns a ledger at a time.

Legacy attribute sets issued with a provider layout declaration retain it in
``credential.attributeLayoutId``. Older records without one remain readable
but cannot authorize a layout for renewal.

Stdlib-only (``sqlite3`` + ``json``).
"""

from __future__ import annotations

import json
import sqlite3
from threading import RLock

from .accumulator import _locked

__all__ = [
    "ISSUANCE_LEDGER_VERSION",
    "IssuanceLedgerError",
    "IssuanceLedgerStore",
    "InMemoryIssuanceLedgerStore",
    "SQLiteIssuanceLedgerStore",
]

ISSUANCE_LEDGER_VERSION = "zkc:issuer-ledger:v1"


class IssuanceLedgerError(RuntimeError):
    """An issuance-ledger store or consistency failure (fail closed)."""


class IssuanceLedgerStore:
    """Interface for the adapter's issuance ledger document.

    ``save_state`` must be atomic: a save that returns is durable and a failed
    save leaves the previous document intact. ``load_state`` returns the last
    saved document, or ``None`` for a fresh store.
    """

    def save_state(self, state: dict) -> None:
        raise NotImplementedError

    def load_state(self):
        raise NotImplementedError


class InMemoryIssuanceLedgerStore(IssuanceLedgerStore):
    """Non-durable reference store (round-trips the document in process)."""

    def __init__(self):
        self._lock = RLock()
        self._document = None

    @_locked
    def save_state(self, state: dict) -> None:
        self._document = json.dumps(state, sort_keys=True)

    @_locked
    def load_state(self):
        return None if self._document is None else json.loads(self._document)


class SQLiteIssuanceLedgerStore(IssuanceLedgerStore):
    """Durable SQLite-backed issuance ledger (WAL + ``synchronous=FULL``).

    The ledger id namespaces the row, so one database file can hold the
    ledgers of several issuers. A connection lock serializes access.
    """

    def __init__(self, path, ledger_id: str, check_same_thread: bool = False):
        if type(ledger_id) is not str or not ledger_id:
            raise IssuanceLedgerError("ledger id must be a non-empty string")
        self._lock = RLock()
        self._ledger_id = ledger_id
        try:
            self._conn = sqlite3.connect(str(path), check_same_thread=check_same_thread)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS issuance_ledger ("
                "  ledger_id TEXT PRIMARY KEY,"
                "  document TEXT NOT NULL"
                ")"
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise IssuanceLedgerError(
                f"could not open issuance ledger: {type(exc).__name__}"
            ) from exc

    @_locked
    def save_state(self, state: dict) -> None:
        document = json.dumps(state, sort_keys=True)
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO issuance_ledger(ledger_id, document) VALUES(?, ?) "
                    "ON CONFLICT(ledger_id) DO UPDATE SET document=excluded.document",
                    (self._ledger_id, document),
                )
        except sqlite3.Error as exc:
            raise IssuanceLedgerError(
                f"could not persist issuance ledger: {type(exc).__name__}"
            ) from exc

    @_locked
    def load_state(self):
        try:
            row = self._conn.execute(
                "SELECT document FROM issuance_ledger WHERE ledger_id = ?",
                (self._ledger_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise IssuanceLedgerError(
                f"could not read issuance ledger: {type(exc).__name__}"
            ) from exc
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except ValueError as exc:
            raise IssuanceLedgerError("corrupt issuance ledger document") from exc

    @_locked
    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
