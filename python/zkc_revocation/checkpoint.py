"""Durable verifier checkpoints and signed equivocation evidence.

Checkpoint writes are monotonic. Several verifier workers, threads, or
holder processes may share one store, so every write re-reads the persisted
checkpoint inside the same atomic step and refuses a document that does not
extend it: a lower head epoch, a replaced retained announcement, or a head
that does not hash-link to the persisted head. ``compare_and_swap_checkpoint``
also requires the persisted head to be the one the caller validated against.

``CatchUpStatus`` reports one step of the resumable, bounded catch-up that
the verifier cache and the private witness provider expose as ``catch_up``.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass

from .service import announcement_hash

__all__ = [
    "CatchUpStatus",
    "VerifierCheckpointStoreError",
    "VerifierCheckpointConflictError",
    "VerifierCheckpointStore",
    "InMemoryVerifierCheckpointStore",
    "SQLiteVerifierCheckpointStore",
]


@dataclass(frozen=True)
class CatchUpStatus:
    """Result of one bounded, resumable revocation catch-up call.

    ``checkpoint_epoch`` is the persisted checkpoint head after the call.
    ``target_epoch`` is the epoch of the current head that the call moved
    toward. The head's signature, linkage, and freshness are verified when
    the checkpoint reaches it, so before that it only sets the direction.
    ``verified`` counts the announcements past the starting checkpoint whose
    signatures this call verified. It never exceeds the consumer's
    ``max_backfill``. While ``complete`` is false, call again: each call
    resumes from the persisted checkpoint, also after a restart or after
    another worker advanced it.
    """

    issuer_id: str
    accumulator_id: str
    checkpoint_epoch: int
    target_epoch: int
    verified: int

    @property
    def remaining(self) -> int:
        """Epochs between the persisted checkpoint and the target head."""
        return self.target_epoch - self.checkpoint_epoch

    @property
    def complete(self) -> bool:
        """True when the persisted checkpoint is the target head itself."""
        return self.checkpoint_epoch == self.target_epoch


class VerifierCheckpointStoreError(RuntimeError):
    """A checkpoint or evidence write could not be completed durably."""


class VerifierCheckpointConflictError(VerifierCheckpointStoreError):
    """The write does not extend the persisted checkpoint head.

    Another worker advanced the checkpoint first, or the document is older
    than, or forks from, the persisted head. The persisted checkpoint is
    unchanged. Re-read it and validate the candidate against it again.
    """


class VerifierCheckpointStore:
    """Persistence contract, scoped by verifier issuer and accumulator ids.

    A checkpoint document carries its head ``announcement`` and the retained
    ``announcements`` window (decimal epoch -> announcement), which must be a
    contiguous, hash-linked run that ends at the head. Both write methods
    re-read the persisted checkpoint atomically with the write and raise
    :class:`VerifierCheckpointConflictError`, leaving it unchanged, unless the
    new document extends it.

    ``save_checkpoint`` accepts only an extension the two documents prove: the
    new window retains the persisted head, or starts at the next epoch and
    commits to the persisted head's hash. ``compare_and_swap_checkpoint``
    first requires the persisted head to equal ``expected_head`` (``None``: no
    checkpoint is persisted). The caller has validated the signed chain from
    that head to the new one, so it can also accept a backfilled gap wider
    than the retained window.
    """

    def load_checkpoint(self, issuer_id: str, accumulator_id: str):
        raise NotImplementedError

    def save_checkpoint(self, issuer_id: str, accumulator_id: str, checkpoint: dict) -> None:
        raise NotImplementedError

    def compare_and_swap_checkpoint(
        self, issuer_id: str, accumulator_id: str, expected_head, checkpoint: dict
    ) -> None:
        raise NotImplementedError

    def retain_evidence(self, issuer_id: str, accumulator_id: str, evidence: dict) -> None:
        raise NotImplementedError

    def evidence(self, issuer_id: str, accumulator_id: str) -> list:
        raise NotImplementedError


def _copy(document):
    return json.loads(json.dumps(document))


# ``save_checkpoint`` writes with no caller-validated head to compare.
_UNCHECKED = object()


def _normalized(document, label: str):
    try:
        return _copy(document)
    except (TypeError, ValueError) as exc:
        raise VerifierCheckpointStoreError(f"{label} is not a JSON document") from exc


def _checkpoint_window(document, label: str):
    """Return ``(head_epoch, window)`` of a well-formed checkpoint document."""
    if type(document) is not dict:
        raise VerifierCheckpointStoreError(f"{label} is not a checkpoint document")
    head = document.get("announcement")
    retained = document.get("announcements")
    if type(head) is not dict or type(retained) is not dict or not retained:
        raise VerifierCheckpointStoreError(f"{label} has no announcement window")
    window = {}
    for key, announcement in retained.items():
        epoch = announcement.get("epoch") if type(announcement) is dict else None
        if type(epoch) is not int or epoch < 0 or key != str(epoch):
            raise VerifierCheckpointStoreError(f"{label} announcement window is malformed")
        window[epoch] = announcement
    head_epoch = head.get("epoch")
    if type(head_epoch) is not int or max(window) != head_epoch or window[head_epoch] != head:
        raise VerifierCheckpointStoreError(
            f"{label} head is not the newest retained announcement"
        )
    first_epoch = min(window)
    if len(window) != head_epoch - first_epoch + 1:
        raise VerifierCheckpointStoreError(f"{label} announcement window is not contiguous")
    try:
        for epoch in range(first_epoch + 1, head_epoch + 1):
            if window[epoch].get("previousAnnouncementHash") != announcement_hash(
                window[epoch - 1]
            ):
                raise VerifierCheckpointStoreError(
                    f"{label} announcement window is not hash-linked"
                )
    except ValueError as exc:
        raise VerifierCheckpointStoreError(f"{label} announcement is malformed") from exc
    return head_epoch, window


def _require_successor(persisted, checkpoint: dict, expected_head) -> None:
    """Fail closed unless ``checkpoint`` may replace ``persisted``.

    Called with both documents JSON-normalized, inside the store's atomic
    read-check-write step.
    """
    new_epoch, new_window = _checkpoint_window(checkpoint, "checkpoint")
    if persisted is None:
        if expected_head is not _UNCHECKED and expected_head is not None:
            raise VerifierCheckpointConflictError(
                "no verifier checkpoint is persisted, but the write expected one"
            )
        return
    old_epoch, old_window = _checkpoint_window(persisted, "persisted checkpoint")
    old_head = old_window[old_epoch]
    if expected_head is not _UNCHECKED and expected_head != old_head:
        raise VerifierCheckpointConflictError(
            "the persisted checkpoint head changed after it was read"
        )
    if new_epoch < old_epoch:
        raise VerifierCheckpointConflictError(
            f"checkpoint epoch {new_epoch} is older than the persisted epoch {old_epoch}"
        )
    for epoch in sorted(old_window.keys() & new_window.keys()):
        if old_window[epoch] != new_window[epoch]:
            raise VerifierCheckpointConflictError(
                f"checkpoint replaces the retained announcement for epoch {epoch}"
            )
    first_epoch = min(new_window)
    if first_epoch <= old_epoch:
        # The window retains the persisted head unchanged and links it forward.
        return
    if first_epoch == old_epoch + 1:
        try:
            linked = new_window[first_epoch].get("previousAnnouncementHash") == (
                announcement_hash(old_head)
            )
        except ValueError as exc:
            raise VerifierCheckpointStoreError(
                "persisted checkpoint head is malformed"
            ) from exc
        if not linked:
            raise VerifierCheckpointConflictError(
                "checkpoint does not extend the persisted head"
            )
        return
    if expected_head is _UNCHECKED:
        raise VerifierCheckpointConflictError(
            "checkpoint window does not reach the persisted head; "
            "write it with compare_and_swap_checkpoint"
        )


class InMemoryVerifierCheckpointStore(VerifierCheckpointStore):
    """Process-local implementation for tests; not durable across restart."""

    def __init__(self):
        self._lock = threading.Lock()
        self._checkpoints = {}
        self._evidence = {}

    def load_checkpoint(self, issuer_id: str, accumulator_id: str):
        with self._lock:
            checkpoint = self._checkpoints.get((issuer_id, accumulator_id))
            return None if checkpoint is None else _copy(checkpoint)

    def save_checkpoint(self, issuer_id: str, accumulator_id: str, checkpoint: dict) -> None:
        self._write_checkpoint(issuer_id, accumulator_id, _UNCHECKED, checkpoint)

    def compare_and_swap_checkpoint(
        self, issuer_id: str, accumulator_id: str, expected_head, checkpoint: dict
    ) -> None:
        self._write_checkpoint(issuer_id, accumulator_id, expected_head, checkpoint)

    def _write_checkpoint(self, issuer_id, accumulator_id, expected_head, checkpoint) -> None:
        candidate = _normalized(checkpoint, "checkpoint")
        if expected_head is not _UNCHECKED:
            expected_head = _normalized(expected_head, "expected checkpoint head")
        with self._lock:
            key = (issuer_id, accumulator_id)
            _require_successor(self._checkpoints.get(key), candidate, expected_head)
            self._checkpoints[key] = candidate

    def retain_evidence(self, issuer_id: str, accumulator_id: str, evidence: dict) -> None:
        with self._lock:
            self._evidence.setdefault((issuer_id, accumulator_id), []).append(_copy(evidence))

    def evidence(self, issuer_id: str, accumulator_id: str) -> list:
        with self._lock:
            return _copy(self._evidence.get((issuer_id, accumulator_id), []))


class SQLiteVerifierCheckpointStore(VerifierCheckpointStore):
    """SQLite-backed checkpoints and append-only evidence records.

    Workers in several processes may open the same database file. Each
    checkpoint write runs in one ``BEGIN IMMEDIATE`` transaction that re-reads
    the persisted checkpoint, so concurrent writers cannot move it backwards.
    A lock serializes this connection when threads share the instance
    (``check_same_thread=False``).
    """

    def __init__(self, path, check_same_thread: bool = True):
        self._lock = threading.RLock()
        try:
            self._conn = sqlite3.connect(str(path), check_same_thread=check_same_thread)
        except sqlite3.Error as exc:
            raise VerifierCheckpointStoreError(
                f"could not open verifier checkpoint store: {type(exc).__name__}"
            ) from exc
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS verifier_checkpoint ("
                " issuer_id TEXT NOT NULL, accumulator_id TEXT NOT NULL,"
                " document TEXT NOT NULL, PRIMARY KEY(issuer_id, accumulator_id))"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS verifier_equivocation_evidence ("
                " evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " issuer_id TEXT NOT NULL, accumulator_id TEXT NOT NULL,"
                " document TEXT NOT NULL)"
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise VerifierCheckpointStoreError(
                f"could not initialize verifier checkpoint store: {type(exc).__name__}"
            ) from exc

    def _read_checkpoint(self, issuer_id: str, accumulator_id: str):
        row = self._conn.execute(
            "SELECT document FROM verifier_checkpoint "
            "WHERE issuer_id = ? AND accumulator_id = ?",
            (issuer_id, accumulator_id),
        ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["document"])
        except ValueError as exc:
            raise VerifierCheckpointStoreError("corrupt verifier checkpoint document") from exc

    def load_checkpoint(self, issuer_id: str, accumulator_id: str):
        with self._lock:
            try:
                return self._read_checkpoint(issuer_id, accumulator_id)
            except sqlite3.Error as exc:
                raise VerifierCheckpointStoreError(
                    f"could not read verifier checkpoint: {type(exc).__name__}"
                ) from exc

    def save_checkpoint(self, issuer_id: str, accumulator_id: str, checkpoint: dict) -> None:
        self._write_checkpoint(issuer_id, accumulator_id, _UNCHECKED, checkpoint)

    def compare_and_swap_checkpoint(
        self, issuer_id: str, accumulator_id: str, expected_head, checkpoint: dict
    ) -> None:
        self._write_checkpoint(issuer_id, accumulator_id, expected_head, checkpoint)

    def _write_checkpoint(self, issuer_id, accumulator_id, expected_head, checkpoint) -> None:
        candidate = _normalized(checkpoint, "checkpoint")
        if expected_head is not _UNCHECKED:
            expected_head = _normalized(expected_head, "expected checkpoint head")
        document = json.dumps(candidate, sort_keys=True)
        with self._lock:
            try:
                # IMMEDIATE takes the database write lock before the re-read,
                # so no other connection can commit between check and write.
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    persisted = self._read_checkpoint(issuer_id, accumulator_id)
                    _require_successor(persisted, candidate, expected_head)
                    self._conn.execute(
                        "INSERT INTO verifier_checkpoint(issuer_id, accumulator_id, document) "
                        "VALUES(?, ?, ?) ON CONFLICT(issuer_id, accumulator_id) "
                        "DO UPDATE SET document=excluded.document",
                        (issuer_id, accumulator_id, document),
                    )
                    self._conn.commit()
                except BaseException:
                    if self._conn.in_transaction:
                        self._conn.rollback()
                    raise
            except sqlite3.Error as exc:
                raise VerifierCheckpointStoreError(
                    f"could not persist verifier checkpoint: {type(exc).__name__}"
                ) from exc

    def retain_evidence(self, issuer_id: str, accumulator_id: str, evidence: dict) -> None:
        document = json.dumps(evidence, sort_keys=True)
        with self._lock:
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO verifier_equivocation_evidence"
                        "(issuer_id, accumulator_id, document) VALUES(?, ?, ?)",
                        (issuer_id, accumulator_id, document),
                    )
            except sqlite3.Error as exc:
                raise VerifierCheckpointStoreError(
                    f"could not persist equivocation evidence: {type(exc).__name__}"
                ) from exc

    def evidence(self, issuer_id: str, accumulator_id: str) -> list:
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT document FROM verifier_equivocation_evidence "
                    "WHERE issuer_id = ? AND accumulator_id = ? ORDER BY evidence_id",
                    (issuer_id, accumulator_id),
                ).fetchall()
            except sqlite3.Error as exc:
                raise VerifierCheckpointStoreError(
                    f"could not read equivocation evidence: {type(exc).__name__}"
                ) from exc
        try:
            return [json.loads(row["document"]) for row in rows]
        except ValueError as exc:
            raise VerifierCheckpointStoreError("corrupt equivocation evidence document") from exc

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
