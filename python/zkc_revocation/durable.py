"""Durable, recoverable revocation accumulator service.

``DurableRevocationAccumulatorService`` is a drop-in
``RevocationAccumulatorService`` that appends to an ``AccumulatorStateStore``
log (see ``store.py``): one epoch record per mutation (the operation and its
issuer-SIGNED announcement) and one signer record per announcement key.
``open`` replays that log after a restart, so the service comes back with
its epoch, root, signed announcement chain and signer history intact and
keeps serving witness updates (including deltas from before the restart,
inside the delta snapshot window).

Recovery fails closed unless the whole log authenticates:

* every announcement verifies under the signer recorded for its epoch and
  commits to its predecessor (genesis commits to the zero hash);
* every replayed accumulator root equals the signed root of its epoch;
* the supplied signing key is the active (last) recorded signer.

Rotation: ``rotate_signing_key`` persists the successor before it signs.
After a restart the service opens with the successor key; a retired or
unknown key fails closed. When only the successor's private key is
available, ``open(..., allow_rotation=True)`` performs that rotation at
open time.

Legacy v2 state (one document rewritten on every mutation) is migrated on
open: the epoch operations are derived from its per-epoch snapshots, the
result is verified under the supplied key like any log, and the store
replaces the document with the log in one transaction.

Because it subclasses the in-process service, it also makes the issuer side
durable for free: ``zkc_issuer.BaseIssuerAdapter`` accepts any
``IssuerAccumulator`` via its ``accumulator=`` parameter, so handing it a
durable service persists every issuance/revocation the adapter performs.
"""

from __future__ import annotations

import time
from threading import RLock

from zkc_crypto import (
    FIELD_MODULUS,
    MERKLE_DEPTH,
    SparseMerkleAccumulator,
    field_to_hex,
    poseidon2,
    zero_subtree_root,
)
from zkc_issuer.accumulator import MAX_EPOCH_LAG, IssuerAccumulator
from zkc_issuer.errors import AdapterError
from zkc_issuer.keys import IssuerSigningKey

from .service import (
    _SIGNER_FIELDS,
    DEFAULT_LIVENESS_INTERVAL,
    DELTA_SNAPSHOT_WINDOW,
    GENESIS_ANNOUNCEMENT_HASH,
    RevocationAccumulatorService,
    _liveness_interval,
    announcement_hash,
    signer_record,
    verify_epoch_announcement,
)
from .store import AccumulatorStateStore, AccumulatorStoreError

__all__ = ["DurableRevocationAccumulatorService"]

STATE_VERSION = "zkc:revocation-accumulator-state:v3"
LEGACY_STATE_VERSION = "zkc:revocation-accumulator-state:v2"

_LOG_FIELDS = frozenset({"header", "signers", "epochs"})
_HEADER_FIELDS = frozenset({"version", "accumulatorId", "maxEpochLag"})
_EPOCH_FIELDS = frozenset({"epoch", "operation", "announcement"})
_OPERATION_FIELDS = {
    "genesis": frozenset({"type"}),
    "register": frozenset({"type", "credentialId"}),
    "revoke": frozenset({"type", "credentialId"}),
    "replace": frozenset({"type", "oldCredentialId", "newCredentialId"}),
}
_LEGACY_FIELDS = frozenset(
    {
        "version", "accumulatorId", "updateEndpoint", "maxEpochLag", "epoch",
        "leaves", "indexByCredential", "revoked", "snapshots", "announcements",
        "lastAnnouncementHash",
    }
)


class _InvalidHistory(Exception):
    """One reason a persisted log cannot be trusted (internal)."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise _InvalidHistory(reason)


# Field elements can exceed JSON's safe integer range; persist as hex.
def _encode_int(value) -> str:
    return format(int(value), "x")


def _decode_int(value) -> int:
    _require(type(value) is str and bool(value), "integer must be a hex string")
    try:
        number = int(value, 16)
    except ValueError:
        raise _InvalidHistory("integer must be hex") from None
    _require(format(number, "x") == value, "integer hex is not canonical")
    return number


def _encode_operation(operation: tuple) -> dict:
    name, *args = operation
    if name == "genesis" and not args:
        return {"type": "genesis"}
    if name in ("register", "revoke") and len(args) == 1:
        return {"type": name, "credentialId": _encode_int(args[0])}
    if name == "replace" and len(args) == 2:
        return {
            "type": "replace",
            "oldCredentialId": _encode_int(args[0]),
            "newCredentialId": _encode_int(args[1]),
        }
    raise ValueError(f"cannot persist accumulator operation {name!r}")


class _IncrementalRoot:
    """Depth-32 Poseidon2 root under single-leaf updates (replay only).

    Matches ``SparseMerkleAccumulator.root``: absent right siblings are empty
    subtrees. Each update costs ``MERKLE_DEPTH`` hashes, so replaying N
    epochs costs O(N) hashes instead of O(N * leaves).
    """

    def __init__(self):
        self._levels = [[] for _ in range(MERKLE_DEPTH + 1)]

    def set(self, index: int, leaf: int) -> None:
        leaves = self._levels[0]
        _require(type(index) is int and 0 <= index <= len(leaves), "leaf index out of order")
        if index == len(leaves):
            leaves.append(leaf)
        else:
            leaves[index] = leaf
        position = index
        for height in range(MERKLE_DEPTH):
            level = self._levels[height]
            left = position & ~1
            right = level[left + 1] if left + 1 < len(level) else zero_subtree_root(height)
            parent = poseidon2(level[left], right)
            position >>= 1
            above = self._levels[height + 1]
            if position == len(above):
                above.append(parent)
            else:
                above[position] = parent

    def root(self) -> int:
        if not self._levels[0]:
            return zero_subtree_root(MERKLE_DEPTH)
        return self._levels[MERKLE_DEPTH][0]


def _apply_operation(replay: IssuerAccumulator, operation) -> list:
    """Apply one persisted mutation; return the changed (index, leaf) slots."""
    _require(type(operation) is dict, "operation must be an object")
    kind = operation.get("type")
    _require(
        kind in ("register", "revoke", "replace")
        and set(operation) == _OPERATION_FIELDS[kind],
        "operation shape is invalid",
    )
    try:
        if kind == "register":
            credential_id = _decode_int(operation["credentialId"])
            index = replay.register(credential_id)
            return [(index, credential_id % FIELD_MODULUS)]
        if kind == "revoke":
            credential_id = _decode_int(operation["credentialId"])
            index = replay._index_by_credential.get(credential_id)
            replay.revoke(credential_id)
            return [(index, 0)]
        old_id = _decode_int(operation["oldCredentialId"])
        new_id = _decode_int(operation["newCredentialId"])
        old_index = replay._index_by_credential.get(old_id)
        new_index = replay.replace(old_id, new_id)
        return [(new_index, new_id % FIELD_MODULUS), (old_index, 0)]
    except (AdapterError, ValueError) as exc:
        raise _InvalidHistory(f"operation cannot be replayed ({type(exc).__name__})") from exc


def _public_key_coordinates(value) -> tuple:
    _require(
        type(value) is str
        and value.startswith("0x")
        and len(value) == 2 + 128
        and value[2:] == value[2:].lower(),
        "signer public key must be 0x-prefixed 64-byte lowercase hex",
    )
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError:
        raise _InvalidHistory("signer public key must be hex") from None
    return raw[:32], raw[32:]


def _validated_signers(signers, head: int) -> list:
    """Check the signer history; return (key id, from epoch, coordinates)."""
    _require(type(signers) is list and bool(signers), "signer history is empty")
    validated = []
    key_ids, public_keys = set(), set()
    for position, signer in enumerate(signers):
        _require(
            type(signer) is dict and set(signer) == _SIGNER_FIELDS,
            "signer record shape is invalid",
        )
        key_id, public_key, from_epoch = signer["keyId"], signer["publicKey"], signer["fromEpoch"]
        _require(type(key_id) is str and bool(key_id), "signer key id is invalid")
        _require(type(from_epoch) is int, "signer fromEpoch is invalid")
        if position == 0:
            _require(from_epoch == 0, "the first signer does not sign from genesis")
        else:
            _require(
                max(1, validated[-1][1]) <= from_epoch <= head + 1,
                "signer fromEpoch is out of order",
            )
        _require(key_id not in key_ids, "signer key id is recorded twice")
        _require(public_key not in public_keys, "signer public key is recorded twice")
        key_ids.add(key_id)
        public_keys.add(public_key)
        validated.append((key_id, from_epoch, _public_key_coordinates(public_key)))
    return validated


def _replay(accumulator_id: str, update_endpoint: str, log) -> dict:
    """Authenticate a persisted log end to end and rebuild the service state."""
    _require(type(log) is dict and set(log) == _LOG_FIELDS, "log shape is invalid")
    header = log["header"]
    _require(type(header) is dict and set(header) == _HEADER_FIELDS, "header shape is invalid")
    _require(header["version"] == STATE_VERSION, "header version is unsupported")
    _require(header["accumulatorId"] == accumulator_id, "header accumulator id differs")
    max_epoch_lag = header["maxEpochLag"]
    _require(
        type(max_epoch_lag) is int and 0 <= max_epoch_lag <= MAX_EPOCH_LAG,
        "header maxEpochLag is invalid",
    )
    epochs = log["epochs"]
    _require(type(epochs) is list and bool(epochs), "epoch log is empty")
    head = len(epochs) - 1
    signers = _validated_signers(log["signers"], head)

    replay = IssuerAccumulator(accumulator_id, update_endpoint, max_epoch_lag)
    tree = _IncrementalRoot()
    announcements, snapshots = {}, {}
    previous_hash = GENESIS_ANNOUNCEMENT_HASH
    active = 0
    for epoch, record in enumerate(epochs):
        _require(
            type(record) is dict and set(record) == _EPOCH_FIELDS,
            f"epoch {epoch} record shape is invalid",
        )
        _require(
            type(record["epoch"]) is int and record["epoch"] == epoch,
            "epoch records are not contiguous",
        )
        if epoch == 0:
            _require(record["operation"] == {"type": "genesis"}, "epoch 0 is not genesis")
        else:
            for index, leaf in _apply_operation(replay, record["operation"]):
                tree.set(index, leaf)
        while active + 1 < len(signers) and signers[active + 1][1] <= epoch:
            active += 1
        key_id, _, (key_x, key_y) = signers[active]
        announcement = record["announcement"]
        _require(
            type(announcement) is dict and announcement.get("signingKeyId") == key_id,
            f"epoch {epoch} is not signed by its recorded signer",
        )
        _require(
            verify_epoch_announcement(
                announcement, key_x, key_y, expected_signing_key_id=key_id
            ),
            f"epoch {epoch} announcement signature is invalid",
        )
        _require(
            announcement["accumulatorId"] == accumulator_id
            and announcement["epoch"] == epoch
            and announcement["maxEpochLag"] == max_epoch_lag,
            f"epoch {epoch} announcement does not describe this accumulator epoch",
        )
        _require(
            announcement["previousAnnouncementHash"] == previous_hash,
            f"epoch {epoch} announcement does not commit to its predecessor",
        )
        _require(
            announcement["root"] == field_to_hex(tree.root()),
            f"epoch {epoch} root does not match the replayed accumulator",
        )
        previous_hash = announcement_hash(announcement)
        announcements[epoch] = announcement
        if epoch >= head - DELTA_SNAPSHOT_WINDOW:
            snapshots[epoch] = replay._accumulator.leaves()
    _require(
        field_to_hex(replay.root()) == announcements[head]["root"],
        "head root does not match the replayed accumulator",
    )
    return {
        "accumulator": replay,
        "maxEpochLag": max_epoch_lag,
        "announcements": announcements,
        "snapshots": snapshots,
        "lastAnnouncementHash": previous_hash,
        "signers": tuple(dict(signer) for signer in log["signers"]),
    }


def _legacy_operation(previous: list, current: list) -> dict:
    """The one mutation between two consecutive v2 leaf snapshots."""
    if len(current) == len(previous) + 1:
        added = current[-1]
        _require(added != 0, "legacy snapshot appends an empty leaf")
        zeroed = [i for i in range(len(previous)) if previous[i] != current[i]]
        if not zeroed:
            return {"type": "register", "credentialId": _encode_int(added)}
        _require(
            len(zeroed) == 1 and current[zeroed[0]] == 0 and previous[zeroed[0]] != 0,
            "legacy snapshots do not differ by one renewal",
        )
        return {
            "type": "replace",
            "oldCredentialId": _encode_int(previous[zeroed[0]]),
            "newCredentialId": _encode_int(added),
        }
    _require(len(current) == len(previous), "legacy snapshots do not differ by one mutation")
    changed = [i for i in range(len(previous)) if previous[i] != current[i]]
    _require(
        len(changed) == 1 and current[changed[0]] == 0 and previous[changed[0]] != 0,
        "legacy snapshots do not differ by one revocation",
    )
    return {"type": "revoke", "credentialId": _encode_int(previous[changed[0]])}


def _legacy_leaves(values) -> list:
    _require(type(values) is list, "legacy leaves must be a list")
    return [_decode_int(value) for value in values]


def _log_from_legacy(legacy: dict, genesis_signer: dict) -> dict:
    """Derive the append-only log equivalent to a v2 state document."""
    _require(set(legacy) == _LEGACY_FIELDS, "legacy document shape is invalid")
    head = legacy["epoch"]
    _require(type(head) is int and head >= 0, "legacy epoch is invalid")
    expected = {str(epoch) for epoch in range(head + 1)}
    snapshots, announcements = legacy["snapshots"], legacy["announcements"]
    _require(
        type(snapshots) is dict and set(snapshots) == expected,
        "legacy snapshots do not cover every epoch",
    )
    _require(
        type(announcements) is dict and set(announcements) == expected,
        "legacy announcements do not cover every epoch",
    )
    leaves = [_legacy_leaves(snapshots[str(epoch)]) for epoch in range(head + 1)]
    _require(leaves[0] == [], "legacy genesis snapshot is not empty")
    epochs = [{"epoch": 0, "operation": {"type": "genesis"}, "announcement": announcements["0"]}]
    for epoch in range(1, head + 1):
        epochs.append(
            {
                "epoch": epoch,
                "operation": _legacy_operation(leaves[epoch - 1], leaves[epoch]),
                "announcement": announcements[str(epoch)],
            }
        )
    return {
        "header": {
            "version": STATE_VERSION,
            "accumulatorId": legacy["accumulatorId"],
            "maxEpochLag": legacy["maxEpochLag"],
        },
        "signers": [genesis_signer],
        "epochs": epochs,
    }


def _check_legacy_consistency(legacy: dict, replayed: dict) -> None:
    replay = replayed["accumulator"]
    _require(
        replay._accumulator.leaves() == _legacy_leaves(legacy["leaves"]),
        "legacy leaves differ from the replayed accumulator",
    )
    index = legacy["indexByCredential"]
    _require(type(index) is dict, "legacy credential index is invalid")
    _require(
        replay._index_by_credential
        == {_decode_int(cid): position for cid, position in index.items()},
        "legacy credential index differs from the replayed accumulator",
    )
    _require(
        replay._revoked == set(_legacy_leaves(legacy["revoked"])),
        "legacy revoked set differs from the replayed accumulator",
    )
    _require(
        legacy["lastAnnouncementHash"] == replayed["lastAnnouncementHash"],
        "legacy chain head differs from the replayed announcements",
    )


class DurableRevocationAccumulatorService(RevocationAccumulatorService):
    """A ``RevocationAccumulatorService`` that persists + recovers its state."""

    def __init__(
        self,
        accumulator_id: str,
        update_endpoint: str,
        signing_key: IssuerSigningKey,
        store: AccumulatorStateStore,
        max_epoch_lag: int = MAX_EPOCH_LAG,
        clock=time.time,
        *,
        liveness_interval: int = DEFAULT_LIVENESS_INTERVAL,
    ):
        if store is None:
            raise ValueError("DurableRevocationAccumulatorService requires a state store")
        self._store = store
        super().__init__(
            accumulator_id, update_endpoint, signing_key, max_epoch_lag, clock,
            liveness_interval=liveness_interval,
        )
        # Genesis is published only once the store holds it; the store
        # refuses to create a log over existing state.
        self._publication_ready = False
        store.create_log(self._header(), self._signers[0], self._epoch_record(0, ("genesis",)))
        self._publication_ready = True

    # --- recovery -----------------------------------------------------------------

    @classmethod
    def open(
        cls,
        accumulator_id: str,
        update_endpoint: str,
        signing_key: IssuerSigningKey,
        store: AccumulatorStateStore,
        max_epoch_lag: int = MAX_EPOCH_LAG,
        clock=time.time,
        *,
        allow_rotation: bool = False,
        liveness_interval: int = DEFAULT_LIVENESS_INTERVAL,
    ) -> "DurableRevocationAccumulatorService":
        """Recover from ``store`` if it holds state, else create + persist fresh.

        The signing key and clock are supplied (never persisted). Recovery
        authenticates the whole log (module docstring) and restores the
        signed announcement chain verbatim, so the chain link is unbroken
        across the restart. ``signing_key`` must be the active recorded
        signer; with ``allow_rotation=True`` a different key instead becomes
        the successor signer (``rotate_signing_key``) once the history has
        been verified. Liveness statements are not persisted: they change no
        chain state, and the recovered service signs a fresh one on demand.
        """
        log = store.load_log()
        legacy = store.load_legacy_state()
        if log is not None and legacy is not None:
            raise AccumulatorStoreError("store holds both a legacy state document and a log")
        if legacy is not None:
            log = cls._migrate_legacy(accumulator_id, update_endpoint, signing_key, store, legacy)
        if log is None:
            return cls(
                accumulator_id, update_endpoint, signing_key, store, max_epoch_lag, clock,
                liveness_interval=liveness_interval,
            )
        return cls._restore(
            accumulator_id, update_endpoint, signing_key, store, clock, log, allow_rotation,
            liveness_interval,
        )

    @classmethod
    def _restore(
        cls, accumulator_id, update_endpoint, signing_key, store, clock, log, allow_rotation,
        liveness_interval=DEFAULT_LIVENESS_INTERVAL,
    ) -> "DurableRevocationAccumulatorService":
        liveness_interval = _liveness_interval(liveness_interval)
        header = log.get("header") if type(log) is dict else None
        version = header.get("version") if type(header) is dict else None
        if version != STATE_VERSION:
            raise AccumulatorStoreError(f"unsupported accumulator state version: {version!r}")
        if header.get("accumulatorId") != accumulator_id:
            raise AccumulatorStoreError(
                "accumulator id in store does not match the service being recovered"
            )
        try:
            replayed = _replay(accumulator_id, update_endpoint, log)
        except _InvalidHistory as exc:
            raise AccumulatorStoreError(f"persisted accumulator history is invalid: {exc}") from exc

        replay = replayed["accumulator"]
        instance = cls.__new__(cls)
        # Reconstruct IssuerAccumulator base fields without re-running __init__.
        instance._lock = RLock()
        instance.accumulator_id = accumulator_id
        instance.update_endpoint = update_endpoint
        instance.max_epoch_lag = replayed["maxEpochLag"]
        instance._accumulator = SparseMerkleAccumulator(replay._accumulator.leaves())
        instance._epoch = replay.epoch
        instance._index_by_credential = dict(replay._index_by_credential)
        instance._revoked = set(replay._revoked)
        # RevocationAccumulatorService fields.
        instance._clock = clock
        instance._snapshots = replayed["snapshots"]
        instance._announcements = replayed["announcements"]
        instance._last_announcement_hash = replayed["lastAnnouncementHash"]
        instance._signers = replayed["signers"]
        instance._store = store
        instance._liveness_interval = liveness_interval
        instance._liveness = None
        instance._publication_ready = True
        instance._resume_signing_key(signing_key, allow_rotation)
        return instance

    def _resume_signing_key(self, signing_key, allow_rotation: bool) -> None:
        active = self._signers[-1]
        record = self._admit_signing_key(signing_key, active["fromEpoch"])
        if record["keyId"] == active["keyId"] and record["publicKey"] == active["publicKey"]:
            self._signing_key = signing_key
            return
        for signer in self._signers:
            if record["keyId"] == signer["keyId"] or record["publicKey"] == signer["publicKey"]:
                raise AccumulatorStoreError(
                    f"signing key {record['keyId']!r} does not match the active announcement "
                    f"signer {active['keyId']!r}: its key id or public key belongs to recorded "
                    f"signer {signer['keyId']!r}, and recorded keys are never reused"
                )
        if not allow_rotation:
            raise AccumulatorStoreError(
                f"signing key {record['keyId']!r} is not the active announcement signer "
                f"{active['keyId']!r} recorded in the store; open with the active key, or "
                "pass allow_rotation=True to make this key its successor"
            )
        try:
            self.rotate_signing_key(signing_key)
        except ValueError as exc:
            raise AccumulatorStoreError(
                f"signing key {record['keyId']!r} cannot succeed the recorded signers: {exc}"
            ) from exc

    @classmethod
    def _migrate_legacy(cls, accumulator_id, update_endpoint, signing_key, store, legacy) -> dict:
        """Verify a v2 state document and replace it with the equivalent log.

        v2 kept a leaf snapshot for every epoch, so each epoch's mutation is
        the difference between consecutive snapshots. v2 recovery required
        the supplied key to have signed every announcement, so its public
        record becomes the genesis signer. The document stays untouched
        unless the derived log authenticates and replays to exactly the v2
        leaves, credential index, revoked set and chain head.
        """
        version = legacy.get("version") if type(legacy) is dict else None
        if version != LEGACY_STATE_VERSION:
            raise AccumulatorStoreError(f"unsupported accumulator state version: {version!r}")
        if legacy.get("accumulatorId") != accumulator_id:
            raise AccumulatorStoreError(
                "accumulator id in store does not match the service being recovered"
            )
        try:
            log = _log_from_legacy(legacy, signer_record(signing_key, 0))
            _check_legacy_consistency(legacy, _replay(accumulator_id, update_endpoint, log))
        except _InvalidHistory as exc:
            raise AccumulatorStoreError(
                f"legacy accumulator state cannot be migrated: {exc}"
            ) from exc
        store.replace_legacy_state(log["header"], log["signers"], log["epochs"])
        return log

    # --- persistence write-through ------------------------------------------------

    def _header(self) -> dict:
        return {
            "version": STATE_VERSION,
            "accumulatorId": self.accumulator_id,
            "maxEpochLag": self.max_epoch_lag,
        }

    def _epoch_record(self, epoch: int, operation: tuple) -> dict:
        return {
            "epoch": epoch,
            "operation": _encode_operation(operation),
            "announcement": self._announcements[epoch],
        }

    # This hook runs on the detached candidate under the accumulator lock.
    # The live service is unchanged until the atomic append returns.
    def _after_epoch_recorded(self, operation: tuple) -> None:
        self._store.append_epoch(self._epoch_record(self.epoch, operation))

    # Runs under the lock before the active signer changes.
    def _after_signer_recorded(self, record: dict) -> None:
        self._store.append_signer(record)

    def _serialize_state(self) -> dict:
        """Diagnostic view of the complete live state (not the stored format)."""
        return {
            "version": STATE_VERSION,
            "accumulatorId": self.accumulator_id,
            "maxEpochLag": self.max_epoch_lag,
            "epoch": self._epoch,
            "leaves": [_encode_int(leaf) for leaf in self._accumulator.leaves()],
            "indexByCredential": {
                _encode_int(cid): int(index) for cid, index in self._index_by_credential.items()
            },
            "revoked": [_encode_int(cid) for cid in sorted(self._revoked)],
            "snapshots": {
                str(epoch): [_encode_int(leaf) for leaf in leaves]
                for epoch, leaves in sorted(self._snapshots.items())
            },
            "announcements": {
                str(epoch): dict(announcement)
                for epoch, announcement in sorted(self._announcements.items())
            },
            "lastAnnouncementHash": self._last_announcement_hash,
            "signers": [dict(signer) for signer in self._signers],
        }
