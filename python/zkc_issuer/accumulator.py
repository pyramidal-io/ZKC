"""Issuer-side non-revocation accumulator state.

Wraps ``zkc_crypto.SparseMerkleAccumulator`` (the depth-32 Poseidon2 Merkle
active-credential set matching ``noir/zkc_nonrevocation``) with the epoch and
metadata the adapter protocol publishes. Adding or revoking a credential
advances the epoch; witnesses are issued against the current root/epoch.
"""

from __future__ import annotations

from functools import wraps
from threading import RLock

from zkc_crypto import FIELD_MODULUS, MERKLE_DEPTH, SparseMerkleAccumulator, field_to_hex

from .errors import AdapterError

__all__ = ["ACCUMULATOR_TYPE", "MAX_EPOCH_LAG", "IssuerAccumulator"]

ACCUMULATOR_TYPE = "POSEIDON2_MERKLE_ACTIVE_SET"

# Mirrors zkc_nonrevocation::MAX_EPOCH_LAG.
MAX_EPOCH_LAG = 10


def _is_canonical_credential_id(credential_id) -> bool:
    return type(credential_id) is int and 0 < credential_id < FIELD_MODULUS


def _require_canonical_credential_id(credential_id) -> int:
    """Credential ids are leaves, so only canonical non-zero field elements.

    The Merkle tree stores a leaf modulo p and zero marks a revoked slot. A
    non-canonical id would alias a canonical leaf while being tracked as a
    separate credential, so every mutation refuses one.
    """
    if not _is_canonical_credential_id(credential_id):
        raise AdapterError(
            "REVOCATION_METADATA_UNAVAILABLE",
            "credential id must be a canonical non-zero field element",
        )
    return credential_id


def _locked(method):
    """Serialize state access with the instance's one reentrant lock."""
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return locked


class IssuerAccumulator:
    """Active-credential accumulator with epoch lifecycle."""

    def __init__(
        self,
        accumulator_id: str,
        update_endpoint: str,
        max_epoch_lag: int = MAX_EPOCH_LAG,
    ):
        if not 0 <= max_epoch_lag <= MAX_EPOCH_LAG:
            raise ValueError(f"max_epoch_lag must be within [0, {MAX_EPOCH_LAG}]")
        self.accumulator_id = accumulator_id
        self.update_endpoint = update_endpoint
        self.max_epoch_lag = max_epoch_lag
        self._lock = RLock()
        self._accumulator = SparseMerkleAccumulator()
        self._epoch = 0
        self._index_by_credential: dict = {}
        self._revoked: set = set()

    # --- lifecycle -----------------------------------------------------------

    @_locked
    def register(self, credential_id: int) -> int:
        """Add an issued credential; advances the epoch. Returns the leaf index."""
        _require_canonical_credential_id(credential_id)
        if credential_id in self._index_by_credential:
            raise ValueError("credential is already registered in the accumulator")
        index = self._accumulator.add(credential_id)
        self._index_by_credential[credential_id] = index
        self._epoch += 1
        return index

    @_locked
    def revoke(self, credential_id: int) -> None:
        """Zero the credential's leaf; advances the epoch."""
        _require_canonical_credential_id(credential_id)
        index = self._index_by_credential.get(credential_id)
        if index is None or credential_id in self._revoked:
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE",
                "credential is not active in this accumulator",
            )
        self._accumulator.remove(index)
        self._revoked.add(credential_id)
        self._epoch += 1

    @_locked
    def replace(self, old_credential_id: int, new_credential_id: int) -> int:
        """ATOMIC renewal slot swap: register the new credential and revoke
        the old one as one epoch transition — both-or-neither.

        All validation happens before any mutation, so a failure leaves the
        accumulator (and its epoch) untouched. Returns the new leaf index.
        """
        _require_canonical_credential_id(old_credential_id)
        _require_canonical_credential_id(new_credential_id)
        old_index = self._index_by_credential.get(old_credential_id)
        if old_index is None or old_credential_id in self._revoked:
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE",
                "renewal source credential is not active in this accumulator",
            )
        if new_credential_id in self._index_by_credential:
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE",
                "renewal target credential is already registered",
            )
        # Mutations: validated above, cannot half-fail below.
        new_index = self._accumulator.add(new_credential_id)
        self._index_by_credential[new_credential_id] = new_index
        self._accumulator.remove(old_index)
        self._revoked.add(old_credential_id)
        self._epoch += 1
        return new_index

    # Queries answer False for a non-canonical id: only canonical ids are ever
    # stored, so such an id names no credential (and cannot alias one).

    @_locked
    def is_active(self, credential_id: int) -> bool:
        return (
            _is_canonical_credential_id(credential_id)
            and credential_id in self._index_by_credential
            and credential_id not in self._revoked
        )

    @_locked
    def is_known(self, credential_id: int) -> bool:
        return _is_canonical_credential_id(credential_id) and credential_id in self._index_by_credential

    @_locked
    def credential_ids(self) -> frozenset:
        """Every credential id ever registered (active or revoked)."""
        return frozenset(self._index_by_credential)

    # --- state ----------------------------------------------------------------

    @property
    @_locked
    def epoch(self) -> int:
        return self._epoch

    @_locked
    def root(self) -> int:
        return self._accumulator.root()

    @_locked
    def witness(self, credential_id: int) -> dict:
        """Membership witness dict (AccumulatorWitness wire shape).

        Fails closed for revoked or unknown credentials.
        """
        if not self.is_active(credential_id):
            raise AdapterError(
                "STALE_ACCUMULATOR_WITNESS",
                "credential is not active in the accumulator (revoked or unknown)",
            )
        index = self._index_by_credential[credential_id]
        path_index, siblings = self._accumulator.witness(index)
        assert len(siblings) == MERKLE_DEPTH
        return {
            "pathIndex": path_index,
            "siblings": [field_to_hex(sibling) for sibling in siblings],
            "accumulatorRoot": field_to_hex(self.root()),
            "accumulatorEpoch": self._epoch,
        }

    @_locked
    def metadata(self) -> dict:
        """The `revocation` block of issuer metadata."""
        return {
            "accumulatorId": self.accumulator_id,
            "type": ACCUMULATOR_TYPE,
            "currentRoot": field_to_hex(self.root()),
            "currentEpoch": self._epoch,
            "maxEpochLag": self.max_epoch_lag,
            "updateEndpoint": self.update_endpoint,
        }
