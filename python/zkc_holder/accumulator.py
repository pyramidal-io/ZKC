"""Accumulator (non-revocation) providers for witness refresh.

`AccumulatorProvider` is the interface issuers expose for witness updates
(spec §2.4, §4.4). `LocalAccumulatorProvider` is the reference in-process
implementation backed by zkc_crypto.SparseMerkleAccumulator — used by the
mock issuer flow and the conformance suite.
"""

from __future__ import annotations

from zkc_crypto import SparseMerkleAccumulator

from .credential import AccumulatorWitness
from .errors import StaleWitnessError

__all__ = ["MAX_EPOCH_LAG", "AccumulatorProvider", "LocalAccumulatorProvider"]

# Mirrors zkc_nonrevocation::MAX_EPOCH_LAG.
MAX_EPOCH_LAG = 10


class AccumulatorProvider:
    """Witness-refresh interface, keyed by issuer."""

    def current_epoch(self, issuer_id: str) -> int:
        raise NotImplementedError

    def witness(self, issuer_id: str, credential_id: int) -> AccumulatorWitness:
        """Fresh membership witness; raises StaleWitnessError when the
        credential is no longer in the accumulator (revoked)."""
        raise NotImplementedError


class LocalAccumulatorProvider(AccumulatorProvider):
    def __init__(self):
        self._accumulators = {}
        self._epochs = {}
        # issuer_id -> epoch -> leaf snapshot, so the issuer's root for any
        # past epoch stays answerable after later registrations/revocations.
        self._history = {}
        self._root_cache = {}

    def _accumulator(self, issuer_id: str) -> SparseMerkleAccumulator:
        if issuer_id not in self._accumulators:
            self._accumulators[issuer_id] = SparseMerkleAccumulator()
            self._epochs[issuer_id] = 0
            self._history[issuer_id] = {0: ()}
        return self._accumulators[issuer_id]

    def _advance(self, issuer_id: str) -> None:
        self._epochs[issuer_id] += 1
        leaves = tuple(self._accumulators[issuer_id].leaves())
        self._history[issuer_id][self._epochs[issuer_id]] = leaves

    def register(self, issuer_id: str, credential_id: int) -> None:
        self._accumulator(issuer_id).add(credential_id)
        self._advance(issuer_id)

    def revoke(self, issuer_id: str, credential_id: int) -> None:
        accumulator = self._accumulator(issuer_id)
        accumulator.remove(accumulator.index_of(credential_id))
        self._advance(issuer_id)

    def advance_epoch(self, issuer_id: str, count: int = 1) -> None:
        self._accumulator(issuer_id)
        for _ in range(count):
            self._advance(issuer_id)

    def current_epoch(self, issuer_id: str) -> int:
        self._accumulator(issuer_id)
        return self._epochs[issuer_id]

    def roots(self, issuer_id: str) -> dict:
        """The issuer's accumulator root for every epoch it has published.

        This is what a verifier records from the issuer (spec section 6.2 step
        4c) to check a proof's ``accumulator_root``: a proof against a root the
        issuer never published -- e.g. a revoked holder's self-made one-leaf
        tree -- has no recorded match and is rejected."""
        self._accumulator(issuer_id)
        roots = {}
        for epoch, leaves in self._history[issuer_id].items():
            if leaves not in self._root_cache:
                self._root_cache[leaves] = SparseMerkleAccumulator(leaves).root()
            roots[epoch] = self._root_cache[leaves]
        return roots

    def witness(self, issuer_id: str, credential_id: int) -> AccumulatorWitness:
        accumulator = self._accumulator(issuer_id)
        try:
            index = accumulator.index_of(credential_id)
        except KeyError:
            raise StaleWitnessError(
                "credential is not present in the issuer accumulator (revoked or never registered)"
            ) from None
        path_index, siblings = accumulator.witness(index)
        return AccumulatorWitness(
            path_index=path_index,
            siblings=siblings,
            accumulator_root=accumulator.root(),
            accumulator_epoch=self._epochs[issuer_id],
        )
