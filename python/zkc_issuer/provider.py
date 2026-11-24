"""Bridge issuer adapters into the holder SDK's AccumulatorProvider interface.

Lets a ``zkc_holder.HolderClient`` refresh non-revocation witnesses directly
from in-process issuer adapters (sandbox/local flows and tests). Revoked or
unknown credentials surface as ``StaleWitnessError`` — the holder SDK's
fail-closed signal.
"""

from __future__ import annotations

from zkc_holder.accumulator import AccumulatorProvider
from zkc_holder.credential import AccumulatorWitness
from zkc_holder.errors import StaleWitnessError

from .errors import AdapterError

__all__ = ["IssuerAdapterAccumulatorProvider"]


class IssuerAdapterAccumulatorProvider(AccumulatorProvider):
    """AccumulatorProvider backed by one or more issuer adapters."""

    def __init__(self, adapters):
        """`adapters`: iterable of SandboxIssuerAdapter (keyed by issuer_id)."""
        self._adapters = {adapter.issuer_id: adapter for adapter in adapters}

    def _adapter(self, issuer_id: str):
        adapter = self._adapters.get(issuer_id)
        if adapter is None:
            raise StaleWitnessError(f"no accumulator source for issuer {issuer_id}")
        return adapter

    def current_epoch(self, issuer_id: str) -> int:
        return self._adapter(issuer_id).accumulator.epoch

    def witness(self, issuer_id: str, credential_id: int) -> AccumulatorWitness:
        try:
            witness = self._adapter(issuer_id).accumulator.witness(credential_id)
        except AdapterError as exc:
            raise StaleWitnessError(
                "issuer reports the credential is not active (revoked or unknown)"
            ) from exc
        return AccumulatorWitness.from_dict(witness)
