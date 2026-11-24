"""Deterministic stub-proof payload shared by the reference holder/verifier.

A stub proof (`zkc:stub:v1:<sha256>`) carries NO cryptographic soundness.
It exists so the reference stack's unit tests run without the Noir
toolchain. Production verification paths MUST reject stub proofs.
"""

from __future__ import annotations

import hashlib
import json

__all__ = ["STUB_PROOF_PREFIX", "stub_proof_payload"]

STUB_PROOF_PREFIX = "zkc:stub:v1:"


def stub_proof_payload(circuit: str, public_inputs: dict) -> str:
    canonical = json.dumps({"circuit": circuit, "publicInputs": public_inputs}, sort_keys=True)
    return STUB_PROOF_PREFIX + hashlib.sha256(canonical.encode()).hexdigest()
