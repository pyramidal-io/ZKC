"""AFP-KDC v1.0.3 registry metadata for credential binding and ZKC claims.

The field-derivation profile and KAT provenance remain the immutable AFP-KDC
v1.0.2 evidence.

Mirrors noir/zkc_lib/src/lib.nr exactly; validated against the golden vectors
in tests/vectors/zkc_core_vectors.json.
"""

from __future__ import annotations

from .field import derive_domain
from .master_seed import master_seed_to_field
from .poseidon2 import poseidon2, poseidon3, poseidon4

__all__ = [
    "DOMAIN_ZKC_CREDENTIAL",
    "DOMAIN_ZKC_BINDING",
    "DOMAIN_ZKC_CLAIM",
    "derive_credential_binding_key",
    "derive_holder_commitment",
    "derive_holder_commitment_from_seed",
    "compute_claim_binding_2",
    "compute_claim_binding_3",
    "compute_claim_binding_4",
]

# Pinned in noir/zkc_lib/src/lib.nr; rederived here from the canonical
# Blake2b construction so drift in either direction fails tests.
DOMAIN_ZKC_CREDENTIAL = derive_domain("zkc/credential")
DOMAIN_ZKC_BINDING = derive_domain("zkc/binding")
DOMAIN_ZKC_CLAIM = derive_domain("zkc/claim")

assert DOMAIN_ZKC_CREDENTIAL == 0x3010B194AEAE94550E7A48D065D9DC931108C2D15136704BF4AD78EAE07F0E26
assert DOMAIN_ZKC_BINDING == 0x12B8B6DE2C8FC6B63102155D15C31799845A1F360AB0DF6266284BDE48E3A93F
assert DOMAIN_ZKC_CLAIM == 0x0B929496A58D5A41CBA03A3302B92F5D7781AD2913285AEC7A5431647C50C9D4


def derive_credential_binding_key(master_seed: int | bytes | str) -> int:
    """cbk = H("zkc/credential", seedToField(masterSeed)) — KDC §A.6."""
    return poseidon2(DOMAIN_ZKC_CREDENTIAL, master_seed_to_field(master_seed))


def derive_holder_commitment(credential_binding_key: int) -> int:
    """holderCommitment = H("zkc/binding", cbk) — KDC §A.6."""
    return poseidon2(DOMAIN_ZKC_BINDING, credential_binding_key)


def derive_holder_commitment_from_seed(master_seed: int | bytes | str) -> int:
    return derive_holder_commitment(derive_credential_binding_key(master_seed))


def compute_claim_binding_2(
    claim_parameter_0: int,
    claim_parameter_1: int,
    proof_context: int,
    timestamp: int,
) -> int:
    """zkc_lib::compute_claim_binding_2."""
    claim_hash = poseidon3(DOMAIN_ZKC_CLAIM, claim_parameter_0, claim_parameter_1)
    return poseidon3(claim_hash, proof_context, timestamp)


def compute_claim_binding_3(
    claim_parameter_0: int,
    claim_parameter_1: int,
    claim_parameter_2: int,
    proof_context: int,
    timestamp: int,
) -> int:
    """zkc_lib::compute_claim_binding_3."""
    claim_hash = poseidon4(
        DOMAIN_ZKC_CLAIM, claim_parameter_0, claim_parameter_1, claim_parameter_2
    )
    return poseidon3(claim_hash, proof_context, timestamp)


def compute_claim_binding_4(
    claim_parameter_0: int,
    claim_parameter_1: int,
    claim_parameter_2: int,
    flag_required: bool,
    proof_context: int,
    timestamp: int,
) -> int:
    """Four-slot request binding used by the remaining-predicate successors.

    ``flag_required`` is deliberately type-strict: APR canonical JSON treats a
    boolean as distinct from ``0``/``1``, so the transcript mirror must not
    collapse those representations before verification.
    """
    if type(flag_required) is not bool:
        raise ValueError("flag_required must be an exact boolean")
    inner = poseidon4(
        DOMAIN_ZKC_CLAIM,
        claim_parameter_0,
        claim_parameter_1,
        claim_parameter_2,
    )
    claim_hash = poseidon2(inner, int(flag_required))
    return poseidon3(claim_hash, proof_context, timestamp)
