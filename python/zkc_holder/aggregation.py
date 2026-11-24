"""Aggregation entry point — mirrors noir/zkc_aggregation.

The aggregation circuit is a simulated-recursion profile: it commits to each
inner proof's (vk, proof bytes, public inputs, proof type) rather than
natively verifying it. This module reproduces those commitments in Python.

Reference packings (deployment-defined; pinned here for the reference stack):

* `pack_bytes_to_fields(data, count, tag)` spreads arbitrary bytes over a
  fixed-size field vector: element i = Blake2b-512(tag || u32(i) || data)
  little-endian mod Fr. Inner proofs/vks exceed 64*31 bytes, so a direct
  chunk packing cannot be injective anyway; the vector is a commitment.
* Public inputs pack their canonical JSON the same way into 12 elements.
* `proof_type` field = zkc_crypto.string_to_field(proofType).
"""

from __future__ import annotations

import hashlib
import json

from zkc_crypto import FIELD_MODULUS, poseidon2, poseidon4, string_to_field

from .errors import ConsentRequiredError, ConstraintViolationError

__all__ = [
    "AGGREGATE_V3_CIRCUIT",
    "AGGREGATE_V3_PROOF_TYPE",
    "VK_SIZE",
    "PROOF_SIZE",
    "PUBLIC_INPUT_SIZE",
    "MAX_AGGREGATED_PROOFS",
    "pack_bytes_to_fields",
    "pack_public_inputs",
    "inner_proof_commitment",
    "aggregate_commitments",
    "aggregated_claim_binding",
]

AGGREGATE_V3_PROOF_TYPE = "zkc:proof:aggregate:v3"
AGGREGATE_V3_CIRCUIT = "zkc_aggregation_v3"

MAX_AGGREGATED_PROOFS = 8
VK_SIZE = 64
PROOF_SIZE = 64
PUBLIC_INPUT_SIZE = 12

DOMAIN_ZKC_AGGREGATION_SEED = 0x11AA333333333333333333333333333333333333333333333333333333333333
DOMAIN_ZKC_AGGREGATION_VERIFY = 0x11AA444444444444444444444444444444444444444444444444444444444444


def pack_bytes_to_fields(data: bytes, count: int, tag: bytes) -> list:
    """Spread `data` deterministically over `count` field elements."""
    fields = []
    for index in range(count):
        digest = hashlib.blake2b(
            tag + index.to_bytes(4, "big") + data, digest_size=64
        ).digest()
        fields.append(int.from_bytes(digest, "little") % FIELD_MODULUS)
    return fields


def pack_public_inputs(public_inputs: dict) -> list:
    canonical = json.dumps(public_inputs, sort_keys=True).encode()
    return pack_bytes_to_fields(canonical, PUBLIC_INPUT_SIZE, b"zkc-agg-inputs-v1")


def _chain(domain: int, fields) -> int:
    acc = domain
    for value in fields:
        acc = poseidon2(acc, value)
    return acc


def inner_proof_commitment(
    vk_fields, proof_fields, input_fields, proof_type_field: int
) -> int:
    """zkc_aggregation::verify_inner_proof."""
    if len(vk_fields) != VK_SIZE or len(proof_fields) != PROOF_SIZE:
        raise ConstraintViolationError("vk/proof field vectors have wrong size")
    if len(input_fields) != PUBLIC_INPUT_SIZE:
        raise ConstraintViolationError("public input field vector has wrong size")
    vk_acc = _chain(DOMAIN_ZKC_AGGREGATION_VERIFY, vk_fields)
    proof_acc = _chain(DOMAIN_ZKC_AGGREGATION_VERIFY, proof_fields)
    input_acc = _chain(DOMAIN_ZKC_AGGREGATION_VERIFY, input_fields)
    return poseidon4(vk_acc, proof_acc, input_acc, proof_type_field)


def commitment_for_envelope_proof(proof_entry: dict, vk_bytes: bytes) -> int:
    """Commitment for one envelope proof entry."""
    proof_bytes = proof_entry["proof"].encode()
    return inner_proof_commitment(
        pack_bytes_to_fields(vk_bytes, VK_SIZE, b"zkc-agg-vk-v1"),
        pack_bytes_to_fields(proof_bytes, PROOF_SIZE, b"zkc-agg-proof-v1"),
        pack_public_inputs(proof_entry["publicInputs"]),
        string_to_field(proof_entry["proofType"]),
    )


def aggregate_commitments(
    context: int,
    holder_commitment: int,
    proof_commitments,
    proof_type_fields,
    consent_flags,
) -> int:
    """zkc_aggregation::aggregate_commitments (active prefix form)."""
    num_proofs = len(proof_commitments)
    if not 1 <= num_proofs <= MAX_AGGREGATED_PROOFS:
        raise ConstraintViolationError("aggregation requires between 1 and 8 proofs")
    if context == 0:
        raise ConstraintViolationError("context must be non-zero")
    if holder_commitment == 0:
        raise ConstraintViolationError("holder commitment must be non-zero")
    acc = poseidon2(DOMAIN_ZKC_AGGREGATION_SEED, context)
    acc = poseidon2(acc, holder_commitment)
    for slot in range(MAX_AGGREGATED_PROOFS):
        if slot < num_proofs:
            if not consent_flags[slot]:
                raise ConsentRequiredError("missing consent for aggregated proof")
            contribution = poseidon2(proof_commitments[slot], proof_type_fields[slot])
        else:
            contribution = 0
        acc = poseidon2(acc, contribution)
    return acc


def aggregated_claim_binding(aggregation_commitment: int, context: int) -> int:
    return poseidon2(aggregation_commitment, context)
