"""Presentation-profile derivations (ADR 0001, design doc §2).

presentation_pseudonym is the only derivation that must be provable
in-circuit, so it uses Poseidon. verifier_identity and scope_id are computed
natively by holder and verifier, so they reuse a Blake2b-to-field reduction in
the same spirit as derive_domain.
"""

import hashlib

from .field import string_to_field
from .kdc import derive_domain
from .poseidon2 import FIELD_MODULUS, poseidon3

__all__ = [
    "ANONYMOUS_PROFILE",
    "SCOPED_PROFILE",
    "LINKABLE_PROFILE",
    "DOMAIN_ZKC_PRESENTATION_SCOPE",
    "DOMAIN_ZKC_SCOPE",
    "DOMAIN_ZKC_VERIFIER_ID",
    "hash_bytes_to_field",
    "derive_verifier_identity",
    "derive_scope_id",
    "derive_presentation_pseudonym",
]

ANONYMOUS_PROFILE = "zkc:presentation:anonymous:v1"
SCOPED_PROFILE = "zkc:presentation:scoped:v1"
LINKABLE_PROFILE = "zkc:presentation:linkable:v1"

DOMAIN_ZKC_PRESENTATION_SCOPE = derive_domain("zkc/presentation-scope:v1")
DOMAIN_ZKC_SCOPE = derive_domain("zkc/scope:v1")
DOMAIN_ZKC_VERIFIER_ID = derive_domain("zkc/verifier-id:v1")


def hash_bytes_to_field(domain: str, payload: bytes) -> int:
    """Blake2b(domain-tag || payload) reduced into the field (native only)."""
    digest = hashlib.blake2b(domain.encode("utf-8") + b"\x00" + payload).digest()
    return int.from_bytes(digest, "big") % FIELD_MODULUS


def derive_verifier_identity(sec1_compressed_pubkey: bytes) -> int:
    """verifier_identity over the APR signer's SEC1 compressed key (design §2)."""
    if len(sec1_compressed_pubkey) != 33 or sec1_compressed_pubkey[0] not in (2, 3):
        raise ValueError("verifier identity requires a SEC1 compressed public key")
    return hash_bytes_to_field("zkc/verifier-id:v1", sec1_compressed_pubkey)


def derive_scope_id(verifier_identity: int, scope_policy: str, rotation_epoch: int) -> int:
    """scope_id = H('zkc/scope:v1', verifier_identity, string_to_field(scope_policy), rotation_epoch).

    Payload layout per design §2:
      field_be_bytes(verifier_identity)
        || field_be_bytes(string_to_field(scope_policy))
        || u64_be_bytes(rotation_epoch)
    """
    if rotation_epoch < 0:
        raise ValueError("rotation_epoch must be non-negative")
    payload = (
        int(verifier_identity).to_bytes(32, "big")
        + int(string_to_field(scope_policy)).to_bytes(32, "big")
        + int(rotation_epoch).to_bytes(8, "big")
    )
    scope_id = hash_bytes_to_field("zkc/scope:v1", payload)
    if scope_id == 0:
        raise ValueError("derived scope_id collided with the anonymous sentinel")
    return scope_id


def derive_presentation_pseudonym(credential_binding_key: int, scope_id: int) -> int:
    """presentationPseudonym = H('zkc/presentation-scope:v1', cbk, scopeId)."""
    if scope_id == 0:
        raise ValueError("scope_id 0 is the anonymous sentinel; no pseudonym exists")
    return poseidon3(DOMAIN_ZKC_PRESENTATION_SCOPE, credential_binding_key, scope_id)
