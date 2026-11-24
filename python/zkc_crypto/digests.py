"""Credential digests signed by ZKC issuers.

Each function mirrors the digest computation inside the corresponding Noir
circuit; the issuer ECDSA signature covers the 32-byte big-endian encoding of
the returned field element.
"""

from __future__ import annotations

from types import MappingProxyType

from .field import FIELD_MODULUS, field_to_hex, hex_to_field, string_to_field
from .kdc import DOMAIN_ZKC_CLAIM
from .poseidon2 import hash_fields, poseidon2, poseidon3, poseidon4

__all__ = [
    "compute_attribute_flags_hash",
    "compute_jurisdiction_credential_digest",
    "compute_jurisdiction_leaf",
    "compute_kyc_credential_digest",
    "compute_profile_digest",
    "compute_profile_digest_v2",
    "compute_rebind_attestation_digest",
    "REBIND_ATTESTATION_TYPE",
    "REBIND_ATTESTATION_VERSION",
    "compute_runtime_attestation_claim_commitment",
    "compute_runtime_attestation_credential_digest",
    "compute_selective_disclosure_binding",
    "compute_selective_disclosure_binding_v3",
    "compute_selective_disclosure_credential_digest",
    "compute_selective_disclosure_credential_digest_v2",
    "digest_to_message_bytes",
    "parse_attribute_layout_id",
    "RUNTIME_ATTESTATION_ROOT_CLASS_CODES",
    "RUNTIME_ATTESTATION_SCHEMA_ID",
]

SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES = 8
SELECTIVE_DISCLOSURE_CREDENTIAL_TYPE = string_to_field("zkc:cred:attribute-set:v1")
SELECTIVE_DISCLOSURE_TRANSCRIPT_TYPE = string_to_field(
    "zkc:proof:selective_disclosure:v1"
)
_ATTRIBUTE_SET_V2_TYPE = string_to_field("zkc:cred:attribute-set:v2")
_SELECTIVE_DISCLOSURE_V3_TYPE = string_to_field("zkc:proof:selective_disclosure:v3")
LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES = frozenset({
    "zkc:proof:selective_disclosure:v1",
    "zkc:proof:selective_disclosure:v2",
})


def parse_attribute_layout_id(value: str) -> int:
    """Parse the exact wire spelling of a nonzero attribute-layout field."""
    if type(value) is not str or len(value) != 66:
        raise ValueError("layoutId must be canonical 32-byte lowercase field hex")
    parsed = hex_to_field(value)
    if parsed == 0 or field_to_hex(parsed) != value:
        raise ValueError("layoutId must be canonical 32-byte lowercase hex for a nonzero field")
    return parsed


def _require_layout_field(value: int) -> int:
    if type(value) is not int or not 0 < value < FIELD_MODULUS:
        raise ValueError("layout_id must be a nonzero canonical field element")
    return value

RUNTIME_ATTESTATION_SCHEMA_ID = "zkc:cred:runtime-attestation:v1"

# Issuer-authenticated credential-rebind transcript (spec section 7.4).
# The issuer signs this digest for every credential it is willing to let the
# holder migrate; the authenticated rebind circuits recompute it from
# constrained fields, so no credential, issuer, schema, holder, or validity
# value in the rebind statement is prover-chosen.
REBIND_ATTESTATION_VERSION = "zkc:attestation:credential-rebind:v1"
REBIND_ATTESTATION_TYPE = string_to_field(REBIND_ATTESTATION_VERSION)
RUNTIME_ATTESTATION_ROOT_CLASS_CODES = MappingProxyType(
    {
        "root:build-provenance": 1,
        "root:tee-attestation": 2,
    }
)


def compute_attribute_flags_hash(attributes) -> int:
    """zkc_kyc::compute_attribute_flags_hash over exactly 5 boolean flags."""
    attributes = list(attributes)
    if len(attributes) != 5:
        raise ValueError("KYC attribute flag vector must have exactly 5 entries")
    acc = 0
    for flag in attributes:
        if not isinstance(flag, bool):
            raise ValueError("KYC attribute flags must be booleans")
        acc = poseidon2(acc, 1 if flag else 0)
    return acc


def compute_kyc_credential_digest(
    holder_commitment: int,
    credential_id: int,
    credential_level: int,
    verified_attributes,
    credential_expires_at: int,
) -> int:
    """zkc_kyc::compute_kyc_credential_digest."""
    attribute_hash = compute_attribute_flags_hash(verified_attributes)
    header_hash = poseidon3(holder_commitment, credential_id, credential_level)
    return poseidon3(header_hash, attribute_hash, credential_expires_at)


def compute_profile_digest(
    holder_commitment: int,
    credential_id: int,
    predicate_type: int,
    claim_0: int,
    claim_1: int,
    valid_until: int,
) -> int:
    """zkc_remaining_predicates::compute_profile_digest."""
    header = poseidon4(holder_commitment, credential_id, predicate_type, valid_until)
    return poseidon3(header, claim_0, claim_1)


def compute_profile_digest_v2(
    holder_commitment: int,
    credential_id: int,
    predicate_type: int,
    claim_0: int,
    claim_1: int,
    valid_from: int,
    valid_until: int,
) -> int:
    """Current profile-credential digest with both validity bounds signed.

    This construction is intentionally additive.  ``compute_profile_digest``
    remains the exact v1--v4 construction so already-issued credentials and
    their historical proofs retain their byte-for-byte digest semantics.
    """
    header = poseidon4(holder_commitment, credential_id, predicate_type, valid_from)
    return poseidon4(header, claim_0, claim_1, valid_until)


def compute_rebind_attestation_digest(
    issuer_id_hash: int,
    schema_id_hash: int,
    holder_commitment: int,
    credential_id: int,
    valid_from: int,
    valid_until: int,
) -> int:
    """Issuer-signed ``zkc:attestation:credential-rebind:v1`` transcript digest.

    ``header = Poseidon4(DOMAIN_ZKC_CLAIM, REBIND_ATTESTATION_TYPE,
    issuer_id_hash, schema_id_hash)``; ``body = Poseidon4(holder_commitment,
    credential_id, valid_from, valid_until)``; ``digest = Poseidon2(header,
    body)``. ``issuer_id_hash`` / ``schema_id_hash`` are
    ``string_to_field(issuerId)`` / ``string_to_field(schemaId)``. The issuer
    signature covers ``digest_to_message_bytes(digest)``. Every field is a
    constrained circuit input in the authenticated rebind circuits.
    """
    for label, value in (
        ("issuer_id_hash", issuer_id_hash),
        ("schema_id_hash", schema_id_hash),
        ("holder_commitment", holder_commitment),
        ("credential_id", credential_id),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < FIELD_MODULUS:
            raise ValueError(f"{label} must be a canonical field element")
    for label, value in (("valid_from", valid_from), ("valid_until", valid_until)):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << 64):
            raise ValueError(f"{label} must fit in u64")
    if valid_until != 0 and valid_until <= valid_from:
        raise ValueError("valid_until must be 0 (no expiry) or after valid_from")
    header = poseidon4(DOMAIN_ZKC_CLAIM, REBIND_ATTESTATION_TYPE, issuer_id_hash, schema_id_hash)
    body = poseidon4(holder_commitment, credential_id, valid_from, valid_until)
    return poseidon2(header, body)


def _selective_disclosure_attributes(attribute_count: int, attributes) -> list[int]:
    attributes = list(attributes)
    if len(attributes) != SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES:
        raise ValueError("selective-disclosure attributes must have exactly 8 slots")
    if type(attribute_count) is not int or not 1 <= attribute_count <= len(attributes):
        raise ValueError("attribute_count must be between 1 and 8")
    normalized = []
    for value in attributes:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("selective-disclosure attributes must be field elements")
        if not 0 <= value < FIELD_MODULUS:
            raise ValueError("selective-disclosure attribute is not a canonical field element")
        normalized.append(value)
    if any(normalized[attribute_count:]):
        raise ValueError("selective-disclosure credential padding must be zero")
    return normalized


def compute_selective_disclosure_credential_digest(
    holder_commitment: int,
    credential_id: int,
    attribute_count: int,
    attributes,
    credential_expires_at: int,
) -> int:
    """Issuer-signed digest for ``zkc:cred:attribute-set:v1``.

    The AFP-KDC registered ``zkc/claim`` domain is followed by an explicit
    credential type field. Every fixed slot is folded with its position, and
    ``attribute_count`` plus canonical zero padding prevent alternate shapes.
    """
    return _attribute_set_digest(
        SELECTIVE_DISCLOSURE_CREDENTIAL_TYPE, None, holder_commitment, credential_id,
        attribute_count, attributes, credential_expires_at,
    )


def compute_selective_disclosure_credential_digest_v2(
    holder_commitment: int,
    credential_id: int,
    layout_id: int,
    attribute_count: int,
    attributes,
    credential_expires_at: int,
) -> int:
    """Issuer-signed digest for the layout-bound attribute-set credential."""
    return _attribute_set_digest(
        _ATTRIBUTE_SET_V2_TYPE, _require_layout_field(layout_id), holder_commitment,
        credential_id, attribute_count, attributes, credential_expires_at,
    )


def _attribute_set_digest(
    credential_type, layout_id, holder_commitment, credential_id, attribute_count,
    attributes, credential_expires_at,
) -> int:
    normalized = _selective_disclosure_attributes(attribute_count, attributes)
    acc = poseidon4(
        DOMAIN_ZKC_CLAIM, credential_type, attribute_count, holder_commitment,
    )
    if layout_id is not None:
        acc = poseidon2(acc, layout_id)
    for position, value in enumerate(normalized):
        acc = poseidon3(acc, position, value)
    return poseidon3(acc, credential_id, credential_expires_at)


def compute_selective_disclosure_binding(
    credential_attribute_count: int,
    disclosed_flags,
    disclosed_attributes,
    proof_context: int,
    timestamp: int,
) -> int:
    """Typed transcript binding for a selective-disclosure statement.

    Flags and values are folded as position-labelled pairs. Consequently a
    disclosed zero (flag 1, value 0) differs from a hidden slot (flag 0,
    canonical value 0), and moving a value changes the transcript.
    """
    return _selective_disclosure_binding(
        SELECTIVE_DISCLOSURE_TRANSCRIPT_TYPE, None, credential_attribute_count,
        disclosed_flags, disclosed_attributes, proof_context, timestamp,
    )


def compute_selective_disclosure_binding_v3(
    layout_id: int,
    credential_attribute_count: int,
    disclosed_flags,
    disclosed_attributes,
    proof_context: int,
    timestamp: int,
) -> int:
    """Layout-bound typed transcript for selective-disclosure proof v3."""
    return _selective_disclosure_binding(
        _SELECTIVE_DISCLOSURE_V3_TYPE, _require_layout_field(layout_id),
        credential_attribute_count, disclosed_flags, disclosed_attributes,
        proof_context, timestamp,
    )


def _selective_disclosure_binding(
    proof_type, layout_id, credential_attribute_count, disclosed_flags,
    disclosed_attributes, proof_context, timestamp,
) -> int:
    flags = list(disclosed_flags)
    values = list(disclosed_attributes)
    if len(flags) != SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES or len(values) != len(flags):
        raise ValueError("selective-disclosure transcript must have exactly 8 slots")
    if not all(isinstance(flag, bool) for flag in flags):
        raise ValueError("selective-disclosure flags must be booleans")
    if (
        type(credential_attribute_count) is not int
        or not 1 <= credential_attribute_count <= len(flags)
    ):
        raise ValueError("credential_attribute_count must be between 1 and 8")
    disclosure_count = sum(flags)
    acc = poseidon4(
        DOMAIN_ZKC_CLAIM,
        proof_type,
        credential_attribute_count,
        disclosure_count,
    )
    if layout_id is not None:
        acc = poseidon2(acc, layout_id)
    for position, (flag, value) in enumerate(zip(flags, values)):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < FIELD_MODULUS:
            raise ValueError("disclosed attributes must be canonical field elements")
        acc = poseidon4(acc, position, 1 if flag else 0, value)
    return poseidon3(acc, proof_context, timestamp)


def compute_jurisdiction_leaf(jurisdiction_code: int, claim_type: int) -> int:
    """zkc_jurisdiction::compute_jurisdiction_leaf."""
    if not 0 <= jurisdiction_code < (1 << 16):
        raise ValueError("jurisdiction code must fit in u16")
    if not 0 <= claim_type < (1 << 8):
        raise ValueError("claim type must fit in u8")
    return poseidon2(jurisdiction_code, claim_type)


def compute_jurisdiction_credential_digest(
    holder_commitment: int,
    credential_id: int,
    jurisdiction_code: int,
    claim_type: int,
    verification_method: int,
    valid_from: int,
    valid_until: int,
) -> int:
    """zkc_jurisdiction::compute_jurisdiction_credential_digest."""
    if not 0 <= verification_method < (1 << 8):
        raise ValueError("verification method must fit in u8")
    jurisdiction_leaf = compute_jurisdiction_leaf(jurisdiction_code, claim_type)
    header_hash = poseidon3(holder_commitment, credential_id, jurisdiction_leaf)
    method_hash = poseidon3(verification_method, valid_from, valid_until)
    return poseidon2(header_hash, method_hash)


def compute_runtime_attestation_claim_commitment(
    attested_manifest_digest: str,
    root_class: str,
    root_authority_identifier: str,
    root_material_digest: str,
    attestation_evidence_digest: str,
    verification_policy_digest: str,
    valid_from: int,
    valid_until: int,
) -> int:
    """Commit the normalized runtime-attestation v1 credential claims."""
    try:
        root_class_code = RUNTIME_ATTESTATION_ROOT_CLASS_CODES[root_class]
    except KeyError:
        raise ValueError("unsupported runtime attestation root class") from None
    return hash_fields(
        [
            string_to_field(attested_manifest_digest),
            root_class_code,
            string_to_field(root_authority_identifier),
            string_to_field(root_material_digest),
            string_to_field(attestation_evidence_digest),
            string_to_field(verification_policy_digest),
            valid_from,
            valid_until,
        ],
        8,
    )


def compute_runtime_attestation_credential_digest(
    holder_commitment: int,
    credential_id: int,
    attested_manifest_digest: str,
    root_class: str,
    root_authority_identifier: str,
    root_material_digest: str,
    attestation_evidence_digest: str,
    verification_policy_digest: str,
    valid_from: int,
    valid_until: int,
) -> int:
    """Issuer-signed runtime-attestation v1 credential digest."""
    claim_commitment = compute_runtime_attestation_claim_commitment(
        attested_manifest_digest,
        root_class,
        root_authority_identifier,
        root_material_digest,
        attestation_evidence_digest,
        verification_policy_digest,
        valid_from,
        valid_until,
    )
    header = hash_fields(
        [
            holder_commitment,
            credential_id,
            string_to_field(RUNTIME_ATTESTATION_SCHEMA_ID),
            valid_until,
        ],
        4,
    )
    return hash_fields([header, claim_commitment], 2)


def digest_to_message_bytes(digest: int) -> bytes:
    """32-byte big-endian message the issuer signs (Field::to_be_bytes)."""
    return digest.to_bytes(32, "big")
