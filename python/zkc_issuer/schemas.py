"""Supported credential schemas and their issuer-signed digests.

The current schemas mirror reviewed circuit digest computations, so their
issued envelopes are provable as-is.  The four profile ``:v1`` schemas remain
registered only to calculate and verify historical credentials; they are not
issuable because their digest does not authenticate ``validFrom``:

* ``zkc:cred:kyc:v1``            → ``zkc_kyc``                  (KYC digest)
* ``zkc:cred:jurisdiction:v1``   → ``zkc_jurisdiction_v3``      (jurisdiction digest)
* ``zkc:cred:{accreditation,source,tax,sanctions}:v2``
  → ``zkc_remaining_predicates_v7`` (profile digest v2, types 1--4)
* ``zkc:cred:attribute-set:v1``  → ``zkc_selective_disclosure_v1`` (typed disclosure)
* ``zkc:cred:attribute-set:v2``  → ``zkc_selective_disclosure_v3`` (layout-bound disclosure)

``zkc:cred:runtime-attestation:v1`` is an issuer credential schema only. Its
reserved proof type has no reviewed Noir circuit or predicate-registry entry,
so Safeguard 4 refusal remains required.

There is NO canonical schema set (Freedom Safeguard 1): this module is the
*sandbox issuer's* supported set; any issuer publishes its own in metadata.
Claims validation fails closed: anything missing, mistyped, or out of range
is an UNSUPPORTED_SCHEMA error at issuance time.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import partial
from typing import Callable

from zkc_crypto import (
    FIELD_MODULUS,
    RUNTIME_ATTESTATION_SCHEMA_ID,
    compute_jurisdiction_credential_digest,
    compute_kyc_credential_digest,
    compute_profile_digest,
    compute_profile_digest_v2,
    compute_runtime_attestation_credential_digest,
    compute_selective_disclosure_credential_digest,
    compute_selective_disclosure_credential_digest_v2,
    parse_attribute_layout_id,
)
from zkc_crypto.canonical_set import CANONICAL_CODE_MAX, CANONICAL_CODE_MIN
from zkc_crypto.code_spaces import (
    CODE_SPACE_CREDENTIAL_TO_KIND,
    get_code_space,
    validate_claim_type,
    validate_verification_method,
)
from zkc_crypto.code_space_transcripts import bind_code_space_digest

from .errors import AdapterError

__all__ = [
    "PREDICATE_ACCREDITATION",
    "PREDICATE_SOURCE_OF_FUNDS",
    "PREDICATE_TAX_RESIDENCY",
    "PREDICATE_SANCTIONS_CLEARANCE",
    "RUNTIME_ATTESTATION_PROOF_TYPE",
    "RUNTIME_ATTESTATION_SCHEMA_ID",
    "RUNTIME_ATTESTATION_MAX_ROOT_AUTHORITY_IDENTIFIER_UTF8_BYTES",
    "CredentialSchema",
    "SUPPORTED_SCHEMAS",
    "get_schema",
]

# Mirror noir/zkc_remaining_predicates/src/main.nr.
PREDICATE_ACCREDITATION = 1
PREDICATE_SOURCE_OF_FUNDS = 2
PREDICATE_TAX_RESIDENCY = 3
PREDICATE_SANCTIONS_CLEARANCE = 4
RUNTIME_ATTESTATION_PROOF_TYPE = "zkc:proof:runtime-attestation:v1"
ATTRIBUTE_SET_V1_SCHEMA_ID = "zkc:cred:attribute-set:v1"
ATTRIBUTE_SET_V2_SCHEMA_ID = "zkc:cred:attribute-set:v2"
RUNTIME_ATTESTATION_MAX_ROOT_AUTHORITY_IDENTIFIER_UTF8_BYTES = 256
RUNTIME_ATTESTATION_CLAIM_KEYS = frozenset(
    {
        "attestedManifestDigest",
        "rootClass",
        "rootAuthorityIdentifier",
        "rootMaterialDigest",
        "attestationEvidenceDigest",
        "verificationPolicyDigest",
        "validFrom",
        "validUntil",
    }
)
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _fail(schema_id: str, reason: str):
    raise AdapterError("UNSUPPORTED_SCHEMA", f"invalid claims for {schema_id}: {reason}")


def _require_uint(schema_id: str, claims: dict, name: str, bits: int) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(schema_id, f"{name} must be an integer")
    if not 0 <= value < (1 << bits):
        _fail(schema_id, f"{name} out of range for u{bits}")
    return value


def _require_field(schema_id: str, claims: dict, name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(schema_id, f"{name} must be an integer field element")
    if not 0 <= value < FIELD_MODULUS:
        _fail(schema_id, f"{name} is not a canonical field element")
    return value


def _require_set_subject_code(schema_id: str, claims: dict, name: str) -> int:
    code = _require_uint(schema_id, claims, name, 16)
    if not CANONICAL_CODE_MIN <= code <= CANONICAL_CODE_MAX:
        _fail(schema_id, f"{name} is reserved for canonical set sentinels")
    return code


def _require_validity(schema_id: str, claims: dict, *, allow_no_expiry: bool) -> tuple:
    valid_from = _require_uint(schema_id, claims, "validFrom", 64)
    valid_until = _require_uint(schema_id, claims, "validUntil", 64)
    if (valid_until != 0 or not allow_no_expiry) and valid_until <= valid_from:
        _fail(schema_id, "validUntil must be after validFrom")
    return valid_from, valid_until


def _require_sha256(schema_id: str, claims: dict, name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(schema_id, f"{name} must be a canonical sha256 digest")
    if value == "sha256:" + "0" * 64:
        _fail(schema_id, f"{name} must be non-zero")
    return value


@dataclass(frozen=True)
class CredentialSchema:
    """A supported issuer schema with validation and signed-digest computation.

    ``circuit`` records the reviewed circuit name where one exists, or an
    explicit ``unreviewed:`` marker for issuance-only extensions.
    """

    schema_id: str
    credential_type: str
    proof_type: str
    circuit: str
    normalize_claims: Callable
    compute_digest: Callable  # (holder_commitment, credential_id, claims, expires_at) -> int
    issuable: bool = True

    def metadata_entry(self) -> dict:
        return {
            "schemaId": self.schema_id,
            "credentialType": self.credential_type,
            "proofType": self.proof_type,
        }


# --- KYC ---------------------------------------------------------------------


def _require_expires_at(schema_id: str, expires_at) -> int:
    # The circuits type expiresAt as u64; a wider value would be reduced
    # into a different signed digest than the one any proof can open.
    if type(expires_at) is not int or not 0 <= expires_at < (1 << 64):
        _fail(schema_id, "expiresAt out of range for u64")
    return expires_at


def _normalize_kyc(claims: dict) -> dict:
    schema_id = "zkc:cred:kyc:v1"
    level = claims.get("level")
    # zkc_kyc types credential_level as u8; zero is not a KYC level.
    if isinstance(level, bool) or not isinstance(level, int) or not 1 <= level <= 255:
        _fail(schema_id, "level must be an integer between 1 and 255")
    attributes = claims.get("verifiedAttributes")
    if not isinstance(attributes, (list, tuple)) or len(attributes) != 5:
        _fail(schema_id, "verifiedAttributes must have exactly 5 entries")
    if not all(isinstance(flag, bool) for flag in attributes):
        _fail(schema_id, "verifiedAttributes must all be booleans")
    return {"level": level, "verifiedAttributes": list(attributes)}


def _kyc_digest(holder_commitment: int, credential_id: int, claims: dict, expires_at: int) -> int:
    # Revalidate: callers may pass claims that bypassed normalize_claims.
    claims = _normalize_kyc(claims)
    return compute_kyc_credential_digest(
        holder_commitment,
        credential_id,
        claims["level"],
        claims["verifiedAttributes"],
        _require_expires_at("zkc:cred:kyc:v1", expires_at),
    )


# --- Issuer-authoritative attribute sets ------------------------------------


def _normalize_attribute_slots(schema_id: str, claims: dict) -> dict:
    count = _require_uint(schema_id, claims, "attributeCount", 8)
    if not 1 <= count <= 8:
        _fail(schema_id, "attributeCount must be between 1 and 8")
    attributes = claims.get("attributes")
    if not isinstance(attributes, (list, tuple)) or len(attributes) not in (count, 8):
        _fail(schema_id, "attributes length must equal attributeCount or the canonical 8 slots")
    normalized = []
    for index, value in enumerate(attributes):
        if isinstance(value, bool) or not isinstance(value, int):
            _fail(schema_id, f"attributes[{index}] must be an integer field element")
        if not 0 <= value < FIELD_MODULUS:
            _fail(schema_id, f"attributes[{index}] is not a canonical field element")
        normalized.append(value)
    if len(normalized) == 8:
        if any(normalized[count:]):
            _fail(schema_id, "canonical padding attributes must be zero")
        return {"attributeCount": count, "attributes": normalized}
    return {"attributeCount": count, "attributes": normalized + [0] * (8 - count)}


def _normalize_attribute_set(claims: dict) -> dict:
    schema_id = ATTRIBUTE_SET_V1_SCHEMA_ID
    if not isinstance(claims, dict) or set(claims) != {"attributeCount", "attributes"}:
        _fail(schema_id, "claims must contain exactly attributeCount and attributes")
    return _normalize_attribute_slots(schema_id, claims)


def _normalize_attribute_set_v2(claims: dict) -> dict:
    schema_id = ATTRIBUTE_SET_V2_SCHEMA_ID
    if not isinstance(claims, dict) or set(claims) != {"layoutId", "attributeCount", "attributes"}:
        _fail(schema_id, "claims must contain exactly layoutId, attributeCount and attributes")
    layout_id = claims["layoutId"]
    try:
        parse_attribute_layout_id(layout_id)
    except ValueError:
        _fail(schema_id, "layoutId must be a canonical nonzero field element")
    return {"layoutId": layout_id, **_normalize_attribute_slots(schema_id, claims)}


def _attribute_set_digest(
    holder_commitment: int, credential_id: int, claims: dict, expires_at: int
) -> int:
    return compute_selective_disclosure_credential_digest(
        holder_commitment,
        credential_id,
        claims["attributeCount"],
        claims["attributes"],
        _require_expires_at(ATTRIBUTE_SET_V1_SCHEMA_ID, expires_at),
    )


def _attribute_set_digest_v2(
    holder_commitment: int, credential_id: int, claims: dict, expires_at: int
) -> int:
    return compute_selective_disclosure_credential_digest_v2(
        holder_commitment,
        credential_id,
        parse_attribute_layout_id(claims["layoutId"]),
        claims["attributeCount"],
        claims["attributes"],
        _require_expires_at(ATTRIBUTE_SET_V2_SCHEMA_ID, expires_at),
    )


# --- Jurisdiction ----------------------------------------------------------------


def _normalize_jurisdiction(claims: dict) -> dict:
    schema_id = "zkc:cred:jurisdiction:v1"
    normalized = {
        "jurisdictionCode": _require_set_subject_code(schema_id, claims, "jurisdictionCode"),
        "claimType": _require_uint(schema_id, claims, "claimType", 8),
        "verificationMethod": _require_uint(schema_id, claims, "verificationMethod", 8),
    }
    normalized["validFrom"], normalized["validUntil"] = _require_validity(
        schema_id, claims, allow_no_expiry=False
    )
    return normalized


def _jurisdiction_digest(
    holder_commitment: int, credential_id: int, claims: dict, expires_at: int
) -> int:
    return compute_jurisdiction_credential_digest(
        holder_commitment,
        credential_id,
        claims["jurisdictionCode"],
        claims["claimType"],
        claims["verificationMethod"],
        claims["validFrom"],
        claims["validUntil"],
    )


# --- Profile predicates (zkc_remaining_predicates) ----------------------------------


def _profile_digest(predicate_type: int):
    def compute(holder_commitment: int, credential_id: int, claims: dict, expires_at: int) -> int:
        return compute_profile_digest(
            holder_commitment,
            credential_id,
            predicate_type,
            claims["claim0"],
            claims["claim1"],
            claims["validUntil"],
        )

    return compute


def _profile_digest_v2(predicate_type: int, schema_id: str):
    def compute(holder_commitment: int, credential_id: int, claims: dict, expires_at: int) -> int:
        if expires_at != claims["validUntil"]:
            _fail(schema_id, "expiresAt must equal validUntil")
        return compute_profile_digest_v2(
            holder_commitment,
            credential_id,
            predicate_type,
            claims["claim0"],
            claims["claim1"],
            claims["validFrom"],
            claims["validUntil"],
        )

    return compute


def _normalize_accreditation(claims: dict, schema_id="zkc:cred:accreditation:v1") -> dict:
    level = _require_uint(schema_id, claims, "accreditationLevel", 8)
    institutional = claims.get("institutional")
    if not isinstance(institutional, bool):
        _fail(schema_id, "institutional must be a boolean")
    valid_from, valid_until = _require_validity(schema_id, claims, allow_no_expiry=True)
    return {
        "accreditationLevel": level,
        "institutional": institutional,
        "claim0": level,
        "claim1": 1 if institutional else 0,
        "validFrom": valid_from,
        "validUntil": valid_until,
    }


def _normalize_source(claims: dict, schema_id="zkc:cred:source:v1") -> dict:
    code = _require_field(schema_id, claims, "sourceOfFundsCode")
    if code == 0:
        _fail(schema_id, "sourceOfFundsCode must be non-zero")
    valid_from, valid_until = _require_validity(schema_id, claims, allow_no_expiry=True)
    return {
        "sourceOfFundsCode": code,
        "claim0": code,
        "claim1": 0,
        "validFrom": valid_from,
        "validUntil": valid_until,
    }


def _normalize_tax(claims: dict, schema_id="zkc:cred:tax:v1") -> dict:
    code = _require_field(schema_id, claims, "taxResidencyCode")
    if code == 0:
        _fail(schema_id, "taxResidencyCode must be non-zero")
    tax_year = _require_uint(schema_id, claims, "taxYear", 64)
    valid_from, valid_until = _require_validity(schema_id, claims, allow_no_expiry=True)
    return {
        "taxResidencyCode": code,
        "taxYear": tax_year,
        "claim0": code,
        "claim1": tax_year,
        "validFrom": valid_from,
        "validUntil": valid_until,
    }


def _normalize_sanctions(claims: dict, schema_id="zkc:cred:sanctions:v1") -> dict:
    if schema_id == "zkc:cred:sanctions:v1":
        # This historical schema can only be used to check existing credentials.
        code = _require_uint(schema_id, claims, "screeningCode", 16)
    else:
        code = _require_set_subject_code(schema_id, claims, "screeningCode")
    valid_from, valid_until = _require_validity(schema_id, claims, allow_no_expiry=True)
    return {
        "screeningCode": code,
        "claim0": code,
        "claim1": 0,
        "validFrom": valid_from,
        "validUntil": valid_until,
    }


# --- Code-space-bound successors ---------------------------------------------


def _normalize_code_space_claims(
    schema_id: str, claims: dict, *, allow_legacy_zero_expiry: bool = False
) -> dict:
    kind = CODE_SPACE_CREDENTIAL_TO_KIND[schema_id]
    code_name = {
        "jurisdiction": "jurisdictionCode", "source": "sourceOfFundsCode",
        "tax": "taxResidencyCode", "sanctions": "screeningCode",
    }[kind]
    keys = {"codeSpaceId", code_name, "validFrom", "validUntil"}
    if kind == "jurisdiction":
        keys.update({"claimType", "verificationMethod"})
    elif kind == "tax":
        keys.add("taxYear")
    # Profile normalizers add canonical internal digest slots. Accept those
    # only when equal to the recomputed slots, including ledger readback.
    internal = {"claim0", "claim1"} if kind != "jurisdiction" else set()
    if type(claims) is not dict or set(claims) not in (keys, keys | internal):
        _fail(schema_id, "claims must contain exactly the code-space schema fields")
    try:
        space = get_code_space(claims["codeSpaceId"], kind)
        code = space.validate_code(claims[code_name])
        if kind == "jurisdiction":
            claim_type = validate_claim_type(claims["claimType"])
            method = validate_verification_method(claims["verificationMethod"])
    except (TypeError, ValueError) as exc:
        _fail(schema_id, str(exc))
    valid_from, valid_until = _require_validity(
        schema_id, claims, allow_no_expiry=kind != "jurisdiction" or allow_legacy_zero_expiry
    )
    normalized = {
        "codeSpaceId": space.id, code_name: code,
        "validFrom": valid_from, "validUntil": valid_until,
    }
    if kind == "jurisdiction":
        normalized.update(claimType=claim_type, verificationMethod=method)
    else:
        claim1 = _require_uint(schema_id, claims, "taxYear", 64) if kind == "tax" else 0
        if kind == "tax":
            normalized["taxYear"] = claim1
        normalized.update(claim0=code, claim1=claim1)
        if any(name in claims and (type(claims[name]) is not int or claims[name] != normalized[name])
               for name in internal):
            _fail(schema_id, "internal digest slots do not match claims")
    return normalized


def _code_space_digest(schema_id: str, predecessor):
    def compute(holder_commitment: int, credential_id: int, claims: dict, expires_at: int) -> int:
        # Keep digest reconstruction available for credentials already signed.
        claims = _normalize_code_space_claims(schema_id, claims, allow_legacy_zero_expiry=True)
        if _require_expires_at(schema_id, expires_at) != claims["validUntil"]:
            _fail(schema_id, "expiresAt must equal validUntil")
        digest = predecessor(holder_commitment, credential_id, claims, expires_at)
        space = get_code_space(claims["codeSpaceId"], CODE_SPACE_CREDENTIAL_TO_KIND[schema_id])
        return bind_code_space_digest(schema_id, space.field_id, digest)

    return compute


# --- Runtime attestation -----------------------------------------------------


def _normalize_runtime_attestation(claims: dict) -> dict:
    schema_id = RUNTIME_ATTESTATION_SCHEMA_ID
    if not isinstance(claims, dict) or set(claims) != RUNTIME_ATTESTATION_CLAIM_KEYS:
        _fail(schema_id, "claims must contain exactly the runtime-attestation v1 fields")
    root_class = claims.get("rootClass")
    if root_class not in ("root:build-provenance", "root:tee-attestation"):
        _fail(schema_id, "rootClass is unsupported")
    authority = claims.get("rootAuthorityIdentifier")
    if (
        not isinstance(authority, str)
        or not authority
        or unicodedata.normalize("NFC", authority) != authority
    ):
        _fail(schema_id, "rootAuthorityIdentifier must be non-empty NFC text")
    try:
        authority_bytes = authority.encode("utf-8")
    except UnicodeEncodeError:
        _fail(schema_id, "rootAuthorityIdentifier must be UTF-8 encodable")
    if (
        len(authority_bytes)
        > RUNTIME_ATTESTATION_MAX_ROOT_AUTHORITY_IDENTIFIER_UTF8_BYTES
    ):
        _fail(schema_id, "rootAuthorityIdentifier exceeds the UTF-8 byte limit")
    valid_from, valid_until = _require_validity(schema_id, claims, allow_no_expiry=False)
    return {
        "attestedManifestDigest": _require_sha256(
            schema_id, claims, "attestedManifestDigest"
        ),
        "rootClass": root_class,
        "rootAuthorityIdentifier": authority,
        "rootMaterialDigest": _require_sha256(schema_id, claims, "rootMaterialDigest"),
        "attestationEvidenceDigest": _require_sha256(
            schema_id, claims, "attestationEvidenceDigest"
        ),
        "verificationPolicyDigest": _require_sha256(
            schema_id, claims, "verificationPolicyDigest"
        ),
        "validFrom": valid_from,
        "validUntil": valid_until,
    }


def _runtime_attestation_digest(
    holder_commitment: int, credential_id: int, claims: dict, expires_at: int
) -> int:
    if expires_at != claims["validUntil"]:
        _fail(RUNTIME_ATTESTATION_SCHEMA_ID, "expiresAt must equal validUntil")
    return compute_runtime_attestation_credential_digest(
        holder_commitment,
        credential_id,
        claims["attestedManifestDigest"],
        claims["rootClass"],
        claims["rootAuthorityIdentifier"],
        claims["rootMaterialDigest"],
        claims["attestationEvidenceDigest"],
        claims["verificationPolicyDigest"],
        claims["validFrom"],
        claims["validUntil"],
    )


SUPPORTED_SCHEMAS = {
    schema.schema_id: schema
    for schema in (
        CredentialSchema(
            schema_id="zkc:cred:kyc:v1",
            credential_type="zkc:cred:kyc:v1",
            proof_type="zkc:proof:kyc:v1",
            circuit="zkc_kyc",
            normalize_claims=_normalize_kyc,
            compute_digest=_kyc_digest,
        ),
        CredentialSchema(
            schema_id="zkc:cred:jurisdiction:v1",
            credential_type="zkc:cred:jurisdiction:v1",
            proof_type="zkc:proof:jurisdiction:v3",
            circuit="zkc_jurisdiction_v3",
            normalize_claims=_normalize_jurisdiction,
            compute_digest=_jurisdiction_digest,
        ),
        CredentialSchema(
            schema_id=ATTRIBUTE_SET_V1_SCHEMA_ID,
            credential_type=ATTRIBUTE_SET_V1_SCHEMA_ID,
            proof_type="zkc:proof:selective_disclosure:v1",
            circuit="zkc_selective_disclosure_v1",
            normalize_claims=_normalize_attribute_set,
            compute_digest=_attribute_set_digest,
        ),
        CredentialSchema(
            schema_id=ATTRIBUTE_SET_V2_SCHEMA_ID,
            credential_type=ATTRIBUTE_SET_V2_SCHEMA_ID,
            proof_type="zkc:proof:selective_disclosure:v3",
            circuit="zkc_selective_disclosure_v3",
            normalize_claims=_normalize_attribute_set_v2,
            compute_digest=_attribute_set_digest_v2,
        ),
        CredentialSchema(
            schema_id="zkc:cred:accreditation:v1",
            credential_type="zkc:cred:accreditation:v1",
            proof_type="zkc:proof:accreditation:v1",
            circuit="zkc_remaining_predicates",
            normalize_claims=_normalize_accreditation,
            compute_digest=_profile_digest(PREDICATE_ACCREDITATION),
            issuable=False,
        ),
        CredentialSchema(
            schema_id="zkc:cred:accreditation:v2",
            credential_type="zkc:cred:accreditation:v2",
            proof_type="zkc:proof:accreditation:v7",
            circuit="zkc_remaining_predicates_v7",
            normalize_claims=lambda claims: _normalize_accreditation(
                claims, "zkc:cred:accreditation:v2"
            ),
            compute_digest=_profile_digest_v2(
                PREDICATE_ACCREDITATION, "zkc:cred:accreditation:v2"
            ),
        ),
        CredentialSchema(
            schema_id="zkc:cred:source:v1",
            credential_type="zkc:cred:source:v1",
            proof_type="zkc:proof:source:v1",
            circuit="zkc_remaining_predicates",
            normalize_claims=_normalize_source,
            compute_digest=_profile_digest(PREDICATE_SOURCE_OF_FUNDS),
            issuable=False,
        ),
        CredentialSchema(
            schema_id="zkc:cred:source:v2",
            credential_type="zkc:cred:source:v2",
            proof_type="zkc:proof:source:v7",
            circuit="zkc_remaining_predicates_v7",
            normalize_claims=lambda claims: _normalize_source(claims, "zkc:cred:source:v2"),
            compute_digest=_profile_digest_v2(
                PREDICATE_SOURCE_OF_FUNDS, "zkc:cred:source:v2"
            ),
        ),
        CredentialSchema(
            schema_id="zkc:cred:tax:v1",
            credential_type="zkc:cred:tax:v1",
            proof_type="zkc:proof:tax:v1",
            circuit="zkc_remaining_predicates",
            normalize_claims=_normalize_tax,
            compute_digest=_profile_digest(PREDICATE_TAX_RESIDENCY),
            issuable=False,
        ),
        CredentialSchema(
            schema_id="zkc:cred:tax:v2",
            credential_type="zkc:cred:tax:v2",
            proof_type="zkc:proof:tax:v7",
            circuit="zkc_remaining_predicates_v7",
            normalize_claims=lambda claims: _normalize_tax(claims, "zkc:cred:tax:v2"),
            compute_digest=_profile_digest_v2(
                PREDICATE_TAX_RESIDENCY, "zkc:cred:tax:v2"
            ),
        ),
        CredentialSchema(
            schema_id="zkc:cred:sanctions:v1",
            credential_type="zkc:cred:sanctions:v1",
            proof_type="zkc:proof:sanctions:v1",
            circuit="zkc_remaining_predicates",
            normalize_claims=_normalize_sanctions,
            compute_digest=_profile_digest(PREDICATE_SANCTIONS_CLEARANCE),
            issuable=False,
        ),
        CredentialSchema(
            schema_id="zkc:cred:sanctions:v2",
            credential_type="zkc:cred:sanctions:v2",
            proof_type="zkc:proof:sanctions:v7",
            circuit="zkc_remaining_predicates_v7",
            normalize_claims=lambda claims: _normalize_sanctions(
                claims, "zkc:cred:sanctions:v2"
            ),
            compute_digest=_profile_digest_v2(
                PREDICATE_SANCTIONS_CLEARANCE, "zkc:cred:sanctions:v2"
            ),
        ),
        CredentialSchema(
            schema_id=RUNTIME_ATTESTATION_SCHEMA_ID,
            credential_type=RUNTIME_ATTESTATION_SCHEMA_ID,
            proof_type=RUNTIME_ATTESTATION_PROOF_TYPE,
            circuit="unreviewed:runtime-attestation:v1",
            normalize_claims=_normalize_runtime_attestation,
            compute_digest=_runtime_attestation_digest,
        ),
    )
}

for _schema_id, _proof_type, _circuit, _predecessor in (
    ("zkc:cred:jurisdiction:v2", "zkc:proof:jurisdiction:v6", "zkc_jurisdiction_v6", _jurisdiction_digest),
    ("zkc:cred:source:v3", "zkc:proof:source:v11", "zkc_remaining_predicates_v11",
     _profile_digest_v2(PREDICATE_SOURCE_OF_FUNDS, "zkc:cred:source:v3")),
    ("zkc:cred:tax:v3", "zkc:proof:tax:v11", "zkc_remaining_predicates_v11",
     _profile_digest_v2(PREDICATE_TAX_RESIDENCY, "zkc:cred:tax:v3")),
    ("zkc:cred:sanctions:v3", "zkc:proof:sanctions:v11", "zkc_remaining_predicates_v11",
     _profile_digest_v2(PREDICATE_SANCTIONS_CLEARANCE, "zkc:cred:sanctions:v3")),
):
    SUPPORTED_SCHEMAS[_schema_id] = CredentialSchema(
        schema_id=_schema_id, credential_type=_schema_id, proof_type=_proof_type,
        circuit=_circuit,
        normalize_claims=partial(_normalize_code_space_claims, _schema_id),
        compute_digest=_code_space_digest(_schema_id, _predecessor),
    )


def get_schema(schema_id) -> CredentialSchema:
    """Resolve a schema id; raises UNSUPPORTED_SCHEMA (fail closed)."""
    schema = SUPPORTED_SCHEMAS.get(schema_id)
    if schema is None:
        raise AdapterError("UNSUPPORTED_SCHEMA", f"unsupported schema: {schema_id}")
    return schema
