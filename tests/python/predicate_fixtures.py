"""Shared fixtures for the non-KYC predicate proofs.

Issues correctly-signed jurisdiction / accreditation / source-of-funds /
tax-residency / sanctions / rebind credentials bound to a holder seed, using
the well-known ZKC test issuer key (tools/zkc_test_issuer.py — public,
TEST-ONLY material). Mirrors holder_fixtures.py for the predicate circuits.
"""

import _path  # noqa: F401  (sys.path side effect)

from zkc_crypto import (
    compute_jurisdiction_credential_digest,
    compute_rebind_attestation_digest,
    string_to_field,
    compute_profile_digest,
    compute_profile_digest_v2,
    derive_credential_binding_key,
    derive_holder_commitment,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
)
from zkc_crypto.ecdsa_secp256k1 import sign
from zkc_holder import Credential, TrustedIssuer
from zkc_holder.credential import RebindAttestation
from zkc_holder.predicates import (
    PREDICATE_ACCREDITATION,
    PREDICATE_SANCTIONS_CLEARANCE,
    PREDICATE_SOURCE_OF_FUNDS,
    PREDICATE_TAX_RESIDENCY,
)

from holder_fixtures import (  # noqa: F401
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    TEST_ISSUER_PRIVATE_KEY,
)

# Current safe routes. Historical identities remain named below for explicit
# compatibility tests but must never become the default fixture path.
JURISDICTION_PROOF_TYPE = "zkc:proof:jurisdiction:v3"
JURISDICTION_V4_PROOF_TYPE = "zkc:proof:jurisdiction:v4"
ACCREDITATION_PROOF_TYPE = "zkc:proof:accreditation:v7"
SOURCE_PROOF_TYPE = "zkc:proof:source:v7"
TAX_PROOF_TYPE = "zkc:proof:tax:v7"
SANCTIONS_PROOF_TYPE = "zkc:proof:sanctions:v7"
ACCREDITATION_V3_PROOF_TYPE = "zkc:proof:accreditation:v3"
SOURCE_V3_PROOF_TYPE = "zkc:proof:source:v3"
TAX_V3_PROOF_TYPE = "zkc:proof:tax:v3"
SANCTIONS_V3_PROOF_TYPE = "zkc:proof:sanctions:v3"
ACCREDITATION_V4_PROOF_TYPE = "zkc:proof:accreditation:v4"
SOURCE_V4_PROOF_TYPE = "zkc:proof:source:v4"
TAX_V4_PROOF_TYPE = "zkc:proof:tax:v4"
SANCTIONS_V4_PROOF_TYPE = "zkc:proof:sanctions:v4"
ACCREDITATION_V5_PROOF_TYPE = "zkc:proof:accreditation:v5"
SOURCE_V5_PROOF_TYPE = "zkc:proof:source:v5"
TAX_V5_PROOF_TYPE = "zkc:proof:tax:v5"
SANCTIONS_V5_PROOF_TYPE = "zkc:proof:sanctions:v5"
ACCREDITATION_V6_PROOF_TYPE = "zkc:proof:accreditation:v6"
SOURCE_V6_PROOF_TYPE = "zkc:proof:source:v6"
TAX_V6_PROOF_TYPE = "zkc:proof:tax:v6"
SANCTIONS_V6_PROOF_TYPE = "zkc:proof:sanctions:v6"
ACCREDITATION_V7_PROOF_TYPE = ACCREDITATION_PROOF_TYPE
SOURCE_V7_PROOF_TYPE = SOURCE_PROOF_TYPE
TAX_V7_PROOF_TYPE = TAX_PROOF_TYPE
SANCTIONS_V7_PROOF_TYPE = SANCTIONS_PROOF_TYPE
ACCREDITATION_V8_PROOF_TYPE = "zkc:proof:accreditation:v8"
SOURCE_V8_PROOF_TYPE = "zkc:proof:source:v8"
TAX_V8_PROOF_TYPE = "zkc:proof:tax:v8"
SANCTIONS_V8_PROOF_TYPE = "zkc:proof:sanctions:v8"
REBIND_PROOF_TYPE = "zkc:proof:credential_rebind:v1"

ALL_PREDICATE_PROOF_TYPES = (
    JURISDICTION_PROOF_TYPE,
    JURISDICTION_V4_PROOF_TYPE,
    ACCREDITATION_PROOF_TYPE,
    SOURCE_PROOF_TYPE,
    TAX_PROOF_TYPE,
    SANCTIONS_PROOF_TYPE,
    ACCREDITATION_V3_PROOF_TYPE,
    SOURCE_V3_PROOF_TYPE,
    TAX_V3_PROOF_TYPE,
    SANCTIONS_V3_PROOF_TYPE,
    ACCREDITATION_V4_PROOF_TYPE,
    SOURCE_V4_PROOF_TYPE,
    TAX_V4_PROOF_TYPE,
    SANCTIONS_V4_PROOF_TYPE,
    ACCREDITATION_V5_PROOF_TYPE,
    SOURCE_V5_PROOF_TYPE,
    TAX_V5_PROOF_TYPE,
    SANCTIONS_V5_PROOF_TYPE,
    ACCREDITATION_V6_PROOF_TYPE,
    SOURCE_V6_PROOF_TYPE,
    TAX_V6_PROOF_TYPE,
    SANCTIONS_V6_PROOF_TYPE,
    ACCREDITATION_V8_PROOF_TYPE,
    SOURCE_V8_PROOF_TYPE,
    TAX_V8_PROOF_TYPE,
    SANCTIONS_V8_PROOF_TYPE,
    REBIND_PROOF_TYPE,
)

DEFAULT_VALID_FROM = 1_000
DEFAULT_VALID_UNTIL = 2_000_000_000


def trusted_predicate_issuer(proof_types=ALL_PREDICATE_PROOF_TYPES) -> TrustedIssuer:
    return TrustedIssuer(
        issuer_id=TEST_ISSUER_ID,
        public_key_x=TEST_ISSUER_KEY_X,
        public_key_y=TEST_ISSUER_KEY_Y,
        proof_types=tuple(proof_types),
    )


def _sign(digest: int) -> bytes:
    return sign(digest_to_message_bytes(digest), TEST_ISSUER_PRIVATE_KEY)


def issue_jurisdiction_credential(
    *,
    master_seed: int,
    credential_id: int,
    jurisdiction_code: int = 840,
    claim_type: int = 1,
    verification_method: int = 1,
    valid_from: int = DEFAULT_VALID_FROM,
    valid_until: int = DEFAULT_VALID_UNTIL,
    provider=None,
    issuer_id: str = TEST_ISSUER_ID,
) -> Credential:
    holder_commitment = derive_holder_commitment_from_seed(master_seed)
    digest = compute_jurisdiction_credential_digest(
        holder_commitment,
        credential_id,
        jurisdiction_code,
        claim_type,
        verification_method,
        valid_from,
        valid_until,
    )
    if provider is not None:
        provider.register(issuer_id, credential_id)
    return Credential(
        credential_type="zkc:cred:jurisdiction:v1",
        proof_type=JURISDICTION_PROOF_TYPE,
        issuer_id=issuer_id,
        holder_commitment=holder_commitment,
        credential_id=credential_id,
        claims={
            "jurisdictionCode": jurisdiction_code,
            "claimType": claim_type,
            "verificationMethod": verification_method,
            "validFrom": valid_from,
            "validUntil": valid_until,
        },
        expires_at=valid_until,
        signature=_sign(digest),
    )


def _issue_profile_credential(
    *,
    master_seed: int,
    credential_id: int,
    proof_type: str,
    credential_type: str,
    predicate_type: int,
    claim0: int,
    claim1: int,
    valid_from: int,
    valid_until: int,
    provider,
    issuer_id: str,
    legacy: bool = False,
) -> Credential:
    holder_commitment = derive_holder_commitment_from_seed(master_seed)
    if legacy:
        digest = compute_profile_digest(
            holder_commitment, credential_id, predicate_type, claim0, claim1, valid_until
        )
    else:
        digest = compute_profile_digest_v2(
            holder_commitment,
            credential_id,
            predicate_type,
            claim0,
            claim1,
            valid_from,
            valid_until,
        )
    if provider is not None:
        provider.register(issuer_id, credential_id)
    return Credential(
        credential_type=credential_type,
        proof_type=proof_type,
        issuer_id=issuer_id,
        holder_commitment=holder_commitment,
        credential_id=credential_id,
        claims={
            "claim0": claim0,
            "claim1": claim1,
            "validFrom": valid_from,
            "validUntil": valid_until,
        },
        expires_at=valid_until,
        signature=_sign(digest),
    )


def issue_legacy_profile_credential(
    *,
    master_seed: int,
    credential_id: int,
    proof_type: str,
    credential_type: str,
    predicate_type: int,
    claim0: int,
    claim1: int = 0,
    valid_from: int = DEFAULT_VALID_FROM,
    valid_until: int = DEFAULT_VALID_UNTIL,
    provider=None,
    issuer_id: str = TEST_ISSUER_ID,
) -> Credential:
    """Issue a historical v1-v6 profile credential with the legacy digest."""
    return _issue_profile_credential(
        master_seed=master_seed,
        credential_id=credential_id,
        proof_type=proof_type,
        credential_type=credential_type,
        predicate_type=predicate_type,
        claim0=claim0,
        claim1=claim1,
        valid_from=valid_from,
        valid_until=valid_until,
        provider=provider,
        issuer_id=issuer_id,
        legacy=True,
    )


def issue_accreditation_credential(
    *,
    master_seed: int,
    credential_id: int,
    accreditation_level: int = 3,
    institutional: bool = True,
    valid_from: int = DEFAULT_VALID_FROM,
    valid_until: int = DEFAULT_VALID_UNTIL,
    provider=None,
    issuer_id: str = TEST_ISSUER_ID,
) -> Credential:
    return _issue_profile_credential(
        master_seed=master_seed,
        credential_id=credential_id,
        proof_type=ACCREDITATION_PROOF_TYPE,
        credential_type="zkc:cred:accreditation:v2",
        predicate_type=PREDICATE_ACCREDITATION,
        claim0=accreditation_level,
        claim1=1 if institutional else 0,
        valid_from=valid_from,
        valid_until=valid_until,
        provider=provider,
        issuer_id=issuer_id,
    )


def issue_source_credential(
    *,
    master_seed: int,
    credential_id: int,
    source_code: int = 7,
    valid_from: int = DEFAULT_VALID_FROM,
    valid_until: int = DEFAULT_VALID_UNTIL,
    provider=None,
    issuer_id: str = TEST_ISSUER_ID,
) -> Credential:
    return _issue_profile_credential(
        master_seed=master_seed,
        credential_id=credential_id,
        proof_type=SOURCE_PROOF_TYPE,
        credential_type="zkc:cred:source:v2",
        predicate_type=PREDICATE_SOURCE_OF_FUNDS,
        claim0=source_code,
        claim1=0,
        valid_from=valid_from,
        valid_until=valid_until,
        provider=provider,
        issuer_id=issuer_id,
    )


def issue_tax_credential(
    *,
    master_seed: int,
    credential_id: int,
    tax_code: int = 840,
    tax_year: int = 2026,
    valid_from: int = DEFAULT_VALID_FROM,
    valid_until: int = DEFAULT_VALID_UNTIL,
    provider=None,
    issuer_id: str = TEST_ISSUER_ID,
) -> Credential:
    return _issue_profile_credential(
        master_seed=master_seed,
        credential_id=credential_id,
        proof_type=TAX_PROOF_TYPE,
        credential_type="zkc:cred:tax:v2",
        predicate_type=PREDICATE_TAX_RESIDENCY,
        claim0=tax_code,
        claim1=tax_year,
        valid_from=valid_from,
        valid_until=valid_until,
        provider=provider,
        issuer_id=issuer_id,
    )


def issue_sanctions_credential(
    *,
    master_seed: int,
    credential_id: int,
    screening_code: int = 150,
    valid_from: int = DEFAULT_VALID_FROM,
    valid_until: int = DEFAULT_VALID_UNTIL,
    provider=None,
    issuer_id: str = TEST_ISSUER_ID,
) -> Credential:
    return _issue_profile_credential(
        master_seed=master_seed,
        credential_id=credential_id,
        proof_type=SANCTIONS_PROOF_TYPE,
        credential_type="zkc:cred:sanctions:v2",
        predicate_type=PREDICATE_SANCTIONS_CLEARANCE,
        claim0=screening_code,
        claim1=0,
        valid_from=valid_from,
        valid_until=valid_until,
        provider=provider,
        issuer_id=issuer_id,
    )


def issue_rebindable_credential(
    *,
    master_seed: int,
    credential_id: int,
    issuer_id_hash: int = 1001,
    schema_id_hash: int = 2002,
    valid_from: int = DEFAULT_VALID_FROM,
    valid_until: int = DEFAULT_VALID_UNTIL,
    issuer_id: str = TEST_ISSUER_ID,
) -> Credential:
    """A credential rebind takes no issuer signature, so the signature here is
    a benign filler the rebind path never reads. The claims carry the issuer /
    schema id hashes and validity the circuit binds against."""
    holder_commitment = derive_holder_commitment_from_seed(master_seed)
    return Credential(
        credential_type="zkc:cred:kyc:v1",
        proof_type=REBIND_PROOF_TYPE,
        issuer_id=issuer_id,
        holder_commitment=holder_commitment,
        credential_id=credential_id,
        claims={
            "issuerIdHash": issuer_id_hash,
            "schemaIdHash": schema_id_hash,
            "validFrom": valid_from,
            "validUntil": valid_until,
        },
        expires_at=valid_until,
        signature=bytes(64),
    )


REBIND_AUTH_PROOF_TYPE = "zkc:proof:credential_rebind:v3"
REBIND_AUTH_V2_PROOF_TYPE = "zkc:proof:rebind:v4"


def issue_authenticated_rebindable_credential(
    *,
    master_seed: int,
    credential_id: int,
    schema_id: str = "zkc:cred:kyc:v1",
    valid_from: int = DEFAULT_VALID_FROM,
    valid_until: int = DEFAULT_VALID_UNTIL,
    provider=None,
    issuer_id: str = TEST_ISSUER_ID,
    signing_key: int = TEST_ISSUER_PRIVATE_KEY,
    attestation_holder_commitment: int = None,
    attestation_credential_id: int = None,
) -> Credential:
    """A credential carrying a genuine issuer-signed rebind attestation.

    ``attestation_holder_commitment`` / ``attestation_credential_id`` /
    ``signing_key`` exist so negative tests can sign a transcript that does not
    match the credential it travels with, or sign it with the wrong key.
    """
    holder_commitment = derive_holder_commitment_from_seed(master_seed)
    digest = compute_rebind_attestation_digest(
        string_to_field(issuer_id),
        string_to_field(schema_id),
        holder_commitment if attestation_holder_commitment is None
        else attestation_holder_commitment,
        credential_id if attestation_credential_id is None else attestation_credential_id,
        valid_from,
        valid_until,
    )
    if provider is not None:
        provider.register(issuer_id, credential_id)
    return Credential(
        credential_type="zkc:cred:kyc:v1",
        proof_type=REBIND_AUTH_PROOF_TYPE,
        issuer_id=issuer_id,
        holder_commitment=holder_commitment,
        credential_id=credential_id,
        claims={"validFrom": valid_from, "validUntil": valid_until},
        expires_at=valid_until,
        signature=bytes(64),
        witness=provider.witness(issuer_id, credential_id) if provider is not None else None,
        rebind_attestation=RebindAttestation(
            schema_id=schema_id,
            valid_from=valid_from,
            valid_until=valid_until,
            signature=sign(digest_to_message_bytes(digest), signing_key),
        ),
    )


def new_rebind_binding_key(seed: int) -> int:
    """Derive the fresh credential binding key a rebind migrates to."""
    return derive_credential_binding_key(seed)


def new_rebind_holder_commitment(seed: int) -> int:
    return derive_holder_commitment(derive_credential_binding_key(seed))
