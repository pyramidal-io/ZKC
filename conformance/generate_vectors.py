#!/usr/bin/env python3
"""Regenerate conformance/vectors/zkc_core.json (deterministic).

Fixtures are derived entirely from pinned material: the well-known TEST-ONLY
issuer key (tools/zkc_test_issuer.py), master seed 42 (the golden-vector
seed), deterministic RFC 6979 signatures, and the deterministic sparse
accumulator. Re-running this script must be a no-op unless the protocol
constructions themselves changed.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from zkc_crypto import (  # noqa: E402
    CANONICAL_SET_EXCLUSION,
    CANONICAL_SET_INCLUSION,
    CANONICAL_SET_PARAM,
    FIELD_MODULUS,
    JURISDICTION_CANONICAL_SET_PARAM,
    PURPOSE_BOUND_PROFILE,
    CanonicalCodeSet,
    SparseMerkleAccumulator,
    compute_jurisdiction_credential_digest,
    compute_jurisdiction_leaf,
    compute_kyc_credential_digest,
    compute_profile_digest_v2,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
    field_to_hex,
    raw_code_leaf,
    sign_apr,
)
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes, sign  # noqa: E402
from zkc_holder.predicates import (  # noqa: E402
    MEMBERSHIP_TYPE_EXCLUSION,
    MEMBERSHIP_TYPE_INCLUSION,
    PREDICATE_ACCREDITATION,
    PREDICATE_SANCTIONS_CLEARANCE,
    PREDICATE_SOURCE_OF_FUNDS,
    PREDICATE_TAX_RESIDENCY,
    single_leaf_inclusion_witness,
    single_leaf_set_root,
)

VECTORS_PATH = ROOT / "conformance" / "vectors" / "zkc_core.json"

KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
JURISDICTION_PROOF_TYPE = "zkc:proof:jurisdiction:v3"
ACCREDITATION_PROOF_TYPE = "zkc:proof:accreditation:v7"
SOURCE_PROOF_TYPE = "zkc:proof:source:v7"
TAX_PROOF_TYPE = "zkc:proof:tax:v7"
SANCTIONS_PROOF_TYPE = "zkc:proof:sanctions:v7"
PREDICATE_PROOF_TYPES = (
    JURISDICTION_PROOF_TYPE,
    ACCREDITATION_PROOF_TYPE,
    SOURCE_PROOF_TYPE,
    TAX_PROOF_TYPE,
    SANCTIONS_PROOF_TYPE,
)
CORE_PROOF_TYPES = (KYC_PROOF_TYPE, *PREDICATE_PROOF_TYPES)
MASTER_SEED = 42

TEST_ISSUER_ID = "did:zkc:test-issuer"
TEST_ISSUER_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-test-issuer-v1").digest(), "big") % N
)

# A second TEST-ONLY key for the untrusted-issuer fixtures.
OTHER_ISSUER_ID = "did:zkc:other-issuer"
OTHER_ISSUER_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-conformance-other-issuer-v1").digest(), "big") % N
)

# A TEST-ONLY verifier identity key for Authenticated Proof Requests (§5.5).
APR_VERIFIER_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-conformance-apr-verifier-v1").digest(), "big") % N
)

ACCESS_PURPOSE = "zkc:purpose:access-gate"
BILLING_PURPOSE = "zkc:purpose:billing-kyc"

# Every credential each TEST-ONLY issuer has issued, in issuance order. An
# issuer publishes ONE accumulator over its active credentials (spec 2.4), so
# all of an issuer's fixtures share its epoch-1 root, and the verifier records
# exactly that root in each request's accumulatorStates.
ISSUER_LEDGERS = {
    TEST_ISSUER_ID: (42, 43, 45, 46, 47, 48, 49, 50),
    OTHER_ISSUER_ID: (44,),
}
# Issued and then revoked before epoch 1: its slot is zeroed in the issuer
# accumulator, so its holder can only "prove" non-revocation against a
# self-made one-leaf tree -- which a verifier recording the issuer root rejects.
REVOKED_CREDENTIAL_IDS = {TEST_ISSUER_ID: (50,)}
ACCUMULATOR_EPOCH = 1


def issuer_accumulator(issuer_id: str) -> SparseMerkleAccumulator:
    accumulator = SparseMerkleAccumulator()
    for credential_id in ISSUER_LEDGERS[issuer_id]:
        accumulator.add(credential_id)
    for credential_id in REVOKED_CREDENTIAL_IDS.get(issuer_id, ()):
        accumulator.remove(accumulator.index_of(credential_id))
    return accumulator


def witness_fixture(accumulator: SparseMerkleAccumulator, credential_id: int) -> dict:
    path_index, siblings = accumulator.witness(accumulator.index_of(credential_id))
    return {
        "pathIndex": path_index,
        "siblings": [field_to_hex(value) for value in siblings],
        "accumulatorRoot": field_to_hex(accumulator.root()),
        "accumulatorEpoch": ACCUMULATOR_EPOCH,
    }


def issuer_witness(issuer_id: str, credential_id: int) -> dict:
    return witness_fixture(issuer_accumulator(issuer_id), credential_id)


def self_made_witness(credential_id: int) -> dict:
    """A revoked holder's own one-leaf tree at the issuer's current epoch."""
    accumulator = SparseMerkleAccumulator()
    accumulator.add(credential_id)
    return witness_fixture(accumulator, credential_id)


def accumulator_state(issuer_id: str, current_epoch: int = ACCUMULATOR_EPOCH) -> dict:
    root = field_to_hex(issuer_accumulator(issuer_id).root())
    return {
        "currentEpoch": current_epoch,
        "roots": {str(epoch): root for epoch in range(ACCUMULATOR_EPOCH, current_epoch + 1)},
    }


def make_kyc_credential(
    *,
    credential_id: int,
    level: int,
    verified_attributes,
    expires_at: int,
    issuer_id: str,
    issuer_private_key: int,
    witness: dict = None,
) -> dict:
    holder_commitment = derive_holder_commitment_from_seed(MASTER_SEED)
    digest = compute_kyc_credential_digest(
        holder_commitment, credential_id, level, list(verified_attributes), expires_at
    )
    signature = sign(digest_to_message_bytes(digest), issuer_private_key)
    return {
        "credentialType": "zkc:kyc:v1",
        "proofType": KYC_PROOF_TYPE,
        "issuerId": issuer_id,
        "holderCommitment": field_to_hex(holder_commitment),
        "credentialId": field_to_hex(credential_id),
        "claims": {"level": level, "verifiedAttributes": list(verified_attributes)},
        "expiresAt": expires_at,
        "signature": "0x" + signature.hex(),
        "witness": witness or issuer_witness(issuer_id, credential_id),
    }


def make_jurisdiction_credential(
    *, credential_id: int, jurisdiction_code: int, claim_type: int
) -> dict:
    """Issue a deterministic, correctly signed jurisdiction credential."""
    holder_commitment = derive_holder_commitment_from_seed(MASTER_SEED)
    valid_from = 1_000
    valid_until = 2_000_000_000
    digest = compute_jurisdiction_credential_digest(
        holder_commitment,
        credential_id,
        jurisdiction_code,
        claim_type,
        1,
        valid_from,
        valid_until,
    )
    signature = sign(digest_to_message_bytes(digest), TEST_ISSUER_PRIVATE_KEY)
    return {
        "credentialType": "zkc:cred:jurisdiction:v1",
        "proofType": JURISDICTION_PROOF_TYPE,
        "issuerId": TEST_ISSUER_ID,
        "holderCommitment": field_to_hex(holder_commitment),
        "credentialId": field_to_hex(credential_id),
        "claims": {
            "jurisdictionCode": jurisdiction_code,
            "claimType": claim_type,
            "verificationMethod": 1,
            "validFrom": valid_from,
            "validUntil": valid_until,
        },
        "expiresAt": valid_until,
        "signature": "0x" + signature.hex(),
        "witness": issuer_witness(TEST_ISSUER_ID, credential_id),
    }


def make_profile_credential(
    *,
    credential_id: int,
    proof_type: str,
    credential_type: str,
    predicate_type: int,
    claim_0: int,
    claim_1: int,
) -> dict:
    """Issue one deterministic credential for the shared predicate circuit."""
    holder_commitment = derive_holder_commitment_from_seed(MASTER_SEED)
    valid_from = 1_000
    valid_until = 2_000_000_000
    digest = compute_profile_digest_v2(
        holder_commitment,
        credential_id,
        predicate_type,
        claim_0,
        claim_1,
        valid_from,
        valid_until,
    )
    signature = sign(digest_to_message_bytes(digest), TEST_ISSUER_PRIVATE_KEY)
    return {
        "credentialType": credential_type,
        "proofType": proof_type,
        "issuerId": TEST_ISSUER_ID,
        "holderCommitment": field_to_hex(holder_commitment),
        "credentialId": field_to_hex(credential_id),
        "claims": {
            "claim0": claim_0,
            "claim1": claim_1,
            "validFrom": valid_from,
            "validUntil": valid_until,
        },
        "expiresAt": valid_until,
        "signature": "0x" + signature.hex(),
        "witness": issuer_witness(TEST_ISSUER_ID, credential_id),
    }


def issuer_fixture(issuer_id: str, private_key: int, proof_types) -> dict:
    key_x, key_y = public_key_bytes(private_key)
    return {
        "issuerId": issuer_id,
        "publicKeyX": "0x" + key_x.hex(),
        "publicKeyY": "0x" + key_y.hex(),
        "proofTypes": list(proof_types),
    }


def build_vectors() -> dict:
    test_issuer = issuer_fixture(TEST_ISSUER_ID, TEST_ISSUER_PRIVATE_KEY, CORE_PROOF_TYPES)
    other_issuer = issuer_fixture(OTHER_ISSUER_ID, OTHER_ISSUER_PRIVATE_KEY, [KYC_PROOF_TYPE])

    context = {
        "profile": "zkc:context:verifier-session:v1",
        "verifierId": "verifier.example",
        "sessionId": field_to_hex(555),
        "timestamp": 1_700_000_000,
    }
    base_request = {
        "proofTypes": [KYC_PROOF_TYPE],
        "parameters": {
            KYC_PROOF_TYPE: {
                "requiredLevel": 1,
                "requiredAttributes": [True, False, True, False, False],
            }
        },
        "context": context,
        "maxProofAge": 3600,
        "trustPolicy": {"issuers": [test_issuer]},
        "accumulatorStates": {TEST_ISSUER_ID: accumulator_state(TEST_ISSUER_ID)},
    }

    def request_with(**overrides) -> dict:
        request = json.loads(json.dumps(base_request))
        request.update(overrides)
        return request

    def predicate_request(proof_type: str, parameters: dict, *, exact_member=False) -> dict:
        request = request_with(
            proofTypes=[proof_type],
            parameters={proof_type: parameters},
        )
        if exact_member:
            request["holderExactMemberConsents"] = {proof_type: True}
        return request

    other_session_context = dict(context, sessionId=field_to_hex(556))

    membership_path_index, membership_siblings = single_leaf_inclusion_witness()
    jurisdiction_inclusion_parameters = {
        "membershipType": MEMBERSHIP_TYPE_INCLUSION,
        "requiredClaimType": 1,
        "jurisdictionSetRoot": single_leaf_set_root(
            compute_jurisdiction_leaf(150, 1)
        ),
        "membershipPathIndex": membership_path_index,
        "membershipSiblings": membership_siblings,
    }
    jurisdiction_blocked_codes = [100, 200]
    jurisdiction_exclusion_set = CanonicalCodeSet.for_jurisdiction(
        jurisdiction_blocked_codes,
        claim_type=1,
        mode=CANONICAL_SET_EXCLUSION,
    )
    jurisdiction_exclusion_parameters = {
        "membershipType": MEMBERSHIP_TYPE_EXCLUSION,
        "requiredClaimType": 1,
        JURISDICTION_CANONICAL_SET_PARAM: jurisdiction_blocked_codes,
        "jurisdictionSetRoot": jurisdiction_exclusion_set.root(),
    }
    accreditation_level_2_parameters = {"required0": 2, "required1": 0}
    accreditation_level_3_parameters = {"required0": 3, "required1": 0}
    source_7_parameters = {
        "required0": 0,
        "required1": 0,
        "setRoot": single_leaf_set_root(7),
        "pathIndex": membership_path_index,
        "siblings": membership_siblings,
    }
    source_alternate_set = CanonicalCodeSet(
        [7, 8], raw_code_leaf, CANONICAL_SET_INCLUSION
    )
    source_alternate_witness = source_alternate_set.membership_witness(7)
    source_7_8_parameters = {
        "required0": 0,
        "required1": 0,
        "setRoot": source_alternate_set.root(),
        "pathIndex": source_alternate_witness.path_index,
        "siblings": list(source_alternate_witness.siblings),
    }
    tax_2025_parameters = {
        "required0": 0,
        "required1": 2025,
        "setRoot": single_leaf_set_root(840),
        "pathIndex": membership_path_index,
        "siblings": membership_siblings,
    }
    tax_2026_parameters = dict(tax_2025_parameters, required1=2026)
    sanctions_base_codes = [100, 200]
    sanctions_base_set = CanonicalCodeSet.for_sanctions(sanctions_base_codes)
    sanctions_base_parameters = {
        "required0": 0,
        "required1": 0,
        CANONICAL_SET_PARAM: sanctions_base_codes,
        "setRoot": sanctions_base_set.root(),
    }
    sanctions_alternate_codes = [120, 180]
    sanctions_alternate_set = CanonicalCodeSet.for_sanctions(sanctions_alternate_codes)
    sanctions_alternate_parameters = {
        "required0": 0,
        "required1": 0,
        CANONICAL_SET_PARAM: sanctions_alternate_codes,
        "setRoot": sanctions_alternate_set.root(),
    }

    credentials = {
        "valid_kyc": make_kyc_credential(
            credential_id=42,
            level=2,
            verified_attributes=[True, True, True, False, True],
            expires_at=2_000_000_000,
            issuer_id=TEST_ISSUER_ID,
            issuer_private_key=TEST_ISSUER_PRIVATE_KEY,
        ),
        "expired_kyc": make_kyc_credential(
            credential_id=43,
            level=2,
            verified_attributes=[True, True, True, False, True],
            expires_at=100,
            issuer_id=TEST_ISSUER_ID,
            issuer_private_key=TEST_ISSUER_PRIVATE_KEY,
        ),
        "revoked_kyc_self_made_root": make_kyc_credential(
            credential_id=50,
            level=2,
            verified_attributes=[True, True, True, False, True],
            expires_at=2_000_000_000,
            issuer_id=TEST_ISSUER_ID,
            issuer_private_key=TEST_ISSUER_PRIVATE_KEY,
            witness=self_made_witness(50),
        ),
        "other_issuer_kyc": make_kyc_credential(
            credential_id=44,
            level=2,
            verified_attributes=[True, True, True, False, True],
            expires_at=2_000_000_000,
            issuer_id=OTHER_ISSUER_ID,
            issuer_private_key=OTHER_ISSUER_PRIVATE_KEY,
        ),
        "valid_jurisdiction": make_jurisdiction_credential(
            credential_id=45,
            jurisdiction_code=150,
            claim_type=1,
        ),
        "valid_accreditation": make_profile_credential(
            credential_id=46,
            proof_type=ACCREDITATION_PROOF_TYPE,
            credential_type="zkc:cred:accreditation:v2",
            predicate_type=PREDICATE_ACCREDITATION,
            claim_0=3,
            claim_1=1,
        ),
        "valid_source": make_profile_credential(
            credential_id=47,
            proof_type=SOURCE_PROOF_TYPE,
            credential_type="zkc:cred:source:v2",
            predicate_type=PREDICATE_SOURCE_OF_FUNDS,
            claim_0=7,
            claim_1=0,
        ),
        "valid_tax": make_profile_credential(
            credential_id=48,
            proof_type=TAX_PROOF_TYPE,
            credential_type="zkc:cred:tax:v2",
            predicate_type=PREDICATE_TAX_RESIDENCY,
            claim_0=840,
            claim_1=2026,
        ),
        "valid_sanctions": make_profile_credential(
            credential_id=49,
            proof_type=SANCTIONS_PROOF_TYPE,
            credential_type="zkc:cred:sanctions:v2",
            predicate_type=PREDICATE_SANCTIONS_CLEARANCE,
            claim_0=150,
            claim_1=0,
        ),
    }

    requests = {
        "kyc_basic": base_request,
        "kyc_other_session": request_with(context=other_session_context),
        "kyc_level_3": request_with(
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 3,
                    "requiredAttributes": [True, False, True, False, False],
                }
            }
        ),
        "kyc_level_modulus_alias": request_with(
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": FIELD_MODULUS + 1,
                    "requiredAttributes": [True, False, True, False, False],
                }
            }
        ),
        "kyc_empty_trust": request_with(trustPolicy={"issuers": []}),
        "kyc_two_types": request_with(
            proofTypes=[KYC_PROOF_TYPE, JURISDICTION_PROOF_TYPE]
        ),
        "kyc_unrecorded_root": request_with(
            accumulatorStates={TEST_ISSUER_ID: {"currentEpoch": ACCUMULATOR_EPOCH}}
        ),
        "kyc_advanced_epoch": request_with(
            accumulatorStates={TEST_ISSUER_ID: accumulator_state(TEST_ISSUER_ID, 2)}
        ),
        "opaque_request": request_with(
            proofTypes=["zkc:proof:unreviewed-scoring:v1"], parameters={}
        ),
        "jurisdiction_inclusion": predicate_request(
            JURISDICTION_PROOF_TYPE, jurisdiction_inclusion_parameters, exact_member=True
        ),
        "jurisdiction_exclusion": predicate_request(
            JURISDICTION_PROOF_TYPE, jurisdiction_exclusion_parameters
        ),
        "accreditation_level_2": predicate_request(
            ACCREDITATION_PROOF_TYPE, accreditation_level_2_parameters
        ),
        "accreditation_level_3": predicate_request(
            ACCREDITATION_PROOF_TYPE, accreditation_level_3_parameters
        ),
        "source_set_7": predicate_request(SOURCE_PROOF_TYPE, source_7_parameters, exact_member=True),
        "source_set_7_8": predicate_request(
            SOURCE_PROOF_TYPE, source_7_8_parameters
        ),
        "tax_year_2025": predicate_request(TAX_PROOF_TYPE, tax_2025_parameters, exact_member=True),
        "tax_year_2026": predicate_request(TAX_PROOF_TYPE, tax_2026_parameters),
        "sanctions_set_100_200": predicate_request(
            SANCTIONS_PROOF_TYPE, sanctions_base_parameters
        ),
        "sanctions_set_120_180": predicate_request(
            SANCTIONS_PROOF_TYPE, sanctions_alternate_parameters
        ),
    }

    # --- Verifier accountability (Safeguard 6, §5.5–§5.7) ------------------
    # Purpose-bound requests: the declared purpose enters the context preimage,
    # so an access-purpose proof and a billing-purpose proof are cryptographically
    # distinct under otherwise identical sessions.
    def purpose_bound_context(purpose: str) -> dict:
        return {
            "profile": PURPOSE_BOUND_PROFILE,
            "verifierId": "verifier.example",
            "sessionId": field_to_hex(555),
            "purpose": purpose,
            "timestamp": 1_700_000_000,
        }

    requests["kyc_purpose_access"] = request_with(context=purpose_bound_context(ACCESS_PURPOSE))
    requests["kyc_purpose_billing"] = request_with(context=purpose_bound_context(BILLING_PURPOSE))

    def build_apr(request_key: str, *, nonce: int, signed: bool) -> dict:
        request = json.loads(json.dumps(requests[request_key]))
        unsigned = {
            "request": request,
            "verifierId": "verifier.example",
            "nonce": field_to_hex(nonce),
            "issuedAt": 1_700_000_000,
            "expiresAt": 1_700_003_600,
        }
        if signed:
            return sign_apr(unsigned, APR_VERIFIER_PRIVATE_KEY)
        # Structurally complete but UNSIGNED: a zero signature never verifies.
        key_x, key_y = public_key_bytes(APR_VERIFIER_PRIVATE_KEY)
        unsigned["signature"] = {
            "scheme": "ECDSA_SECP256K1",
            "value": "0x" + "00" * 64,
            "verifierKey": {"x": "0x" + key_x.hex(), "y": "0x" + key_y.hex()},
        }
        return unsigned

    aprs = {
        "apr_access_signed": build_apr("kyc_purpose_access", nonce=0xACCE55, signed=True),
        # A distinct request avoids replaying the preceding successful APR;
        # this vector must reach the purpose check, not the nonce gate.
        "apr_access_purpose_check": build_apr("kyc_purpose_access", nonce=0xACCE56, signed=True),
        "apr_access_unsigned": build_apr("kyc_purpose_access", nonce=0xBADBAD, signed=False),
        "apr_billing_signed": build_apr("kyc_purpose_billing", nonce=0xB111, signed=True),
    }

    cases = [
        # --- acceptance -----------------------------------------------------
        {
            "id": "core-roundtrip-valid",
            "description": "holder generates a Core KYC proof; verifier accepts it",
            "kind": "roundtrip",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "expect": {"valid": True},
        },
        {
            "id": "core-roundtrip-jurisdiction-valid",
            "description": "holder generates the requested jurisdiction inclusion proof",
            "kind": "roundtrip",
            "request": "jurisdiction_inclusion",
            "credentials": ["valid_jurisdiction"],
            "expect": {"valid": True},
        },
        {
            "id": "core-roundtrip-accreditation-valid",
            "description": "holder generates the requested accreditation-level proof",
            "kind": "roundtrip",
            "request": "accreditation_level_2",
            "credentials": ["valid_accreditation"],
            "expect": {"valid": True},
        },
        {
            "id": "core-roundtrip-source-valid",
            "description": "holder generates source-of-funds membership in the requested set",
            "kind": "roundtrip",
            "request": "source_set_7",
            "credentials": ["valid_source"],
            "expect": {"valid": True},
        },
        {
            "id": "core-roundtrip-tax-valid",
            "description": "holder generates tax-residency membership for the requested year",
            "kind": "roundtrip",
            "request": "tax_year_2025",
            "credentials": ["valid_tax"],
            "expect": {"valid": True},
        },
        {
            "id": "core-roundtrip-sanctions-valid",
            "description": "holder generates sanctions clearance against the requested blocked set",
            "kind": "roundtrip",
            "request": "sanctions_set_100_200",
            "credentials": ["valid_sanctions"],
            "expect": {"valid": True},
        },
        # --- holder refusals (fail closed, structured codes) ----------------
        {
            "id": "safeguard-4-opaque-refusal",
            "description": "Freedom Safeguard 4: holder refuses an unreviewed predicate by default",
            "kind": "holder_refusal",
            "request": "opaque_request",
            "credentials": ["valid_kyc"],
            "expect": {"anyCode": ["OPAQUE_PREDICATE_REFUSED"]},
        },
        {
            "id": "core-holder-unknown-issuer",
            "description": "holder refuses when no credential issuer is in the verifier trust policy",
            "kind": "holder_refusal",
            "request": "kyc_basic",
            "credentials": ["other_issuer_kyc"],
            "expect": {"anyCode": ["UNKNOWN_ISSUER"]},
        },
        {
            "id": "core-holder-stale-credential",
            "description": "holder refuses an expired credential",
            "kind": "holder_refusal",
            "request": "kyc_basic",
            "credentials": ["expired_kyc"],
            "expect": {"anyCode": ["STALE_CREDENTIAL"]},
        },
        {
            "id": "core-holder-no-credential",
            "description": "holder refuses when it has no matching credential",
            "kind": "holder_refusal",
            "request": "kyc_basic",
            "credentials": [],
            "expect": {"anyCode": ["NO_MATCHING_CREDENTIAL"]},
        },
        # --- verifier rejections (mutations on a fresh round-trip envelope) --
        {
            "id": "core-verifier-stale-proof",
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "mutations": [
                {"op": "set", "path": "metadata/generatedAt", "value": "2020-01-01T00:00:00Z"}
            ],
            "expect": {"valid": False, "anyCode": ["STALE_PROOF"]},
        },
        {
            "id": "core-verifier-expired-proof",
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "mutations": [
                {"op": "set", "path": "metadata/expiresAt", "value": "2020-01-01T00:00:00Z"}
            ],
            "expect": {"valid": False, "anyCode": ["EXPIRED_PROOF"]},
        },
        {
            "id": "core-verifier-wrong-context",
            "description": "envelope generated for one session must not verify for another",
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "verifyRequest": "kyc_other_session",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["CONTEXT_MISMATCH"]},
        },
        {
            "id": "core-verifier-tampered-binding",
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "mutations": [
                {
                    "op": "set",
                    "path": "holderBinding/commitment",
                    "value": field_to_hex(12345),
                }
            ],
            "expect": {"valid": False, "anyCode": ["INVALID_BINDING", "INVALID_PROOF"]},
        },
        {
            "id": "core-verifier-tampered-proof-inputs",
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "mutations": [
                {
                    "op": "set",
                    "path": "proofs/0/publicInputs/claim_binding",
                    "value": field_to_hex(1),
                }
            ],
            "expect": {"valid": False, "anyCode": ["INVALID_PROOF"]},
        },
        {
            "id": "core-verifier-missing-proof",
            "description": "an envelope missing a required proof type is rejected",
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "verifyRequest": "kyc_two_types",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["MISSING_PROOF"]},
        },
        {
            "id": "safeguard-1-no-canonical-issuer",
            "description": (
                "Freedom Safeguard 1: an empty verifier trust policy trusts nobody — "
                "not even the well-known test issuer"
            ),
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "verifyRequest": "kyc_empty_trust",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["UNTRUSTED_ISSUER"]},
        },
        {
            "id": "safeguard-1-registry-membership-not-trust",
            "description": (
                "Registry governance safeguard: the credential's issuer key is "
                "published in the repo's discovery registry (registry/issuers/), "
                "but this verifier's policy does not list it — discovery-registry "
                "membership must never substitute for the verifier's key-exact "
                "allowlist (the registry is an advisory cache, not a trust anchor)"
            ),
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "verifyRequest": "kyc_empty_trust",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["UNTRUSTED_ISSUER"]},
        },
        {
            "id": "core-verifier-stale-accumulator",
            "description": "issuer accumulator advanced (e.g. revocation) after generation",
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "verifyRequest": "kyc_advanced_epoch",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["STALE_ACCUMULATOR"]},
        },
        {
            "id": "core-verifier-revoked-self-made-root",
            "description": (
                "a revoked credential proves membership only in its holder's self-made "
                "one-leaf tree at the issuer's current epoch; the verifier records the "
                "issuer's published root for that epoch and rejects the proof"
            ),
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["revoked_kyc_self_made_root"],
            "verifyRequest": "kyc_basic",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["STALE_ACCUMULATOR"]},
        },
        {
            "id": "core-verifier-unrecorded-accumulator-root",
            "description": (
                "an honest proof is rejected when the verifier records no issuer root "
                "for the proof's accumulator epoch: an unchecked root enforces no "
                "revocation, so the verifier fails closed"
            ),
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "verifyRequest": "kyc_unrecorded_root",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["STALE_ACCUMULATOR"]},
        },
        {
            "id": "core-verifier-requirements-not-met",
            "description": "proof attesting level 1 requirements rejected for a level-3 request",
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "verifyRequest": "kyc_level_3",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["REQUIREMENTS_NOT_MET"]},
        },
        {
            "id": "core-verifier-noncanonical-requirement",
            "description": (
                "an untouched level-1 proof is rejected when the request shifts "
                "requiredLevel by the BN254 modulus instead of naming a canonical u8"
            ),
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "verifyRequest": "kyc_level_modulus_alias",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["REQUIREMENTS_NOT_MET"]},
        },
        {
            "id": "core-verifier-jurisdiction-requirements-not-met",
            "description": (
                "an untouched jurisdiction inclusion proof is rejected for an "
                "internally valid exclusion request over the same credential"
            ),
            "kind": "verifier_mutation",
            "request": "jurisdiction_inclusion",
            "credentials": ["valid_jurisdiction"],
            "verifyRequest": "jurisdiction_exclusion",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["REQUIREMENTS_NOT_MET"]},
        },
        {
            "id": "core-verifier-accreditation-requirements-not-met",
            "description": (
                "an untouched level-2 accreditation proof is rejected for a level-3 "
                "request that the credential could otherwise satisfy"
            ),
            "kind": "verifier_mutation",
            "request": "accreditation_level_2",
            "credentials": ["valid_accreditation"],
            "verifyRequest": "accreditation_level_3",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["REQUIREMENTS_NOT_MET"]},
        },
        {
            "id": "core-verifier-source-requirements-not-met",
            "description": (
                "an untouched source proof for the singleton set is rejected for a "
                "different valid set that still contains the credential code"
            ),
            "kind": "verifier_mutation",
            "request": "source_set_7",
            "credentials": ["valid_source"],
            "verifyRequest": "source_set_7_8",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["REQUIREMENTS_NOT_MET"]},
        },
        {
            "id": "core-verifier-tax-requirements-not-met",
            "description": (
                "an untouched tax-year-2025 proof is rejected for a tax-year-2026 "
                "request that the credential could otherwise satisfy"
            ),
            "kind": "verifier_mutation",
            "request": "tax_year_2025",
            "credentials": ["valid_tax"],
            "verifyRequest": "tax_year_2026",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["REQUIREMENTS_NOT_MET"]},
        },
        {
            "id": "core-verifier-sanctions-requirements-not-met",
            "description": (
                "an untouched sanctions proof is rejected for a different, "
                "self-consistent blocked set under which the subject is also clear"
            ),
            "kind": "verifier_mutation",
            "request": "sanctions_set_100_200",
            "credentials": ["valid_sanctions"],
            "verifyRequest": "sanctions_set_120_180",
            "mutations": [],
            "expect": {"valid": False, "anyCode": ["REQUIREMENTS_NOT_MET"]},
        },
        {
            "id": "core-verifier-malformed-mutation",
            "kind": "verifier_mutation",
            "request": "kyc_basic",
            "credentials": ["valid_kyc"],
            "mutations": [{"op": "delete", "path": "holderBinding"}],
            "expect": {"valid": False, "anyCode": ["MALFORMED_PROOF"]},
        },
        # --- static malformed envelopes --------------------------------------
        {
            "id": "core-verifier-static-garbage",
            "kind": "verifier_static",
            "request": "kyc_basic",
            "envelope": {"version": "zkc:proof:v1"},
            "expect": {"valid": False, "anyCode": ["MALFORMED_PROOF"]},
        },
        {
            "id": "core-verifier-static-wrong-version",
            "kind": "verifier_static",
            "request": "kyc_basic",
            "envelope": {
                "version": "zkc:proof:v0",
                "metadata": {},
                "proofs": [],
                "holderBinding": {},
            },
            "expect": {"valid": False, "anyCode": ["MALFORMED_PROOF"]},
        },
        # --- Safeguard 6 — Verifier Accountability (§5.5–§5.7, §6.2) --------
        {
            "id": "safeguard-6-apr-roundtrip-valid",
            "description": (
                "Safeguard 6: holder answers a valid purpose-bound Authenticated "
                "Proof Request; verifier accepts under the authenticated path"
            ),
            "kind": "apr_roundtrip",
            "request": "kyc_purpose_access",
            "apr": "apr_access_signed",
            "credentials": ["valid_kyc"],
            "expect": {"valid": True},
        },
        {
            "id": "safeguard-6-unsigned-request-refusal",
            "description": (
                "Safeguard 6: a conforming SDK refuses by default to generate a "
                "proof for a request that is not a validly signed APR"
            ),
            "kind": "apr_generation_refusal",
            "request": "kyc_purpose_access",
            "apr": "apr_access_unsigned",
            "credentials": ["valid_kyc"],
            "expect": {"anyCode": ["UNSIGNED_REQUEST"]},
        },
        {
            "id": "safeguard-6-purpose-mismatch",
            "description": (
                "Safeguard 6: a billing-purpose proof presented to an "
                "access-purpose request is rejected with PURPOSE_MISMATCH"
            ),
            "kind": "apr_purpose_mismatch",
            "genRequest": "kyc_purpose_billing",
            "genApr": "apr_billing_signed",
            "verifyRequest": "kyc_purpose_access",
            "verifyApr": "apr_access_purpose_check",
            "credentials": ["valid_kyc"],
            "expect": {"valid": False, "anyCode": ["PURPOSE_MISMATCH"]},
        },
        {
            "id": "safeguard-6-receipt-roundtrip",
            "description": (
                "Safeguard 6: a Disclosure Receipt round-trips — a third party "
                "verifies the verifier and holder signatures with no operator, "
                "issuer, or registry in the loop"
            ),
            "kind": "apr_receipt_roundtrip",
            "request": "kyc_purpose_access",
            "apr": "apr_access_signed",
            "credentials": ["valid_kyc"],
            "expect": {"receiptValid": True},
        },
        {
            "id": "safeguard-6-receipt-tampered",
            "description": (
                "Safeguard 6: a receipt whose bound contextValue is altered fails "
                "third-party verification"
            ),
            "kind": "apr_receipt_roundtrip",
            "request": "kyc_purpose_access",
            "apr": "apr_access_signed",
            "credentials": ["valid_kyc"],
            "mutations": [
                {"op": "set", "path": "response/contextValue", "value": field_to_hex(999)}
            ],
            "expect": {"receiptValid": False},
        },
        {
            "id": "safeguard-6-hosted-retention-refusal",
            "description": (
                "Safeguard 6: a hosted SDK answering on the holder's behalf hands "
                "the receipt back and retains nothing"
            ),
            "kind": "hosted_retention_refusal",
            "request": "kyc_purpose_access",
            "apr": "apr_access_signed",
            "credentials": ["valid_kyc"],
            "expect": {"retained": False},
        },
    ]

    return {
        "version": "zkc-conformance:v1",
        "profile": "core",
        "description": (
            "ZKC-Core conformance vectors. TEST-ONLY key material throughout; "
            "regenerate with conformance/generate_vectors.py."
        ),
        "masterSeed": field_to_hex(MASTER_SEED),
        "issuers": {"test": test_issuer, "other": other_issuer},
        "credentials": credentials,
        "requests": requests,
        "aprs": aprs,
        "cases": cases,
    }


def main() -> int:
    vectors = build_vectors()
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(json.dumps(vectors, indent=2, sort_keys=False) + "\n")
    print(f"wrote {VECTORS_PATH.relative_to(ROOT)} ({len(vectors['cases'])} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
