"""Shared fixtures: a deterministic test issuer wired to the holder SDK.

Uses the well-known ZKC test issuer key (tools/zkc_test_issuer.py) — public,
TEST-ONLY material.
"""

import dataclasses
import hashlib

import _path  # noqa: F401  (sys.path side effect)

from zkc_crypto import (
    LINKABLE_PROFILE,
    compute_kyc_credential_digest,
    compute_selective_disclosure_credential_digest,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
)
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes, sign
from zkc_holder import Credential, TrustedIssuer

TEST_ISSUER_ID = "did:zkc:test-issuer"
TEST_ISSUER_PRIVATE_KEY = int.from_bytes(hashlib.sha256(b"zkc-test-issuer-v1").digest(), "big") % N
TEST_ISSUER_KEY_X, TEST_ISSUER_KEY_Y = public_key_bytes(TEST_ISSUER_PRIVATE_KEY)

KYC_PROOF_TYPE = "zkc:proof:kyc:v1"

# Safeguard 4: every v2 presentation sibling (for example zkc:proof:kyc:v2) is
# a `draft` registry entry, so a default holder refuses it on the anonymous and
# scoped paths. Fixtures that test presentation or verifier behaviour, not the
# review gate, opt in to draft entries explicitly through this holder policy.
DRAFT_OPT_IN_REVIEW_STATUSES = ("reviewed", "self_attested", "draft")


def generate_unauthenticated_linkable(holder, request, **kwargs):
    """Answer ``request`` on the legacy linkable v1 path without an APR.

    For tests whose subject is the frozen ``zkc:proof:v1`` envelope, its
    witnesses or its verification, not Safeguard 6 admission or the
    presentation default. It states both explicit holder decisions that path
    now needs: the holder's linkable consent (``allow_linkable=True`` for
    the linkable profile, which discloses ``holderBinding``) and the logged
    ``allow_unauthenticated=True`` override. ``request`` is not mutated.
    """
    return holder.generate_proof(
        dataclasses.replace(request, presentation_profile=LINKABLE_PROFILE),
        allow_unauthenticated=True,
        allow_linkable=True,
        **kwargs,
    )


def apr_verifier_identity(private_key=0xA9701, verifier_id="verifier.example"):
    """Independent verifier configuration from a known TEST-ONLY signing key."""
    key_x, key_y = public_key_bytes(private_key)
    return {
        "verifier_id": verifier_id,
        "verifier_signing_keys": (bytes([2 + (key_y[-1] & 1)]) + key_x,),
    }


def trusted_test_issuer(proof_types=(KYC_PROOF_TYPE,)) -> TrustedIssuer:
    return TrustedIssuer(
        issuer_id=TEST_ISSUER_ID,
        public_key_x=TEST_ISSUER_KEY_X,
        public_key_y=TEST_ISSUER_KEY_Y,
        proof_types=tuple(proof_types),
    )


def issue_kyc_credential(
    *,
    master_seed: int,
    credential_id: int,
    level: int = 2,
    verified_attributes=(True, True, True, False, True),
    expires_at: int = 2_000_000,
    provider=None,
    issuer_id: str = TEST_ISSUER_ID,
) -> Credential:
    """Issue a properly signed KYC credential bound to the holder seed."""
    holder_commitment = derive_holder_commitment_from_seed(master_seed)
    digest = compute_kyc_credential_digest(
        holder_commitment, credential_id, level, list(verified_attributes), expires_at
    )
    signature = sign(digest_to_message_bytes(digest), TEST_ISSUER_PRIVATE_KEY)
    if provider is not None:
        provider.register(issuer_id, credential_id)
    return Credential(
        credential_type="zkc:kyc:v1",
        proof_type=KYC_PROOF_TYPE,
        issuer_id=issuer_id,
        holder_commitment=holder_commitment,
        credential_id=credential_id,
        claims={"level": level, "verifiedAttributes": list(verified_attributes)},
        expires_at=expires_at,
        signature=signature,
    )


def issue_attribute_set_credential(
    *,
    master_seed: int,
    credential_id: int,
    attributes=(0, 11, 22, 33),
    expires_at: int = 2_000_000,
    provider=None,
    issuer_id: str = TEST_ISSUER_ID,
) -> Credential:
    """Issue a signed, fixed-slot selective-disclosure credential."""
    active = list(attributes)
    if not 1 <= len(active) <= 8:
        raise ValueError("attribute-set fixture requires between 1 and 8 values")
    padded = active + [0] * (8 - len(active))
    holder_commitment = derive_holder_commitment_from_seed(master_seed)
    digest = compute_selective_disclosure_credential_digest(
        holder_commitment,
        credential_id,
        len(active),
        padded,
        expires_at,
    )
    signature = sign(digest_to_message_bytes(digest), TEST_ISSUER_PRIVATE_KEY)
    if provider is not None:
        provider.register(issuer_id, credential_id)
    return Credential(
        credential_type="zkc:cred:attribute-set:v1",
        proof_type="zkc:proof:selective_disclosure:v1",
        issuer_id=issuer_id,
        holder_commitment=holder_commitment,
        credential_id=credential_id,
        claims={"attributeCount": len(active), "attributes": padded},
        expires_at=expires_at,
        signature=signature,
    )


def verify_receipt_as_holder(receipt: dict) -> dict:
    """Verify a Disclosure Receipt as the holder that keeps it in custody.

    Only the holder knows which key it signed with, so only the holder may
    anchor a receipt to the key the receipt itself carries. A third party
    MUST pass an expected holder key it obtained from the holder out of band
    (spec 5.6.1); see test_receipt_holder_keys for those anchors."""
    from zkc_crypto import verify_receipt

    return verify_receipt(
        receipt, expected_holder_key=receipt["holderSignature"]["holderKey"]
    )
