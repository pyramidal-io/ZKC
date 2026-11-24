#!/usr/bin/env python3
"""Discovery-registry Freedom Safeguard checks (Safeguard 1, executable).

The discovery registry (registry/issuers + registry/verifiers) provides
DISCOVERY ONLY. This script proves, with real envelopes, that:

1. REGISTRY MEMBERSHIP IS NEVER SUFFICIENT FOR TRUST — an envelope from an
   issuer that is published in registry/issuers/ MUST be rejected
   (UNTRUSTED_ISSUER) by a verifier whose own policy does not list that
   issuer's key. An empty policy trusts nobody.
2. REGISTRY ABSENCE IS NEVER A TRUST FAILURE — a verifier policy that lists
   an issuer key found in NO registry verifies that issuer's proofs
   normally: trust is by key, not by membership.
3. NO DEFAULT ISSUER — discovery lookups return ALL matches deterministically
   (no ranking, no blessed first result), and the zkc_registry code contains
   no hardcoded issuer key material.

Exit code 0 only when every check passes. Standard library only.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for path in (str(ROOT / "python"), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from zkc_crypto import (  # noqa: E402
    LINKABLE_PROFILE,
    ProofContext,
    compute_kyc_credential_digest,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
)
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes, sign  # noqa: E402
from zkc_holder import (  # noqa: E402
    Credential,
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    TrustedIssuer,
)
from zkc_registry import DiscoveryRegistry, to_verifier_trust_policy  # noqa: E402
from zkc_verifier import (  # noqa: E402
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)

KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
MASTER_SEED = 0x5EED

# Well-known, public, TEST-ONLY key material.
REGISTRY_LISTED_ISSUER_ID = "zkc:issuer:zkc-test-issuer"
REGISTRY_LISTED_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-test-issuer-v1").digest(), "big") % N
)
OUT_OF_REGISTRY_ISSUER_ID = "did:zkc:out-of-registry-issuer"
OUT_OF_REGISTRY_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-out-of-registry-issuer-v1").digest(), "big") % N
)

failures = []


def check(condition: bool, label: str, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(label)


def generate_envelope(issuer_id: str, private_key: int, provider, trust_policy):
    """Issue a KYC credential from `issuer_id` and generate a real envelope."""
    holder_commitment = derive_holder_commitment_from_seed(MASTER_SEED)
    credential_id = 4242
    digest = compute_kyc_credential_digest(
        holder_commitment, credential_id, 2, [True, True, True, False, True], 2_000_000
    )
    signature = sign(digest_to_message_bytes(digest), private_key)
    provider.register(issuer_id, credential_id)
    credential = Credential(
        credential_type="zkc:cred:kyc:v1",
        proof_type=KYC_PROOF_TYPE,
        issuer_id=issuer_id,
        holder_commitment=holder_commitment,
        credential_id=credential_id,
        claims={"level": 2, "verifiedAttributes": [True, True, True, False, True]},
        expires_at=2_000_000,
        signature=signature,
    )
    client = HolderClient.from_seed(
        MASTER_SEED,
        PredicateRegistry.from_repo(ROOT),
        StubBackend(),
        accumulator_provider=provider,
    )
    client.store_credential(credential)
    request = ProofRequest(
        proof_types=[KYC_PROOF_TYPE],
        parameters={
            KYC_PROOF_TYPE: {
                "requiredLevel": 2,
                "requiredAttributes": [True, False, False, False, False],
            }
        },
        context=ProofContext.verifier_session("did:zkc:verifier", 0xABCDEF, 1_700_000),
        trust_policy=trust_policy,
        # This check exercises verifier trust over the linkable v1 envelope.
        presentation_profile=LINKABLE_PROFILE,
    )
    # No APR here: the explicit, logged Safeguard 6 opt-in and the explicit
    # linkable consent (neither is the default).
    return client.generate_proof(request, allow_unauthenticated=True, allow_linkable=True)


def verification_request(provider, issuer_id):
    return VerificationRequest(
        proof_types=[KYC_PROOF_TYPE],
        parameters={
            KYC_PROOF_TYPE: {
                "requiredLevel": 2,
                "requiredAttributes": [True, False, False, False, False],
            }
        },
        context=ProofContext.verifier_session("did:zkc:verifier", 0xABCDEF, 1_700_000),
        accumulator_states={
            issuer_id: IssuerAccumulatorState(
                current_epoch=provider.current_epoch(issuer_id),
                roots=provider.roots(issuer_id),
            )
        },
    )


def issuer_trust(issuer_id: str, private_key: int) -> TrustedIssuer:
    key_x, key_y = public_key_bytes(private_key)
    return TrustedIssuer(
        issuer_id=issuer_id,
        public_key_x=key_x,
        public_key_y=key_y,
        proof_types=(KYC_PROOF_TYPE,),
    )


def main() -> int:
    registry = DiscoveryRegistry.from_repo(ROOT)

    # --- 1. Registry membership must never be sufficient for trust. --------
    listed = registry.issuer(REGISTRY_LISTED_ISSUER_ID)
    check(listed is not None, "registry lists the well-known test issuer (fixture)")
    key_x, key_y = public_key_bytes(REGISTRY_LISTED_PRIVATE_KEY)
    check(
        listed is not None and (key_x, key_y) in listed.public_keys(),
        "registry document carries the test issuer's published key",
    )

    provider = LocalAccumulatorProvider()
    # Holder-side policy trusts the issuer (the holder chose to), but the
    # VERIFIER's policy is empty — registry membership must not fill it.
    envelope = generate_envelope(
        REGISTRY_LISTED_ISSUER_ID,
        REGISTRY_LISTED_PRIVATE_KEY,
        provider,
        TrustPolicy(issuers=(issuer_trust(REGISTRY_LISTED_ISSUER_ID, REGISTRY_LISTED_PRIVATE_KEY),)),
    )
    empty_policy_verifier = ZKCVerifier(ROOT, VerifierTrustPolicy(issuers=()), StubVerifyBackend())
    result = empty_policy_verifier.verify(
        envelope, verification_request(provider, REGISTRY_LISTED_ISSUER_ID)
    )
    check(
        not result.valid and "UNTRUSTED_ISSUER" in result.codes(),
        "registry-listed issuer is REJECTED by a verifier whose policy does not list it "
        "(membership is not trust)",
        str(result.to_dict()),
    )

    # --- 2. Policies may trust issuers outside the registry. ---------------
    check(
        registry.issuer(OUT_OF_REGISTRY_ISSUER_ID) is None,
        "out-of-registry issuer is genuinely absent from registry/issuers",
    )
    published = registry.verifier_policy("did:zkc:verifier:example-exchange")
    check(published is not None, "example verifier policy is published")
    check(
        published is not None
        and published.trusts_issuer_id(OUT_OF_REGISTRY_ISSUER_ID, KYC_PROOF_TYPE),
        "published policy trusts an issuer that is in NO registry (trust is by key)",
    )

    provider2 = LocalAccumulatorProvider()
    envelope2 = generate_envelope(
        OUT_OF_REGISTRY_ISSUER_ID,
        OUT_OF_REGISTRY_PRIVATE_KEY,
        provider2,
        TrustPolicy(issuers=(issuer_trust(OUT_OF_REGISTRY_ISSUER_ID, OUT_OF_REGISTRY_PRIVATE_KEY),)),
    )
    policy_verifier = ZKCVerifier(ROOT, to_verifier_trust_policy(published), StubVerifyBackend())
    result2 = policy_verifier.verify(
        envelope2, verification_request(provider2, OUT_OF_REGISTRY_ISSUER_ID)
    )
    check(
        result2.valid,
        "out-of-registry issuer's proof VERIFIES under the policy that pins its key "
        "(registry absence is not a failure)",
        str(result2.to_dict()),
    )

    # --- 3. No default issuer / no ranking. ---------------------------------
    all_issuers = registry.lookup_issuers()
    check(
        list(all_issuers) == sorted(all_issuers, key=lambda issuer: issuer.issuer_id),
        "lookup_issuers returns ALL issuers in deterministic sorted order (no ranking)",
    )
    kyc_issuers = registry.lookup_issuers(proof_type=KYC_PROOF_TYPE)
    check(len(kyc_issuers) >= 2, "multiple independent issuers coexist for the same proof type")

    source_blob = "\n".join(
        path.read_text() for path in sorted((ROOT / "python" / "zkc_registry").glob("*.py"))
    )
    check(
        not re.search(r"0x[0-9a-fA-F]{64}", source_blob),
        "zkc_registry code contains no hardcoded issuer key material",
    )
    check(
        not re.search(r"default_issuer|DEFAULT_ISSUER|canonical_issuer", source_blob),
        "zkc_registry code defines no default/canonical issuer path",
    )

    print()
    if failures:
        print(f"discovery safeguard checks FAILED: {failures}", file=sys.stderr)
        return 1
    print("all discovery safeguard checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
