"""Deliberately NON-CONFORMANT adapters.

These exist to prove the conformance suite has teeth: each one violates a
Freedom Safeguard the way a real implementation might, and the suite MUST
fail it (tests/python/test_conformance.py asserts that it does).

DO NOT use these as a starting point for an implementation.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "python") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "python"))
if str(REPO_ROOT / "conformance") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "conformance"))

from adapters.reference import (  # noqa: E402
    ReferenceHolderAdapter,
    ReferenceVerifierAdapter,
    _proof_request,
    _receipt_anchor,
)
from zkc_crypto import master_seed_to_bytes, sign_receipt, verify_receipt  # noqa: E402
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes  # noqa: E402


class CanonicalIssuerVerifierAdapter(ReferenceVerifierAdapter):
    """VIOLATES Freedom Safeguard 1: silently injects a hardcoded
    'canonical' issuer into every verifier trust policy, so proofs from that
    issuer pass even when the verifier's policy never trusted it."""

    def verify(self, envelope: dict, request: dict) -> dict:
        canonical_private_key = (
            int.from_bytes(hashlib.sha256(b"zkc-test-issuer-v1").digest(), "big") % N
        )
        key_x, key_y = public_key_bytes(canonical_private_key)
        doctored = dict(request)
        doctored["trustPolicy"] = {
            "issuers": list(request["trustPolicy"]["issuers"])
            + [
                {
                    # Matches the well-known test issuer so the violation
                    # manifests as a wrongly ACCEPTED proof.
                    "issuerId": "did:zkc:test-issuer",
                    "publicKeyX": "0x" + key_x.hex(),
                    "publicKeyY": "0x" + key_y.hex(),
                    "proofTypes": ["zkc:proof:kyc:v1"],
                }
            ]
        }
        return super().verify(envelope, doctored)


class RegistryMembershipTrustingVerifierAdapter(ReferenceVerifierAdapter):
    """VIOLATES Freedom Safeguard 1 (registry governance): treats DISCOVERY-
    registry membership as trust — every issuer published in registry/issuers/
    is silently appended (by key) to the verifier's allowlist, so a proof from
    a registry-listed issuer passes even when the verifier's policy never
    trusted it. The registry is an advisory cache; membership must never
    substitute for the key-exact allowlist."""

    def verify(self, envelope: dict, request: dict) -> dict:
        from zkc_registry import DiscoveryRegistry

        registry = DiscoveryRegistry.from_repo(REPO_ROOT)
        injected = list(request["trustPolicy"]["issuers"])
        for issuer in registry.issuers():
            for key_x, key_y in issuer.public_keys():
                injected.append(
                    {
                        "issuerId": issuer.issuer_id,
                        "publicKeyX": "0x" + key_x.hex(),
                        "publicKeyY": "0x" + key_y.hex(),
                        "proofTypes": list(issuer.proof_types()),
                    }
                )
        doctored = dict(request)
        doctored["trustPolicy"] = {"issuers": injected}
        return super().verify(envelope, doctored)


class SelfAnchoringReceiptVerifierAdapter(ReferenceVerifierAdapter):
    """VIOLATES Freedom Safeguard 6 receipt anchoring (spec 5.6.1): trusts
    the holder key carried in the receipt itself, ignoring the relying
    party's expected key. Anyone could then sign a receipt under their own
    key and have it accepted as the holder's."""

    def verify_receipt(self, receipt: dict, *, expected_holder_key: dict = None) -> dict:
        try:
            carried = receipt["holderSignature"]["holderKey"]
        except (KeyError, TypeError):
            carried = None
        if not isinstance(carried, dict):
            return verify_receipt(receipt, expected_holder_key=expected_holder_key)
        return verify_receipt(receipt, expected_holder_key=carried)


class _ResigningReceiptHolderAdapter(ReferenceHolderAdapter):
    """Re-signs the reference receipt under ``_receipt_key`` and echoes that
    key as ``receiptHolderKey``: the echo is self-consistent, so only the
    runner's key-scope probes can catch the bad scope."""

    def _receipt_key(self, master_seed: str) -> int:
        raise NotImplementedError

    def generate_authenticated(self, request, apr, credentials, master_seed):
        result = super().generate_authenticated(request, apr, credentials, master_seed)
        if "receipt" in result:
            unsigned = {k: v for k, v in result["receipt"].items() if k != "holderSignature"}
            result["receipt"] = sign_receipt(unsigned, self._receipt_key(master_seed))
            result["receiptHolderKey"] = dict(result["receipt"]["holderSignature"]["holderKey"])
        return result


class GlobalReceiptKeyHolderAdapter(_ResigningReceiptHolderAdapter):
    """VIOLATES receipt key scope (spec 5.6.1): signs every receipt under the
    pre-R3.7 seed-global key, a cross-verifier linking handle."""

    def _receipt_key(self, master_seed: str) -> int:
        seed = master_seed_to_bytes(master_seed)
        digest = hashlib.blake2b(b"ZKC-Receipt-Key" + seed, digest_size=64).digest()
        return int.from_bytes(digest, "big") % N or 1


class UnstableReceiptKeyHolderAdapter(_ResigningReceiptHolderAdapter):
    """VIOLATES receipt key scope (spec 5.6.1): signs every receipt, linkable
    ones included, under a new random key, so no relying party can anchor a
    linkable receipt."""

    def _receipt_key(self, master_seed: str) -> int:
        import secrets

        return secrets.randbelow(N - 1) + 1


class CombinedViolationsVerifierAdapter(
    CanonicalIssuerVerifierAdapter,
    RegistryMembershipTrustingVerifierAdapter,
    SelfAnchoringReceiptVerifierAdapter,
):
    """Cooperative MRO chains both Safeguard-1 violations so one seeded run
    exercises the canonical-issuer AND registry-membership negatives (the
    canonical injection runs first so its violation still manifests as a
    wrongly ACCEPTED proof; the registry-membership violation is also
    exercised in isolation via adapters.seeded_registry_trust), plus the
    self-anchoring receipt verifier."""


class OpaqueAcceptingHolderAdapter(ReferenceHolderAdapter):
    """VIOLATES Freedom Safeguard 4: instead of refusing predicates that do
    not resolve to a reviewed registry entry, it fabricates an envelope."""

    def generate(self, request: dict, credentials: list, master_seed: str) -> dict:
        result = super().generate(request, credentials, master_seed)
        refusal = result.get("refusal", {})
        if refusal.get("code") == "OPAQUE_PREDICATE_REFUSED":
            return {
                "envelope": {
                    "version": "zkc:proof:v1",
                    "metadata": {
                        "generatedAt": "2026-01-01T00:00:00Z",
                        "expiresAt": "2026-01-01T01:00:00Z",
                        "context": {
                            "profile": request["context"]["profile"],
                            "value": "0x" + "00" * 32,
                            "timestamp": int(request["context"]["timestamp"]),
                        },
                    },
                    "proofs": [
                        {
                            "proofType": request["proofTypes"][0],
                            "proof": "opaque-predicate-proof",
                            "publicInputs": {},
                            "principalConsent": True,
                        }
                    ],
                    "holderBinding": {"commitment": "0x" + "11" * 32},
                }
            }
        return result


class Safeguard6ViolatingHolderAdapter(OpaqueAcceptingHolderAdapter):
    """VIOLATES Freedom Safeguard 6 (verifier accountability):

    * answers an UNSIGNED Authenticated Proof Request instead of refusing by
      default (no fail-closed posture toward an unauthenticated demand), and
    * as a hosted SDK, RETAINS the holder's Disclosure Receipt (operator
      custody) instead of handing it back and keeping nothing.

    The suite MUST catch both (tests/python/test_conformance.py asserts it).
    It returns the honest receipt anchor."""

    def generate_authenticated(self, request, apr, credentials, master_seed):
        client = self._client(credentials, master_seed)
        # Override the default refusal — answer even an unauthenticated request.
        result = client.generate_authenticated_proof(
            apr, _proof_request(request), allow_unauthenticated=True,
            now=_proof_request(request).context.timestamp
        )
        # Supply the honest receipt anchor, so a receipt-roundtrip failure is
        # attributable to the self-anchoring verifier, not a missing anchor.
        result["receiptHolderKey"] = _receipt_anchor(client, apr, result["receipt"])
        return result

    def answer_hosted(self, request, apr, credentials, master_seed):
        result = self.generate_authenticated(request, apr, credentials, master_seed)
        # Operator custody (the violation): claims to retain the receipt.
        return {
            "envelope": result.get("envelope"),
            "receipt": result.get("receipt"),
            "retained": True,
            "custody": "operator",
        }


def make_holder_adapter():
    return Safeguard6ViolatingHolderAdapter()


def make_verifier_adapter():
    return CombinedViolationsVerifierAdapter()
