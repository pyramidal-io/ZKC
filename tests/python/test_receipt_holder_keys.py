"""Receipt and audit-authorization holder keys (security review R3.7).

Regression tests from the review PoC: receipt keys are scoped to the active
presentation profile (spec 5.6.1, 5.9.3), so anonymous receipts carry fresh,
unlinkable keys; scoped receipts are stable within a scope only; and neither
``verify_receipt`` nor ``verify_audit_bundle`` accepts a key carried in the
document as proof that the holder signed it.
"""

import copy
import hashlib
import hmac
import json
import pickle
import unittest
from unittest import mock

from _path import REPO_ROOT
from holder_fixtures import (
    DRAFT_OPT_IN_REVIEW_STATUSES,
    KYC_PROOF_TYPE,
    apr_verifier_identity,
    issue_kyc_credential,
    trusted_test_issuer,
)
from zkc_crypto import (
    ProofContext,
    apr_signer_pubkey,
    derive_verifier_identity,
    field_to_hex,
    holder_public_key,
    sign_apr,
    sign_receipt,
    verify_receipt,
)
from zkc_crypto.holder_keys import (
    derive_audit_authorization_key,
    derive_audit_authorization_root,
    _derive_fresh_receipt_key_kat,
    derive_fresh_receipt_key,
    derive_linkable_receipt_key,
    derive_scoped_receipt_key,
    holder_key_matches,
)
from zkc_crypto.ecdsa_secp256k1 import N
from zkc_crypto.presentation import ANONYMOUS_PROFILE, LINKABLE_PROFILE, SCOPED_PROFILE
from zkc_holder import (
    AuditBundleError,
    AuditExporter,
    HolderClient,
    HolderError,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    verify_audit_bundle,
)

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
MASTER_SEED = 42
TIMESTAMP = 1_700_000_000
PARAMS = {KYC_PROOF_TYPE: {"requiredLevel": 1, "requiredAttributes": [False] * 5}}
AUDITOR = "did:zkc:auditor:x#1"
VERIFIER_A = ("did:zkc:verifier:a", 0xA11)
VERIFIER_B = ("did:zkc:verifier:b", 0xB22)
SCOPED_VERIFIER = {"profile": SCOPED_PROFILE, "scopePolicy": "verifier", "rotationEpochSeconds": 0}


def holder_key_of(receipt):
    return receipt["holderSignature"]["holderKey"]


class ReceiptKeyBase(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.holder = HolderClient.from_seed(
            MASTER_SEED,
            REGISTRY,
            StubBackend(),
            accumulator_provider=self.provider,
            accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        self.holder.store_credential(
            issue_kyc_credential(
                master_seed=MASTER_SEED,
                credential_id=7,
                provider=self.provider,
                expires_at=2_000_000_000,
            )
        )
        self.trust = TrustPolicy(
            issuers=(trusted_test_issuer((KYC_PROOF_TYPE, "zkc:proof:kyc:v2")),)
        )

    def exchange(self, verifier, nonce, profile=ANONYMOUS_PROFILE, presentation=None,
                 timestamp=TIMESTAMP):
        verifier_id, apr_key = verifier
        context = ProofContext.verifier_session(verifier_id, nonce, timestamp)
        signed_request = {
            "proofTypes": [KYC_PROOF_TYPE],
            "parameters": PARAMS,
            "context": {
                "profile": context.profile,
                "verifierId": verifier_id,
                "sessionId": field_to_hex(nonce),
                "timestamp": timestamp,
            },
        }
        if presentation is not None:
            signed_request["presentation"] = presentation
        apr = sign_apr(
            {
                "request": signed_request,
                "verifierId": verifier_id,
                "nonce": field_to_hex(nonce),
                "issuedAt": timestamp - 1,
                "expiresAt": timestamp + 600,
            },
            apr_key,
        )
        request = ProofRequest(
            [KYC_PROOF_TYPE], PARAMS, context, self.trust, presentation_profile=profile
        )
        return apr, self.holder.generate_authenticated_proof(apr, request, now=timestamp)


class ReceiptKeyDerivationTests(ReceiptKeyBase):
    def test_anonymous_receipts_carry_fresh_unlinkable_keys(self):
        _, out_a = self.exchange(VERIFIER_A, 11)
        _, out_b = self.exchange(VERIFIER_B, 22)
        _, out_a2 = self.exchange(VERIFIER_A, 12)
        self.assertEqual(out_a["envelope"]["version"], "zkc:proof:v2")
        self.assertNotIn("holderCommitment", out_a["receipt"]["response"])
        keys = {holder_key_of(out["receipt"])["x"] for out in (out_a, out_b, out_a2)}
        # Different verifiers AND the same verifier twice: three distinct keys.
        self.assertEqual(len(keys), 3)
        # The fresh key is none of the holder's stable keys.
        for verifier_id, apr_key in (VERIFIER_A, VERIFIER_B):
            signer = apr_verifier_identity(apr_key, verifier_id)["verifier_signing_keys"][0]
            identity = derive_verifier_identity(signer)
            self.assertNotIn(
                self.holder.receipt_public_key(verifier_identity=identity)["x"], keys
            )

    def test_refusal_receipts_carry_fresh_keys(self):
        apr_a, _ = self.exchange(VERIFIER_A, 31)
        request = ProofRequest(
            [KYC_PROOF_TYPE], PARAMS,
            ProofContext.verifier_session(VERIFIER_A[0], 31, TIMESTAMP), self.trust,
        )
        first = self.holder.refusal_receipt(apr_a, request)
        second = self.holder.refusal_receipt(apr_a, request)
        self.assertNotEqual(holder_key_of(first), holder_key_of(second))

    def test_scoped_receipts_are_stable_within_a_scope_and_differ_across_scopes(self):
        _, first = self.exchange(VERIFIER_A, 41, SCOPED_PROFILE, SCOPED_VERIFIER)
        _, second = self.exchange(VERIFIER_A, 42, SCOPED_PROFILE, SCOPED_VERIFIER)
        _, other_verifier = self.exchange(VERIFIER_B, 43, SCOPED_PROFILE, SCOPED_VERIFIER)
        rotating = dict(SCOPED_VERIFIER, rotationEpochSeconds=3600)
        _, epoch_one = self.exchange(VERIFIER_A, 44, SCOPED_PROFILE, rotating)
        _, epoch_two = self.exchange(
            VERIFIER_A, 45, SCOPED_PROFILE, rotating, timestamp=TIMESTAMP + 3600
        )
        self.assertEqual(
            first["receipt"]["response"]["scopeId"], second["receipt"]["response"]["scopeId"]
        )
        self.assertEqual(holder_key_of(first["receipt"]), holder_key_of(second["receipt"]))
        for other in (other_verifier, epoch_one, epoch_two):
            self.assertNotEqual(holder_key_of(first["receipt"]), holder_key_of(other["receipt"]))
        self.assertNotEqual(holder_key_of(epoch_one["receipt"]), holder_key_of(epoch_two["receipt"]))
        # The holder can re-derive the scope key to anchor it out of band.
        scope_id = int(first["receipt"]["response"]["scopeId"], 16)
        anchor = self.holder.receipt_public_key(scope_id=scope_id)
        self.assertEqual(anchor, holder_key_of(first["receipt"]))
        self.assertTrue(verify_receipt(first["receipt"], expected_holder_key=anchor)["valid"])

    def test_linkable_receipts_use_one_key_per_authenticated_verifier(self):
        apr_a, first = self.exchange(VERIFIER_A, 51, LINKABLE_PROFILE)
        _, second = self.exchange(VERIFIER_A, 52, LINKABLE_PROFILE)
        apr_b, other = self.exchange(VERIFIER_B, 53, LINKABLE_PROFILE)
        self.assertEqual(holder_key_of(first["receipt"]), holder_key_of(second["receipt"]))
        self.assertNotEqual(holder_key_of(first["receipt"]), holder_key_of(other["receipt"]))
        for apr, out in ((apr_a, first), (apr_b, other)):
            anchor = self.holder.receipt_public_key(
                verifier_identity=derive_verifier_identity(apr_signer_pubkey(apr))
            )
            self.assertEqual(anchor, holder_key_of(out["receipt"]))
            self.assertTrue(verify_receipt(out["receipt"], expected_holder_key=anchor)["valid"])

    def test_reference_conformance_anchor_follows_the_effective_profile(self):
        import sys

        conformance = str(REPO_ROOT / "conformance")
        if conformance not in sys.path:
            sys.path.insert(0, conformance)
        from adapters.reference import _receipt_anchor

        apr_s, scoped = self.exchange(VERIFIER_A, 81, SCOPED_PROFILE, SCOPED_VERIFIER)
        apr_l, linkable = self.exchange(VERIFIER_A, 82, LINKABLE_PROFILE)
        apr_a, anonymous = self.exchange(VERIFIER_A, 83)
        scope_id = int(scoped["receipt"]["response"]["scopeId"], 16)
        self.assertEqual(
            _receipt_anchor(self.holder, apr_s, scoped["receipt"]),
            self.holder.receipt_public_key(scope_id=scope_id),
        )
        self.assertEqual(
            _receipt_anchor(self.holder, apr_l, linkable["receipt"]),
            self.holder.receipt_public_key(
                verifier_identity=derive_verifier_identity(apr_signer_pubkey(apr_l))
            ),
        )
        # Fresh key: only the holder's own assertion of its receipt's key.
        self.assertEqual(
            _receipt_anchor(self.holder, apr_a, anonymous["receipt"]),
            holder_key_of(anonymous["receipt"]),
        )

    def test_reference_conformance_anchor_for_unauthenticated_linkable_answer(self):
        import sys

        conformance = str(REPO_ROOT / "conformance")
        if conformance not in sys.path:
            sys.path.insert(0, conformance)
        from adapters.reference import _receipt_anchor

        # A validly signed but expired APR, answered through the override:
        # the linkable receipt carries a fresh key, not the per-verifier key.
        holder = HolderClient.from_seed(
            MASTER_SEED, REGISTRY, StubBackend(), accumulator_provider=self.provider,
        )
        holder.store_credential(issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=8, provider=self.provider,
            expires_at=2_000_000_000,
        ))
        apr, _ = self.exchange(VERIFIER_A, 84, LINKABLE_PROFILE)
        context = ProofContext.verifier_session(VERIFIER_A[0], 84, TIMESTAMP)
        request = ProofRequest([KYC_PROOF_TYPE], PARAMS, context, self.trust,
                               presentation_profile=LINKABLE_PROFILE)
        out = holder.generate_authenticated_proof(
            apr, request, allow_unauthenticated=True, allow_linkable=True,
            now=TIMESTAMP + 10_000,
        )
        self.assertIn("holderCommitment", out["receipt"]["response"])
        per_verifier = holder.receipt_public_key(
            verifier_identity=derive_verifier_identity(apr_signer_pubkey(apr))
        )
        self.assertNotEqual(holder_key_of(out["receipt"]), per_verifier)
        self.assertEqual(
            _receipt_anchor(holder, apr, out["receipt"]), holder_key_of(out["receipt"])
        )
        # The signed but stale demand still verifies; the receipt is not anchorable.
        self.assertTrue(verify_receipt(out["receipt"])["aprValid"])

    def test_receipt_public_key_takes_exactly_one_scope(self):
        with self.assertRaises(HolderError):
            self.holder.receipt_public_key()
        with self.assertRaises(HolderError):
            self.holder.receipt_public_key(verifier_identity=1, scope_id=1)
        with self.assertRaises(HolderError):
            self.holder.receipt_public_key(scope_id=0)


class DerivationFunctionTests(unittest.TestCase):
    def test_labels_and_inputs_are_domain_separated(self):
        nonce = bytes(32)
        keys = {
            derive_linkable_receipt_key(MASTER_SEED, 1),
            derive_scoped_receipt_key(MASTER_SEED, 1),
            _derive_fresh_receipt_key_kat(MASTER_SEED, nonce, 1),
            _derive_fresh_receipt_key_kat(MASTER_SEED, nonce, 2),
            derive_linkable_receipt_key(MASTER_SEED, 2),
            derive_linkable_receipt_key(MASTER_SEED + 1, 1),
            derive_audit_authorization_key(derive_audit_authorization_root(MASTER_SEED), "a"),
            derive_audit_authorization_key(derive_audit_authorization_root(MASTER_SEED), "b"),
        }
        self.assertEqual(len(keys), 8)
        self.assertEqual(
            _derive_fresh_receipt_key_kat(MASTER_SEED, nonce, 1),
            _derive_fresh_receipt_key_kat(MASTER_SEED, nonce, 1),
        )
        self.assertNotEqual(
            derive_fresh_receipt_key(MASTER_SEED, 1), derive_fresh_receipt_key(MASTER_SEED, 1)
        )

    def test_fresh_key_api_takes_no_nonce(self):
        import zkc_crypto

        self.assertFalse(hasattr(zkc_crypto, "_derive_fresh_receipt_key_kat"))
        with self.assertRaises(TypeError):
            derive_fresh_receipt_key(MASTER_SEED, 1, bytes(32))

    def test_repeated_rng_output_still_separates_different_receipts(self):
        # A VM snapshot clone can repeat the RNG; the receipt digest still
        # separates the keys of two different receipts.
        with mock.patch("zkc_crypto.holder_keys.secrets.token_bytes", return_value=bytes(32)):
            first = derive_fresh_receipt_key(MASTER_SEED, 1)
            second = derive_fresh_receipt_key(MASTER_SEED, 2)
            again = derive_fresh_receipt_key(MASTER_SEED, 1)
        self.assertNotEqual(first, second)
        self.assertEqual(first, again)

    def test_invalid_inputs_are_refused(self):
        for bad in (-1, 1 << 254, True, "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    derive_scoped_receipt_key(MASTER_SEED, bad)
                with self.assertRaises(ValueError):
                    derive_linkable_receipt_key(MASTER_SEED, bad)
        with self.assertRaises(ValueError):
            _derive_fresh_receipt_key_kat(MASTER_SEED, bytes(31), 1)
        for bad in (-1, 1 << 254, True):
            with self.assertRaises(ValueError):
                derive_fresh_receipt_key(MASTER_SEED, bad)
        root = derive_audit_authorization_root(MASTER_SEED)
        for bad_id in ("", None, b"id"):
            with self.assertRaises(ValueError):
                derive_audit_authorization_key(root, bad_id)
        with self.assertRaises(ValueError):
            derive_audit_authorization_key(root[:32], AUDITOR)

    def test_expected_key_comparison_is_exact(self):
        key = holder_public_key(derive_linkable_receipt_key(MASTER_SEED, 1))
        self.assertTrue(holder_key_matches(key, key))
        self.assertTrue(holder_key_matches({k: v.upper().replace("0X", "0x") for k, v in key.items()}, key))
        self.assertFalse(holder_key_matches({"x": key["x"]}, key))
        self.assertFalse(holder_key_matches(None, key))
        self.assertFalse(holder_key_matches(dict(key, extra="0x00"), key))
        for bad in (None, {"x": key["x"]}, {"x": key["x"][:-2], "y": key["y"]}):
            with self.assertRaises(ValueError):
                holder_key_matches(key, bad)


class KnownAnswerTests(unittest.TestCase):
    """Pins spec 5.6.1 with an independent transcription of the derivation."""

    VECTORS = json.loads(
        (REPO_ROOT / "tests" / "vectors" / "zkc_holder_keys_v2.json").read_text("utf-8")
    )

    @staticmethod
    def frame(*parts):
        return b"".join(len(part).to_bytes(4, "big") + part for part in parts)

    def spec_scalar(self, key, *parts):
        digest = hmac.new(key, self.frame(*parts), hashlib.sha512).digest()
        return int.from_bytes(digest, "big") % (N - 1) + 1

    def spec_key(self, seed, case):
        receipt = b"zkc/receipt-key:v2"
        if case["kind"] == "linkable":
            return self.spec_scalar(seed, receipt, b"linkable-verifier",
                                    bytes.fromhex(case["verifierIdentity"][2:]))
        if case["kind"] == "scoped":
            return self.spec_scalar(seed, receipt, b"scoped", bytes.fromhex(case["scopeId"][2:]))
        if case["kind"] == "fresh":
            return self.spec_scalar(seed, receipt, b"fresh", bytes.fromhex(case["nonce"][2:]),
                                    bytes.fromhex(case["receiptDigest"][2:]))
        root = hmac.new(seed, self.frame(b"zkc/audit-authorization-root:v2"), hashlib.sha512).digest()
        return self.spec_scalar(root, b"zkc/audit-authorization-key:v2",
                                case["auditorKeyId"].encode("utf-8"))

    def library_key(self, seed, case):
        if case["kind"] == "linkable":
            return derive_linkable_receipt_key(seed, int(case["verifierIdentity"], 16))
        if case["kind"] == "scoped":
            return derive_scoped_receipt_key(seed, int(case["scopeId"], 16))
        if case["kind"] == "fresh":
            return _derive_fresh_receipt_key_kat(
                seed, bytes.fromhex(case["nonce"][2:]), int(case["receiptDigest"], 16)
            )
        root = derive_audit_authorization_root(seed)
        return derive_audit_authorization_key(root, case["auditorKeyId"])

    def test_vectors(self):
        seed = bytes.fromhex(self.VECTORS["masterSeed"][2:])
        self.assertEqual(
            {case["kind"] for case in self.VECTORS["cases"]},
            {"linkable", "scoped", "fresh", "audit-authorization"},
        )
        for case in self.VECTORS["cases"]:
            with self.subTest(case=case):
                expected = case["publicKey"]
                self.assertEqual(holder_public_key(self.spec_key(seed, case)), expected)
                self.assertEqual(holder_public_key(self.library_key(seed, case)), expected)
        auditor = next(c for c in self.VECTORS["cases"] if c["kind"] == "audit-authorization")
        self.assertEqual(
            AuditExporter(seed).authorization_public_key(auditor["auditorKeyId"]),
            auditor["publicKey"],
        )


class ReceiptAnchoringTests(ReceiptKeyBase):
    def test_receipt_without_expected_key_is_never_valid(self):
        apr, out = self.exchange(VERIFIER_A, 61, LINKABLE_PROFILE)
        result = verify_receipt(out["receipt"])
        self.assertTrue(result["aprValid"])
        self.assertTrue(result["holderValid"])
        self.assertFalse(result["holderKeyAnchored"])
        self.assertFalse(result["valid"])

    def test_forged_victim_commitment_receipt_fails(self):
        # PoC (2): a verifier holding the victim's linkable commitment signs an
        # "answered" receipt under its own key.
        apr, out = self.exchange(VERIFIER_A, 62, LINKABLE_PROFILE)
        victim_commitment = out["receipt"]["response"]["holderCommitment"]
        forged = sign_receipt(
            {
                "apr": apr,
                "outcome": "answered",
                "recordedAt": 1,
                "response": {
                    "holderCommitment": victim_commitment,
                    "contextValue": out["receipt"]["response"]["contextValue"],
                    "answeredProofTypes": [KYC_PROOF_TYPE],
                },
            },
            0x5EC12E7,
        )
        victim_key = self.holder.receipt_public_key(
            verifier_identity=derive_verifier_identity(apr_signer_pubkey(apr))
        )
        result = verify_receipt(forged, expected_holder_key=victim_key)
        self.assertTrue(result["aprValid"])
        self.assertTrue(result["holderValid"])
        self.assertFalse(result["holderKeyAnchored"])
        self.assertFalse(result["valid"])
        self.assertFalse(verify_receipt(forged)["valid"])

    def test_swapping_in_the_expected_key_breaks_the_signature(self):
        apr, out = self.exchange(VERIFIER_A, 63, LINKABLE_PROFILE)
        anchor = holder_key_of(out["receipt"])
        forged = sign_receipt(
            {key: value for key, value in out["receipt"].items() if key != "holderSignature"},
            0x5EC12E7,
        )
        forged["holderSignature"]["holderKey"] = copy.deepcopy(anchor)
        result = verify_receipt(forged, expected_holder_key=anchor)
        # A matching key that did not sign the receipt anchors nothing.
        self.assertFalse(result["holderKeyAnchored"])
        self.assertFalse(result["holderValid"])
        self.assertFalse(result["valid"])

    def test_malformed_expected_key_is_a_caller_error(self):
        _, out = self.exchange(VERIFIER_A, 64, LINKABLE_PROFILE)
        with self.assertRaises(ValueError):
            verify_receipt(out["receipt"], expected_holder_key={"x": "0x01"})


class AuditBundleAnchoringTests(ReceiptKeyBase):
    def bundle(self, exporter, auditor=AUDITOR):
        _, out = self.exchange(VERIFIER_A, 71, LINKABLE_PROFILE)
        return exporter.export(
            [{"envelope": out["envelope"], "verification": {
                "proofTypes": [KYC_PROOF_TYPE], "parameters": PARAMS,
                "context": ProofContext.verifier_session(VERIFIER_A[0], 71, TIMESTAMP).to_metadata(),
            }}],
            auditor_key_id=auditor, valid_from=1, valid_until=2_000_000_000,
            purpose="holder-consented audit",
        )

    def test_honest_bundle_verifies_with_the_expected_holder_key(self):
        exporter = AuditExporter(MASTER_SEED)
        bundle = self.bundle(exporter)
        result = verify_audit_bundle(
            bundle, now=TIMESTAMP,
            expected_holder_key=exporter.authorization_public_key(AUDITOR),
            expected_auditor_key_id=AUDITOR,
        )
        self.assertTrue(result.valid, result.errors)

    def test_bundle_without_expected_key_fails_closed(self):
        result = verify_audit_bundle(self.bundle(AuditExporter(MASTER_SEED)), now=TIMESTAMP)
        self.assertEqual(result.codes(), ["HOLDER_KEY_UNANCHORED"])

    def test_verifier_minted_bundle_fails(self):
        # PoC (1): verifier A holds the holder's envelope and signs a bundle
        # under a key of its own.
        holder_key = AuditExporter(MASTER_SEED).authorization_public_key(AUDITOR)
        forged = self.bundle(AuditExporter(b"\x99" * 32))
        result = verify_audit_bundle(
            forged, now=TIMESTAMP, expected_holder_key=holder_key,
            expected_auditor_key_id=AUDITOR,
        )
        self.assertEqual(result.codes(), ["HOLDER_KEY_MISMATCH"])

    def test_exporter_never_serializes_or_reveals_its_root(self):
        exporter = AuditExporter(MASTER_SEED)
        root = derive_audit_authorization_root(MASTER_SEED)
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.assertRaises(TypeError):
                pickle.dumps(exporter, protocol=protocol)
        self.assertFalse(hasattr(exporter, "__dict__"))
        for text in (repr(exporter), str(exporter)):
            self.assertNotIn(root.hex(), text)
            self.assertNotIn(str(int.from_bytes(root, "big")), text)
        with self.assertRaises(AttributeError):
            exporter._authorization_root = bytes(64)
        with self.assertRaises(AttributeError):
            del exporter._authorization_root
        with self.assertRaises(TypeError):
            exporter.__getstate__()
        self.assertIs(copy.deepcopy(exporter), exporter)
        self.assertEqual(exporter.authorization_public_key(AUDITOR)["x"][:2], "0x")

    def test_bad_auditor_id_failure_never_holds_the_root(self):
        import traceback

        def failing_traceback(bad):
            # The root is not a local here, so only library frames could show it.
            exporter = AuditExporter(MASTER_SEED)
            try:
                exporter.authorization_public_key(bad)
            except AuditBundleError as exc:
                self.assertIsNone(exc.__cause__)
                return "".join(traceback.TracebackException.from_exception(
                    exc, capture_locals=True).format())
            self.fail("bad auditor id was accepted")

        root = derive_audit_authorization_root(MASTER_SEED)
        for bad in ("", None, b"id", 7, "\ud800"):
            with self.subTest(bad=repr(bad)):
                rendered = failing_traceback(bad)
                self.assertIn("_require_auditor_key_id", rendered)
                for needle in (root.hex(), repr(root), str(int.from_bytes(root, "big"))):
                    self.assertNotIn(needle, rendered)

    def test_authorization_keys_are_per_auditor(self):
        exporter = AuditExporter(MASTER_SEED)
        key_x = exporter.authorization_public_key("did:zkc:auditor:x#1")
        key_y = exporter.authorization_public_key("did:zkc:auditor:y#1")
        self.assertNotEqual(key_x, key_y)
        # A bundle for auditor x does not validate for auditor y's anchor.
        bundle = self.bundle(exporter, "did:zkc:auditor:x#1")
        result = verify_audit_bundle(bundle, now=TIMESTAMP, expected_holder_key=key_y)
        self.assertEqual(result.codes(), ["HOLDER_KEY_MISMATCH"])
        self.assertEqual(bundle["authorization"]["holderAuthorizationKey"], key_x)


if __name__ == "__main__":
    unittest.main()
