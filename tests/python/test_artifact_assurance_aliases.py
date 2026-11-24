"""Assurance follows the verified VK, including aliases under other labels.

The deterministic backend binds a payload to actual manifest-pinned VK bytes
and public inputs, deliberately ignoring the presentation label/circuit name.
It models key selection, not cryptographic soundness. The live test uses BB.
"""

import copy
import dataclasses
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

import _path  # noqa: F401
from _path import REPO_ROOT
from holder_fixtures import (
    TEST_ISSUER_ID,
    apr_verifier_identity,
    issue_kyc_credential,
    trusted_test_issuer,
)
from zkc_crypto import ProofContext, derive_credential_binding_key, field_to_hex, sign_apr
from zkc_crypto.presentation import ANONYMOUS_PROFILE
from zkc_holder import LocalAccumulatorProvider, NargoBackend, PredicateRegistry, StubBackend
from zkc_holder.backend import build_kyc_witness_v2
from zkc_registry.predicate_v2 import request_extension
from zkc_verifier import (
    BBVerifyBackend,
    IssuerAccumulatorState,
    VerificationRequest,
    VerificationKeyStore,
    VerifierTrustPolicy,
    VerifyBackend,
    ZKCVerifier,
)
from zkc_verifier.errors import VerificationErrorCode as Code, VerificationResult

KYC_V2 = "zkc:proof:kyc:v2"
KYC_V3 = "zkc:proof:kyc:v3"
PARAMETERS = {"requiredLevel": 1, "requiredAttributes": [True, False, True, False, False]}
CONTEXT = ProofContext.verifier_session("verifier.example", 555, 1_700_000_000)
APR_KEY = 0xA9701
ACCEPTED = ("reviewed", "self_attested")


SUCCESSOR_NARGO = os.environ.get("ZKC_SUCCESSOR_NARGO", "nargo")
SUCCESSOR_BB = os.environ.get("ZKC_SUCCESSOR_BB", "bb")


def _successor_toolchain():
    try:
        nargo = subprocess.run([SUCCESSOR_NARGO, "--version"], check=True,
                               capture_output=True, text=True).stdout
        bb = subprocess.run([SUCCESSOR_BB, "--version"], check=True,
                            capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return False
    return "1.0.0-beta.25" in nargo and bb.strip() == "5.0.0"


class KeyBoundBackend(VerifyBackend):
    """Test-only key-bound oracle; exercises production VK lookup/pin checks."""

    name = "test-key-bound"
    is_production = True

    def __init__(self):
        self.keys = []

    @staticmethod
    def payload(vk_bytes, inputs):
        return "0x" + hashlib.sha256(
            vk_bytes + json.dumps(inputs, sort_keys=True).encode()
        ).hexdigest()

    def verify(self, circuit, proof, public_inputs, vk_bytes):
        self.keys.append(hashlib.sha256(vk_bytes).hexdigest())
        return proof == self.payload(vk_bytes, public_inputs)


class ArtifactAssuranceInventoryTests(unittest.TestCase):
    def test_public_registry_inventory_uses_only_published_key_bindings(self):
        registry = PredicateRegistry.from_repo(REPO_ROOT)
        bindings = registry.bindings_for("zkc-kyc", "4.0.0", KYC_V2)
        self.assertEqual(len(bindings), 2)
        for binding in bindings:
            sources, builds = registry.artifact_review_statuses(binding.vk_hash)
            self.assertIn("self_attested", sources)
            self.assertEqual(builds, ("self_attested",))
        for invalid in (None, "", "0x", "0x" + "z" * 64):
            self.assertEqual(registry.artifact_review_statuses(invalid), ((), ()))


class ArtifactAssuranceAliasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = PredicateRegistry.from_repo(REPO_ROOT)
        cls.bindings = cls.registry.bindings_for("zkc-kyc", "4.0.0", KYC_V2)
        cls.successor = next(b for b in cls.bindings if b.toolchain["id"] == "successor")
        cls.historical = next(b for b in cls.bindings if b.toolchain["id"] == "historical")
        provider = LocalAccumulatorProvider()
        credential = issue_kyc_credential(
            master_seed=1111, credential_id=7, provider=provider, expires_at=2_000_000_000
        )
        witness = provider.witness(TEST_ISSUER_ID, 7)
        cls.witness = build_kyc_witness_v2(
            credential_binding_key=derive_credential_binding_key(1111),
            credential=credential,
            issuer=trusted_test_issuer(),
            witness=witness,
            required_level=PARAMETERS["requiredLevel"],
            required_attributes=PARAMETERS["requiredAttributes"],
            proof_context=CONTEXT.value,
            timestamp=CONTEXT.timestamp,
            current_epoch=provider.current_epoch(TEST_ISSUER_ID),
            scope_id=0,
        )
        cls.inputs = StubBackend().public_inputs("zkc_kyc_v3", cls.witness)
        cls.states = {TEST_ISSUER_ID: IssuerAccumulatorState(
            current_epoch=provider.current_epoch(TEST_ISSUER_ID),
            roots={witness.accumulator_epoch: witness.accumulator_root},
        )}
        cls.vk = (REPO_ROOT / cls.successor.artifacts["vk"]).read_bytes()
        cls.proof = KeyBoundBackend.payload(cls.vk, cls.inputs)

    def verifier(self, statuses=ACCEPTED, backend=None, **policy):
        return ZKCVerifier(REPO_ROOT, VerifierTrustPolicy(
            issuers=(trusted_test_issuer((KYC_V2, KYC_V3)),),
            **apr_verifier_identity(APR_KEY),
            accepted_review_statuses=statuses,
            **policy,
        ), backend or KeyBoundBackend())

    def exchange(self, label, selector=None, proof=None):
        entry = {"proofType": label, "proof": proof or self.proof,
                 "publicInputs": copy.deepcopy(self.inputs), "principalConsent": True}
        if selector is not None:
            entry["bindingSelector"] = selector
        envelope = {
            "version": "zkc:proof:v2",
            "metadata": {"generatedAt": "2023-11-14T22:13:20Z",
                         "expiresAt": "2033-11-14T22:13:20Z", "context": CONTEXT.to_metadata()},
            "presentationBinding": {"profile": ANONYMOUS_PROFILE}, "proofs": [entry],
        }
        request = VerificationRequest(
            proof_types=[label], parameters={label: dict(PARAMETERS)}, context=CONTEXT,
            accumulator_states=self.states,
            binding_selectors={label: selector} if selector else {},
        )
        unsigned_request = {
            "proofTypes": [label], "parameters": {label: dict(PARAMETERS)},
            "context": {"profile": CONTEXT.profile, "verifierId": "verifier.example",
                        "sessionId": field_to_hex(555), "timestamp": CONTEXT.timestamp},
            "presentation": {"profile": ANONYMOUS_PROFILE},
        }
        if selector:
            unsigned_request["extensions"] = request_extension({label: selector})
        apr = sign_apr({"request": unsigned_request, "verifierId": "verifier.example",
                        "nonce": field_to_hex(456), "issuedAt": CONTEXT.timestamp,
                        "expiresAt": CONTEXT.timestamp + 3600}, APR_KEY)
        return apr, envelope, request

    def test_committed_aliases_publish_identical_acir_and_vk(self):
        entry = json.loads((REPO_ROOT / "registry/predicates/zkc-kyc/3.0.0/entry.json").read_text())
        self.assertEqual(entry["review"]["status"], "draft")
        self.assertEqual(self.successor.review_status, "self_attested")
        for field in ("acirHash", "vkHash", "vkSha256"):
            self.assertEqual(entry["circuit"][field], {
                "acirHash": self.successor.acir_hash, "vkHash": self.successor.vk_hash,
                "vkSha256": self.successor.vk_sha256,
            }[field])
        self.assertEqual(self.vk, (REPO_ROOT / "artifacts/zkc_kyc_v3/vk").read_bytes())

    def test_same_bytes_both_labels_refused_on_both_entry_points(self):
        for authenticated in (False, True):
            for label, selector in ((KYC_V3, None), (KYC_V2, self.successor.selector)):
                with self.subTest(authenticated=authenticated, label=label):
                    backend = KeyBoundBackend()
                    verifier = self.verifier(backend=backend)
                    apr, envelope, request = self.exchange(label, selector)
                    result = (verifier.verify_authenticated(apr, envelope, request, now=CONTEXT.timestamp)
                              if authenticated else verifier.verify(envelope, request))
                    self.assertEqual(result.codes(), [Code.UNREVIEWED_PREDICATE], result.to_dict())
                    self.assertEqual(backend.keys, [])

    def test_explicit_draft_acceptance_and_empty_source_policy_keep_honest_aliases(self):
        for statuses in ((), (*ACCEPTED, "draft")):
            for authenticated in (False, True):
                backend = KeyBoundBackend()
                for label, selector in ((KYC_V3, None), (KYC_V2, self.successor.selector)):
                    verifier = self.verifier(statuses, backend=backend)
                    apr, envelope, request = self.exchange(label, selector)
                    result = (verifier.verify_authenticated(apr, envelope, request, now=CONTEXT.timestamp)
                              if authenticated else verifier.verify(envelope, request))
                    self.assertTrue(result.valid, result.to_dict())
                self.assertEqual(backend.keys, [hashlib.sha256(self.vk).hexdigest()] * 2)

    def test_selector_free_v2_still_uses_different_historical_key(self):
        backend = KeyBoundBackend()
        verifier = self.verifier((), backend=backend)
        _, envelope, request = self.exchange(KYC_V2)
        result = verifier.verify(envelope, request)
        self.assertIn(Code.INVALID_PROOF, result.codes(), result.to_dict())
        self.assertNotIn(Code.UNREVIEWED_PREDICATE, result.codes())
        self.assertEqual(backend.keys, [self.historical.vk_sha256.removeprefix("sha256:")])

    def test_v2_source_and_binding_aliases_constrain_legacy_key(self):
        source = self.registry.resolve_binding(KYC_V2, self.historical.selector).source
        legacy = dataclasses.replace(self.registry.resolve(KYC_V2, allow_unaccepted=True), review_status="self_attested")
        for kind in ("source", "binding"):
            with self.subTest(kind=kind):
                registry = PredicateRegistry(
                    [legacy, dataclasses.replace(source, review_status="draft") if kind == "source" else source],
                    [dataclasses.replace(self.historical, review_status="draft") if kind == "binding" else self.historical],
                )
                verifier = self.verifier()
                verifier._predicate_registry = registry
                for selector in (None, self.historical.selector):
                    result = VerificationResult()
                    selected = verifier._resolve_proof_artifact(
                        {"proofType": KYC_V2, **({"bindingSelector": selector} if selector else {})}, result
                    )
                    self.assertIsNone(selected)
                    self.assertEqual(result.codes(), [Code.UNREVIEWED_PREDICATE])

    def test_unbound_source_and_other_build_do_not_withdraw_assurance(self):
        legacy = dataclasses.replace(self.registry.resolve(KYC_V2, allow_unaccepted=True), review_status="self_attested")
        source = self.registry.resolve_binding(KYC_V2, self.historical.selector).source
        unbound = dataclasses.replace(source, predicate_id="unbound-draft", review_status="draft")
        other_build = self.registry.resolve(KYC_V3, allow_unaccepted=True)
        registry = PredicateRegistry([legacy, source, unbound, other_build], [self.historical])
        self.assertEqual(registry.artifact_review_statuses(self.historical.vk_hash),
                         (("self_attested",), ("self_attested",)))
        verifier = self.verifier()
        verifier._predicate_registry = registry
        for selector in (None, self.historical.selector):
            result = VerificationResult()
            selected = verifier._resolve_proof_artifact(
                {"proofType": KYC_V2, **({"bindingSelector": selector} if selector else {})}, result
            )
            self.assertEqual(result.codes(), [])
            self.assertEqual(selected[1], (REPO_ROOT / self.historical.artifacts["vk"]).read_bytes())

    def test_deprecated_binding_cannot_be_hidden_by_legacy_label(self):
        source = self.registry.resolve_binding(KYC_V2, self.historical.selector).source
        registry = PredicateRegistry(
            [dataclasses.replace(self.registry.resolve(KYC_V2, allow_unaccepted=True), review_status="self_attested"), source],
            [dataclasses.replace(self.historical, review_status="deprecated")],
        )
        verifier = self.verifier()
        verifier._predicate_registry = registry
        for selector in (None, self.historical.selector):
            result = VerificationResult()
            self.assertTrue(verifier._resolve_proof_artifact(
                {"proofType": KYC_V2, **({"bindingSelector": selector} if selector else {})}, result
            ) is None)
            self.assertEqual(result.codes(), [Code.DEPRECATED_BINDING])

    @unittest.skipUnless(_successor_toolchain(), "beta.25 nargo / bb 5.0.0 not available")
    def test_live_same_ultrahonk_proof_both_labels(self):
        prover = NargoBackend(REPO_ROOT, nargo=SUCCESSOR_NARGO, bb=SUCCESSOR_BB)
        proof = prover.prove("zkc_kyc_v3", self.witness)
        backend = BBVerifyBackend(REPO_ROOT, bb=SUCCESSOR_BB)
        for authenticated in (False, True):
            for statuses in (ACCEPTED, ()):
                for label, selector in ((KYC_V3, None), (KYC_V2, self.successor.selector)):
                    with self.subTest(authenticated=authenticated, statuses=statuses, label=label):
                        verifier = self.verifier(statuses, backend=backend)
                        apr, envelope, request = self.exchange(label, selector, proof)
                        result = (verifier.verify_authenticated(apr, envelope, request, now=CONTEXT.timestamp)
                                  if authenticated else verifier.verify(envelope, request))
                        self.assertEqual(result.codes(), [Code.UNREVIEWED_PREDICATE] if statuses else [],
                                         result.to_dict())

    def test_sha256_only_individual_key_store_keeps_alias_policy_and_honest_control(self):
        legacy = dataclasses.replace(self.registry.resolve(KYC_V2, allow_unaccepted=True), review_status="self_attested")
        source = self.registry.resolve_binding(KYC_V2, self.historical.selector).source
        with tempfile.TemporaryDirectory() as directory:
            manifest = pathlib.Path(directory) / "manifest.json"
            manifest.write_text(json.dumps({"circuits": [{
                "name": legacy.circuit, "vkSha256": self.historical.vk_sha256,
                "artifacts": {"vk": self.historical.artifacts["vk"]},
            }]}))
            for alias_status in ("self_attested", "draft"):
                verifier = self.verifier()
                verifier._vk_store = VerificationKeyStore(manifest, base_dir=REPO_ROOT)
                verifier._predicate_registry = PredicateRegistry([
                    legacy, dataclasses.replace(source, review_status=alias_status)
                ], [self.historical])
                result = VerificationResult()
                selected = verifier._resolve_proof_artifact({"proofType": KYC_V2}, result)
                self.assertEqual(result.codes(), [] if alias_status == "self_attested"
                                 else [Code.UNREVIEWED_PREDICATE])
                self.assertEqual(selected is not None, alias_status == "self_attested")

    def test_review_policy_refuses_missing_manifest_key_identity(self):
        legacy = dataclasses.replace(self.registry.resolve(KYC_V2, allow_unaccepted=True), review_status="reviewed")
        with tempfile.TemporaryDirectory() as directory:
            verifier = self.verifier(("reviewed",))
            verifier._predicate_registry = PredicateRegistry([legacy])
            verifier._vk_store = VerificationKeyStore(directory + "/missing.json", base_dir=directory)
            result = VerificationResult()
            self.assertTrue(verifier._resolve_proof_artifact({"proofType": KYC_V2}, result) is None)
            self.assertEqual(result.codes(), [Code.UNKNOWN_VERIFICATION_KEY])

    def test_independent_same_encoder_listing_is_retained_and_cannot_upgrade_assurance(self):
        legacy = self.registry.resolve(KYC_V2, allow_unaccepted=True)
        reviewed = dataclasses.replace(legacy, predicate_id="independent-author", review_status="reviewed")
        registry = PredicateRegistry([legacy, reviewed])
        self.assertEqual(len(registry.resolve_all(KYC_V2)), 2)
        verifier = self.verifier(("reviewed",))
        verifier._predicate_registry = registry
        result = VerificationResult()
        self.assertTrue(verifier._resolve_proof_artifact({"proofType": KYC_V2}, result) is None)
        self.assertEqual(result.codes(), [Code.UNREVIEWED_PREDICATE])
        # A real local inventory in which all claims satisfy policy still
        # admits the key, and retains both independent lineages. The key store
        # pins the same key but declares no entry-v2 binding row: a declared
        # binding absent from this inventory would fail closed (spec 4.2a).
        manifest = json.loads((REPO_ROOT / "artifacts/manifest.json").read_text())
        row = next(item for item in manifest["circuits"] if item["name"] == legacy.circuit)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(json.dumps({"circuits": [row]}))
            verifier._vk_store = VerificationKeyStore(path, base_dir=REPO_ROOT)
            verifier._predicate_registry = PredicateRegistry([
                dataclasses.replace(legacy, review_status="reviewed"), reviewed
            ])
            result = VerificationResult()
            self.assertTrue(
                verifier._resolve_proof_artifact({"proofType": KYC_V2}, result) is not None
            )
            self.assertEqual(result.codes(), [])
        # With the committed manifest, the declared binding is unavailable in
        # this inventory, so its lifecycle cannot be checked.
        verifier._vk_store = VerificationKeyStore.from_repo(REPO_ROOT)
        result = VerificationResult()
        self.assertTrue(verifier._resolve_proof_artifact({"proofType": KYC_V2}, result) is None)
        self.assertEqual(result.codes(), [Code.UNKNOWN_BINDING])


if __name__ == "__main__":
    unittest.main()
