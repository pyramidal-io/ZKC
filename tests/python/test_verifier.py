"""Verifier library tests: every error code deterministically, plus
holder-SDK integration (stub backend; live bb path in test_live_proving)."""

import copy
import hashlib
import json
import pathlib
import tempfile
import unittest

from _path import REPO_ROOT
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402

from holder_fixtures import (
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_kyc_credential,
    trusted_test_issuer,
)
from zkc_crypto import FIELD_MODULUS, ProofContext, field_to_hex
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_verifier import (
    BBVerifyBackend,
    IssuerAccumulatorState,
    StubVerifyBackend,
    TrustedIssuer,
    VerificationErrorCode as Code,
    VerificationKeyStore,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)

MASTER_SEED = 42
REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
CONTEXT = ProofContext.verifier_session("verifier.example", 555, 1_700_000_000)
KYC_PARAMETERS = {
    KYC_PROOF_TYPE: {
        "requiredLevel": 1,
        "requiredAttributes": [True, False, True, False, False],
    }
}


def issuer_entry(proof_types=(KYC_PROOF_TYPE,)):
    return TrustedIssuer(
        issuer_id=TEST_ISSUER_ID,
        public_key_x=TEST_ISSUER_KEY_X,
        public_key_y=TEST_ISSUER_KEY_Y,
        proof_types=tuple(proof_types),
    )


class VerifierTestBase(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.client = HolderClient.from_seed(
            MASTER_SEED, REGISTRY, StubBackend(), accumulator_provider=self.provider
        )
        self.credential = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=42, provider=self.provider,
            expires_at=2_000_000_000,
        )
        self.client.store_credential(self.credential)
        self.envelope = generate_unauthenticated_linkable(
            self.client, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=KYC_PARAMETERS,
                context=CONTEXT,
                trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
            )
        )
        self.accumulator_states = {
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                roots=self.provider.roots(TEST_ISSUER_ID),
            )
        }

    def make_verifier(self, policy=None, backend=None):
        return ZKCVerifier(
            REPO_ROOT,
            policy or VerifierTrustPolicy(issuers=(issuer_entry(),)),
            backend or StubVerifyBackend(),
        )

    def make_request(self, **overrides):
        defaults = dict(
            proof_types=[KYC_PROOF_TYPE],
            parameters=copy.deepcopy(KYC_PARAMETERS),
            context=CONTEXT,
            max_proof_age=3600,
            accumulator_states=dict(self.accumulator_states),
        )
        defaults.update(overrides)
        return VerificationRequest(**defaults)


class AcceptanceTests(VerifierTestBase):
    def test_valid_core_proof_accepted(self):
        result = self.make_verifier().verify(self.envelope, self.make_request())
        self.assertEqual(result.codes(), [])
        self.assertTrue(result.valid)
        self.assertEqual(result.to_dict(), {"valid": True, "errors": [], "warnings": []})

    def test_extra_unrequested_proof_is_ignored(self):
        envelope = copy.deepcopy(self.envelope)
        extra = copy.deepcopy(envelope["proofs"][0])
        extra["proofType"] = "zkc:proof:extra:v1"
        envelope["proofs"].append(extra)
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertTrue(result.valid)

    def aggregated_envelope(self):
        return generate_unauthenticated_linkable(
            self.client, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=KYC_PARAMETERS,
                context=CONTEXT,
                trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
            ),
            aggregate=True,
        )

    def test_aggregated_envelope_accepted(self):
        envelope = self.aggregated_envelope()
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertTrue(result.valid, result.to_dict())

    def test_aggregation_proof_bytes_are_ignored(self):
        envelope = self.aggregated_envelope()
        envelope["aggregation"]["proof"] = "ignored placeholder"
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertTrue(result.valid, result.to_dict())

    def test_valid_aggregation_commitment_does_not_replace_request_checks(self):
        envelope = self.aggregated_envelope()
        request = self.make_request()
        request.parameters[KYC_PROOF_TYPE]["requiredLevel"] = 3
        result = self.make_verifier().verify(envelope, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())

    def test_valid_aggregation_commitment_cannot_cover_unrequested_proof(self):
        envelope = self.aggregated_envelope()
        verifier = self.make_verifier()
        request = self.make_request(proof_types=[], parameters={})
        result = verifier.verify(envelope, request)
        self.assertEqual(result.codes(), [Code.INVALID_AGGREGATION], result.to_dict())
        self.assertEqual(result.warning_codes(), ["OVER_DISCLOSURE"])

        del envelope["aggregation"]
        ordinary = verifier.verify(envelope, request)
        self.assertTrue(ordinary.valid, ordinary.to_dict())
        self.assertEqual(ordinary.warning_codes(), ["OVER_DISCLOSURE"])

    def test_aggregation_fails_closed_without_manifest_vk_pin(self):
        envelope = self.aggregated_envelope()
        with tempfile.TemporaryDirectory() as tmp:
            verifier = ZKCVerifier(
                REPO_ROOT,
                VerifierTrustPolicy(issuers=(issuer_entry(),)),
                StubVerifyBackend(),
                vk_store=VerificationKeyStore(pathlib.Path(tmp) / "manifest.json"),
            )
            result = verifier.verify(envelope, self.make_request())
        self.assertEqual(result.codes(), [Code.INVALID_AGGREGATION], result.to_dict())


class ErrorCodeTests(VerifierTestBase):
    """One deterministic test per VerificationErrorCode member."""

    def test_malformed_proof(self):
        envelope = copy.deepcopy(self.envelope)
        del envelope["holderBinding"]
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertEqual(result.codes(), [Code.MALFORMED_PROOF])

    def test_malformed_public_inputs(self):
        envelope = copy.deepcopy(self.envelope)
        proof_entry = envelope["proofs"][0]
        del proof_entry["publicInputs"]["accumulator_epoch"]
        result = self.make_verifier().verify(envelope, self.make_request())
        # Stub backend digests the public inputs, so the mutation surfaces as
        # an invalid proof before parsing; both are rejections.
        self.assertTrue(
            set(result.codes()) & {Code.MALFORMED_PROOF, Code.INVALID_PROOF},
            result.codes(),
        )

    def test_stale_proof(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["metadata"]["generatedAt"] = "2020-01-01T00:00:00Z"
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertIn(Code.STALE_PROOF, result.codes())

    def test_expired_proof(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["metadata"]["expiresAt"] = "2020-01-01T00:00:00Z"
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertIn(Code.EXPIRED_PROOF, result.codes())

    def test_context_mismatch_wrong_session(self):
        other_context = ProofContext.verifier_session("verifier.example", 556, 1_700_000_000)
        result = self.make_verifier().verify(
            self.envelope, self.make_request(context=other_context)
        )
        self.assertIn(Code.CONTEXT_MISMATCH, result.codes())
        self.assertFalse(result.valid)

    def test_context_mismatch_tampered_structured_fields(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["metadata"]["context"]["verifierId"] = "attacker.example"
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertIn(Code.CONTEXT_MISMATCH, result.codes())

    def test_context_profile_policy_requirement(self):
        policy = VerifierTrustPolicy(
            issuers=(issuer_entry(),), required_context_profile="afp:session_context:v1"
        )
        result = self.make_verifier(policy=policy).verify(self.envelope, self.make_request())
        self.assertIn(Code.CONTEXT_MISMATCH, result.codes())

    def test_invalid_binding(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["holderBinding"]["commitment"] = field_to_hex(12345)
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertIn(Code.INVALID_BINDING, result.codes())

    def test_invalid_proof(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["proofs"][0]["proof"] = "zkc:stub:v1:" + "00" * 32
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertEqual(result.codes(), [Code.INVALID_PROOF])

    def test_invalid_proof_on_tampered_public_inputs(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["proofs"][0]["publicInputs"]["claim_binding"] = field_to_hex(1)
        result = self.make_verifier().verify(envelope, self.make_request())
        self.assertIn(Code.INVALID_PROOF, result.codes())

    def test_unknown_proof_type(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["proofs"][0]["proofType"] = "zkc:proof:unreviewed:v1"
        request = self.make_request(proof_types=["zkc:proof:unreviewed:v1"])
        result = self.make_verifier().verify(envelope, request)
        self.assertIn(Code.UNKNOWN_PROOF_TYPE, result.codes())

    def test_unknown_verification_key_without_manifest(self):
        class FakeProductionBackend(StubVerifyBackend):
            is_production = True

        with tempfile.TemporaryDirectory() as tmp:
            verifier = ZKCVerifier(
                REPO_ROOT,
                VerifierTrustPolicy(issuers=(issuer_entry(),)),
                FakeProductionBackend(),
                vk_store=VerificationKeyStore(pathlib.Path(tmp) / "manifest.json"),
            )
            result = verifier.verify(self.envelope, self.make_request())
        self.assertIn(Code.UNKNOWN_VERIFICATION_KEY, result.codes())

    def test_unknown_verification_key_on_manifest_pin_mismatch(self):
        class FakeProductionBackend(StubVerifyBackend):
            is_production = True

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            build = tmp_path / "artifacts" / "build"
            (build / "zkc_kyc").mkdir(parents=True)
            (build / "zkc_kyc" / "vk").write_bytes(b"not the pinned vk")
            (build / "manifest.json").write_text(json.dumps({
                "circuits": [{
                    "name": "zkc_kyc",
                    "vkSha256": "sha256:" + "00" * 32,
                    "artifacts": {"vk": "artifacts/build/zkc_kyc/vk"},
                }]
            }))
            verifier = ZKCVerifier(
                REPO_ROOT,
                VerifierTrustPolicy(issuers=(issuer_entry(),)),
                FakeProductionBackend(),
                vk_store=VerificationKeyStore(build / "manifest.json"),
            )
            result = verifier.verify(self.envelope, self.make_request())
        self.assertIn(Code.UNKNOWN_VERIFICATION_KEY, result.codes())

    def test_vk_store_from_repo_prefers_committed_manifest(self):
        # A fresh checkout resolves keys from the committed manifest — no
        # local toolchain build required.
        store = VerificationKeyStore.from_repo(REPO_ROOT)
        self.assertTrue(store.available())
        committed = json.loads((REPO_ROOT / "artifacts" / "manifest.json").read_text())
        expected = next(c for c in committed["circuits"] if c["name"] == "zkc_kyc")
        self.assertEqual(store.vk_hash("zkc_kyc"), bytes.fromhex(expected["vkHash"][2:]))
        vk_bytes = store.lookup("zkc_kyc")
        self.assertIsNotNone(vk_bytes)
        self.assertEqual(
            "sha256:" + hashlib.sha256(vk_bytes).hexdigest(), expected["vkSha256"]
        )

    def test_vk_hash_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            missing = VerificationKeyStore(tmp_path / "manifest.json")
            self.assertIsNone(missing.vk_hash("zkc_kyc"))
            (tmp_path / "manifest.json").write_text(json.dumps({
                "circuits": [
                    {"name": "zkc_kyc", "vkHash": "not-hex"},
                    {"name": "zkc_jurisdiction", "vkHash": "0x1234"},
                ]
            }))
            malformed = VerificationKeyStore(tmp_path / "manifest.json")
            self.assertIsNone(malformed.vk_hash("zkc_kyc"))
            self.assertIsNone(malformed.vk_hash("zkc_jurisdiction"))
            self.assertIsNone(malformed.vk_hash("zkc_unknown"))

    def test_stale_accumulator_no_state(self):
        result = self.make_verifier().verify(
            self.envelope, self.make_request(accumulator_states={})
        )
        self.assertIn(Code.STALE_ACCUMULATOR, result.codes())

    def test_stale_accumulator_after_revocation_epoch_advance(self):
        # Issuer revokes another credential after proof generation: the
        # verifier's accumulator view advances, the proof's current_epoch is
        # now behind — the revoked/stale-accumulator rejection path.
        states = {
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=self.provider.current_epoch(TEST_ISSUER_ID) + 1,
                roots=self.provider.roots(TEST_ISSUER_ID),
            )
        }
        result = self.make_verifier().verify(
            self.envelope, self.make_request(accumulator_states=states)
        )
        self.assertIn(Code.STALE_ACCUMULATOR, result.codes())

    def test_stale_accumulator_policy_tightened_lag(self):
        # Witness epoch 1, provider epoch advanced by 5 — fine for the
        # protocol bound (10) but stale under a policy lag of 2.
        self.provider.advance_epoch(TEST_ISSUER_ID, 5)
        envelope = generate_unauthenticated_linkable(
            self.client, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=KYC_PARAMETERS,
                context=CONTEXT,
                trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
            )
        )
        # The refreshed witness tracks the latest root but keep its epoch:
        # LocalAccumulatorProvider reports the registration epoch + advances.
        envelope["proofs"][0]["publicInputs"]["accumulator_epoch"] = 1
        # Re-stub the proof so the stub backend still accepts it; we are
        # exercising the verifier's policy-lag branch, not proof validity.
        from zkc_crypto.stub import stub_proof_payload

        envelope["proofs"][0]["proof"] = stub_proof_payload(
            "zkc_kyc", envelope["proofs"][0]["publicInputs"]
        )
        policy = VerifierTrustPolicy(issuers=(issuer_entry(),), max_epoch_lag=2)
        states = {
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                roots=self.provider.roots(TEST_ISSUER_ID),
            )
        }
        result = self.make_verifier(policy=policy).verify(
            envelope, self.make_request(accumulator_states=states)
        )
        self.assertIn(Code.STALE_ACCUMULATOR, result.codes())

    def test_stale_accumulator_rejects_epoch_ahead_of_verifier_view(self):
        envelope = copy.deepcopy(self.envelope)
        state_epoch = self.provider.current_epoch(TEST_ISSUER_ID)
        envelope["proofs"][0]["publicInputs"]["accumulator_epoch"] = state_epoch + 1
        from zkc_crypto.stub import stub_proof_payload

        envelope["proofs"][0]["proof"] = stub_proof_payload(
            "zkc_kyc", envelope["proofs"][0]["publicInputs"]
        )
        states = {
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=state_epoch, roots=self.provider.roots(TEST_ISSUER_ID)
            )
        }

        result = self.make_verifier().verify(
            envelope, self.make_request(accumulator_states=states)
        )

        self.assertIn(Code.STALE_ACCUMULATOR, result.codes())

    def test_stale_accumulator_unrecognized_root(self):
        epoch = self.envelope["proofs"][0]["publicInputs"]["accumulator_epoch"]
        states = {
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                roots={epoch: 999999},  # not the root the proof used
            )
        }
        result = self.make_verifier().verify(
            self.envelope, self.make_request(accumulator_states=states)
        )
        self.assertIn(Code.STALE_ACCUMULATOR, result.codes())

    def test_untrusted_issuer_unknown_key(self):
        from zkc_crypto.ecdsa_secp256k1 import public_key_bytes

        other_x, other_y = public_key_bytes(7777)
        policy = VerifierTrustPolicy(
            issuers=(
                TrustedIssuer(
                    issuer_id="did:zkc:someone-else",
                    public_key_x=other_x,
                    public_key_y=other_y,
                    proof_types=(KYC_PROOF_TYPE,),
                ),
            )
        )
        result = self.make_verifier(policy=policy).verify(self.envelope, self.make_request())
        self.assertIn(Code.UNTRUSTED_ISSUER, result.codes())

    def test_untrusted_issuer_wrong_proof_type(self):
        policy = VerifierTrustPolicy(
            issuers=(issuer_entry(proof_types=("zkc:proof:jurisdiction:v1",)),)
        )
        result = self.make_verifier(policy=policy).verify(self.envelope, self.make_request())
        self.assertIn(Code.UNTRUSTED_ISSUER, result.codes())

    def test_requirements_not_met(self):
        request = self.make_request(
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 2,  # proof attests requiredLevel 1
                    "requiredAttributes": [True, False, True, False, False],
                }
            }
        )
        result = self.make_verifier().verify(self.envelope, request)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())

    def test_requirements_not_met_on_unusable_parameters(self):
        request = self.make_request(parameters={KYC_PROOF_TYPE: {}})
        result = self.make_verifier().verify(self.envelope, request)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())

    def test_requirements_not_met_on_non_boolean_attribute_parameters(self):
        request = self.make_request(
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 1,
                    # Python considers 1 == True, but the request contract is
                    # JSON-type-strict and must not normalize this alias.
                    "requiredAttributes": [1, False, True, False, False],
                }
            }
        )
        result = self.make_verifier().verify(self.envelope, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())

    def test_requirements_not_met_on_non_mapping_parameter_table(self):
        request = self.make_request(parameters=None)
        result = self.make_verifier().verify(self.envelope, request)  # must not raise
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())

    def test_requirements_not_met_on_missing_proof_parameter_map(self):
        request = self.make_request(parameters={})
        result = self.make_verifier().verify(self.envelope, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())

    def test_requirements_not_met_on_modulus_shifted_level(self):
        # Claim-binding arithmetic lives in BN254, but request values are exact:
        # level 1 + r must not alias the proof's attested u8 level 1.
        request = self.make_request(
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": FIELD_MODULUS + 1,
                    "requiredAttributes": [True, False, True, False, False],
                }
            }
        )
        result = self.make_verifier().verify(self.envelope, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())

    def test_missing_proof(self):
        request = self.make_request(
            proof_types=[KYC_PROOF_TYPE, "zkc:proof:jurisdiction:v1"]
        )
        result = self.make_verifier().verify(self.envelope, request)
        self.assertIn(Code.MISSING_PROOF, result.codes())

    def test_invalid_aggregation(self):
        envelope = generate_unauthenticated_linkable(
            self.client, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=KYC_PARAMETERS,
                context=CONTEXT,
                trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
            ),
            aggregate=True,
        )
        tampered = copy.deepcopy(envelope)
        tampered["aggregation"]["aggregationCommitment"] = field_to_hex(1)
        result = self.make_verifier().verify(tampered, self.make_request())
        self.assertIn(Code.INVALID_AGGREGATION, result.codes())

        tampered = copy.deepcopy(envelope)
        tampered["aggregation"]["inputProofCommitments"] = [field_to_hex(2)]
        result = self.make_verifier().verify(tampered, self.make_request())
        self.assertIn(Code.INVALID_AGGREGATION, result.codes())

        tampered = copy.deepcopy(envelope)
        tampered["aggregation"]["aggregatedClaimBinding"] = field_to_hex(3)
        result = self.make_verifier().verify(tampered, self.make_request())
        self.assertIn(Code.INVALID_AGGREGATION, result.codes())


class FailClosedTests(VerifierTestBase):
    def test_production_backend_rejects_stub_proofs(self):
        backend = BBVerifyBackend(REPO_ROOT)
        self.assertFalse(
            backend.verify(
                "zkc_kyc",
                self.envelope["proofs"][0]["proof"],  # a zkc:stub:v1 payload
                self.envelope["proofs"][0]["publicInputs"],
                b"some vk",
            )
        )

    def test_stub_backend_rejects_binary_proofs(self):
        self.assertFalse(
            StubVerifyBackend().verify(
                "zkc_kyc", "0xdeadbeef", self.envelope["proofs"][0]["publicInputs"], None
            )
        )

    def test_empty_trust_policy_trusts_nobody(self):
        policy = VerifierTrustPolicy(issuers=())
        result = self.make_verifier(policy=policy).verify(self.envelope, self.make_request())
        self.assertIn(Code.UNTRUSTED_ISSUER, result.codes())

    def test_error_codes_are_closed_set(self):
        from zkc_verifier.errors import VerificationError

        with self.assertRaises(ValueError):
            VerificationError(code="NOT_A_CODE", message="x")


if __name__ == "__main__":
    unittest.main()
