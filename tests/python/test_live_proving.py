"""Live proving integration test: issuer -> holder -> bb verify.

Requires the pinned toolchain (`nargo`, `bb`) on PATH; skips otherwise (the
CI python job runs without the toolchain — the `artifacts` job covers circuit
compilation, and this test covers real proof generation when run locally).
"""

import pathlib
import subprocess
import tempfile
import unittest

from _path import REPO_ROOT
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from _live_toolchain import historical_toolchain_available

from holder_fixtures import KYC_PROOF_TYPE, issue_kyc_credential, trusted_test_issuer
from zkc_crypto import ProofContext, PublicInputEncoder, validate_compliance_proof_v1
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    NargoBackend,
    PredicateRegistry,
    ProofRequest,
    TrustPolicy,
)

TOOLCHAIN = historical_toolchain_available()


def _write_vk_manifest(tmp_path: pathlib.Path) -> pathlib.Path:
    """Build a minimal manifest-backed VK store from the compiled circuit."""
    import hashlib
    import json

    build = tmp_path / "artifacts" / "build"
    circuit_dir = build / "zkc_kyc"
    circuit_dir.mkdir(parents=True)
    artifact = REPO_ROOT / "artifacts" / "zkc_kyc" / "zkc_kyc.json"
    subprocess.run(
        ["bb", "write_vk", "-b", str(artifact), "-o", str(circuit_dir)],
        check=True, capture_output=True,
    )
    vk_bytes = (circuit_dir / "vk").read_bytes()
    manifest = {
        "circuits": [
            {
                "name": "zkc_kyc",
                "vkSha256": "sha256:" + hashlib.sha256(vk_bytes).hexdigest(),
                "artifacts": {"vk": "artifacts/build/zkc_kyc/vk"},
            }
        ]
    }
    manifest_path = build / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    return manifest_path


@unittest.skipUnless(TOOLCHAIN, "pinned historical nargo/bb toolchain not on PATH")
class LiveProvingTests(unittest.TestCase):
    def test_holder_generates_real_kyc_proof_and_bb_verifies(self):
        provider = LocalAccumulatorProvider()
        client = HolderClient.from_seed(
            42,
            PredicateRegistry.from_repo(REPO_ROOT),
            NargoBackend(REPO_ROOT),
            accumulator_provider=provider,
        )
        client.store_credential(
            issue_kyc_credential(master_seed=42, credential_id=42, provider=provider)
        )
        request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 1,
                    "requiredAttributes": [True, False, True, False, False],
                }
            },
            context=ProofContext.verifier_session("verifier.example", 555, 1_700_000),
            trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
        )
        envelope = generate_unauthenticated_linkable(client, request)
        validate_compliance_proof_v1(envelope)
        proof_hex = envelope["proofs"][0]["proof"]
        self.assertTrue(proof_hex.startswith("0x"))
        self.assertGreater(len(proof_hex), 1000, "expected a real UltraHonk proof")

        # Independent verification with bb against the compiled circuit, with
        # public inputs re-encoded from the envelope via the published encoder.
        encoder = PublicInputEncoder.load(
            REPO_ROOT / "schemas" / "public-inputs" / "zkc_kyc.json"
        )
        public_input_bytes = encoder.encode_bytes(envelope["proofs"][0]["publicInputs"])
        with tempfile.TemporaryDirectory(prefix="zkc-live-verify-") as tmp:
            tmp_path = pathlib.Path(tmp)
            artifact = REPO_ROOT / "artifacts" / "zkc_kyc" / "zkc_kyc.json"
            self.assertTrue(artifact.is_file(), "committed zkc_kyc ACIR must exist")
            subprocess.run(
                ["bb", "write_vk", "-b", str(artifact), "-o", str(tmp_path)],
                check=True, capture_output=True,
            )
            (tmp_path / "proof").write_bytes(bytes.fromhex(proof_hex.removeprefix("0x")))
            (tmp_path / "public_inputs").write_bytes(public_input_bytes)
            result = subprocess.run(
                [
                    "bb", "verify",
                    "-k", str(tmp_path / "vk"),
                    "-p", str(tmp_path / "proof"),
                    "-i", str(tmp_path / "public_inputs"),
                ],
                capture_output=True, text=True,
            )
            self.assertEqual(
                result.returncode, 0,
                f"bb verify failed: {result.stderr.strip()[-500:]}",
            )

            # A tampered public input (different context) must NOT verify.
            tampered = dict(envelope["proofs"][0]["publicInputs"])
            tampered["proof_context"] = "0x" + (1).to_bytes(32, "big").hex()
            (tmp_path / "tampered_inputs").write_bytes(encoder.encode_bytes(tampered))
            tampered_result = subprocess.run(
                [
                    "bb", "verify",
                    "-k", str(tmp_path / "vk"),
                    "-p", str(tmp_path / "proof"),
                    "-i", str(tmp_path / "tampered_inputs"),
                ],
                capture_output=True, text=True,
            )
            self.assertNotEqual(tampered_result.returncode, 0, "tampered inputs must fail")


@unittest.skipUnless(TOOLCHAIN, "pinned historical nargo/bb toolchain not on PATH")
class LiveLowSSignatureTests(unittest.TestCase):
    """Spec 2.4.1: the stub constraint mirror and nargo agree on high-s."""

    def test_stub_mirror_and_nargo_both_refuse_a_high_s_credential_signature(self):
        from unittest import mock

        from zkc_crypto import derive_credential_binding_key
        from zkc_crypto.ecdsa_secp256k1 import N
        from zkc_holder import ConstraintViolationError, StubBackend, build_kyc_witness
        from zkc_holder import backend as backend_module
        from zkc_holder.errors import BackendUnavailableError

        seed = bytes.fromhex("5e" * 32)
        provider = LocalAccumulatorProvider()
        credential = issue_kyc_credential(
            master_seed=seed, credential_id=7, provider=provider, expires_at=2_000_000_000
        )
        accumulator = provider.witness("did:zkc:test-issuer", 7)
        low = credential.signature
        s = int.from_bytes(low[32:], "big")

        def witness_for(signature):
            credential.signature = signature
            return build_kyc_witness(
                credential_binding_key=derive_credential_binding_key(seed),
                credential=credential, issuer=trusted_test_issuer(), witness=accumulator,
                required_level=1, required_attributes=[False] * 5, proof_context=12345,
                timestamp=1_700_000_000, current_epoch=accumulator.accumulator_epoch,
            )

        high_witness = witness_for(low[:32] + (N - s).to_bytes(32, "big"))
        with self.assertRaisesRegex(ConstraintViolationError, "invalid issuer signature"):
            StubBackend().prove("zkc_kyc", high_witness)

        # Bypass the mirror so the circuit itself decides.
        checks = dict(backend_module._CONSTRAINT_CHECKS)
        checks.pop("zkc_kyc")
        with mock.patch.object(backend_module, "_CONSTRAINT_CHECKS", checks):
            proof = NargoBackend(REPO_ROOT).prove("zkc_kyc", witness_for(low))
            self.assertTrue(proof.startswith("0x"))
            with self.assertRaisesRegex(BackendUnavailableError, "proving tool failed"):
                NargoBackend(REPO_ROOT).prove("zkc_kyc", high_witness)




@unittest.skipUnless(TOOLCHAIN, "pinned historical nargo/bb toolchain not on PATH")
class LiveVerifierTests(unittest.TestCase):
    def test_full_issuer_holder_verifier_round_trip(self):
        """Real proof from the holder SDK, verified by ZKCVerifier via bb."""
        from holder_fixtures import (
            TEST_ISSUER_ID,
            TEST_ISSUER_KEY_X,
            TEST_ISSUER_KEY_Y,
        )
        from zkc_verifier import (
            BBVerifyBackend,
            IssuerAccumulatorState,
            TrustedIssuer,
            VerificationErrorCode,
            VerificationKeyStore,
            VerificationRequest,
            VerifierTrustPolicy,
            ZKCVerifier,
        )

        provider = LocalAccumulatorProvider()
        client = HolderClient.from_seed(
            42,
            PredicateRegistry.from_repo(REPO_ROOT),
            NargoBackend(REPO_ROOT),
            accumulator_provider=provider,
        )
        client.store_credential(
            issue_kyc_credential(master_seed=42, credential_id=42, provider=provider)
        )
        context = ProofContext.verifier_session("verifier.example", 555, 1_700_000)
        parameters = {
            KYC_PROOF_TYPE: {
                "requiredLevel": 1,
                "requiredAttributes": [True, False, True, False, False],
            }
        }
        envelope = generate_unauthenticated_linkable(
            client, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=parameters,
                context=context,
                trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
            )
        )

        with tempfile.TemporaryDirectory(prefix="zkc-live-vkstore-") as tmp:
            manifest_path = _write_vk_manifest(pathlib.Path(tmp))
            verifier = ZKCVerifier(
                REPO_ROOT,
                VerifierTrustPolicy(
                    issuers=(
                        TrustedIssuer(
                            issuer_id=TEST_ISSUER_ID,
                            public_key_x=TEST_ISSUER_KEY_X,
                            public_key_y=TEST_ISSUER_KEY_Y,
                            proof_types=(KYC_PROOF_TYPE,),
                        ),
                    )
                ),
                BBVerifyBackend(REPO_ROOT),
                vk_store=VerificationKeyStore(manifest_path),
            )
            request = VerificationRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=parameters,
                context=context,
                accumulator_states={
                    TEST_ISSUER_ID: IssuerAccumulatorState(
                        current_epoch=provider.current_epoch(TEST_ISSUER_ID),
                        roots=provider.roots(TEST_ISSUER_ID),
                    )
                },
            )
            result = verifier.verify(envelope, request)
            self.assertTrue(result.valid, result.to_dict())

            # Independent dynamic request-binding gate: the level-2 credential
            # could answer either request, and the real proof remains valid for
            # its original public inputs. Reusing that untouched proof for a
            # different, internally valid parent request must fail specifically
            # at request binding, not at Barretenberg proof verification.
            out_of_request = VerificationRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters={
                    KYC_PROOF_TYPE: {
                        "requiredLevel": 2,
                        "requiredAttributes": [True, False, True, False, False],
                    }
                },
                context=context,
                accumulator_states=request.accumulator_states,
            )
            out_of_request_result = verifier.verify(envelope, out_of_request)
            self.assertFalse(out_of_request_result.valid, out_of_request_result.to_dict())
            self.assertEqual(
                out_of_request_result.codes(),
                [VerificationErrorCode.REQUIREMENTS_NOT_MET],
                out_of_request_result.to_dict(),
            )

            # Tampered claim binding must fail bb verification (INVALID_PROOF).
            import copy

            tampered = copy.deepcopy(envelope)
            tampered["proofs"][0]["publicInputs"]["claim_binding"] = (
                "0x" + (1).to_bytes(32, "big").hex()
            )
            tampered_result = verifier.verify(tampered, request)
            self.assertIn(VerificationErrorCode.INVALID_PROOF, tampered_result.codes())

            # A stub proof must NEVER pass the production verifier.
            from zkc_crypto.stub import stub_proof_payload

            stubbed = copy.deepcopy(envelope)
            stubbed["proofs"][0]["proof"] = stub_proof_payload(
                "zkc_kyc", stubbed["proofs"][0]["publicInputs"]
            )
            stub_result = verifier.verify(stubbed, request)
            self.assertIn(VerificationErrorCode.INVALID_PROOF, stub_result.codes())

if __name__ == "__main__":
    unittest.main()
