"""Integration: zkc_issuer -> zkc_holder -> zkc_verifier round trips.

The stub round trip runs everywhere (no toolchain). The live classes prove
and verify with the real nargo/bb toolchain and skip when it is absent.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from _path import REPO_ROOT
from _live_toolchain import historical_toolchain_available

if str(REPO_ROOT / "conformance") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "conformance"))

from zkc_crypto import ProofContext, derive_holder_commitment_from_seed, field_to_hex
from zkc_holder import (
    Credential,
    HolderClient,
    NargoBackend,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    TrustedIssuer,
)
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import (
    FORBIDDEN_FIELDS,
    IssuerAdapterAccumulatorProvider,
    IssuerSigningKey,
    RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE,
    RUNTIME_ATTESTATION_SCHEMA_ID,
    RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
    RuntimeAttestationAdapter,
    SandboxIssuerAdapter,
    StaticPreverifiedRuntimeAttestationProviderClient,
    reference_runtime_attestation_adapter,
)
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationErrorCode,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer

KYC_SCHEMA_ID = "zkc:cred:kyc:v1"
KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
MASTER_SEED = 4242
# Inside the sandbox signing key validity window (2026) and before every
# fixture credential expiry.
TIMESTAMP = 1_770_000_000
TEST_HOLDER = field_to_hex(derive_holder_commitment_from_seed(MASTER_SEED))


def _trusted_issuer_from_metadata(metadata: dict, cls, proof_types):
    """Build a trust-policy entry from published issuer metadata (key-exact)."""
    public_key = bytes.fromhex(metadata["signingKeys"][0]["publicKey"].removeprefix("0x"))
    return cls(
        issuer_id=metadata["issuerId"],
        public_key_x=public_key[:32],
        public_key_y=public_key[32:],
        proof_types=tuple(proof_types),
    )


def _obtain_credential(adapter, client, schema_id=KYC_SCHEMA_ID, fixture_id="sandbox-alice-basic"):
    """Holder obtains a credential through the 4-stage adapter protocol.

    Returns (credential, sent_payloads) — every payload the issuer received,
    for privacy-boundary assertions.
    """
    sent = []

    def call(stage, payload):
        sent.append(payload)
        return stage(payload)

    holder_commitment_hex = field_to_hex(client.get_binding_commitment())
    subject = call(
        adapter.verify_subject, {"schemaId": schema_id, "fixtureId": fixture_id}
    )
    challenge = call(
        adapter.request_binding_challenge,
        {
            "subjectRef": subject["subjectRef"],
            "holderCommitment": holder_commitment_hex,
            "schemaId": schema_id,
        },
    )
    response = client.binding_challenge_response(
        adapter.issuer_id, schema_id, challenge["nonce"], challenge["expiresAt"]
    )
    call(
        adapter.bind_holder_commitment,
        {
            "subjectRef": subject["subjectRef"],
            "holderCommitment": holder_commitment_hex,
            "schemaId": schema_id,
            "nonce": challenge["nonce"],
            "challengeResponse": response,
        },
    )
    envelope = call(
        adapter.issue_credential,
        {"subjectRef": subject["subjectRef"], "schemaId": schema_id},
    )
    credential = Credential.from_dict(envelope["credential"])
    client.store_credential(credential)
    return credential, sent


def _kyc_request_parameters():
    return {
        KYC_PROOF_TYPE: {
            "requiredLevel": 1,
            "requiredAttributes": [True, False, False, False, True],
        }
    }


class StubRoundTripTests(unittest.TestCase):
    def _build_stack(self):
        adapter = SandboxIssuerAdapter(clock=lambda: TIMESTAMP)
        provider = IssuerAdapterAccumulatorProvider([adapter])
        client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=provider,
        )
        metadata = adapter.issuer_metadata()
        context = ProofContext.verifier_session("verifier.example", 99, TIMESTAMP)
        holder_request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=_kyc_request_parameters(),
            context=context,
            trust_policy=TrustPolicy(
                issuers=(
                    _trusted_issuer_from_metadata(metadata, TrustedIssuer, [KYC_PROOF_TYPE]),
                )
            ),
        )
        verifier = ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                issuers=(
                    _trusted_issuer_from_metadata(
                        metadata, VerifierTrustedIssuer, [KYC_PROOF_TYPE]
                    ),
                )
            ),
            StubVerifyBackend(),
        )
        return adapter, client, holder_request, verifier, context

    def _verification_request(self, adapter, context):
        return VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=_kyc_request_parameters(),
            context=context,
            accumulator_states={
                adapter.issuer_id: IssuerAccumulatorState(
                    current_epoch=adapter.accumulator.epoch,
                    roots={adapter.accumulator.epoch: adapter.accumulator.root()},
                )
            },
        )

    def test_issue_prove_verify_round_trip(self):
        adapter, client, holder_request, verifier, context = self._build_stack()
        credential, sent_payloads = _obtain_credential(adapter, client)

        # Privacy boundary: nothing the issuer received contains wallet material.
        wire = json.dumps(sent_payloads)
        for forbidden in FORBIDDEN_FIELDS:
            self.assertNotIn(forbidden, wire)

        envelope = generate_unauthenticated_linkable(client, holder_request)
        result = verifier.verify(envelope, self._verification_request(adapter, context))
        self.assertTrue(result.valid, result.to_dict())

    def test_revocation_blocks_witness_refresh_and_verification(self):
        adapter, client, holder_request, verifier, context = self._build_stack()
        credential, _ = _obtain_credential(adapter, client)
        envelope = generate_unauthenticated_linkable(client, holder_request)

        adapter.revoke_credential(credential.credential_id)

        # Witness refresh fails closed at the holder.
        with self.assertRaises(StaleWitnessError):
            client.update_witness(credential.credential_id)
        with self.assertRaises(StaleWitnessError):
            generate_unauthenticated_linkable(client, holder_request)

        # The pre-revocation envelope no longer verifies against the
        # issuer's advanced accumulator state.
        result = verifier.verify(envelope, self._verification_request(adapter, context))
        self.assertFalse(result.valid)
        self.assertIn(VerificationErrorCode.STALE_ACCUMULATOR, result.codes())

    def test_untrusted_issuer_key_is_rejected(self):
        adapter, client, holder_request, verifier, context = self._build_stack()
        # Re-key the issuer with a key the verifier never allowlisted.
        rogue = SandboxIssuerAdapter(
            signing_key=IssuerSigningKey.generate("rogue-2026"), clock=lambda: TIMESTAMP
        )
        rogue_provider = IssuerAdapterAccumulatorProvider([rogue])
        rogue_client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=rogue_provider,
        )
        _obtain_credential(rogue, rogue_client)
        rogue_metadata = rogue.issuer_metadata()
        rogue_request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=_kyc_request_parameters(),
            context=context,
            trust_policy=TrustPolicy(
                issuers=(
                    _trusted_issuer_from_metadata(
                        rogue_metadata, TrustedIssuer, [KYC_PROOF_TYPE]
                    ),
                )
            ),
        )
        envelope = generate_unauthenticated_linkable(rogue_client, rogue_request)
        request = self._verification_request(rogue, context)
        result = verifier.verify(envelope, request)
        self.assertFalse(result.valid)
        self.assertIn(VerificationErrorCode.UNTRUSTED_ISSUER, result.codes())

    def test_runtime_public_outputs_and_renewal_exclude_private_machine_evidence(self):
        from issuer_adapter import kit as issuer_adapter_kit

        manifest = "sha256:" + "61" * 32
        # Exact scheme-native signed report/collateral bytes; the sentinels
        # below must never surface in any public adapter output.
        report_bytes = (
            b"\x04\x00\x02\x00"
            b"raw-report-quote-sentinel\x00"
            b"host-test-serial\x00"
            b"/customers/example/build/worktree\x00"
            + bytes.fromhex("63" * 32)
        )
        collateral_bytes = b"\x30\x82raw-collateral-sentinel\x02\x01\x03"
        evidence_store = {
            "evidence-1": {
                "subjectIdentity": "private-runtime-subject",
                "rootClass": "root:tee-attestation",
                "rootAuthorityIdentifier": "example:tee-root:v1",
                "attestedManifestDigest": manifest,
                "verificationPolicyDigest": "sha256:" + "62" * 32,
                "validFrom": TIMESTAMP - 60,
                "validUntil": TIMESTAMP + 3_600,
                "rootMaterial": {
                    "endorsementChainVerified": True,
                    "revocationCurrent": True,
                    "collateralFresh": True,
                    "collateral": {
                        "digestProfile": (
                            RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE
                        ),
                        "kind": "tee-endorsement-collateral",
                        "scheme": "example-tee-collateral:v1",
                        "signedBytesHex": collateral_bytes.hex(),
                    },
                },
                "rawEvidence": {
                    "holderCommitment": TEST_HOLDER,
                    "reportAuthenticated": True,
                    "fresh": True,
                    "measurementAccepted": True,
                    "reportDataBound": True,
                    "attestedManifestDigest": manifest,
                    "verificationContextDigest": (
                        RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
                    ),
                    "report": {
                        "digestProfile": (
                            RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE
                        ),
                        "kind": "tee-report",
                        "scheme": "example-tee-quote:v4",
                        "signedBytesHex": report_bytes.hex(),
                    },
                },
            }
        }
        adapter = RuntimeAttestationAdapter(
            StaticPreverifiedRuntimeAttestationProviderClient(
                evidence_store, RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
            ),
            session_identity=lambda: "test-session", clock=lambda: TIMESTAMP,
        )
        client = HolderClient.from_seed(
            MASTER_SEED, PredicateRegistry.from_repo(REPO_ROOT), StubBackend()
        )
        holder_commitment = field_to_hex(client.get_binding_commitment())
        subject = adapter.verify_subject(
            {
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                "holderCommitment": TEST_HOLDER,
                "evidenceRef": "evidence-1",
                "verificationContextDigest": RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
            }
        )
        challenge = adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment,
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
            }
        )
        response = client.binding_challenge_response(
            adapter.issuer_id,
            RUNTIME_ATTESTATION_SCHEMA_ID,
            challenge["nonce"],
            challenge["expiresAt"],
        )
        binding = adapter.bind_holder_commitment(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment,
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                "nonce": challenge["nonce"],
                "challengeResponse": response,
            }
        )
        envelope = adapter.issue_credential(
            {
                "subjectRef": subject["subjectRef"],
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
            }
        )
        publication = adapter.publish_revocation_handle(
            {"credentialId": envelope["credential"]["credentialId"]}
        )
        metadata = adapter.issuer_metadata()
        renewal = adapter.renew_credential(
            {"credentialId": envelope["credential"]["credentialId"]}
        )

        for output in (subject, challenge, binding):
            issuer_adapter_kit._assert_no_forbidden_machine_material(
                output,
                allowed_subject_ref_paths=frozenset({("subjectRef",)}),
            )
        for output in (envelope, publication, metadata, renewal):
            issuer_adapter_kit._assert_no_forbidden_machine_material(output)
        rendered = json.dumps(
            [subject, challenge, binding, envelope, publication, metadata, renewal],
            sort_keys=True,
        )
        for sentinel in (
            "raw-report-quote-sentinel",
            "host-test-serial",
            "/customers/example/build/worktree",
        ):
            self.assertNotIn(sentinel, rendered)

    def test_runtime_renewal_scan_rejects_raw_private_evidence(self):
        from issuer_adapter import kit as issuer_adapter_kit

        class LeakyRenewalAdapter(RuntimeAttestationAdapter):
            def renew_credential(self, payload):
                result = super().renew_credential(payload)
                result["note"] = "raw-report-quote-sentinel"
                return result

        reference = reference_runtime_attestation_adapter()
        reference._provider_client._evidence_store["reference-build-provenance"]["rawEvidence"]["holderCommitment"] = TEST_HOLDER
        adapter = LeakyRenewalAdapter(
            reference._provider_client, session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
        )
        client = HolderClient.from_seed(
            MASTER_SEED, PredicateRegistry.from_repo(REPO_ROOT), StubBackend()
        )
        holder_commitment = field_to_hex(client.get_binding_commitment())
        subject = adapter.verify_subject(
            {
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                **adapter.conformance_subject_payload,
                "holderCommitment": TEST_HOLDER,
            }
        )
        challenge = adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment,
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
            }
        )
        response = client.binding_challenge_response(
            adapter.issuer_id,
            RUNTIME_ATTESTATION_SCHEMA_ID,
            challenge["nonce"],
            challenge["expiresAt"],
        )
        adapter.bind_holder_commitment(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment,
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                "nonce": challenge["nonce"],
                "challengeResponse": response,
            }
        )
        envelope = adapter.issue_credential(
            {
                "subjectRef": subject["subjectRef"],
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
            }
        )
        renewal = adapter.renew_credential(
            {"credentialId": envelope["credential"]["credentialId"]}
        )
        with self.assertRaises(issuer_adapter_kit.CaseFailure):
            issuer_adapter_kit._assert_no_forbidden_machine_material(renewal)


TOOLCHAIN = historical_toolchain_available()


def _write_vk_manifest(tmp_path: pathlib.Path) -> pathlib.Path:
    import hashlib

    build = tmp_path / "artifacts" / "build"
    circuit_dir = build / "zkc_kyc"
    circuit_dir.mkdir(parents=True)
    artifact = REPO_ROOT / "artifacts" / "zkc_kyc" / "zkc_kyc.json"
    subprocess.run(
        ["bb", "write_vk", "-b", str(artifact), "-o", str(circuit_dir)],
        check=True,
        capture_output=True,
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
class LiveIssuerRoundTripTests(unittest.TestCase):
    def test_adapter_issued_credential_proves_and_verifies_with_bb(self):
        from zkc_verifier import BBVerifyBackend, VerificationKeyStore

        adapter = SandboxIssuerAdapter(clock=lambda: TIMESTAMP)
        provider = IssuerAdapterAccumulatorProvider([adapter])
        client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            NargoBackend(REPO_ROOT),
            accumulator_provider=provider,
        )
        _obtain_credential(adapter, client)
        metadata = adapter.issuer_metadata()
        context = ProofContext.verifier_session("verifier.example", 555, TIMESTAMP)
        envelope = generate_unauthenticated_linkable(
            client, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=_kyc_request_parameters(),
                context=context,
                trust_policy=TrustPolicy(
                    issuers=(
                        _trusted_issuer_from_metadata(
                            metadata, TrustedIssuer, [KYC_PROOF_TYPE]
                        ),
                    )
                ),
            )
        )
        self.assertGreater(len(envelope["proofs"][0]["proof"]), 1000)

        with tempfile.TemporaryDirectory(prefix="zkc-issuer-live-") as tmp:
            manifest_path = _write_vk_manifest(pathlib.Path(tmp))
            verifier = ZKCVerifier(
                REPO_ROOT,
                VerifierTrustPolicy(
                    issuers=(
                        _trusted_issuer_from_metadata(
                            metadata, VerifierTrustedIssuer, [KYC_PROOF_TYPE]
                        ),
                    )
                ),
                BBVerifyBackend(REPO_ROOT),
                vk_store=VerificationKeyStore(manifest_path),
            )
            request = VerificationRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=_kyc_request_parameters(),
                context=context,
                accumulator_states={
                    adapter.issuer_id: IssuerAccumulatorState(
                        current_epoch=adapter.accumulator.epoch,
                        roots={adapter.accumulator.epoch: adapter.accumulator.root()},
                    )
                },
            )
            result = verifier.verify(envelope, request)
            self.assertTrue(result.valid, result.to_dict())

            # Tampering with the holder commitment must fail bb verification.
            import copy

            tampered = copy.deepcopy(envelope)
            tampered["proofs"][0]["publicInputs"]["holder_commitment"] = field_to_hex(1)
            tampered_result = verifier.verify(tampered, request)
            self.assertFalse(tampered_result.valid)


if __name__ == "__main__":
    unittest.main()
