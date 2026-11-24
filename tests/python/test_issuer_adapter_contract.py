"""Issuer adapter contract + conformance kit tests (production interop).

Covers req: production issuer adapter interoperability — the IssuerAdapter
contract, the conformance kit (reference adapters pass; a seeded-bad adapter
is caught), and the definition-of-done flow: a holder receives a credential
through a supported adapter, proves only the required predicate, and the
verifier accepts/rejects through the standard ZKC envelope.
"""

import hashlib
import json
import logging
import struct
import sys
import unittest
from types import MappingProxyType

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from _path import REPO_ROOT

if str(REPO_ROOT / "conformance") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "conformance"))

from issuer_adapter import seeded_bad_adapter  # noqa: E402
from issuer_adapter.kit import (  # noqa: E402
    CONFORMANCE_CASES,
    CaseFailure,
    _validated_revocation_announcement,
    run_conformance,
)
from issuer_adapter.seeded_bad_adapter import make_adapter as make_bad_adapter  # noqa: E402

from zkc_crypto import (  # noqa: E402
    ProofContext,
    compute_merkle_root,
    digest_to_message_bytes,
    field_to_hex,
    derive_holder_commitment_from_seed,
)
from zkc_crypto.ecdsa_secp256k1 import verify as ecdsa_verify  # noqa: E402
from zkc_holder import (  # noqa: E402
    Credential,
    HolderClient,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    TrustedIssuer,
)
from zkc_issuer import (  # noqa: E402
    AdapterError,
    BaseIssuerAdapter,
    IssuerAdapter,
    IssuerAdapterAccumulatorProvider,
    ProviderDecision,
    RUNTIME_ATTESTATION_SCHEMA_ID,
    RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
    RuntimeAttestationAdapter,
    StaticPreverifiedRuntimeAttestationProviderClient,
    SandboxIssuerAdapter,
    StaticProviderClient,
    get_schema,
    reference_external_adapter,
    reference_runtime_attestation_adapter,
)
import zkc_issuer.runtime_attestation as runtime_attestation  # noqa: E402
from zkc_issuer.runtime_attestation import (  # noqa: E402
    RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
    RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_ENDORSEMENT_COLLATERAL,
    RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_REPORT,
    RUNTIME_ATTESTATION_ARTIFACT_KIND_TRANSPARENCY_CHECKPOINT,
    RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE,
    _digest_json,
    compute_external_artifact_digest,
)
from zkc_verifier import (  # noqa: E402
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationErrorCode,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer  # noqa: E402

KYC_SCHEMA_ID = "zkc:cred:kyc:v1"
KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
TIMESTAMP = 1_770_000_000
MASTER_SEED = 777
TEST_HOLDER = field_to_hex(derive_holder_commitment_from_seed(MASTER_SEED))

EXTERNAL_ARTIFACT_VECTORS_PATH = (
    REPO_ROOT / "tests" / "vectors" / "runtime_attestation_external_artifact_v2.json"
)


def _afp_external_artifact_digest(kind, scheme, signed_bytes):
    """Independent AFP-verifier-side framing, straight from the spec text.

    Deliberately not a call into zkc_issuer: this is the cross-implementation
    check that an AFP verifier following docs/afp_specification.md@7d10e0e
    derives the same public digest as the ZKC issuer reference.
    """

    kind_bytes = kind.encode("ascii")
    scheme_bytes = scheme.encode("ascii")
    framing = (
        b"AFP-External-Artifact-v2\x00"
        + struct.pack(">I", len(kind_bytes))
        + kind_bytes
        + struct.pack(">I", len(scheme_bytes))
        + scheme_bytes
        + struct.pack(">Q", len(signed_bytes))
        + signed_bytes
    )
    return "sha256:" + hashlib.sha256(framing).hexdigest()


def _external_artifact(kind, scheme, signed_bytes):
    return {
        "digestProfile": RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE,
        "kind": kind,
        "scheme": scheme,
        "signedBytesHex": signed_bytes.hex(),
    }


def _sandbox_factory():
    return SandboxIssuerAdapter(session_identity=lambda: "test-session", clock=lambda: TIMESTAMP)


class ConformanceKitTests(unittest.TestCase):
    def test_kit_rejects_zero_credential_id_in_issuance_output(self):
        class ZeroCredentialIdAdapter(SandboxIssuerAdapter):
            def issue_credential(self, payload):
                result = super().issue_credential(payload)
                result["credential"]["credentialId"] = field_to_hex(0)
                return result

        case = dict(CONFORMANCE_CASES)["envelope-holder-consumable"]
        with self.assertRaisesRegex(CaseFailure, "issued credentialId must be nonzero"):
            case(lambda: ZeroCredentialIdAdapter(
                session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
            ))

    def test_kit_rejects_zero_credential_id_in_renewal_output(self):
        class ZeroRenewalIdAdapter(SandboxIssuerAdapter):
            def renew_credential(self, payload):
                result = super().renew_credential(payload)
                result["credential"]["credentialId"] = field_to_hex(0)
                return result

        case = dict(CONFORMANCE_CASES)["renewal-credential-id"]
        with self.assertRaisesRegex(CaseFailure, "renewed credentialId must be nonzero"):
            case(lambda: ZeroRenewalIdAdapter(
                session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
            ))

    def test_malformed_revocation_key_is_a_conformance_failure(self):
        class MalformedRevocationKeyAdapter(SandboxIssuerAdapter):
            def issuer_metadata(self):
                metadata = super().issuer_metadata()
                metadata["signingKeys"][0]["publicKey"] = "0x01"
                return metadata

        adapter = MalformedRevocationKeyAdapter(session_identity=lambda: "test-session", clock=lambda: TIMESTAMP)
        with self.assertRaisesRegex(CaseFailure, "64-byte secp256k1"):
            _validated_revocation_announcement(adapter)

    def test_case_ids_are_stable(self):
        self.assertEqual(
            [case_id for case_id, _ in CONFORMANCE_CASES],
            [
                "issuer-metadata-valid",
                "stage-order-binding-requires-verified-subject",
                "stage-order-issuance-requires-binding",
                "binding-rejects-wrong-response",
                "binding-nonce-single-use",
                "rejects-unsupported-schema",
                "privacy-boundary-every-stage",
                "envelope-holder-consumable",
                "signature-verifies-under-published-key",
                "witness-verifies-against-published-root",
                "revocation-publication",
                "renewal-credential-id",
            ],
        )

    def test_sandbox_adapter_is_the_passing_reference(self):
        report = run_conformance(_sandbox_factory)
        self.assertTrue(report["allPassed"], report)
        self.assertEqual(report["passed"], len(CONFORMANCE_CASES))

    def test_external_provider_adapter_passes(self):
        report = run_conformance(reference_external_adapter)
        self.assertTrue(report["allPassed"], report)

    def test_runtime_attestation_adapter_passes(self):
        report = run_conformance(reference_runtime_attestation_adapter)
        self.assertTrue(report["allPassed"], report)
        self.assertEqual(report["passed"], len(CONFORMANCE_CASES))

    def test_kit_catches_the_seeded_bad_adapter(self):
        report = run_conformance(make_bad_adapter)
        self.assertFalse(report["allPassed"])
        failed = sorted(r["id"] for r in report["results"] if r["status"] == "FAIL")
        self.assertEqual(
            failed,
            [
                "binding-nonce-single-use",
                "binding-rejects-wrong-response",
                "privacy-boundary-every-stage",
                "stage-order-issuance-requires-binding",
            ],
        )

    def test_valid_machine_declaration_with_human_only_enforcement_fails_only_privacy(self):
        class HumanOnlyRuntimeAdapter(RuntimeAttestationAdapter):
            def _active_privacy_profiles(self):
                return frozenset({"human"})

        def make_human_only_runtime_adapter():
            reference = reference_runtime_attestation_adapter()
            return HumanOnlyRuntimeAdapter(
                reference._provider_client, session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
            )

        report = run_conformance(make_human_only_runtime_adapter)
        failed = [result["id"] for result in report["results"] if result["status"] == "FAIL"]
        self.assertEqual(failed, ["privacy-boundary-every-stage"], report)

    def test_runtime_schema_cannot_be_misdeclared_as_human_only(self):
        class MisdeclaredRuntimeAdapter(RuntimeAttestationAdapter):
            schema_required_privacy_profiles = MappingProxyType(
                {RUNTIME_ATTESTATION_SCHEMA_ID: frozenset({"human"})}
            )

        reference = reference_runtime_attestation_adapter()
        with self.assertRaisesRegex(
            ValueError, "schema privacy profiles omit a mandatory profile"
        ):
            MisdeclaredRuntimeAdapter(
                reference._provider_client, session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
            )

    def test_machine_probes_apply_when_a_nonselected_schema_requires_machine(self):
        class WeakMixedAdapter(SandboxIssuerAdapter):
            supported_schema_ids = frozenset(
                {KYC_SCHEMA_ID, RUNTIME_ATTESTATION_SCHEMA_ID}
            )
            schema_required_privacy_profiles = MappingProxyType(
                {
                    KYC_SCHEMA_ID: frozenset({"human"}),
                    RUNTIME_ATTESTATION_SCHEMA_ID: frozenset(
                        {"human", "machine"}
                    ),
                }
            )
            conformance_schema_id = KYC_SCHEMA_ID

            def _active_privacy_profiles(self):
                return frozenset({"human"})

        report = run_conformance(lambda: WeakMixedAdapter(session_identity=lambda: "test-session", clock=lambda: TIMESTAMP))
        failed = [result["id"] for result in report["results"] if result["status"] == "FAIL"]
        self.assertEqual(failed, ["privacy-boundary-every-stage"], report)

    def test_seeded_machine_privacy_adapter_fails_only_privacy(self):
        report = run_conformance(seeded_bad_adapter.make_machine_privacy_adapter)
        failed = [result["id"] for result in report["results"] if result["status"] == "FAIL"]
        self.assertEqual(failed, ["privacy-boundary-every-stage"], report)

    def test_conformance_rejects_machine_material_in_public_outputs_and_metadata(self):
        class StringSubclass(str):
            pass

        class HostileStringSubclass(str):
            def __contains__(self, item):
                return False

        leaks = (
            ("verify_subject", "teeQuote", {"hostSerial": "host-test-serial"}),
            (
                "request_binding_challenge",
                "provenance",
                {"buildPath": "/customers/example/build/worktree"},
            ),
            ("bind_holder_commitment", "host.serial", "host-test-serial"),
            ("issue_credential", "rawEvidence", "raw-report-quote-sentinel"),
            (
                "publish_revocation_handle",
                "build.components.path",
                "/customers/example/build/worktree",
            ),
            ("verify_subject", "providerRef", "private-provider-reference"),
            ("issue_credential", "evidenceRef", "private-evidence-reference"),
            ("publish_revocation_handle", "note", "raw-report-quote-sentinel"),
            (
                "publish_revocation_handle",
                "note",
                "wrapped raw-report-quote-sentinel value",
            ),
            (
                "verify_subject",
                "continuation",
                {"subjectRef": "nested-stage-1-leak"},
            ),
            (
                "request_binding_challenge",
                "continuation",
                {"subjectRef": "nested-stage-2a-leak"},
            ),
            (
                "bind_holder_commitment",
                "continuation",
                {"subjectRef": "nested-stage-2b-leak"},
            ),
            (
                "publish_revocation_handle",
                "raw-report-quote-sentinel-wrapped-key",
                "safe",
            ),
            (
                "publish_revocation_handle",
                "note",
                StringSubclass("wrapped raw-report-quote-sentinel value"),
            ),
            (
                "publish_revocation_handle",
                "note",
                HostileStringSubclass(
                    "wrapped raw-report-quote-sentinel value"
                ),
            ),
        )
        for method_name, key, value in leaks:
            with self.subTest(method_name=method_name):
                def leaking_method(self, payload, method_name=method_name, key=key, value=value):
                    result = getattr(super(type(self), self), method_name)(payload)
                    result[key] = value
                    return result

                LeakyRuntimeAdapter = type(
                    "LeakyRuntimeAdapter",
                    (RuntimeAttestationAdapter,),
                    {method_name: leaking_method},
                )

                def make_leaky_runtime_adapter(adapter_type=LeakyRuntimeAdapter):
                    reference = reference_runtime_attestation_adapter()
                    return adapter_type(
                        reference._provider_client, session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
                    )

                report = run_conformance(make_leaky_runtime_adapter)
                failed = {
                    result["id"]
                    for result in report["results"]
                    if result["status"] == "FAIL"
                }
                self.assertIn("privacy-boundary-every-stage", failed, report)

        class LeakyMetadataRuntimeAdapter(RuntimeAttestationAdapter):
            def issuer_metadata(self):
                result = super().issuer_metadata()
                result["note"] = "raw-report-quote-sentinel"
                return result

        def make_leaky_metadata_adapter():
            reference = reference_runtime_attestation_adapter()
            return LeakyMetadataRuntimeAdapter(
                reference._provider_client, session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
            )

        report = run_conformance(make_leaky_metadata_adapter)
        failed = {result["id"] for result in report["results"] if result["status"] == "FAIL"}
        self.assertIn("issuer-metadata-valid", failed, report)

    def test_metadata_schema_ids_must_exactly_match_declared_capabilities(self):
        class ExtraMetadataAdapter(SandboxIssuerAdapter):
            def issuer_metadata(self):
                metadata = super().issuer_metadata()
                runtime_metadata = reference_runtime_attestation_adapter().issuer_metadata()
                metadata["supportedSchemas"].append(
                    runtime_metadata["supportedSchemas"][0]
                )
                return metadata

        report = run_conformance(
            lambda: ExtraMetadataAdapter(session_identity=lambda: "test-session", clock=lambda: TIMESTAMP)
        )
        failed = [
            result["id"]
            for result in report["results"]
            if result["status"] == "FAIL"
        ]
        self.assertEqual(failed, ["issuer-metadata-valid"], report)

    def test_overbroad_schema_resolver_fails_only_unsupported_schema_case(self):
        class OverbroadResolverAdapter(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({KYC_SCHEMA_ID})
            schema_required_privacy_profiles = MappingProxyType(
                {KYC_SCHEMA_ID: frozenset({"human"})}
            )

            def _get_supported_schema(self, schema_id):
                return get_schema(schema_id)

        report = run_conformance(
            lambda: OverbroadResolverAdapter(session_identity=lambda: "test-session", clock=lambda: TIMESTAMP)
        )
        failed = [
            result["id"]
            for result in report["results"]
            if result["status"] == "FAIL"
        ]
        self.assertEqual(failed, ["rejects-unsupported-schema"], report)

    def test_adapters_implement_the_contract_abc(self):
        self.assertTrue(issubclass(SandboxIssuerAdapter, IssuerAdapter))
        self.assertTrue(issubclass(BaseIssuerAdapter, IssuerAdapter))
        adapter = reference_external_adapter()
        self.assertIsInstance(adapter, IssuerAdapter)
        # The base class cannot be instantiated (subject resolution abstract).
        with self.assertRaises(TypeError):
            BaseIssuerAdapter(issuer_id="zkc:issuer:x", display_name="x")


class ProviderBoundaryTests(unittest.TestCase):
    def test_failed_provider_decisions_surface_as_provider_verification_failed(self):
        from zkc_issuer import AdapterError, ExternalProviderAdapter

        adapter = ExternalProviderAdapter(
            StaticProviderClient({}), session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
        )
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject({"schemaId": KYC_SCHEMA_ID, "subjectId": "nobody"})
        self.assertEqual(ctx.exception.code, "PROVIDER_VERIFICATION_FAILED")

    def test_unrecognized_provider_decisions_fail_closed(self):
        from zkc_issuer import AdapterError, ExternalProviderAdapter, ProviderClient

        class BrokenClient(ProviderClient):
            def verify_subject(self, schema_id, payload, *, authenticated_session):
                return {"verified": True}  # not a ProviderDecision

        adapter = ExternalProviderAdapter(BrokenClient(), session_identity=lambda: "test-session", clock=lambda: TIMESTAMP)
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject({"schemaId": KYC_SCHEMA_ID, "subjectId": "applicant-1"})
        self.assertEqual(ctx.exception.code, "PROVIDER_VERIFICATION_FAILED")

    def test_provider_decision_defaults_fail_closed(self):
        decision = ProviderDecision(verified=False)
        self.assertFalse(decision.verified)
        self.assertEqual(decision.claims, {})


class ProviderContainmentTests(unittest.TestCase):
    RUNTIME_CLAIMS = {
        "attestedManifestDigest": "sha256:" + "71" * 32,
        "rootClass": "root:build-provenance",
        "rootAuthorityIdentifier": "sigstore:rekor:public-good:v1",
        "rootMaterialDigest": "sha256:" + "72" * 32,
        "attestationEvidenceDigest": "sha256:" + "73" * 32,
        "verificationPolicyDigest": "sha256:" + "74" * 32,
        "validFrom": TIMESTAMP - 60,
        "validUntil": TIMESTAMP + 3_600,
    }

    class _ReturningClient:
        def __init__(self, value):
            self.value = value

        def verify_subject(self, schema_id, payload, *, authenticated_session):
            return self.value

    class _RaisingClient:
        def verify_subject(self, schema_id, payload, *, authenticated_session):
            raise RuntimeError("provider-sentinel")

    class _StoppingClient:
        def verify_subject(self, schema_id, payload, *, authenticated_session):
            raise KeyboardInterrupt("provider-sentinel")

    class _LogCapture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.messages = []

        def emit(self, record):
            self.messages.append(self.format(record))

    def _assert_fixed_failure(self, adapter, payload):
        capture = self._LogCapture()
        issuer_logger = logging.getLogger("zkc_issuer")
        issuer_logger.addHandler(capture)
        try:
            with self.assertRaises(AdapterError) as caught:
                adapter.verify_subject(payload)
        finally:
            issuer_logger.removeHandler(capture)
        error = caught.exception
        self.assertEqual(
            error.to_dict(),
            {
                "code": "PROVIDER_VERIFICATION_FAILED",
                "message": "provider verification failed",
            },
        )
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertNotIn("provider-sentinel", repr(error.to_dict()))
        self.assertNotIn("provider-sentinel", "\n".join(capture.messages))
        self.assertEqual(adapter._verified, {})

    def _runtime_adapter(self, decision):
        return RuntimeAttestationAdapter(
            self._ReturningClient(decision), session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
        )

    def _bind_and_issue(self, adapter, subject, schema_id):
        holder = HolderClient.from_seed(
            MASTER_SEED, PredicateRegistry.from_repo(REPO_ROOT), StubBackend()
        )
        holder_commitment = field_to_hex(holder.get_binding_commitment())
        challenge = adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment,
                "schemaId": schema_id,
            }
        )
        response = holder.binding_challenge_response(
            adapter.issuer_id,
            schema_id,
            challenge["nonce"],
            challenge["expiresAt"],
        )
        adapter.bind_holder_commitment(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment,
                "schemaId": schema_id,
                "nonce": challenge["nonce"],
                "challengeResponse": response,
            }
        )
        return adapter.issue_credential(
            {"subjectRef": subject["subjectRef"], "schemaId": schema_id}
        )

    def test_provider_exceptions_false_decisions_and_non_decisions_are_contained(self):
        from zkc_issuer import ExternalProviderAdapter

        cases = (
            self._RaisingClient(),
            self._ReturningClient(
                ProviderDecision(
                    holder_commitment=TEST_HOLDER,
                    verified=False,
                    failure_reason="provider-sentinel",
                    claims={"provider-sentinel": True},
                )
            ),
            self._ReturningClient({"provider-sentinel": True}),
        )
        payload = {"schemaId": KYC_SCHEMA_ID, "subjectId": "applicant-1"}
        for client in cases:
            with self.subTest(client=type(client).__name__):
                self._assert_fixed_failure(
                    ExternalProviderAdapter(client, session_identity=lambda: "test-session", clock=lambda: TIMESTAMP), payload
                )

    def test_exact_provider_decisions_with_missing_fields_are_contained(self):
        payload = {
            "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
            "holderCommitment": TEST_HOLDER,
            "evidenceRef": "evidence-1",
        }
        for missing_field in ("verified", "provider_ref", "claims", "expires_at"):
            with self.subTest(missing_field=missing_field):
                decision = ProviderDecision(
                    holder_commitment=TEST_HOLDER,
                    verified=True,
                    provider_ref="provider-sentinel-reference",
                    claims=dict(self.RUNTIME_CLAIMS),
                    expires_at=TIMESTAMP + 3_600,
                )
                object.__delattr__(decision, missing_field)
                self._assert_fixed_failure(self._runtime_adapter(decision), payload)

    def test_provider_base_exceptions_are_not_caught(self):
        from zkc_issuer import ExternalProviderAdapter

        adapter = ExternalProviderAdapter(
            self._StoppingClient(), session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
        )
        with self.assertRaises(KeyboardInterrupt):
            adapter.verify_subject(
                {"schemaId": KYC_SCHEMA_ID, "subjectId": "applicant-1"}
            )
        self.assertEqual(adapter._verified, {})

    def test_provider_reference_is_exact_bounded_utf8_text(self):
        class StringSubclass(str):
            pass

        invalid = ("", StringSubclass("case-1"), "bad\ud800", "x" * 257)
        for provider_ref in invalid:
            with self.subTest(provider_ref_type=type(provider_ref).__name__):
                adapter = self._runtime_adapter(
                    ProviderDecision(
                        holder_commitment=TEST_HOLDER,
                        verified=True,
                        provider_ref=provider_ref,
                        claims=dict(self.RUNTIME_CLAIMS),
                        expires_at=TIMESTAMP + 3_600,
                    )
                )
                self._assert_fixed_failure(
                    adapter,
                    {
                        "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                        "holderCommitment": TEST_HOLDER,
                        "evidenceRef": "evidence-1",
                    },
                )

    def test_provider_reference_and_expiry_accept_exact_boundaries(self):
        from zkc_issuer import ExternalProviderAdapter

        adapter = ExternalProviderAdapter(
            self._ReturningClient(
                ProviderDecision(
                    holder_commitment=TEST_HOLDER,
                    verified=True,
                    provider_ref="é" * 128,
                    claims={
                        "level": 2,
                        "verifiedAttributes": [True, True, True, False, True],
                    },
                    expires_at=(1 << 64) - 1,
                )
            ),
            session_identity=lambda: "test-session", clock=lambda: TIMESTAMP,
        )
        result = adapter.verify_subject(
            {"schemaId": KYC_SCHEMA_ID, "subjectId": "applicant-1"}
        )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(len(adapter._verified), 1)

    def test_expiry_is_an_exact_unsigned_64_bit_integer(self):
        for expires_at in (True, -1, 1 << 64):
            with self.subTest(expires_at=expires_at):
                adapter = self._runtime_adapter(
                    ProviderDecision(
                        holder_commitment=TEST_HOLDER,
                        verified=True,
                        provider_ref="case-1",
                        claims=dict(self.RUNTIME_CLAIMS),
                        expires_at=expires_at,
                    )
                )
                self._assert_fixed_failure(
                    adapter,
                    {
                        "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                        "holderCommitment": TEST_HOLDER,
                        "evidenceRef": "evidence-1",
                    },
                )

    def test_runtime_expiry_must_equal_normalized_valid_until(self):
        adapter = self._runtime_adapter(
            ProviderDecision(
                holder_commitment=TEST_HOLDER,
                verified=True,
                provider_ref="case-1",
                claims=dict(self.RUNTIME_CLAIMS),
                expires_at=TIMESTAMP + 3_599,
            )
        )
        self._assert_fixed_failure(
            adapter,
            {
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                "holderCommitment": TEST_HOLDER,
                "evidenceRef": "evidence-1",
            },
        )

    def test_provider_claim_aliases_cannot_change_an_issued_credential(self):
        from zkc_issuer import ExternalProviderAdapter

        provider_attributes = [True, True, True, False, True]
        decision = ProviderDecision(
            holder_commitment=TEST_HOLDER,
            verified=True,
            provider_ref="case-1",
            claims={
                "level": 2,
                "verifiedAttributes": provider_attributes,
                "optionalProviderValue": None,
            },
            expires_at=TIMESTAMP + 3_600,
        )
        adapter = ExternalProviderAdapter(
            self._ReturningClient(decision), session_identity=lambda: "test-session", clock=lambda: TIMESTAMP
        )
        holder = HolderClient.from_seed(
            MASTER_SEED, PredicateRegistry.from_repo(REPO_ROOT), StubBackend()
        )
        holder_commitment = field_to_hex(holder.get_binding_commitment())
        subject = adapter.verify_subject(
            {"schemaId": KYC_SCHEMA_ID, "subjectId": "applicant-1"}
        )
        provider_attributes[:] = [False, False, False, False, False]
        decision.claims["level"] = 99
        challenge = adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment,
                "schemaId": KYC_SCHEMA_ID,
            }
        )
        response = holder.binding_challenge_response(
            adapter.issuer_id,
            KYC_SCHEMA_ID,
            challenge["nonce"],
            challenge["expiresAt"],
        )
        adapter.bind_holder_commitment(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment,
                "schemaId": KYC_SCHEMA_ID,
                "nonce": challenge["nonce"],
                "challengeResponse": response,
            }
        )
        envelope = adapter.issue_credential(
            {"subjectRef": subject["subjectRef"], "schemaId": KYC_SCHEMA_ID}
        )
        self.assertEqual(
            envelope["credential"]["claims"],
            {
                "level": 2,
                "verifiedAttributes": [True, True, True, False, True],
            },
        )

    def test_provider_claim_copy_rejects_nonplain_or_oversized_containers(self):
        from zkc_issuer import ExternalProviderAdapter

        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class TupleSubclass(tuple):
            pass

        too_deep = None
        for _ in range(32):
            too_deep = [too_deep]
        shared = [True, True, True, False, True]
        invalid_claims = (
            DictSubclass(
                {"level": 2, "verifiedAttributes": [True] * 5}
            ),
            {"level": 2, "verifiedAttributes": ListSubclass([True] * 5)},
            {"level": 2, "verifiedAttributes": TupleSubclass([True] * 5)},
            {
                "level": 2,
                "verifiedAttributes": [True] * 5,
                "safe": too_deep,
            },
            {
                "level": 2,
                "verifiedAttributes": [True] * 5,
                "safe": [None] * 4096,
            },
            {
                "level": 2,
                "verifiedAttributes": [True] * 5,
                "x" * 4097: None,
            },
            {"level": 2, "verifiedAttributes": shared, "safe": shared},
        )
        for claims in invalid_claims:
            with self.subTest(claims_type=type(claims).__name__):
                adapter = ExternalProviderAdapter(
                    self._ReturningClient(
                        ProviderDecision(
                            holder_commitment=TEST_HOLDER,
                            verified=True,
                            provider_ref="case-1",
                            claims=claims,
                            expires_at=TIMESTAMP + 3_600,
                        )
                    ),
                    session_identity=lambda: "test-session", clock=lambda: TIMESTAMP,
                )
                self._assert_fixed_failure(
                    adapter,
                    {"schemaId": KYC_SCHEMA_ID, "subjectId": "applicant-1"},
                )

    def test_provider_claim_scalar_subclasses_fail_before_retention(self):
        from zkc_issuer import ExternalProviderAdapter

        class StringSubclass(str):
            pass

        class IntSubclass(int):
            pass

        runtime_claims = dict(self.RUNTIME_CLAIMS)
        runtime_claims["attestedManifestDigest"] = StringSubclass(
            runtime_claims["attestedManifestDigest"]
        )
        cases = (
            (
                self._runtime_adapter(
                    ProviderDecision(
                        holder_commitment=TEST_HOLDER,
                        verified=True,
                        provider_ref="case-runtime-subclass",
                        claims=runtime_claims,
                        expires_at=TIMESTAMP + 3_600,
                    )
                ),
                {
                    "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                    "holderCommitment": TEST_HOLDER,
                    "evidenceRef": "evidence-1",
                },
            ),
            (
                ExternalProviderAdapter(
                    self._ReturningClient(
                        ProviderDecision(
                            holder_commitment=TEST_HOLDER,
                            verified=True,
                            provider_ref="case-kyc-subclass",
                            claims={
                                "level": IntSubclass(2),
                                "verifiedAttributes": [
                                    True,
                                    True,
                                    True,
                                    False,
                                    True,
                                ],
                            },
                            expires_at=TIMESTAMP + 3_600,
                        )
                    ),
                    session_identity=lambda: "test-session", clock=lambda: TIMESTAMP,
                ),
                {"schemaId": KYC_SCHEMA_ID, "subjectId": "applicant-1"},
            ),
        )
        for adapter, payload in cases:
            with self.subTest(schema_id=payload["schemaId"]):
                self._assert_fixed_failure(adapter, payload)

    def test_hostile_scalar_methods_never_run_or_reach_verified_state(self):
        class HostileString(str):
            encode_calls = 0

            def encode(self, *args, **kwargs):
                type(self).encode_calls += 1
                raise RuntimeError("provider-sentinel-hostile-encode")

        claims = dict(self.RUNTIME_CLAIMS)
        claims["attestedManifestDigest"] = HostileString(
            claims["attestedManifestDigest"]
        )
        adapter = self._runtime_adapter(
            ProviderDecision(
                holder_commitment=TEST_HOLDER,
                verified=True,
                provider_ref="case-hostile-scalar",
                claims=claims,
                expires_at=TIMESTAMP + 3_600,
            )
        )
        payload = {
            "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
            "holderCommitment": TEST_HOLDER,
            "evidenceRef": "evidence-1",
        }
        try:
            adapter.verify_subject(payload)
        except AdapterError as error:
            self.assertEqual(
                error.to_dict(),
                {
                    "code": "PROVIDER_VERIFICATION_FAILED",
                    "message": "provider verification failed",
                },
            )
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertEqual(adapter._verified, {})
            self.assertEqual(HostileString.encode_calls, 0)
            return

        subject = next(iter(adapter._verified))
        with self.assertRaisesRegex(
            RuntimeError, "provider-sentinel-hostile-encode"
        ):
            self._bind_and_issue(
                adapter,
                {"subjectRef": subject},
                RUNTIME_ATTESTATION_SCHEMA_ID,
            )
        self.fail("hostile provider scalar survived stage 1 into issuer state")

    def test_unsupported_provider_scalar_leaves_fail_even_when_schema_discards_them(self):
        from zkc_issuer import ExternalProviderAdapter

        class BoolLike:
            def __bool__(self):
                raise RuntimeError("provider-sentinel-bool-like")

        for unsupported in (1.5, b"bytes", object(), {"set-value"}, BoolLike()):
            with self.subTest(value_type=type(unsupported).__name__):
                adapter = ExternalProviderAdapter(
                    self._ReturningClient(
                        ProviderDecision(
                            holder_commitment=TEST_HOLDER,
                            verified=True,
                            provider_ref="case-unsupported-scalar",
                            claims={
                                "level": 2,
                                "verifiedAttributes": [
                                    True,
                                    True,
                                    True,
                                    False,
                                    True,
                                ],
                                "discardedBySchema": unsupported,
                            },
                            expires_at=TIMESTAMP + 3_600,
                        )
                    ),
                    session_identity=lambda: "test-session", clock=lambda: TIMESTAMP,
                )
                self._assert_fixed_failure(
                    adapter,
                    {"schemaId": KYC_SCHEMA_ID, "subjectId": "applicant-1"},
                )

    def test_exact_builtin_runtime_scalars_survive_provider_reassignment(self):
        provider_claims = dict(self.RUNTIME_CLAIMS)
        adapter = self._runtime_adapter(
            ProviderDecision(
                holder_commitment=TEST_HOLDER,
                verified=True,
                provider_ref="case-exact-scalars",
                claims=provider_claims,
                expires_at=TIMESTAMP + 3_600,
            )
        )
        subject = adapter.verify_subject(
            {
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                "holderCommitment": TEST_HOLDER,
                "evidenceRef": "evidence-1",
            }
        )
        provider_claims["attestedManifestDigest"] = "provider-sentinel-reassigned"
        provider_claims["validFrom"] = 0
        envelope = self._bind_and_issue(
            adapter, subject, RUNTIME_ATTESTATION_SCHEMA_ID
        )
        self.assertEqual(envelope["credential"]["claims"], self.RUNTIME_CLAIMS)

    def test_raw_machine_fields_in_provider_claims_fail_before_retention(self):
        for field, sentinel in (
            ("hostSerial", "provider-sentinel-host"),
            ("buildPath", "/provider-sentinel/build"),
        ):
            with self.subTest(field=field):
                claims = {**self.RUNTIME_CLAIMS, field: sentinel}
                adapter = self._runtime_adapter(
                    ProviderDecision(
                        holder_commitment=TEST_HOLDER,
                        verified=True,
                        provider_ref="case-1",
                        claims=claims,
                        expires_at=TIMESTAMP + 3_600,
                    )
                )
                self._assert_fixed_failure(
                    adapter,
                    {
                        "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                        "holderCommitment": TEST_HOLDER,
                        "evidenceRef": "evidence-1",
                    },
                )

    def test_runtime_adapter_declares_only_immutable_human_machine_capability(self):
        adapter = self._runtime_adapter(
            ProviderDecision(
                holder_commitment=TEST_HOLDER,
                verified=True,
                provider_ref="case-1",
                claims=dict(self.RUNTIME_CLAIMS),
                expires_at=TIMESTAMP + 3_600,
            )
        )
        self.assertEqual(
            adapter.supported_schema_ids,
            frozenset({RUNTIME_ATTESTATION_SCHEMA_ID}),
        )
        self.assertIs(type(adapter.supported_schema_ids), frozenset)
        self.assertIs(type(adapter.schema_required_privacy_profiles), MappingProxyType)
        self.assertEqual(
            dict(adapter.schema_required_privacy_profiles),
            {RUNTIME_ATTESTATION_SCHEMA_ID: frozenset({"human", "machine"})},
        )
        verified = adapter.verify_subject(
            {
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                "holderCommitment": TEST_HOLDER,
                "evidenceRef": "provider-sentinel-evidence",
            }
        )
        self.assertNotIn("provider-sentinel", json.dumps(verified, sort_keys=True))
        metadata = adapter.issuer_metadata()
        self.assertEqual(
            [entry["schemaId"] for entry in metadata["supportedSchemas"]],
            [RUNTIME_ATTESTATION_SCHEMA_ID],
        )
        self.assertNotIn("provider-sentinel", json.dumps(metadata, sort_keys=True))


class RuntimeAttestationCanonicalJsonTests(unittest.TestCase):
    def test_profile_limits_are_pinned(self):
        self.assertEqual(
            (
                runtime_attestation.RUNTIME_ATTESTATION_MAX_EVIDENCE_STORE_ENTRIES,
                runtime_attestation.RUNTIME_ATTESTATION_MAX_CANONICAL_JSON_NODES,
                runtime_attestation.RUNTIME_ATTESTATION_MAX_STRING_UTF8_BYTES,
                runtime_attestation.RUNTIME_ATTESTATION_MAX_EVIDENCE_REF_UTF8_BYTES,
                runtime_attestation.RUNTIME_ATTESTATION_MAX_ROOT_AUTHORITY_IDENTIFIER_UTF8_BYTES,
            ),
            (256, 4096, 4096, 256, 256),
        )

    def test_canonical_json_orders_keys_by_unicode_scalar_value(self):
        value = {"\U0001f600": "astral", "\ue000": "bmp"}
        expected = b'{"\xee\x80\x80":"bmp","\xf0\x9f\x98\x80":"astral"}'
        self.assertEqual(runtime_attestation._canonical_json_bytes(value), expected)
        self.assertEqual(
            _digest_json(value),
            "sha256:4874d36535a1b5dfdad7f2b3af83f87debd2f0795ae7d2d09447e17223c42dd0",
        )

    def test_canonical_digest_known_answers(self):
        cases = (
            (
                {"z": 1, "a": 2},
                "sha256:c2985c5ba6f7d2a55e768f92490ca09388e95bc4cccb9fdf11b15f4d42f93e73",
            ),
            (
                {"é": "雪"},
                "sha256:161cb330a3b13a70cc861bd5c5a890d82ef7bde916023522f767392ededf09f1",
            ),
            (
                {"min": -(1 << 63), "max": (1 << 63) - 1},
                "sha256:161a1dcda7bae00f28f0ba32675f218fd4977065d2aa0439cf451c6d066dbbfb",
            ),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(_digest_json(value), expected)

    def test_profile_accepts_only_plain_bounded_json_values(self):
        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        invalid = (
            1.5,
            float("nan"),
            float("inf"),
            float("-inf"),
            1 << 63,
            -(1 << 63) - 1,
            object(),
            {"set"},
            {1: "non-string-key"},
            "bad\ud800text",
            {"bad\ud800key": "value"},
            DictSubclass({"key": "value"}),
            ListSubclass(["value"]),
        )
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError):
                    _digest_json(value)

        self.assertTrue(_digest_json({"bool": True, "null": None, "items": []}))

    def test_profile_rejects_excessive_nesting(self):
        at_limit = None
        for _ in range(32):
            at_limit = [at_limit]
        self.assertTrue(_digest_json(at_limit))
        with self.assertRaises(ValueError):
            _digest_json([at_limit])

    def test_profile_enforces_total_nodes_and_string_bytes(self):
        self.assertTrue(_digest_json([None] * 4095))
        with self.assertRaises(ValueError):
            _digest_json([None] * 4096)

        self.assertTrue(_digest_json("é" * 2048))
        with self.assertRaises(ValueError):
            _digest_json("é" * 2049)

    def test_constructor_rejects_invalid_store_with_fixed_message(self):
        class HostileMapping(dict):
            def items(self):
                raise RuntimeError("raw-secret-from-items")

            def keys(self):
                raise RuntimeError("raw-secret-from-keys")

            def __iter__(self):
                raise RuntimeError("raw-secret-from-iter")

        too_deep = None
        for _ in range(33):
            too_deep = [too_deep]
        invalid = (
            {"bad": float("nan")},
            {"bad": float("inf")},
            {"bad": object()},
            {"bad": "surrogate\ud800"},
            {"bad": too_deep},
            HostileMapping({"evidence": {}}),
        )
        for evidence_store in invalid:
            with self.subTest(store_type=type(evidence_store).__name__):
                with self.assertRaises(ValueError) as ctx:
                    StaticPreverifiedRuntimeAttestationProviderClient(
                        evidence_store,
                        RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
                    )
                self.assertEqual(
                    str(ctx.exception),
                    "invalid runtime attestation evidence store",
                )

    def test_constructor_enforces_store_size_and_canonical_context_digest(self):
        accepted = {f"evidence-{index}": {} for index in range(256)}
        StaticPreverifiedRuntimeAttestationProviderClient(
            accepted, RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
        )

        invalid = (
            (
                {f"evidence-{index}": {} for index in range(257)},
                RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
            ),
            ({}, "sha256:" + "00" * 32),
            ({}, "sha256:" + "AA" * 32),
            ({}, "sha512:" + "aa" * 32),
            ({}, "sha256:1234"),
        )
        for evidence_store, context in invalid:
            with self.subTest(entries=len(evidence_store), context=context):
                with self.assertRaises(ValueError) as ctx:
                    StaticPreverifiedRuntimeAttestationProviderClient(
                        evidence_store, context
                    )
                self.assertEqual(
                    str(ctx.exception),
                    "invalid runtime attestation evidence store",
                )


class RuntimeAttestationExternalArtifactDigestTests(unittest.TestCase):
    """AFP External Artifact v2 alignment (interoperability requirement).

    The public rootMaterialDigest and attestationEvidenceDigest are SHA-256
    over the AFP-External-Artifact-v2 domain/kind/scheme/length framing of
    the exact scheme-native signed bytes, never over a canonical-JSON
    re-encoding.
    """

    @classmethod
    def setUpClass(cls):
        with open(EXTERNAL_ARTIFACT_VECTORS_PATH, encoding="utf-8") as handle:
            cls.document = json.load(handle)

    def test_vector_file_pins_profile_and_domain(self):
        self.assertEqual(
            self.document["profile"],
            RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE,
        )
        self.assertEqual(
            bytes.fromhex(self.document["domainHex"]),
            b"AFP-External-Artifact-v2\x00",
        )
        self.assertEqual(
            {vector["name"] for vector in self.document["vectors"]},
            {
                "build-provenance-statement",
                "transparency-log-checkpoint",
                "tee-attestation-report",
                "tee-endorsement-collateral",
            },
        )

    def test_known_answer_vectors_match_zkc_and_afp_implementations(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                signed_bytes = bytes.fromhex(vector["signedBytesHex"])
                zkc_digest = compute_external_artifact_digest(
                    vector["kind"], vector["scheme"], signed_bytes
                )
                afp_digest = _afp_external_artifact_digest(
                    vector["kind"], vector["scheme"], signed_bytes
                )
                self.assertEqual(zkc_digest, vector["digest"])
                self.assertEqual(afp_digest, vector["digest"])
                framing = bytes.fromhex(vector["framingHex"])
                self.assertTrue(
                    framing.startswith(b"AFP-External-Artifact-v2\x00")
                )
                self.assertTrue(framing.endswith(signed_bytes))
                self.assertEqual(
                    vector["digest"],
                    "sha256:" + hashlib.sha256(framing).hexdigest(),
                )

    def test_reference_adapter_claims_equal_vector_digests(self):
        by_name = {
            vector["name"]: vector["digest"]
            for vector in self.document["vectors"]
        }
        adapter = reference_runtime_attestation_adapter()
        decision = adapter._provider_client.verify_subject(
            RUNTIME_ATTESTATION_SCHEMA_ID, adapter.conformance_subject_payload,
            authenticated_session="test-session",
        )
        self.assertTrue(decision.verified)
        self.assertEqual(
            decision.claims["attestationEvidenceDigest"],
            by_name["build-provenance-statement"],
        )
        self.assertEqual(
            decision.claims["rootMaterialDigest"],
            by_name["transparency-log-checkpoint"],
        )

    def test_json_reencoding_produces_rejected_different_digest(self):
        (rejected,) = self.document["rejectedVectors"]
        statement_vector = next(
            vector
            for vector in self.document["vectors"]
            if vector["name"] == "build-provenance-statement"
        )
        exact_bytes = bytes.fromhex(statement_vector["signedBytesHex"])
        reencoded = runtime_attestation._canonical_json_bytes(
            json.loads(exact_bytes)
        )
        self.assertEqual(reencoded.hex(), rejected["signedBytesHex"])
        self.assertNotEqual(reencoded, exact_bytes)
        self.assertEqual(
            compute_external_artifact_digest(
                rejected["kind"], rejected["scheme"], reencoded
            ),
            rejected["digest"],
        )
        self.assertEqual(
            rejected["mustNotEqualDigest"], statement_vector["digest"]
        )
        self.assertNotEqual(rejected["digest"], rejected["mustNotEqualDigest"])

    def test_signed_bytes_are_authoritative_over_parsed_equality(self):
        compact = b'{"a":1}'
        spaced = b'{"a": 1}'
        self.assertEqual(json.loads(compact), json.loads(spaced))
        self.assertNotEqual(
            compute_external_artifact_digest("kind", "scheme", compact),
            compute_external_artifact_digest("kind", "scheme", spaced),
        )

    def test_framing_is_domain_and_length_separated(self):
        signed = b"payload"
        baseline = compute_external_artifact_digest("ab", "cd", signed)
        # Moving one byte across the kind/scheme boundary must change the
        # digest: the u32be length prefixes make the framing injective.
        self.assertNotEqual(
            baseline, compute_external_artifact_digest("abc", "d", signed)
        )
        self.assertNotEqual(
            baseline, compute_external_artifact_digest("a", "bcd", signed)
        )
        # Swapping kind and scheme must change the digest.
        self.assertNotEqual(
            baseline, compute_external_artifact_digest("cd", "ab", signed)
        )
        # Moving bytes between scheme and payload must change the digest.
        self.assertNotEqual(
            baseline,
            compute_external_artifact_digest("ab", "cdp", b"ayload"),
        )

    def test_digest_rejects_invalid_kind_scheme_or_bytes(self):
        invalid = (
            ("", "scheme", b"x"),
            ("kind", "", b"x"),
            ("kind", "scheme", b""),
            ("kind", "scheme", "not-bytes"),
            ("kind", "scheme", bytearray(b"x")),
            ("kindé", "scheme", b"x"),
            ("kind", "sch eme", b"x"),
            ("kind", "scheme\x00", b"x"),
            (".leading-dot", "scheme", b"x"),
            ("k" * 129, "scheme", b"x"),
            (None, "scheme", b"x"),
            ("kind", None, b"x"),
        )
        for kind, scheme, signed_bytes in invalid:
            with self.subTest(kind=kind, scheme=scheme):
                with self.assertRaises(ValueError):
                    compute_external_artifact_digest(kind, scheme, signed_bytes)

    def test_legacy_canonical_json_entries_fail_closed(self):
        """AC4: v1 canonical-JSON evidence is rejected, never reinterpreted."""

        manifest = "sha256:" + "51" * 32
        legacy_statement = {
            "statementType": "https://in-toto.io/Statement/v1",
            "artifactDigest": manifest,
            "builder": "https://builder.example/reference",
        }
        legacy_entry = {
            "rootClass": "root:build-provenance",
            "rootAuthorityIdentifier": "sigstore:rekor:public-good:v1",
            "attestedManifestDigest": manifest,
            "verificationPolicyDigest": "sha256:" + "52" * 32,
            "validFrom": TIMESTAMP - 60,
            "validUntil": TIMESTAMP + 3_600,
            "rootMaterial": {
                "checkpointAuthenticated": True,
                "inclusionVerified": True,
                "checkpoint": {"origin": "rekor.sigstore.dev", "treeSize": 42},
                "inclusionPath": ["sha256:" + "53" * 32],
                "includedStatementDigest": _digest_json(legacy_statement),
            },
            "rawEvidence": {
                "holderCommitment": TEST_HOLDER,
                "signatureVerified": True,
                "builderIdentityAccepted": True,
                "artifactDigest": manifest,
                "statement": legacy_statement,
            },
        }
        client = StaticPreverifiedRuntimeAttestationProviderClient(
            {"legacy-1": legacy_entry}, RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
        )
        decision = client.verify_subject(
            RUNTIME_ATTESTATION_SCHEMA_ID,
            {
                "holderCommitment": TEST_HOLDER,
                "evidenceRef": "legacy-1",
                "verificationContextDigest": (
                    RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
                ),
            },
            authenticated_session="test-session",
        )
        self.assertFalse(decision.verified)
        self.assertEqual(
            decision.failure_reason, "runtime attestation evidence rejected"
        )
        self.assertEqual(decision.claims, {})

    def test_store_carrier_requires_exact_v2_shape(self):
        valid = {
            "digestProfile": RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE,
            "kind": RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
            "scheme": "in-toto-dsse:v1",
            "signedBytesHex": b"exact signed bytes".hex(),
        }
        digest = runtime_attestation._external_artifact_digest_from_store(
            valid, RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT
        )
        self.assertEqual(
            digest,
            _afp_external_artifact_digest(
                valid["kind"], valid["scheme"], b"exact signed bytes"
            ),
        )
        invalid = (
            {**valid, "digestProfile": "zkc:runtime-attestation:canonical-json:v1"},
            {**valid, "kind": RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_REPORT},
            {**valid, "signedBytesHex": ""},
            {**valid, "signedBytesHex": "0F"},
            {**valid, "signedBytesHex": "abc"},
            {**valid, "signedBytesHex": "gg"},
            {**valid, "signedBytesHex": "00" * 2049},
            {**valid, "scheme": ""},
            {**valid, "extra": "key"},
            {key: value for key, value in valid.items() if key != "scheme"},
            [],
            "not-a-carrier",
            None,
        )
        for carrier in invalid:
            with self.subTest(carrier=carrier):
                self.assertIsNone(
                    runtime_attestation._external_artifact_digest_from_store(
                        carrier,
                        RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
                    )
                )


class RuntimeAttestationProviderBoundaryTests(unittest.TestCase):
    STATEMENT_SCHEME = "in-toto-dsse:v1"
    CHECKPOINT_SCHEME = "signed-note:v1"
    REPORT_SCHEME = "example-tee-quote:v4"
    COLLATERAL_SCHEME = "example-tee-collateral:v1"

    STATEMENT_BYTES = (
        b'{"statementType": "https://in-toto.io/Statement/v1", '
        b'"artifactDigest": "sha256:' + b"51" * 32 + b'", '
        b'"builder": "https://builder.example/reference", '
        b'"marker": "raw-provenance-must-stay-provider-side"}'
    )
    CHECKPOINT_BYTES = (
        b"rekor.sigstore.dev - test-log\n42\n"
        b"raw-checkpoint-must-stay-provider-side\n"
    )
    REPORT_BYTES = (
        b"\x04\x00\x02\x00raw-tee-report-must-stay-provider-side\x00\xff"
    )
    COLLATERAL_BYTES = (
        b"\x30\x82raw-collateral-must-stay-provider-side\x02\x01\x03"
    )

    def _build_entry(self):
        manifest = "sha256:" + "51" * 32
        return {
            "subjectIdentity": "private-runtime-subject",
            "rootClass": "root:build-provenance",
            "rootAuthorityIdentifier": "sigstore:rekor:public-good:v1",
            "attestedManifestDigest": manifest,
            "verificationPolicyDigest": "sha256:" + "52" * 32,
            "validFrom": TIMESTAMP - 60,
            "validUntil": TIMESTAMP + 3_600,
            "rootMaterial": {
                "checkpointAuthenticated": True,
                "inclusionVerified": True,
                "checkpoint": _external_artifact(
                    RUNTIME_ATTESTATION_ARTIFACT_KIND_TRANSPARENCY_CHECKPOINT,
                    self.CHECKPOINT_SCHEME,
                    self.CHECKPOINT_BYTES,
                ),
                "inclusionPath": ["sha256:" + "53" * 32],
                "includedStatementDigest": _afp_external_artifact_digest(
                    RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
                    self.STATEMENT_SCHEME,
                    self.STATEMENT_BYTES,
                ),
            },
            "rawEvidence": {
                "holderCommitment": TEST_HOLDER,
                "signatureVerified": True,
                "builderIdentityAccepted": True,
                "artifactDigest": manifest,
                "statement": _external_artifact(
                    RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
                    self.STATEMENT_SCHEME,
                    self.STATEMENT_BYTES,
                ),
            },
        }

    def _tee_entry(self):
        manifest = "sha256:" + "61" * 32
        return {
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
                "collateral": _external_artifact(
                    RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_ENDORSEMENT_COLLATERAL,
                    self.COLLATERAL_SCHEME,
                    self.COLLATERAL_BYTES,
                ),
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
                "report": _external_artifact(
                    RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_REPORT,
                    self.REPORT_SCHEME,
                    self.REPORT_BYTES,
                ),
            },
        }

    def _verify(self, store, evidence_ref="evidence-1", context=None):
        client = StaticPreverifiedRuntimeAttestationProviderClient(
            store, RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
        )
        return client.verify_subject(
            RUNTIME_ATTESTATION_SCHEMA_ID,
            {
                "holderCommitment": TEST_HOLDER,
                "evidenceRef": evidence_ref,
                "verificationContextDigest": (
                    RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
                    if context is None
                    else context
                ),
            },
            authenticated_session="test-session",
        )

    def test_build_provenance_requires_preverified_log_verdict(self):
        entry = self._build_entry()
        for root_material in (
            {**entry["rootMaterial"], "checkpointAuthenticated": False},
            {**entry["rootMaterial"], "inclusionVerified": False},
        ):
            with self.subTest(root_material=root_material):
                decision = self._verify(
                    {"evidence-1": {**entry, "rootMaterial": root_material}}
                )
                self.assertFalse(decision.verified)
                self.assertEqual(
                    decision.failure_reason,
                    "runtime attestation evidence rejected",
                )

    def test_build_preverified_verdict_rejects_signature_only_claim(self):
        entry = self._build_entry()
        entry["rootMaterial"] = {
            "checkpointAuthenticated": False,
            "inclusionVerified": False,
        }
        self.assertFalse(self._verify({"evidence-1": entry}).verified)

    def test_build_provenance_rejects_boolean_only_evidence(self):
        entry = self._build_entry()
        entry["rootMaterial"] = {
            "checkpointAuthenticated": True,
            "inclusionVerified": True,
        }
        entry["rawEvidence"] = {
            "signatureVerified": True,
            "builderIdentityAccepted": True,
            "artifactDigest": entry["attestedManifestDigest"],
        }
        decision = self._verify({"evidence-1": entry})
        self.assertFalse(decision.verified)
        self.assertEqual(
            decision.failure_reason, "runtime attestation evidence rejected"
        )

    def test_build_provenance_requires_exact_included_statement(self):
        entry = self._build_entry()
        cases = (
            {
                **entry,
                "rootMaterial": {**entry["rootMaterial"], "checkpoint": {}},
            },
            {
                **entry,
                "rootMaterial": {**entry["rootMaterial"], "inclusionPath": []},
            },
            {
                **entry,
                "rootMaterial": {
                    **entry["rootMaterial"],
                    "includedStatementDigest": "sha256:" + "ff" * 32,
                },
            },
            {
                **entry,
                "rawEvidence": {
                "holderCommitment": TEST_HOLDER,**entry["rawEvidence"], "statement": {}},
            },
            # Tampered signed bytes: the recomputed external-artifact digest
            # no longer equals the accepted includedStatementDigest.
            {
                **entry,
                "rawEvidence": {
                "holderCommitment": TEST_HOLDER,
                    **entry["rawEvidence"],
                    "statement": {
                        **entry["rawEvidence"]["statement"],
                        "signedBytesHex": (b"tampered" + self.STATEMENT_BYTES).hex(),
                    },
                },
            },
            # Provider-asserted subject binding must match the entry manifest.
            {
                **entry,
                "rawEvidence": {
                "holderCommitment": TEST_HOLDER,
                    **entry["rawEvidence"],
                    "artifactDigest": "sha256:" + "ff" * 32,
                },
            },
        )
        for malformed in cases:
            with self.subTest(entry=malformed):
                decision = self._verify({"evidence-1": malformed})
                self.assertFalse(decision.verified)
                self.assertEqual(
                    decision.failure_reason,
                    "runtime attestation evidence rejected",
                )

    def test_provider_decision_contains_only_normalized_claims(self):
        entry = self._build_entry()
        decision = self._verify({"evidence-1": entry})
        self.assertTrue(decision.verified)
        rendered = repr(decision)
        self.assertNotIn("raw-checkpoint-must-stay-provider-side", rendered)
        self.assertNotIn("raw-provenance-must-stay-provider-side", rendered)
        self.assertEqual(
            set(decision.claims),
            {
                "attestedManifestDigest",
                "rootClass",
                "rootAuthorityIdentifier",
                "rootMaterialDigest",
                "attestationEvidenceDigest",
                "verificationPolicyDigest",
                "validFrom",
                "validUntil",
            },
        )
        expected_root_digest = _afp_external_artifact_digest(
            RUNTIME_ATTESTATION_ARTIFACT_KIND_TRANSPARENCY_CHECKPOINT,
            self.CHECKPOINT_SCHEME,
            self.CHECKPOINT_BYTES,
        )
        expected_evidence_digest = _afp_external_artifact_digest(
            RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
            self.STATEMENT_SCHEME,
            self.STATEMENT_BYTES,
        )
        self.assertEqual(decision.claims["rootMaterialDigest"], expected_root_digest)
        self.assertEqual(
            decision.claims["attestationEvidenceDigest"], expected_evidence_digest
        )

    def test_tee_requires_every_preverified_verdict_condition(self):
        entry = self._tee_entry()
        required = (
            ("rootMaterial", "endorsementChainVerified"),
            ("rootMaterial", "revocationCurrent"),
            ("rootMaterial", "collateralFresh"),
            ("rawEvidence", "reportAuthenticated"),
            ("rawEvidence", "fresh"),
            ("rawEvidence", "measurementAccepted"),
            ("rawEvidence", "reportDataBound"),
        )
        accepted = self._verify({"evidence-1": entry})
        self.assertTrue(accepted.verified)
        self.assertEqual(accepted.claims["rootClass"], "root:tee-attestation")
        self.assertEqual(
            accepted.claims["rootMaterialDigest"],
            _afp_external_artifact_digest(
                RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_ENDORSEMENT_COLLATERAL,
                self.COLLATERAL_SCHEME,
                self.COLLATERAL_BYTES,
            ),
        )
        self.assertEqual(
            accepted.claims["attestationEvidenceDigest"],
            _afp_external_artifact_digest(
                RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_REPORT,
                self.REPORT_SCHEME,
                self.REPORT_BYTES,
            ),
        )
        for section, flag in required:
            changed = {**entry, section: {**entry[section], flag: False}}
            with self.subTest(flag=flag):
                self.assertFalse(self._verify({"evidence-1": changed}).verified)

    def test_tee_rejects_boolean_only_evidence(self):
        entry = self._tee_entry()
        entry["rootMaterial"] = {
            "endorsementChainVerified": True,
            "revocationCurrent": True,
            "collateralFresh": True,
        }
        entry["rawEvidence"] = {
            "reportAuthenticated": True,
            "fresh": True,
            "measurementAccepted": True,
            "reportDataBound": True,
        }
        decision = self._verify({"evidence-1": entry})
        self.assertFalse(decision.verified)
        self.assertEqual(
            decision.failure_reason, "runtime attestation evidence rejected"
        )

    def test_tee_requires_artifacts_and_report_bindings(self):
        entry = self._tee_entry()
        cases = (
            {
                **entry,
                "rootMaterial": {**entry["rootMaterial"], "collateral": {}},
            },
            {
                **entry,
                "rawEvidence": {
                "holderCommitment": TEST_HOLDER,**entry["rawEvidence"], "report": {}},
            },
            # Tampered report bytes still form a valid carrier, but the
            # provider-asserted bindings below must match the entry exactly.
            {
                **entry,
                "rawEvidence": {
                "holderCommitment": TEST_HOLDER,
                    **entry["rawEvidence"],
                    "attestedManifestDigest": "sha256:" + "ff" * 32,
                },
            },
            {
                **entry,
                "rawEvidence": {
                "holderCommitment": TEST_HOLDER,
                    **entry["rawEvidence"],
                    "verificationContextDigest": "sha256:" + "ff" * 32,
                },
            },
        )
        for malformed in cases:
            with self.subTest(entry=malformed):
                decision = self._verify({"evidence-1": malformed})
                self.assertFalse(decision.verified)
                self.assertEqual(
                    decision.failure_reason,
                    "runtime attestation evidence rejected",
                )

    def test_unknown_root_context_or_evidence_fails_closed(self):
        entry = self._build_entry()
        cases = (
            (
                {"evidence-1": {**entry, "rootClass": "root:publisher-manifest"}},
                "evidence-1",
                RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
            ),
            (
                {"evidence-1": {**entry, "rootClass": "root:unknown"}},
                "evidence-1",
                RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
            ),
            (
                {"evidence-1": entry},
                "missing",
                RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
            ),
            ({"evidence-1": entry}, "evidence-1", "sha256:" + "00" * 32),
        )
        for store, evidence_ref, context in cases:
            with self.subTest(evidence_ref=evidence_ref, context=context):
                decision = self._verify(store, evidence_ref, context)
                self.assertFalse(decision.verified)
                self.assertEqual(
                    decision.failure_reason,
                    "runtime attestation evidence rejected",
                )

    def test_evidence_ref_enforces_utf8_byte_limit(self):
        accepted_ref = "é" * 128
        rejected_ref = "é" * 129
        entry = self._build_entry()
        self.assertTrue(self._verify({accepted_ref: entry}, accepted_ref).verified)
        decision = self._verify({rejected_ref: entry}, rejected_ref)
        self.assertFalse(decision.verified)
        self.assertEqual(
            decision.failure_reason, "runtime attestation evidence rejected"
        )

    def test_root_authority_identifier_enforces_utf8_byte_limit(self):
        entry = self._build_entry()
        accepted = {**entry, "rootAuthorityIdentifier": "é" * 128}
        rejected = {**entry, "rootAuthorityIdentifier": "é" * 129}
        self.assertTrue(self._verify({"evidence-1": accepted}).verified)
        decision = self._verify({"evidence-1": rejected})
        self.assertFalse(decision.verified)
        self.assertEqual(
            decision.failure_reason, "runtime attestation evidence rejected"
        )

    def test_payload_context_must_be_canonical_nonzero_sha256(self):
        entry = self._build_entry()
        invalid_contexts = (
            "sha256:" + "00" * 32,
            "sha256:" + "AA" * 32,
            "sha512:" + "aa" * 32,
            "sha256:1234",
        )
        for context in invalid_contexts:
            with self.subTest(context=context):
                decision = self._verify({"evidence-1": entry}, context=context)
                self.assertFalse(decision.verified)
                self.assertEqual(
                    decision.failure_reason,
                    "runtime attestation evidence rejected",
                )

    def test_adapter_failure_uses_closed_code_and_safe_reason(self):
        adapter = RuntimeAttestationAdapter(
            StaticPreverifiedRuntimeAttestationProviderClient(
                {}, RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
            ),
            session_identity=lambda: "test-session", clock=lambda: TIMESTAMP,
        )
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject(
                {
                    "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                    "holderCommitment": TEST_HOLDER,
                    "evidenceRef": "missing",
                    "verificationContextDigest": (
                        RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
                    ),
                }
            )
        self.assertEqual(ctx.exception.code, "PROVIDER_VERIFICATION_FAILED")
        self.assertEqual(
            ctx.exception.message, "provider verification failed"
        )

    def test_malformed_entries_fail_with_one_safe_reason(self):
        entry = self._build_entry()
        cases = (
            {**entry, "rootMaterial": []},
            {**entry, "rawEvidence": []},
            {**entry, "attestedManifestDigest": None},
            {**entry, "rootAuthorityIdentifier": None},
            {**entry, "verificationPolicyDigest": None},
            {**entry, "validFrom": True},
            {**entry, "validUntil": "tomorrow"},
        )
        for malformed in cases:
            with self.subTest(entry=malformed):
                decision = self._verify({"evidence-1": malformed})
                self.assertFalse(decision.verified)
                self.assertEqual(
                    decision.failure_reason,
                    "runtime attestation evidence rejected",
                )

    def test_constructor_snapshots_nested_evidence(self):
        entry = self._build_entry()
        store = {"evidence-1": entry}
        client = StaticPreverifiedRuntimeAttestationProviderClient(
            store, RUNTIME_ATTESTATION_VERIFICATION_CONTEXT
        )
        entry["rootMaterial"]["checkpoint"].clear()
        entry["rawEvidence"]["statement"]["signedBytesHex"] = "ff"
        decision = client.verify_subject(
            RUNTIME_ATTESTATION_SCHEMA_ID,
            {
                "holderCommitment": TEST_HOLDER,
                "evidenceRef": "evidence-1",
                "verificationContextDigest": RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
            },
            authenticated_session="test-session",
        )
        self.assertTrue(decision.verified)

    def test_reference_factory_instances_do_not_share_evidence(self):
        first = reference_runtime_attestation_adapter()
        second = reference_runtime_attestation_adapter()
        checkpoint = first._provider_client._evidence_store[
            "reference-build-provenance"
        ]["rootMaterial"]["checkpoint"]
        original = dict(checkpoint)
        try:
            checkpoint.clear()
            subject = second.verify_subject(
                {
                    "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                    **second.conformance_subject_payload,
                }
            )
            self.assertEqual(subject["status"], "verified")
        finally:
            checkpoint.update(original)

    def test_tee_uses_configured_verification_context(self):
        context = "sha256:" + "b6" * 32
        entry = self._tee_entry()
        entry["rawEvidence"]["verificationContextDigest"] = context
        client = StaticPreverifiedRuntimeAttestationProviderClient(
            {"tee-1": entry}, context
        )
        decision = client.verify_subject(
            RUNTIME_ATTESTATION_SCHEMA_ID,
            {"holderCommitment": TEST_HOLDER, "evidenceRef": "tee-1", "verificationContextDigest": context},
            authenticated_session="test-session",
        )
        self.assertTrue(decision.verified)

    def test_provider_exception_is_contained_without_raw_text(self):
        class ExplodingEntry(dict):
            def get(self, key, default=None):
                raise RuntimeError("raw-provider-secret")

        client = StaticPreverifiedRuntimeAttestationProviderClient(
            {"evidence-1": self._build_entry()},
            RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
        )
        client._evidence_store["evidence-1"] = ExplodingEntry()
        decision = client.verify_subject(
            RUNTIME_ATTESTATION_SCHEMA_ID,
            {
                "holderCommitment": TEST_HOLDER,
                "evidenceRef": "evidence-1",
                "verificationContextDigest": RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
            },
            authenticated_session="test-session",
        )
        self.assertFalse(decision.verified)
        self.assertEqual(
            decision.failure_reason, "runtime attestation evidence rejected"
        )
        self.assertNotIn("raw-provider-secret", repr(decision))

    def test_hostile_schema_identifier_exception_is_contained(self):
        class ExplodingSchemaId:
            def __ne__(self, other):
                raise RuntimeError("raw-schema-secret")

        client = StaticPreverifiedRuntimeAttestationProviderClient(
            {"evidence-1": self._build_entry()},
            RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
        )
        decision = client.verify_subject(ExplodingSchemaId(), {}, authenticated_session="test-session")
        self.assertFalse(decision.verified)
        self.assertEqual(
            decision.failure_reason, "runtime attestation evidence rejected"
        )
        self.assertNotIn("raw-schema-secret", repr(decision))

    def test_full_flow_signs_normalized_claims_without_raw_evidence(self):
        adapter = reference_runtime_attestation_adapter()
        adapter._provider_client._evidence_store["reference-build-provenance"]["rawEvidence"]["holderCommitment"] = TEST_HOLDER
        self.assertIsInstance(adapter, RuntimeAttestationAdapter)
        provider = IssuerAdapterAccumulatorProvider([adapter])
        client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=provider,
        )
        holder_commitment_hex = field_to_hex(client.get_binding_commitment())
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
                "holderCommitment": holder_commitment_hex,
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
                "holderCommitment": holder_commitment_hex,
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
        credential = Credential.from_dict(envelope["credential"])
        metadata = adapter.issuer_metadata()
        self.assertIn(
            RUNTIME_ATTESTATION_SCHEMA_ID,
            {entry["schemaId"] for entry in metadata["supportedSchemas"]},
        )

        schema = get_schema(RUNTIME_ATTESTATION_SCHEMA_ID)
        digest = schema.compute_digest(
            credential.holder_commitment,
            credential.credential_id,
            schema.normalize_claims(envelope["credential"]["claims"]),
            credential.expires_at,
        )
        public_key = bytes.fromhex(
            metadata["signingKeys"][0]["publicKey"].removeprefix("0x")
        )
        self.assertTrue(
            ecdsa_verify(
                public_key[:32],
                public_key[32:],
                credential.signature,
                digest_to_message_bytes(digest),
            )
        )
        tampered = {
            **envelope["credential"]["claims"],
            "verificationPolicyDigest": "sha256:" + "ff" * 32,
        }
        tampered_digest = schema.compute_digest(
            credential.holder_commitment,
            credential.credential_id,
            schema.normalize_claims(tampered),
            credential.expires_at,
        )
        self.assertFalse(
            ecdsa_verify(
                public_key[:32],
                public_key[32:],
                credential.signature,
                digest_to_message_bytes(tampered_digest),
            )
        )
        witness = credential.witness
        self.assertEqual(
            compute_merkle_root(
                credential.credential_id, witness.path_index, witness.siblings
            ),
            witness.accumulator_root,
        )
        publication = adapter.publish_revocation_handle(
            {"credentialId": envelope["credential"]["credentialId"]}
        )
        self.assertEqual(publication["status"], "active")

        rendered = json.dumps(
            [subject, envelope, metadata, publication], sort_keys=True
        )
        for forbidden in (
            "evidenceRef",
            "providerRef",
            "rawEvidence",
            "checkpoint",
            "statement",
            "report",
            "collateral",
        ):
            self.assertNotIn(forbidden, rendered)
        published = json.dumps([envelope, metadata, publication], sort_keys=True)
        self.assertNotIn("subjectRef", published)


class DefinitionOfDoneTests(unittest.TestCase):
    """Holder gets a credential via the adapter interface, proves ONLY the
    required predicate, and the verifier accepts (and rejects) through the
    standard zkc:proof:v1 envelope."""

    def _stack(self):
        adapter = reference_external_adapter()
        provider = IssuerAdapterAccumulatorProvider([adapter])
        client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=provider,
        )
        metadata = adapter.issuer_metadata()
        public_key = bytes.fromhex(metadata["signingKeys"][0]["publicKey"].removeprefix("0x"))
        context = ProofContext.verifier_session("verifier.example", 1234, TIMESTAMP)
        return adapter, client, metadata, public_key, context

    def _obtain(self, adapter, client):
        holder_commitment_hex = field_to_hex(client.get_binding_commitment())
        subject = adapter.verify_subject(
            {"schemaId": KYC_SCHEMA_ID, "subjectId": "applicant-1"}
        )
        challenge = adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment_hex,
                "schemaId": KYC_SCHEMA_ID,
            }
        )
        response = client.binding_challenge_response(
            adapter.issuer_id, KYC_SCHEMA_ID, challenge["nonce"], challenge["expiresAt"]
        )
        adapter.bind_holder_commitment(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment_hex,
                "schemaId": KYC_SCHEMA_ID,
                "nonce": challenge["nonce"],
                "challengeResponse": response,
            }
        )
        envelope = adapter.issue_credential(
            {"subjectRef": subject["subjectRef"], "schemaId": KYC_SCHEMA_ID}
        )
        credential = Credential.from_dict(envelope["credential"])
        client.store_credential(credential)
        return credential

    def _parameters(self, required_level=1):
        return {
            KYC_PROOF_TYPE: {
                "requiredLevel": required_level,
                "requiredAttributes": [True, False, False, False, False],
            }
        }

    def test_holder_proves_only_the_required_predicate_and_verifier_accepts(self):
        adapter, client, metadata, public_key, context = self._stack()
        self._obtain(adapter, client)

        parameters = self._parameters()
        envelope = generate_unauthenticated_linkable(
            client, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=parameters,
                context=context,
                trust_policy=TrustPolicy(
                    issuers=(
                        TrustedIssuer(
                            issuer_id=adapter.issuer_id,
                            public_key_x=public_key[:32],
                            public_key_y=public_key[32:],
                            proof_types=(KYC_PROOF_TYPE,),
                        ),
                    )
                ),
            )
        )

        # Minimal disclosure: exactly the requested predicate, and the public
        # inputs are the closed circuit set — no claim values leak.
        self.assertEqual([p["proofType"] for p in envelope["proofs"]], [KYC_PROOF_TYPE])
        self.assertEqual(
            sorted(envelope["proofs"][0]["publicInputs"]),
            sorted(
                [
                    "holder_commitment",
                    "claim_binding",
                    "proof_context",
                    "accumulator_root",
                    "accumulator_epoch",
                    "timestamp",
                    "current_epoch",
                    "issuer_public_key_x",
                    "issuer_public_key_y",
                ]
            ),
        )
        rendered = str(envelope)
        self.assertNotIn("verifiedAttributes", rendered)
        self.assertNotIn("level", rendered)

        verifier = ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                issuers=(
                    VerifierTrustedIssuer(
                        issuer_id=adapter.issuer_id,
                        public_key_x=public_key[:32],
                        public_key_y=public_key[32:],
                        proof_types=(KYC_PROOF_TYPE,),
                    ),
                )
            ),
            StubVerifyBackend(),
        )
        request = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=parameters,
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

        # Rejection path: the same envelope does not satisfy a verifier that
        # required a stronger predicate (claim binding attests level 1).
        stricter = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=self._parameters(required_level=2),
            context=context,
            accumulator_states=request.accumulator_states,
        )
        rejected = verifier.verify(envelope, stricter)
        self.assertFalse(rejected.valid)
        self.assertIn(VerificationErrorCode.REQUIREMENTS_NOT_MET, rejected.codes())


if __name__ == "__main__":
    unittest.main()
