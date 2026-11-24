"""Holder-authorized audit disclosure tests (zkc:audit-bundle:v1).

Covers: scoped export, schema-level forbidden-content rejection, hash-chain
tamper detection, validity-window enforcement (expired / not-yet-valid),
auditor binding, authorization signature, auditor re-verification via
zkc_verifier, and the agent-API principal-authorization integration.
"""

import copy
import json
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
from zkc_agent import ApprovalNotFoundError, ZKCAgentClient
from zkc_crypto import ProofContext, derive_credential_binding_key, field_to_hex
from zkc_holder import (
    AuditBundleError,
    AuditExporter,
    ForbiddenMaterialError,
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    reverify_bundle_proofs,
    scan_forbidden_material,
    verify_audit_bundle,
)
from zkc_holder.audit_export import derive_authorization_key
from zkc_registry import to_verifier_trust_policy
from zkc_registry.store import _policy_from_document, validate_verifier_policy
from zkc_verifier import StubVerifyBackend, ZKCVerifier

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
MASTER_SEED = 42
AUDITOR_KEY_ID = "did:zkc:auditor:acme-audit#key-1"
KYC_PARAMETERS = {
    KYC_PROOF_TYPE: {
        "requiredLevel": 1,
        "requiredAttributes": [True, False, False, False, False],
    }
}
NOW = 1_700_000_000


def policy_snapshot():
    document = {
        "version": "zkc:registry:verifier-policy:v1",
        "verifierId": "did:zkc:verifier:audited-exchange",
        "displayName": "Audited Exchange",
        "acceptedProofTypes": [KYC_PROOF_TYPE],
        # Mirrors the shipped example policy: this registry's entries are
        # self-attested, so a ["reviewed"]-only policy would reject them all.
        "requiredReviewStatuses": ["reviewed", "self_attested"],
        "trustedIssuers": [
            {
                "issuerId": TEST_ISSUER_ID,
                "publicKeyX": "0x" + TEST_ISSUER_KEY_X.hex(),
                "publicKeyY": "0x" + TEST_ISSUER_KEY_Y.hex(),
                "proofTypes": [KYC_PROOF_TYPE],
            }
        ],
        "acceptsOutOfRegistryIssuers": True,
        "requiredContextProfile": "",
        "maxEpochLag": 10,
        "updatedAt": "2026-06-11T00:00:00Z",
    }
    validate_verifier_policy(document, "<snapshot>")
    return document


def auditor_verifier_factory(snapshot):
    policy_document = _policy_from_document(snapshot, "<bundle>")
    return ZKCVerifier(
        REPO_ROOT, to_verifier_trust_policy(policy_document), StubVerifyBackend()
    )


class AuditBundleTestBase(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.holder = HolderClient.from_seed(
            MASTER_SEED, REGISTRY, StubBackend(), accumulator_provider=self.provider
        )
        self.credential = issue_kyc_credential(
            master_seed=MASTER_SEED,
            credential_id=7,
            provider=self.provider,
            expires_at=2_000_000_000,
        )
        self.holder.store_credential(self.credential)
        self.context = ProofContext.verifier_session(
            "did:zkc:verifier:audited-exchange", 555, NOW
        )
        self.envelope = generate_unauthenticated_linkable(
            self.holder, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=copy.deepcopy(KYC_PARAMETERS),
                context=self.context,
                trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
            )
        )
        self.proof_record = {
            "envelope": self.envelope,
            "verification": {
                "proofTypes": [KYC_PROOF_TYPE],
                "parameters": copy.deepcopy(KYC_PARAMETERS),
                "context": self.context.to_metadata(),
                "accumulatorStates": {
                    TEST_ISSUER_ID: {
                        "currentEpoch": self.provider.current_epoch(TEST_ISSUER_ID),
                        "roots": {
                            str(epoch): field_to_hex(root)
                            for epoch, root in self.provider.roots(TEST_ISSUER_ID).items()
                        },
                    }
                },
                "policySnapshot": policy_snapshot(),
                "registryRefs": [
                    {
                        "predicateId": REGISTRY.resolve(KYC_PROOF_TYPE).predicate_id,
                        "entryVersion": REGISTRY.resolve(KYC_PROOF_TYPE).entry_version,
                    }
                ],
            },
        }
        self.exporter = AuditExporter(MASTER_SEED)

    def holder_key(self, auditor_key_id=AUDITOR_KEY_ID):
        """The key the holder hands this auditor out of band."""
        return self.exporter.authorization_public_key(auditor_key_id)

    def export(self, **overrides):
        defaults = dict(
            auditor_key_id=AUDITOR_KEY_ID,
            valid_from=NOW - 100,
            valid_until=NOW + 86_400,
            purpose="annual compliance audit FY2026",
        )
        defaults.update(overrides)
        return self.exporter.export([self.proof_record], **defaults)


class ScopedExportTests(AuditBundleTestBase):
    def test_scoped_export_validates(self):
        bundle = self.export()
        self.assertEqual(bundle["version"], "zkc:audit-bundle:v1")
        self.assertEqual(len(bundle["members"]), 1)
        result = verify_audit_bundle(
            bundle,
            now=NOW,
            expected_holder_key=self.holder_key(),
            expected_auditor_key_id=AUDITOR_KEY_ID,
        )
        self.assertTrue(result.valid, result.errors)
        # Content-addressed: the bundle hash is the chain head.
        self.assertEqual(bundle["bundleHash"], bundle["members"][-1]["chainHash"])
        # JSON round-trip stable.
        round_tripped = json.loads(json.dumps(bundle))
        self.assertTrue(
            verify_audit_bundle(
                round_tripped, now=NOW, expected_holder_key=self.holder_key()
            ).valid
        )

    def test_export_requires_scope_fields(self):
        with self.assertRaises(AuditBundleError):
            self.export(auditor_key_id="")
        with self.assertRaises(AuditBundleError):
            self.export(valid_from=NOW, valid_until=NOW - 1)
        with self.assertRaises(AuditBundleError):
            self.export(purpose="")
        with self.assertRaises(AuditBundleError):
            self.exporter.export(
                [],
                auditor_key_id=AUDITOR_KEY_ID,
                valid_from=NOW,
                valid_until=NOW + 1,
                purpose="x",
            )

    def test_authorization_key_is_dedicated(self):
        # Deterministic per auditor, and distinct from the credential binding key.
        key = derive_authorization_key(MASTER_SEED, AUDITOR_KEY_ID)
        self.assertEqual(key, derive_authorization_key(MASTER_SEED, AUDITOR_KEY_ID))
        self.assertNotEqual(key, derive_credential_binding_key(MASTER_SEED))


class ForbiddenContentTests(AuditBundleTestBase):
    def test_export_rejects_credential_material(self):
        for forbidden_key, value in (
            ("claims", {"level": 2}),
            ("witness", {"pathIndex": 0}),
            ("seed", 42),
            ("credential", {"anything": 1}),
        ):
            record = copy.deepcopy(self.proof_record)
            record["verification"][forbidden_key] = value
            with self.assertRaises(ForbiddenMaterialError, msg=forbidden_key):
                self.exporter.export(
                    [record],
                    auditor_key_id=AUDITOR_KEY_ID,
                    valid_from=NOW,
                    valid_until=NOW + 10,
                    purpose="x",
                )

    def test_export_rejects_payment_history(self):
        record = copy.deepcopy(self.proof_record)
        record["verification"]["transactionHistory"] = [{"amount": 5}]
        with self.assertRaises(ForbiddenMaterialError):
            self.exporter.export(
                [record],
                auditor_key_id=AUDITOR_KEY_ID,
                valid_from=NOW,
                valid_until=NOW + 10,
                purpose="x",
            )

    def test_auditor_rejects_smuggled_content(self):
        # A bundle assembled outside the exporter with forbidden material
        # must be refused by the auditor-side check.
        bundle = self.export()
        bundle["members"][0]["content"]["verification"]["claims"] = {"level": 2}
        result = verify_audit_bundle(bundle, now=NOW)
        self.assertIn("FORBIDDEN_CONTENT", result.codes())

    def test_scan_is_recursive(self):
        with self.assertRaises(ForbiddenMaterialError):
            scan_forbidden_material({"a": [{"b": {"masterSeed": 1}}]})


class TamperDetectionTests(AuditBundleTestBase):
    def test_member_content_tamper_detected(self):
        bundle = self.export()
        bundle["members"][0]["content"]["verification"]["parameters"][KYC_PROOF_TYPE][
            "requiredLevel"
        ] = 3
        result = verify_audit_bundle(bundle, now=NOW)
        self.assertIn("TAMPERED", result.codes())

    def test_bundle_hash_tamper_detected(self):
        bundle = self.export()
        bundle["bundleHash"] = "0x" + "ab" * 32
        result = verify_audit_bundle(bundle, now=NOW)
        self.assertIn("TAMPERED", result.codes())

    def test_authorization_tamper_invalidates_signature(self):
        bundle = self.export()
        bundle["authorization"]["purpose"] = "totally different purpose"
        result = verify_audit_bundle(bundle, now=NOW)
        self.assertIn("BAD_AUTHORIZATION_SIGNATURE", result.codes())

    def test_proof_refs_mismatch_detected(self):
        bundle = self.export()
        bundle["authorization"]["proofRefs"] = []
        result = verify_audit_bundle(bundle, now=NOW)
        self.assertIn("PROOF_REFS_MISMATCH", result.codes())


class AuthorizationWindowTests(AuditBundleTestBase):
    def test_expired_authorization_rejected(self):
        bundle = self.export(valid_until=NOW + 100)
        result = verify_audit_bundle(bundle, now=NOW + 101)
        self.assertIn("AUTHORIZATION_EXPIRED", result.codes())

    def test_not_yet_valid_rejected(self):
        bundle = self.export(valid_from=NOW + 50, valid_until=NOW + 100)
        result = verify_audit_bundle(bundle, now=NOW)
        self.assertIn("AUTHORIZATION_NOT_YET_VALID", result.codes())

    def test_auditor_mismatch_rejected(self):
        bundle = self.export()
        result = verify_audit_bundle(
            bundle, now=NOW, expected_auditor_key_id="did:zkc:auditor:someone-else"
        )
        self.assertIn("AUDITOR_MISMATCH", result.codes())


class ReverificationTests(AuditBundleTestBase):
    def issuer_roots(self):
        """The auditor's own authenticated view of the issuer's roots."""
        return {TEST_ISSUER_ID: self.provider.roots(TEST_ISSUER_ID)}

    def test_auditor_reverifies_contained_proofs(self):
        bundle = self.export()
        result = reverify_bundle_proofs(bundle, auditor_verifier_factory, self.issuer_roots())
        self.assertTrue(result.valid, result.errors)

    def test_reverification_fails_on_mismatched_parameters(self):
        bundle = self.export()
        # Claimed verification parameters that the proof does not attest.
        bundle["members"][0]["content"]["verification"]["parameters"][KYC_PROOF_TYPE][
            "requiredLevel"
        ] = 3
        result = reverify_bundle_proofs(bundle, auditor_verifier_factory, self.issuer_roots())
        self.assertFalse(result.valid)
        self.assertEqual(result.codes(), ["REVERIFICATION_FAILED"])


class AgentIntegrationTests(AuditBundleTestBase):
    def test_audit_export_requires_principal_authorization(self):
        notifications = []
        agent = ZKCAgentClient(
            self.holder,
            REGISTRY,
            principal_notifier=lambda event, payload: notifications.append((event, payload)),
        )
        export_id = agent.request_audit_export(
            self.exporter,
            [self.proof_record],
            auditor_key_id=AUDITOR_KEY_ID,
            valid_from=NOW - 100,
            valid_until=NOW + 86_400,
            purpose="annual compliance audit FY2026",
        )
        # The principal is notified; nothing is released yet.
        self.assertEqual(notifications[0][0], "audit_export_requested")
        bundle = agent.approve_audit_export(export_id)
        self.assertTrue(
            verify_audit_bundle(bundle, now=NOW, expected_holder_key=self.holder_key()).valid
        )
        with self.assertRaises(ApprovalNotFoundError):
            agent.approve_audit_export(export_id)
        events = [event["event"] for event in agent.audit_log.events]
        self.assertIn("audit_export_requested", events)
        self.assertIn("audit_export_released", events)
        # The audit log records scope, never bundle content.
        released = [
            event
            for event in agent.audit_log.events
            if event["event"] == "audit_export_released"
        ][0]
        self.assertNotIn("members", released)
        self.assertEqual(released["bundle_hash"], bundle["bundleHash"])

    def test_denied_export_releases_nothing(self):
        agent = ZKCAgentClient(self.holder, REGISTRY)
        export_id = agent.request_audit_export(
            self.exporter,
            [self.proof_record],
            auditor_key_id=AUDITOR_KEY_ID,
            valid_from=NOW,
            valid_until=NOW + 10,
            purpose="x",
        )
        agent.deny_audit_export(export_id)
        with self.assertRaises(ApprovalNotFoundError):
            agent.approve_audit_export(export_id)


if __name__ == "__main__":
    unittest.main()
