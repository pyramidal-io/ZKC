"""Discovery registry tests (issuer lookup, verifier policy publication).

Acceptance: the registry provides discovery only; trust decisions remain
verifier-local; policies can include issuers outside the well-known registry;
no code path blesses a default issuer or credential type.
"""

import json
import pathlib
import shutil
import tempfile
import unittest

import _path  # noqa: F401  (sys.path side effect)
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import (
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_kyc_credential,
)
from predicate_fixtures import issue_jurisdiction_credential

from zkc_crypto import (
    CANONICAL_SET_INCLUSION,
    JURISDICTION_CANONICAL_SET_PARAM,
    CanonicalCodeSet,
    ProofContext,
)
from zkc_crypto.presentation import ANONYMOUS_PROFILE
from zkc_issuer import SandboxIssuerAdapter
from zkc_holder import (
    HolderClient,
    JURISDICTION_PROOF_TYPE,
    JURISDICTION_V4_PROOF_TYPE,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
)
from zkc_holder.client import _Presentation
from zkc_registry import (
    DiscoveryRegistry,
    DuplicateRegistryIdError,
    RegistryValidationError,
    to_holder_trust_policy,
    to_verifier_trust_policy,
)
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationErrorCode,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY_ISSUER_ID = "zkc:issuer:zkc-test-issuer"
EXAMPLE_VERIFIER_ID = "did:zkc:verifier:example-exchange"
OUT_OF_REGISTRY_ISSUER_ID = "did:zkc:out-of-registry-issuer"
MASTER_SEED = 0x5EED


def repo_discovery() -> DiscoveryRegistry:
    return DiscoveryRegistry.from_repo(REPO_ROOT)


def temp_registry_copy() -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = pathlib.Path(tmp.name)
    shutil.copytree(REPO_ROOT / "registry", root / "registry")
    return tmp


class LookupTests(unittest.TestCase):
    def test_lookup_by_proof_type_returns_all_matches(self):
        issuers = repo_discovery().lookup_issuers(proof_type=KYC_PROOF_TYPE)
        ids = [issuer.issuer_id for issuer in issuers]
        self.assertIn("zkc:issuer:sandbox", ids)
        self.assertIn(REGISTRY_ISSUER_ID, ids)
        self.assertEqual(ids, sorted(ids))  # deterministic, no ranking

    def test_lookup_by_schema_and_credential_type(self):
        registry = repo_discovery()
        by_schema = registry.lookup_issuers(schema_id="zkc:cred:kyc:v1")
        self.assertTrue(by_schema)
        by_credential = registry.lookup_issuers(credential_type="zkc:cred:kyc:v1")
        self.assertEqual(
            {issuer.issuer_id for issuer in by_schema},
            {issuer.issuer_id for issuer in by_credential},
        )

    def test_unknown_filters_return_empty_not_error(self):
        registry = repo_discovery()
        self.assertEqual(registry.lookup_issuers(proof_type="zkc:proof:nope:v1"), ())
        self.assertEqual(registry.lookup_issuers(schema_id="zkc:cred:nope:v9"), ())
        self.assertIsNone(registry.issuer("zkc:issuer:does-not-exist"))

    def test_duplicate_issuer_id_fails_closed(self):
        with temp_registry_copy() as tmp:
            root = pathlib.Path(tmp)
            source = root / "registry" / "issuers" / "sandbox.json"
            shutil.copy(source, root / "registry" / "issuers" / "zz-shadow.json")
            with self.assertRaises(DuplicateRegistryIdError):
                DiscoveryRegistry.from_repo(root)

    def test_malformed_issuer_document_fails_closed(self):
        with temp_registry_copy() as tmp:
            root = pathlib.Path(tmp)
            path = root / "registry" / "issuers" / "sandbox.json"
            document = json.loads(path.read_text())
            del document["signingKeys"]
            path.write_text(json.dumps(document))
            with self.assertRaises(RegistryValidationError):
                DiscoveryRegistry.from_repo(root)

    def test_exclusivity_keys_in_discovery_documents_are_rejected(self):
        with temp_registry_copy() as tmp:
            root = pathlib.Path(tmp)
            path = root / "registry" / "issuers" / "sandbox.json"
            document = json.loads(path.read_text())
            document["canonical"] = True
            path.write_text(json.dumps(document))
            with self.assertRaises(RegistryValidationError):
                DiscoveryRegistry.from_repo(root)

    def test_registry_loads_from_a_local_copy_without_repo_context(self):
        # Advisory cache: a bare copy of registry/ is fully usable offline.
        with temp_registry_copy() as tmp:
            registry = DiscoveryRegistry.from_repo(pathlib.Path(tmp))
            self.assertTrue(registry.lookup_issuers(proof_type=KYC_PROOF_TYPE))

    def test_registry_discovery_accepts_authenticated_metadata_v2(self):
        with temp_registry_copy() as tmp:
            root = pathlib.Path(tmp)
            path = root / "registry" / "issuers" / "sandbox.json"
            path.write_text(json.dumps(SandboxIssuerAdapter().issuer_metadata()))
            registry = DiscoveryRegistry.from_repo(root)
            issuer = registry.issuer("zkc:issuer:sandbox")
            self.assertEqual(issuer.raw["version"], "zkc:issuer-metadata:v2")
            self.assertIn("currentAnnouncement", issuer.raw["revocation"])

    def test_registry_rejects_metadata_version_masquerading(self):
        with temp_registry_copy() as tmp:
            root = pathlib.Path(tmp)
            path = root / "registry" / "issuers" / "sandbox.json"
            document = SandboxIssuerAdapter().issuer_metadata()
            del document["revocation"]["currentAnnouncement"]
            path.write_text(json.dumps(document))
            with self.assertRaises(RegistryValidationError):
                DiscoveryRegistry.from_repo(root)

        with temp_registry_copy() as tmp:
            root = pathlib.Path(tmp)
            path = root / "registry" / "issuers" / "sandbox.json"
            document = json.loads(path.read_text())
            document["revocation"]["currentAnnouncement"] = {}
            path.write_text(json.dumps(document))
            with self.assertRaises(RegistryValidationError):
                DiscoveryRegistry.from_repo(root)

    def test_missing_discovery_dirs_mean_empty_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = DiscoveryRegistry.from_repo(pathlib.Path(tmp))
            self.assertEqual(registry.issuers(), ())
            self.assertEqual(registry.verifier_policies(), ())


class FindAcceptingVerifiersTests(unittest.TestCase):
    def test_holder_finds_verifiers_for_its_credential(self):
        credential = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=7, issuer_id=REGISTRY_ISSUER_ID
        )
        matches = repo_discovery().find_accepting_verifiers(
            KYC_PROOF_TYPE, credential=credential
        )
        self.assertEqual([policy.verifier_id for policy in matches], [EXAMPLE_VERIFIER_ID])

    def test_lookup_by_issuer_key(self):
        matches = repo_discovery().find_accepting_verifiers(
            KYC_PROOF_TYPE, issuer_public_key=(TEST_ISSUER_KEY_X, TEST_ISSUER_KEY_Y)
        )
        self.assertEqual([policy.verifier_id for policy in matches], [EXAMPLE_VERIFIER_ID])

    def test_policies_can_trust_out_of_registry_issuers(self):
        registry = repo_discovery()
        self.assertIsNone(registry.issuer(OUT_OF_REGISTRY_ISSUER_ID))
        matches = registry.find_accepting_verifiers(
            KYC_PROOF_TYPE, issuer_id=OUT_OF_REGISTRY_ISSUER_ID
        )
        self.assertEqual([policy.verifier_id for policy in matches], [EXAMPLE_VERIFIER_ID])

    def test_unknown_issuer_finds_no_verifier(self):
        matches = repo_discovery().find_accepting_verifiers(
            KYC_PROOF_TYPE, issuer_id="did:zkc:nobody-trusts-me"
        )
        self.assertEqual(matches, ())

    def test_unaccepted_proof_type_finds_no_verifier(self):
        matches = repo_discovery().find_accepting_verifiers("zkc:proof:tax:v1")
        self.assertEqual(matches, ())


class PolicyPublicationTests(unittest.TestCase):
    """A holder plans against a published policy; the verifier loads the same
    document as its own runtime policy. Trust stays verifier-local."""

    def _roundtrip_envelope(self, provider):
        registry = repo_discovery()
        published = registry.verifier_policy(EXAMPLE_VERIFIER_ID)
        client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=provider,
        )
        client.store_credential(
            issue_kyc_credential(
                master_seed=MASTER_SEED,
                credential_id=42,
                issuer_id=REGISTRY_ISSUER_ID,
                provider=provider,
            )
        )
        request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 2,
                    "requiredAttributes": [True, False, False, False, False],
                }
            },
            context=ProofContext.verifier_session(EXAMPLE_VERIFIER_ID, 0xABCDEF, 1_700_000),
            # Holder planning: trust policy comes from the PUBLISHED document.
            trust_policy=to_holder_trust_policy(published),
        )
        return generate_unauthenticated_linkable(client, request), published

    def _verification_request(self, provider):
        return VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 2,
                    "requiredAttributes": [True, False, False, False, False],
                }
            },
            context=ProofContext.verifier_session(EXAMPLE_VERIFIER_ID, 0xABCDEF, 1_700_000),
            accumulator_states={
                REGISTRY_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=provider.current_epoch(REGISTRY_ISSUER_ID),
                    roots=provider.roots(REGISTRY_ISSUER_ID),
                )
            },
        )

    def test_published_policy_roundtrip(self):
        provider = LocalAccumulatorProvider()
        envelope, published = self._roundtrip_envelope(provider)
        verifier = ZKCVerifier(
            REPO_ROOT, to_verifier_trust_policy(published), StubVerifyBackend()
        )
        result = verifier.verify(envelope, self._verification_request(provider))
        self.assertTrue(result.valid, result.to_dict())

    def test_published_policy_roundtrips_safe_anonymous_jurisdiction(self):
        provider = LocalAccumulatorProvider()
        published = repo_discovery().verifier_policy(EXAMPLE_VERIFIER_ID)
        client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=provider,
        )
        credential = issue_jurisdiction_credential(
            master_seed=MASTER_SEED,
            credential_id=43,
            jurisdiction_code=840,
            claim_type=1,
            provider=provider,
            issuer_id=REGISTRY_ISSUER_ID,
        )
        client.store_credential(credential)
        codes = [840]
        canonical = CanonicalCodeSet.for_jurisdiction(
            codes, claim_type=1, mode=CANONICAL_SET_INCLUSION
        )
        parameters = {
            "membershipType": 0,
            "requiredClaimType": 1,
            JURISDICTION_CANONICAL_SET_PARAM: codes,
            "jurisdictionSetRoot": canonical.root(),
        }
        context = ProofContext.verifier_session(EXAMPLE_VERIFIER_ID, 0xABCDF0, 1_700_000)
        request = ProofRequest(
            proof_types=[JURISDICTION_PROOF_TYPE],
            parameters={JURISDICTION_PROOF_TYPE: parameters},
            context=context,
            trust_policy=to_holder_trust_policy(published),
        )
        envelope = client._generate_envelope(
            request, _Presentation(ANONYMOUS_PROFILE)
        )
        self.assertEqual(envelope["proofs"][0]["proofType"], JURISDICTION_V4_PROOF_TYPE)

        verifier = ZKCVerifier(
            REPO_ROOT, to_verifier_trust_policy(published), StubVerifyBackend()
        )
        result = verifier.verify(
            envelope,
            VerificationRequest(
                proof_types=[JURISDICTION_V4_PROOF_TYPE],
                parameters={JURISDICTION_V4_PROOF_TYPE: parameters},
                context=context,
                accumulator_states={
                    REGISTRY_ISSUER_ID: IssuerAccumulatorState(
                        current_epoch=provider.current_epoch(REGISTRY_ISSUER_ID),
                        roots=provider.roots(REGISTRY_ISSUER_ID),
                    )
                },
            ),
        )
        self.assertTrue(result.valid, result.to_dict())

    def test_published_policy_carries_review_status_requirement(self):
        published = repo_discovery().verifier_policy(EXAMPLE_VERIFIER_ID)
        policy = to_verifier_trust_policy(published)
        # The example policy accepts self-attested entries as well, because
        # that is what this registry actually contains (see the policy's own
        # description + docs/zkc_predicate_registry_governance.md §2).
        self.assertEqual(
            policy.accepted_review_statuses, ("reviewed", "self_attested")
        )
        self.assertEqual(policy.max_epoch_lag, 10)

    def test_registry_membership_is_never_sufficient_for_trust(self):
        # The issuer is in registry/issuers/, but THIS verifier's policy is
        # empty — the proof must be rejected. Discovery is not trust.
        provider = LocalAccumulatorProvider()
        envelope, _ = self._roundtrip_envelope(provider)
        verifier = ZKCVerifier(REPO_ROOT, VerifierTrustPolicy(issuers=()), StubVerifyBackend())
        result = verifier.verify(envelope, self._verification_request(provider))
        self.assertFalse(result.valid)
        self.assertIn(VerificationErrorCode.UNTRUSTED_ISSUER, result.codes())

    def test_holder_credential_from_unpublished_issuer_fails_planning(self):
        # Holder-side: planning against the published policy refuses
        # credentials from issuers the verifier does not trust.
        from zkc_holder import UnknownIssuerError

        provider = LocalAccumulatorProvider()
        registry = repo_discovery()
        published = registry.verifier_policy(EXAMPLE_VERIFIER_ID)
        client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=provider,
        )
        client.store_credential(
            issue_kyc_credential(
                master_seed=MASTER_SEED,
                credential_id=43,
                issuer_id=TEST_ISSUER_ID,  # did:zkc:test-issuer — not in the policy
                provider=provider,
            )
        )
        request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 2,
                    "requiredAttributes": [True, False, False, False, False],
                }
            },
            context=ProofContext.verifier_session(EXAMPLE_VERIFIER_ID, 0xABCDEF, 1_700_000),
            trust_policy=to_holder_trust_policy(published),
        )
        with self.assertRaises(UnknownIssuerError):
            generate_unauthenticated_linkable(client, request)


class NoDefaultIssuerTests(unittest.TestCase):
    def test_no_api_builds_trust_from_membership(self):
        # The only trust-policy constructors require an explicit PUBLISHED
        # policy document; an issuer document is never accepted.
        issuer = repo_discovery().issuer(REGISTRY_ISSUER_ID)
        with self.assertRaises(AttributeError):
            to_verifier_trust_policy(issuer)
        with self.assertRaises(AttributeError):
            to_holder_trust_policy(issuer)

    def test_registry_code_has_no_default_issuer_material(self):
        import re

        blob = "\n".join(
            path.read_text()
            for path in sorted((REPO_ROOT / "python" / "zkc_registry").glob("*.py"))
        )
        self.assertIsNone(re.search(r"0x[0-9a-fA-F]{64}", blob))
        self.assertNotIn("default_issuer", blob)

    def test_verifier_policy_schema_defines_no_exclusivity_fields(self):
        schema = json.loads(
            (REPO_ROOT / "registry" / "schema" / "verifier-policy.schema.json").read_text()
        )

        def keys_of(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "properties" and isinstance(value, dict):
                        yield from value.keys()
                    yield from keys_of(value)
            elif isinstance(node, list):
                for item in node:
                    yield from keys_of(item)

        forbidden = {"canonical", "default", "official", "mandatory", "blessed"}
        self.assertFalse({key.lower() for key in keys_of(schema)} & forbidden)

    def test_empty_published_allowlist_trusts_nobody(self):
        document = {
            "version": "zkc:registry:verifier-policy:v1",
            "verifierId": "did:zkc:verifier:closed",
            "displayName": "Closed verifier",
            "acceptedProofTypes": [KYC_PROOF_TYPE],
            "requiredReviewStatuses": [],
            "trustedIssuers": [],
            "acceptsOutOfRegistryIssuers": False,
            "requiredContextProfile": "",
            "maxEpochLag": 10,
            "updatedAt": "2026-06-11T00:00:00Z",
        }
        from zkc_registry.store import _policy_from_document, validate_verifier_policy

        validate_verifier_policy(document, "inline")
        policy = to_verifier_trust_policy(_policy_from_document(document, "inline"))
        self.assertEqual(policy.issuers, ())


if __name__ == "__main__":
    unittest.main()
