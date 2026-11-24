"""Registry governance and discovery safeguards (capstone tests).

Proves the registry is an ADVISORY CACHE, never a policy chokepoint:

* predicate pluralism — multiple entries per predicate type from different
  authors coexist, and lookups return all of them, never a blessed one;
* chokepoint resistance — everything works from a LOCAL copy with no network
  dependency, and registry ABSENCE is never a verification failure when the
  verifier's local policy pins predicates directly;
* the conformance suite fails an implementation that treats registry
  membership as trust (seeded negative).
"""

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

import _path  # noqa: F401  (sys.path side effect)
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import KYC_PROOF_TYPE, issue_kyc_credential, trusted_test_issuer

from zkc_crypto import ProofContext
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MASTER_SEED = 0x5EED


def copy_tree(*, include_registry: bool) -> tempfile.TemporaryDirectory:
    """A LOCAL copy of the surfaces the SDKs need — optionally with no
    registry/ directory at all.

    Request-binding sidecars are verifier contracts, not registry trust data,
    so a registry-free verifier still carries its local sidecar snapshot.
    """
    tmp = tempfile.TemporaryDirectory()
    root = pathlib.Path(tmp.name)
    shutil.copytree(REPO_ROOT / "schemas" / "public-inputs", root / "schemas" / "public-inputs")
    shutil.copytree(
        REPO_ROOT / "schemas" / "public-input-bindings",
        root / "schemas" / "public-input-bindings",
    )
    for circuit_dir in (REPO_ROOT / "noir").iterdir():
        src = circuit_dir / "src"
        if src.is_dir():
            shutil.copytree(src, root / "noir" / circuit_dir.name / "src")
    if include_registry:
        shutil.copytree(REPO_ROOT / "registry", root / "registry")
    return tmp


def roundtrip(tree_root) -> tuple:
    """Generate and verify a real envelope entirely inside `tree_root`."""
    provider = LocalAccumulatorProvider()
    client = HolderClient.from_seed(
        MASTER_SEED,
        PredicateRegistry.from_repo(tree_root),
        StubBackend(),
        accumulator_provider=provider,
    )
    client.store_credential(
        issue_kyc_credential(master_seed=MASTER_SEED, credential_id=42, provider=provider)
    )
    issuer = trusted_test_issuer()
    parameters = {
        KYC_PROOF_TYPE: {
            "requiredLevel": 2,
            "requiredAttributes": [True, False, False, False, False],
        }
    }
    context = ProofContext.verifier_session("did:zkc:verifier", 0xABCDEF, 1_700_000)
    envelope = generate_unauthenticated_linkable(
        client, ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=parameters,
            context=context,
            trust_policy=TrustPolicy(issuers=(issuer,)),
        )
    )
    # The verifier's LOCAL policy pins the issuer key and accepts the proof
    # type directly — it does not need any registry to exist.
    verifier = ZKCVerifier(
        tree_root,
        VerifierTrustPolicy(
            issuers=(
                VerifierTrustedIssuer(
                    issuer_id=issuer.issuer_id,
                    public_key_x=issuer.public_key_x,
                    public_key_y=issuer.public_key_y,
                    proof_types=(KYC_PROOF_TYPE,),
                ),
            )
        ),
        StubVerifyBackend(),
    )
    result = verifier.verify(
        envelope,
        VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=parameters,
            context=context,
            accumulator_states={
                issuer.issuer_id: IssuerAccumulatorState(
                    current_epoch=provider.current_epoch(issuer.issuer_id),
                    roots=provider.roots(issuer.issuer_id),
                )
            },
        ),
    )
    return envelope, result


class PluralismTests(unittest.TestCase):
    def test_multiple_listings_coexist_for_one_proof_type(self):
        # Pluralism is about the MECHANISM: independent lineages can serve one
        # proof type and neither is blessed. Both listings shipped here are
        # authored by the same party (`community-kyc` is a seed, not a
        # third-party listing), so this asserts coexistence — not independent
        # authorship, which the registry does not currently have.
        registry = PredicateRegistry.from_repo(REPO_ROOT)
        entries = registry.resolve_all(KYC_PROOF_TYPE)
        self.assertEqual(
            [entry.predicate_id for entry in entries], ["community-kyc", "zkc-kyc"]
        )
        self.assertTrue(all(entry.usable_by_default for entry in entries))
        # Nothing here has been independently reviewed.
        self.assertFalse(any(entry.reviewed for entry in entries))
        self.assertTrue(all(entry.self_attested for entry in entries))

    def test_lookups_return_all_matches_never_a_blessed_one(self):
        registry = PredicateRegistry.from_repo(REPO_ROOT)
        entries = registry.resolve_all(KYC_PROOF_TYPE)
        # No entry carries any primacy marker; order is a documented
        # deterministic sort, not a ranking field.
        for entry in entries:
            raw = json.loads(
                (
                    REPO_ROOT
                    / "registry"
                    / "predicates"
                    / entry.predicate_id
                    / entry.entry_version
                    / "entry.json"
                ).read_text()
            )
            for forbidden in ("canonical", "default", "preferred", "rank", "priority"):
                self.assertNotIn(forbidden, json.dumps(raw).lower().split('"'))

    def test_holder_can_select_either_author_explicitly(self):
        registry = PredicateRegistry.from_repo(REPO_ROOT)
        for predicate_id in ("community-kyc", "zkc-kyc"):
            entry = registry.resolve(KYC_PROOF_TYPE, preferred_predicate_id=predicate_id)
            self.assertEqual(entry.predicate_id, predicate_id)


class ChokepointResistanceTests(unittest.TestCase):
    def test_full_roundtrip_from_a_local_copy(self):
        # The registry is an advisory cache: a plain filesystem copy is fully
        # functional with no network and no repo context.
        with copy_tree(include_registry=True) as tmp:
            _, result = roundtrip(pathlib.Path(tmp))
            self.assertTrue(result.valid, result.to_dict())

    def test_registry_absence_is_not_a_verification_failure(self):
        # The verifier's local policy pins the predicate (via the committed
        # encoder + circuit hashes) and the issuer key directly; with NO
        # registry/ directory anywhere, verification still succeeds.
        with copy_tree(include_registry=False) as tmp:
            root = pathlib.Path(tmp)
            self.assertFalse((root / "registry").exists())
            _, result = roundtrip(root)
            self.assertTrue(result.valid, result.to_dict())

    def test_no_network_dependency_in_registry_code(self):
        # Static: registry loading/validation must not import any network
        # machinery — lookups are local-file reads, period.
        sources = [
            REPO_ROOT / "registry" / "validate.py",
            REPO_ROOT / "python" / "zkc_holder" / "registry.py",
            *sorted((REPO_ROOT / "python" / "zkc_registry").glob("*.py")),
        ]
        for source in sources:
            text = source.read_text()
            for module in ("socket", "urllib", "http.client", "requests", "ssl"):
                self.assertNotRegex(
                    text,
                    rf"^\s*(import {module}\b|from {module}\b)",
                    f"{source} must not import {module}",
                )

    def test_envelope_generated_with_registry_verifies_without_it(self):
        # Cross-tree: holder uses the governed registry; verifier runs in a
        # tree with no registry at all. Registry absence on the verifier side
        # must not invalidate the proof.
        with copy_tree(include_registry=True) as holder_tmp, copy_tree(
            include_registry=False
        ) as verifier_tmp:
            provider = LocalAccumulatorProvider()
            client = HolderClient.from_seed(
                MASTER_SEED,
                PredicateRegistry.from_repo(pathlib.Path(holder_tmp)),
                StubBackend(),
                accumulator_provider=provider,
            )
            client.store_credential(
                issue_kyc_credential(
                    master_seed=MASTER_SEED, credential_id=42, provider=provider
                )
            )
            issuer = trusted_test_issuer()
            parameters = {
                KYC_PROOF_TYPE: {
                    "requiredLevel": 2,
                    "requiredAttributes": [True, False, False, False, False],
                }
            }
            context = ProofContext.verifier_session("did:zkc:verifier", 0xABCDEF, 1_700_000)
            envelope = generate_unauthenticated_linkable(
                client, ProofRequest(
                    proof_types=[KYC_PROOF_TYPE],
                    parameters=parameters,
                    context=context,
                    trust_policy=TrustPolicy(issuers=(issuer,)),
                )
            )
            verifier = ZKCVerifier(
                pathlib.Path(verifier_tmp),
                VerifierTrustPolicy(
                    issuers=(
                        VerifierTrustedIssuer(
                            issuer_id=issuer.issuer_id,
                            public_key_x=issuer.public_key_x,
                            public_key_y=issuer.public_key_y,
                            proof_types=(KYC_PROOF_TYPE,),
                        ),
                    )
                ),
                StubVerifyBackend(),
            )
            result = verifier.verify(
                envelope,
                VerificationRequest(
                    proof_types=[KYC_PROOF_TYPE],
                    parameters=parameters,
                    context=context,
                    accumulator_states={
                        issuer.issuer_id: IssuerAccumulatorState(
                            current_epoch=provider.current_epoch(issuer.issuer_id),
                            roots=provider.roots(issuer.issuer_id),
                        )
                    },
                ),
            )
            self.assertTrue(result.valid, result.to_dict())


class RegistryMembershipSeededNegativeTests(unittest.TestCase):
    """An implementation that treats registry membership as trust MUST fail
    the conformance suite."""

    def _run_suite(self, *arguments):
        process = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "conformance" / "run_zkc_core.py"),
                "--json",
                *arguments,
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        return process, json.loads(process.stdout)

    def test_membership_trusting_verifier_fails_the_suite(self):
        process, report = self._run_suite("--adapter", "adapters.seeded_negatives")
        self.assertEqual(process.returncode, 1)
        failed_ids = {r["id"] for r in report["results"] if r["status"] == "FAIL"}
        self.assertIn("safeguard-1-registry-membership-not-trust", failed_ids)

    def test_reference_implementation_passes_the_membership_case(self):
        process, report = self._run_suite(
            "--case", "safeguard-1-registry-membership-not-trust"
        )
        self.assertEqual(process.returncode, 0, report)

    def test_isolated_membership_trusting_adapter_fails(self):
        # Teeth in isolation: even without any other violation in play, an
        # implementation whose ONLY flaw is trusting registry membership
        # must fail the suite.
        process, report = self._run_suite("--adapter", "adapters.seeded_registry_trust")
        self.assertEqual(process.returncode, 1)
        failed_ids = {r["id"] for r in report["results"] if r["status"] == "FAIL"}
        self.assertIn("safeguard-1-registry-membership-not-trust", failed_ids)


if __name__ == "__main__":
    unittest.main()
