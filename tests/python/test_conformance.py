"""Conformance suite tests.

Asserts (a) the reference implementation passes the published ZKC-Core
vectors, (b) the suite CATCHES seeded Freedom Safeguard violations, (c) the
vectors are deterministic, and (d) the reference packages contain no
hardcoded canonical-issuer material (Freedom Safeguard 1, static check).
"""

import json
import re
import subprocess
import sys
import unittest

from _path import REPO_ROOT
from zkc_crypto import LINKABLE_PROFILE
from zkc_holder.predicates import resolve_presentation_proof_type

RUNNER = REPO_ROOT / "conformance" / "run_zkc_core.py"
PRESENTATION_RUNNER = REPO_ROOT / "conformance" / "run_presentation.py"

# The presentation-profile pipeline lives under conformance/, not python/.
if str(REPO_ROOT / "conformance") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "conformance"))


def run_suite(*arguments):
    process = subprocess.run(
        [sys.executable, str(RUNNER), "--json", *arguments],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    return process, json.loads(process.stdout) if process.stdout.strip() else {}


class ReferenceConformanceTests(unittest.TestCase):
    def test_reference_implementation_passes_core_suite(self):
        process, report = run_suite()
        self.assertEqual(report.get("failed"), 0, report)
        self.assertEqual(process.returncode, 0)
        self.assertGreaterEqual(report.get("total", 0), 15)

    def test_suite_results_are_deterministic(self):
        _, first = run_suite()
        _, second = run_suite()
        self.assertEqual(first, second)


class SeededNegativeTests(unittest.TestCase):
    """The suite must have teeth: deliberately broken adapters must fail."""

    def test_seeded_negatives_are_caught(self):
        process, report = run_suite("--adapter", "adapters.seeded_negatives")
        self.assertEqual(process.returncode, 1)
        failed_ids = {r["id"] for r in report["results"] if r["status"] == "FAIL"}
        self.assertIn("safeguard-1-no-canonical-issuer", failed_ids)
        self.assertIn("safeguard-1-registry-membership-not-trust", failed_ids)
        self.assertIn("safeguard-4-opaque-refusal", failed_ids)
        # Safeguard 6: the fail-open holder must be caught answering an
        # unauthenticated request and retaining a receipt as a hosted service.
        self.assertIn("safeguard-6-unsigned-request-refusal", failed_ids)
        self.assertIn("safeguard-6-hosted-retention-refusal", failed_ids)
        # Receipt anchoring (spec 5.6.1): the self-anchoring verifier trusts
        # the receipt's own holderKey and must be caught by the runner's
        # anchoring probes, not by a missing anchor.
        reasons = {r["id"]: r.get("reason", "") for r in report["results"]}
        for case_id in ("safeguard-6-receipt-roundtrip", "safeguard-6-receipt-tampered"):
            self.assertIn(case_id, failed_ids)
            self.assertIn("no expected holder key", reasons[case_id])

    def test_receipt_key_scope_violations_are_caught(self):
        """Holders that echo a self-consistent but badly scoped receipt key
        (spec 5.6.1) fail on the runner's key-scope probes."""
        for adapter, reason in (
            ("adapters.seeded_global_receipt_key", "two verifier identities carry the same holder key"),
            ("adapters.seeded_unstable_receipt_key", "not stable across answers to the same APR"),
        ):
            with self.subTest(adapter=adapter):
                process, report = run_suite("--adapter", adapter)
                self.assertEqual(process.returncode, 1)
                failed = {r["id"]: r.get("reason", "") for r in report["results"]
                          if r["status"] == "FAIL"}
                self.assertEqual(
                    set(failed),
                    {"safeguard-6-receipt-roundtrip", "safeguard-6-receipt-tampered"},
                )
                for message in failed.values():
                    self.assertIn(reason, message)

    def test_runner_rejects_receipt_verifiers_that_ignore_the_anchor(self):
        """Each anchoring probe catches its own broken verifier."""
        import importlib

        runner = importlib.import_module("run_zkc_core")
        from adapters.reference import ReferenceVerifierAdapter
        from zkc_crypto import holder_public_key, sign_receipt, verify_receipt

        from zkc_crypto import context_value_from_fixture, field_to_hex

        honest_key = holder_public_key(0xA11CE)
        vectors = json.loads((REPO_ROOT / "conformance" / "vectors" / "zkc_core.json").read_text())
        apr = vectors["aprs"]["apr_access_signed"]

        receipt = sign_receipt({
            "apr": apr, "outcome": "answered", "recordedAt": 1,
            "response": {
                "holderCommitment": field_to_hex(7),
                "contextValue": field_to_hex(context_value_from_fixture(apr["request"]["context"])),
                "answeredProofTypes": list(apr["request"]["proofTypes"]),
            },
        }, 0xA11CE)
        self.assertTrue(ReferenceVerifierAdapter().verify_receipt(
            receipt, expected_holder_key=honest_key)["valid"])
        runner.check_receipt_anchoring(ReferenceVerifierAdapter(), receipt, honest_key)

        class IgnoresMissingAnchor(ReferenceVerifierAdapter):
            def verify_receipt(self, receipt, *, expected_holder_key=None):
                return verify_receipt(receipt, expected_holder_key=expected_holder_key or honest_key)

        class AcceptsAnyAnchor(ReferenceVerifierAdapter):
            def verify_receipt(self, receipt, *, expected_holder_key=None):
                if expected_holder_key is None:
                    return {"valid": False}
                return verify_receipt(receipt, expected_holder_key=receipt["holderSignature"]["holderKey"])

        for broken, message in (
            (IgnoresMissingAnchor(), "no expected holder key"),
            (AcceptsAnyAnchor(), "foreign expected holder key"),
        ):
            with self.subTest(broken=type(broken).__name__):
                with self.assertRaisesRegex(runner.CaseFailure, message):
                    runner.check_receipt_anchoring(broken, receipt, honest_key)

    def test_canonical_issuer_violation_manifests_as_wrong_acceptance(self):
        process, report = run_suite(
            "--adapter", "adapters.seeded_negatives", "--case", "safeguard-1-no-canonical-issuer"
        )
        self.assertEqual(process.returncode, 1)
        failure = report["results"][0]
        self.assertEqual(failure["status"], "FAIL")
        self.assertIn("valid=True", failure["reason"])


class ExpansionHookTests(unittest.TestCase):
    def test_unpublished_profile_reports_not_published(self):
        process, report = run_suite("--profile", "full")
        self.assertEqual(process.returncode, 2, "an unpublished profile must not exit 0")
        self.assertEqual(report.get("status"), "not_published")


class VectorHygieneTests(unittest.TestCase):
    def test_core_vectors_use_each_predicate_familys_current_linkable_type(self):
        vectors = json.loads(
            (REPO_ROOT / "conformance" / "vectors" / "zkc_core.json").read_text()
        )
        request_keys = {
            "jurisdiction": ("jurisdiction_inclusion", "jurisdiction_exclusion"),
            "accreditation": ("accreditation_level_2", "accreditation_level_3"),
            "source": ("source_set_7", "source_set_7_8"),
            "tax": ("tax_year_2025", "tax_year_2026"),
            "sanctions": ("sanctions_set_100_200", "sanctions_set_120_180"),
        }

        for family, requests in request_keys.items():
            proof_type = resolve_presentation_proof_type(family, LINKABLE_PROFILE)
            with self.subTest(family=family, proof_type=proof_type):
                self.assertEqual(
                    vectors["credentials"][f"valid_{family}"]["proofType"],
                    proof_type,
                )
                for request_key in requests:
                    request = vectors["requests"][request_key]
                    self.assertEqual(request["proofTypes"], [proof_type])
                    self.assertEqual(list(request["parameters"]), [proof_type])

    def test_step_4e_dispatcher_is_defined_in_spec_and_reference_verifier(self):
        specification = (REPO_ROOT / "docs" / "zkc_specification.md").read_text()
        verifier = (REPO_ROOT / "python" / "zkc_verifier" / "verifier.py").read_text()
        self.assertIn("function verifyTypeSpecificRequirements(", specification)
        self.assertIn("def _verify_type_specific_requirements(", verifier)

    def test_vectors_regenerate_deterministically(self):
        committed = (REPO_ROOT / "conformance" / "vectors" / "zkc_core.json").read_text()
        process = subprocess.run(
            [sys.executable, str(REPO_ROOT / "conformance" / "generate_vectors.py")],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        regenerated = (REPO_ROOT / "conformance" / "vectors" / "zkc_core.json").read_text()
        self.assertEqual(committed, regenerated, "generate_vectors.py must be deterministic")

    def test_vector_cases_have_unique_ids_and_known_kinds(self):
        vectors = json.loads(
            (REPO_ROOT / "conformance" / "vectors" / "zkc_core.json").read_text()
        )
        ids = [case["id"] for case in vectors["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        kinds = {case["kind"] for case in vectors["cases"]}
        self.assertLessEqual(
            kinds,
            {
                "roundtrip",
                "holder_refusal",
                "verifier_mutation",
                "verifier_static",
                # Safeguard 6 — verifier accountability (§5.5–§5.7, §6.2).
                "apr_roundtrip",
                "apr_generation_refusal",
                "apr_purpose_mismatch",
                "apr_receipt_roundtrip",
                "hosted_retention_refusal",
            },
        )
        # Safeguard cases must exist — CI relies on them.
        self.assertIn("safeguard-1-no-canonical-issuer", ids)
        self.assertIn("safeguard-1-registry-membership-not-trust", ids)
        self.assertIn("safeguard-4-opaque-refusal", ids)
        self.assertIn("safeguard-6-unsigned-request-refusal", ids)
        self.assertIn("safeguard-6-purpose-mismatch", ids)
        self.assertIn("safeguard-6-hosted-retention-refusal", ids)
        self.assertIn("core-verifier-noncanonical-requirement", ids)

    def test_every_non_kyc_core_predicate_has_honest_and_out_of_request_vectors(self):
        vectors = json.loads(
            (REPO_ROOT / "conformance" / "vectors" / "zkc_core.json").read_text()
        )
        by_id = {case["id"]: case for case in vectors["cases"]}
        for predicate in ("jurisdiction", "accreditation", "source", "tax", "sanctions"):
            honest_id = f"core-roundtrip-{predicate}-valid"
            rejection_id = f"core-verifier-{predicate}-requirements-not-met"
            self.assertIn(honest_id, by_id)
            self.assertIn(rejection_id, by_id)

            rejection = by_id[rejection_id]
            self.assertEqual(rejection["kind"], "verifier_mutation")
            self.assertEqual(rejection["mutations"], [])
            self.assertNotEqual(rejection["request"], rejection["verifyRequest"])
            self.assertEqual(rejection["expect"]["anyCode"], ["REQUIREMENTS_NOT_MET"])


def run_presentation_suite(*arguments):
    process = subprocess.run(
        [sys.executable, str(PRESENTATION_RUNNER), "--json", *arguments],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    return process, json.loads(process.stdout) if process.stdout.strip() else {}


class PresentationVectorTests(unittest.TestCase):
    """The eight ``presentation-*`` conformance vectors (design §8 matrix).

    Each vector runs through the REAL reference holder→verifier pipeline
    (generate → verify → assert), never a hand-built envelope. Scoped vectors
    negotiate scope via an authenticated APR so the holder derives ``scope_id``
    itself; cross-scope / scope-mismatch use two distinct verifier identities.
    """

    EXPECTED_VECTOR_IDS = (
        "presentation-anonymous-unlinkable",
        "presentation-scoped-cross-scope",
        "presentation-scoped-within-scope",
        "presentation-scoped-rotation",
        "presentation-profile-replay",
        "presentation-scope-mismatch",
        "presentation-profile-not-accepted",
        "presentation-determinism-invariant",
        # Same-holder composites (security review 2026-10-04).
        "presentation-anonymous-composite-pooling",
        "presentation-session-scoped-composite",
        "presentation-session-scope-unlinkable",
    )

    def test_reference_pipeline_passes_all_presentation_vectors(self):
        import presentation_vectors

        results = presentation_vectors.run_all()
        failures = [r for r in results if r["status"] != "PASS"]
        self.assertEqual(failures, [], failures)
        got_ids = [r["id"] for r in results]
        # Every declared vector ran, and exactly the design §8 set.
        self.assertEqual(set(got_ids), set(self.EXPECTED_VECTOR_IDS))

    def test_declared_vectors_match_spec_and_implementation(self):
        # The machine-readable spec is the source of truth for the id set; the
        # pipeline module must implement exactly those ids (no drift either way).
        import presentation_vectors

        spec = json.loads(
            (REPO_ROOT / "conformance" / "vectors" / "zkc_presentation.json").read_text()
        )
        spec_ids = [entry["id"] for entry in spec["vectors"]]
        self.assertEqual(set(spec_ids), set(self.EXPECTED_VECTOR_IDS))
        # No duplicate ids, and every vector declares a kind.
        self.assertEqual(len(spec_ids), len(set(spec_ids)))
        kinds = {entry["kind"] for entry in spec["vectors"]}
        self.assertLessEqual(kinds, {"positive", "negative", "invariant"})
        self.assertEqual(set(presentation_vectors.declared_vector_ids()), set(spec_ids))

    def test_runner_reports_all_passing_via_cli(self):
        process, report = run_presentation_suite()
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(report.get("failed"), 0, report)
        self.assertEqual(report.get("total"), len(self.EXPECTED_VECTOR_IDS))

    def test_cross_scope_vector_has_teeth(self):
        # Directly exercise the load-bearing negative: the same credential under
        # two DISTINCT verifier scopes must produce DIFFERENT pseudonyms, so a
        # colluding-verifier equality join fails. This asserts the vector is not
        # vacuously green — a real cross-scope join over the real pipeline.
        from presentation_vectors import Pipeline, _kyc_public_inputs, APR_VERIFIER_A_PRIVATE_KEY, APR_VERIFIER_B_PRIVATE_KEY

        pipe = Pipeline()
        env_a = pipe.generate_scoped(
            private_key=APR_VERIFIER_A_PRIVATE_KEY, session_id=301, timestamp=1_700_000_000, nonce=0xB1,
        )
        env_b = pipe.generate_scoped(
            private_key=APR_VERIFIER_B_PRIVATE_KEY, session_id=302, timestamp=1_700_000_400, nonce=0xB2,
        )
        pub_a = _kyc_public_inputs(env_a)
        pub_b = _kyc_public_inputs(env_b)
        self.assertNotEqual(pub_a["presentation_pseudonym"], pub_b["presentation_pseudonym"])
        self.assertNotEqual(pub_a["scope_id"], pub_b["scope_id"])


class NoCanonicalIssuerStaticScan(unittest.TestCase):
    """Freedom Safeguard 1, static form: the reference packages must not
    hardcode any issuer identity or issuer key material. Issuer identities
    may only live in fixtures, vectors, and tests."""

    SCAN_DIRS = ("python/zkc_holder", "python/zkc_verifier", "python/zkc_crypto")
    SCAN_FILES = ("conformance/adapters/reference.py", "conformance/run_zkc_core.py")
    ISSUER_ID_PATTERN = re.compile(r"did:zkc:")
    # The well-known test issuer key coordinates (hex, from tools/zkc_test_issuer.py).
    TEST_ISSUER_KEY_FRAGMENTS = ("1310fe42b7df28ba", "502c40fd1bc33d2d")

    def _scan(self, text: str, where: str):
        self.assertIsNone(
            self.ISSUER_ID_PATTERN.search(text),
            f"hardcoded issuer identity found in {where}",
        )
        lowered = text.lower()
        for fragment in self.TEST_ISSUER_KEY_FRAGMENTS:
            self.assertNotIn(
                fragment, lowered, f"hardcoded issuer key material found in {where}"
            )

    def test_reference_sources_contain_no_issuer_material(self):
        for directory in self.SCAN_DIRS:
            for path in sorted((REPO_ROOT / directory).rglob("*.py")):
                self._scan(path.read_text(), str(path.relative_to(REPO_ROOT)))
        for file_name in self.SCAN_FILES:
            path = REPO_ROOT / file_name
            self._scan(path.read_text(), file_name)


if __name__ == "__main__":
    unittest.main()
