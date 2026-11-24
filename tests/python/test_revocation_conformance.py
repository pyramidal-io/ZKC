"""Launch conformance for authenticated revocation and equivocation handling."""

import copy
import sys
import unittest
from unittest import mock

import _path  # noqa: F401
from _path import REPO_ROOT

if str(REPO_ROOT / "conformance") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "conformance"))

from revocation_vectors import (  # noqa: E402
    EXPECTED_CASE_IDS,
    independent_announcement_hash,
    independent_digest_hex,
    independent_transcript,
    independent_verify,
    load_vectors,
    run_conformance,
    validate_vector_document,
)
from zkc_revocation import (
    announcement_hash,
    announcement_transcript,
    compute_announcement_digest,
)
import revocation_vectors  # noqa: E402


class RevocationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = load_vectors()

    def test_independent_validator_accepts_checked_in_vectors(self):
        validate_vector_document(self.vectors)

    def test_production_and_independent_serializers_agree(self):
        for name, record in self.vectors["announcements"].items():
            with self.subTest(name=name):
                announcement = record["announcement"]
                self.assertEqual(
                    "0x" + independent_transcript(announcement).hex(),
                    record["transcriptHex"],
                )
                self.assertEqual(
                    independent_digest_hex(announcement), record["signingDigest"]
                )
                self.assertEqual(
                    independent_announcement_hash(announcement),
                    record["announcementHash"],
                )
                self.assertEqual(
                    announcement_transcript(announcement),
                    independent_transcript(announcement),
                )
                self.assertEqual(announcement_hash(announcement), record["announcementHash"])
                self.assertEqual(
                    f"0x{compute_announcement_digest(announcement):064x}",
                    record["signingDigest"],
                )

    def test_every_signed_field_tamper_is_rejected(self):
        record = self.vectors["announcements"]["revocation"]
        public_key = self.vectors["keys"]["primary"]["publicKey"]
        required = {
            "version",
            "root",
            "epoch",
            "accumulatorId",
            "announcedAt",
            "maxEpochLag",
            "previousAnnouncementHash",
            "signingKeyId",
            "signature",
        }
        self.assertEqual(
            {case["field"] for case in self.vectors["tamperCases"]}, required
        )
        for case in self.vectors["tamperCases"]:
            with self.subTest(field=case["field"]):
                candidate = copy.deepcopy(record["announcement"])
                candidate[case["field"]] = case["value"]
                self.assertFalse(independent_verify(candidate, public_key))


class RevocationConformanceRunnerTests(unittest.TestCase):
    def test_case_ids_and_launch_scenarios_are_stable(self):
        report = run_conformance()
        self.assertEqual([item["id"] for item in report["results"]], EXPECTED_CASE_IDS)
        self.assertTrue(report["allPassed"], report)
        self.assertEqual(report["passed"], len(EXPECTED_CASE_IDS))

    def test_case_registry_divergence_fails_instead_of_truncating(self):
        with mock.patch.object(
            revocation_vectors, "_CASES", revocation_vectors._CASES[:-1]
        ):
            with self.assertRaisesRegex(
                revocation_vectors.ConformanceFailure, "callable list diverged"
            ):
                run_conformance()

    def test_spec_publishes_launch_vectors_and_local_only_cold_start(self):
        spec = (REPO_ROOT / "docs" / "zkc_specification.md").read_text()
        self.assertIn("tests/vectors/revocation_equivocation_v1.json", spec)
        self.assertIn("conformance/run_revocation.py", spec)
        self.assertIn("local checkpoint", spec)
        self.assertIn("no global consistency", spec)


if __name__ == "__main__":
    unittest.main()
