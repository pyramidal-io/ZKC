"""ZKC consumer checks for the canonical protocol-family interface epoch."""

import json
import unittest

from _path import REPO_ROOT
from scripts.validate_protocol_family import evaluate_vector_case, validate_repository


class ProtocolFamilyConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        package = REPO_ROOT / "protocol-family"
        cls.manifest = json.loads(
            (package / "interface-manifest-v1.json").read_text(encoding="utf-8")
        )
        cls.vectors = json.loads(
            (package / "golden-vectors-v1.json").read_text(encoding="utf-8")
        )

    def test_zkc_projection_and_snapshot_lock_validate(self):
        self.assertEqual(validate_repository(REPO_ROOT, "zkc"), [])

    def test_zkc_consumes_every_declared_composite_outcome(self):
        for case in self.vectors["cases"]:
            observed = evaluate_vector_case(self.manifest, case)
            expected = None if case["expected"] == "accept" else case["failure_code"]
            self.assertEqual(observed, expected, case["case_id"])


if __name__ == "__main__":
    unittest.main()
