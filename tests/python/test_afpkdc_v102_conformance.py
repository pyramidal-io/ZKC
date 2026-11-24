"""AFP-KDC v1.0.2 conformance gates for ZKC's explicit Poseidon2 implementation."""

from __future__ import annotations

import hashlib
import json
import unittest

from _path import REPO_ROOT

from zkc_crypto import MASTER_SEED_PROFILE, field_to_hex
from zkc_crypto._poseidon2_constants import (
    INTERNAL_DIAG_MINUS_ONE,
    ROUND_CONSTANTS,
)
from zkc_crypto.poseidon2 import hash_fields


VECTOR_PATH = (
    REPO_ROOT / "tests" / "vectors" / "crypto" / "afp_kdc_v1_0_2_conformance.json"
)
VECTOR_SHA256 = "61e6a3770e2a8c4637f62bd3683fc5341c3fe3c7edcc2e3c85c1eefe7e714262"
PARAMETER_DIGEST = "8cb18652f4afeac5b6819b156c13fbbc327deacba568b9d8d961ab134123214c"
EXPECTED_LENGTHS = [0, 1, 2, 3, 4, 6, 7]
FAMILY_EPOCH = "zka:protocol-family:2026-11-19.1"
CANONICAL_ZKA_COMMIT = "69bc82ac6685e91f23e386dfdacab78dd1e8cfbc"
SNAPSHOT_DIGESTS = {
    "manifest_sha256": (
        "protocol-family/interface-manifest-v1.json",
        "sha256:aa5b0202fc972239dbae4cbaecacad66aa2a9db5a722f48da6c9ae7fd107a33b",
    ),
    "schema_sha256": (
        "protocol-family/interface-manifest-v1.schema.json",
        "sha256:f5f0b956bab54656e961efe84c498e256a2c2db89e38fc786afa5117c36d8e3b",
    ),
    "vectors_sha256": (
        "protocol-family/golden-vectors-v1.json",
        "sha256:67fb6895510e9008fe1442bdb10f4250f1c2be63e2622e81b6e75069ff422a17",
    ),
    "validator_sha256": (
        "scripts/validate_protocol_family.py",
        "sha256:b66781b0cb95c138c80ff78fa8cdba189101f4fb0df4c133971592db4819469d",
    ),
}
CURRENT_REFERENCE_PATHS = (
    "docs/zkc_specification.md",
    "docs/zkc_selective_disclosure.md",
    "noir/zkc_lib/src/lib.nr",
    "python/zkc_crypto/kdc.py",
    "tests/vectors/zkc_core_vectors.json",
)


class AfpKdcV102ConformanceTests(unittest.TestCase):
    def test_authority_bytes_and_shape(self) -> None:
        raw = VECTOR_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), VECTOR_SHA256)

        package = json.loads(raw)
        self.assertEqual(package["profile"], "afp-kdc:poseidon2:v1.0.2")
        self.assertEqual(package["parameterDigest"], PARAMETER_DIGEST)
        self.assertEqual(
            [case["inputLength"] for case in package["rawSponge"]],
            EXPECTED_LENGTHS,
        )
        for case in package["rawSponge"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["inputLength"], len(case["inputs"]))

    def test_raw_sponge_kats(self) -> None:
        package = json.loads(VECTOR_PATH.read_bytes())

        for case in package["rawSponge"]:
            inputs = [int(value, 16) for value in case["inputs"]]
            with self.subTest(case=case["name"]):
                self.assertEqual(field_to_hex(hash_fields(inputs)), case["output"])

    def test_explicit_parameter_table_digest(self) -> None:
        values = [value for row in ROUND_CONSTANTS for value in row]
        values.extend(INTERNAL_DIAG_MINUS_ONE)
        encoded = b"".join(value.to_bytes(32, "big") for value in values)

        self.assertEqual(len(values), 260)
        self.assertEqual(len(encoded), 8_320)
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), PARAMETER_DIGEST)

    def test_canonical_family_snapshot_is_zkm_aware_and_locked(self) -> None:
        manifest = json.loads(
            (REPO_ROOT / "protocol-family/interface-manifest-v1.json").read_bytes()
        )
        lock = json.loads(
            (REPO_ROOT / "protocol-family/snapshot-lock.json").read_bytes()
        )

        self.assertEqual(manifest["epoch"], FAMILY_EPOCH)
        self.assertEqual(lock["epoch"], FAMILY_EPOCH)
        self.assertIn("zkm", manifest["protocols"])
        self.assertIn("zkm", manifest["projections"])
        self.assertEqual(lock["canonical_commit"], CANONICAL_ZKA_COMMIT)
        self.assertNotIn("pending_republish", lock)

        for lock_key, (relative_path, expected_digest) in SNAPSHOT_DIGESTS.items():
            with self.subTest(path=relative_path):
                observed = "sha256:" + hashlib.sha256(
                    (REPO_ROOT / relative_path).read_bytes()
                ).hexdigest()
                self.assertEqual(observed, expected_digest)
                self.assertEqual(lock[lock_key], expected_digest)

    def test_current_normative_surfaces_reference_v103(self) -> None:
        for relative_path in CURRENT_REFERENCE_PATHS:
            with self.subTest(path=relative_path):
                text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn("AFP-KDC v1.0.3", text)

        specification = (REPO_ROOT / "docs/zkc_specification.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(FAMILY_EPOCH, specification)

    def test_current_family_tuple_matches_manifest(self) -> None:
        manifest = json.loads(
            (REPO_ROOT / "protocol-family/interface-manifest-v1.json").read_bytes()
        )
        specification = (REPO_ROOT / "docs/zkc_specification.md").read_text(
            encoding="utf-8"
        )

        self.assertEqual(manifest["protocols"]["afp"]["version"], "0.3.14-draft")
        supported_tuple_versions = {
            combination["afp"]
            for combination in manifest["compatibility"]
            if combination["state"] == "supported"
        }
        self.assertEqual(
            supported_tuple_versions, {manifest["protocols"]["afp"]["version"]}
        )
        self.assertIn(
            f"AFP v{manifest['protocols']['afp']['version']}", specification
        )

    def test_current_vector_registry_authority_is_v103(self) -> None:
        specification = (REPO_ROOT / "docs/zkc_specification.md").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "AFP-KDC v1.0.3 current registry's `zkc/claim` operational domain",
            specification,
        )
        self.assertIn("immutable AFP-KDC v1.0.2 crypto evidence", specification)

    def test_v101_master_seed_identity_remains_frozen(self) -> None:
        historical_vector = json.loads(
            (REPO_ROOT / "tests/vectors/kdc_master_seed_v1.json").read_bytes()
        )

        self.assertEqual(MASTER_SEED_PROFILE, "afp-kdc:master-seed:v1.0.1")
        self.assertEqual(historical_vector["profile"], MASTER_SEED_PROFILE)


if __name__ == "__main__":
    unittest.main()
