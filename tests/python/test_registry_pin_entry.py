"""Focused coverage for the read-only predicate-entry pin helper."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
HELPER = REPO / "registry" / "pin_entry.py"


class RegistryPinEntryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "encoders").mkdir()
        (self.root / "artifacts").mkdir()
        source_dir = self.root / "noir" / "zkc_next" / "src"
        source_dir.mkdir(parents=True)
        (source_dir / "main.nr").write_text("fn main() {}\n")
        (source_dir.parent / "Nargo.toml").write_text(
            '[package]\nname = "zkc_next"\ntype = "bin"\n'
        )
        (self.root / "noir" / "Nargo.toml").write_text(
            '[workspace]\nmembers = ["zkc_next"]\n'
        )
        self.encoder_path = "encoders/next.json"
        (self.root / self.encoder_path).write_text(json.dumps({
            "version": "zkc:public-inputs:v1",
            "circuit": "zkc_next",
            "proofSystem": "ultra_honk",
            "curve": "BN254",
            "encoding": {
                "fieldElement": "field",
                "order": "order",
                "booleans": "bool",
                "integers": "integer",
                "byteArrays": "bytes",
            },
            "proofTypes": ["zkc:proof:next:v1"],
            "totalFieldElements": 1,
            "publicInputs": [
                {
                    "index": 0,
                    "offset": 0,
                    "name": "value",
                    "abiType": "Field",
                    "fieldElements": 1,
                    "description": "fixture",
                }
            ],
        }))
        self.manifest_path = "artifacts/manifest.json"
        (self.root / self.manifest_path).write_text(json.dumps({"circuits": [{
            "name": "zkc_next", "publicInputEncoder": self.encoder_path,
            "scheme": "ultra_honk",
            "acirHash": "sha256:" + "a" * 64,
            "vkHash": "0x" + "b" * 64,
            "vkSha256": "sha256:" + "c" * 64,
        }]}))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_helper(self, predicate_id="new-lineage", version="1.0.0", **changes):
        args = [sys.executable, str(HELPER), "--root", str(self.root),
                "--predicate-id", predicate_id, "--entry-version", version,
                "--circuit", changes.get("circuit", "zkc_next"),
                "--source-path", changes.get("source_path", "noir/zkc_next/src/main.nr"),
                "--public-input-encoder", changes.get("encoder_path", self.encoder_path),
                "--manifest", changes.get("manifest_path", self.manifest_path)]
        return subprocess.run(args, text=True, capture_output=True, check=False)

    def write_existing(self, predicate_id="lineage", version="1.0.0", source="circuits/old.nr",
                       encoder="encoders/old.json", proof_types=None) -> None:
        proof_types = proof_types or ["zkc:proof:old:v1"]
        path = self.root / "registry" / "predicates" / predicate_id / version
        path.mkdir(parents=True)
        (path / "entry.json").write_text(json.dumps({
            "circuit": {"sourcePath": source}, "publicInputEncoder": encoder,
            "proofTypes": proof_types,
        }))

    def test_prints_exact_pins_without_mutating_repository(self) -> None:
        before = {p.relative_to(self.root).as_posix(): p.read_bytes()
                  for p in self.root.rglob("*") if p.is_file()}
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "entryPath": "registry/predicates/new-lineage/1.0.0/entry.json",
            "predicateId": "new-lineage", "entryVersion": "1.0.0",
            "proofTypes": ["zkc:proof:next:v1"],
            "publicInputEncoder": "encoders/next.json",
            "circuit": {
                "name": "zkc_next", "scheme": "ultra_honk",
                "sourcePath": "noir/zkc_next/src/main.nr",
                "sourceSha256": hashlib.sha256(b"fn main() {}\n").hexdigest(),
                "acirHash": "sha256:" + "a" * 64,
                "vkHash": "0x" + "b" * 64,
                "vkSha256": "sha256:" + "c" * 64,
            },
        })
        after = {p.relative_to(self.root).as_posix(): p.read_bytes()
                 for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(after, before)

    def test_refuses_existing_entry_and_unsafe_paths(self) -> None:
        self.write_existing("new-lineage")
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("prospective entry already exists", result.stderr)
        result = self.run_helper(
            predicate_id="another", source_path="../noir/zkc_next/src/main.nr"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("safe repository-relative", result.stderr)
        link = self.root / "noir/zkc_next/src/linked-main.nr"
        link.symlink_to("main.nr")
        result = self.run_helper(
            predicate_id="another", source_path="noir/zkc_next/src/linked-main.nr"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("must not traverse a symlink", result.stderr)

    def test_refuses_same_lineage_source_reuse(self) -> None:
        self.write_existing(source="noir/zkc_next/src/main.nr")
        result = self.run_helper(predicate_id="lineage", version="2.0.0")
        self.assertEqual(result.returncode, 1)
        self.assertIn("already references source package", result.stderr)

    def test_refuses_same_lineage_proof_overlap(self) -> None:
        self.write_existing(predicate_id="overlap", proof_types=["zkc:proof:next:v1"])
        result = self.run_helper(predicate_id="overlap", version="2.0.0")
        self.assertEqual(result.returncode, 1)
        self.assertIn("proofTypes must be disjoint", result.stderr)

    def test_refuses_source_referenced_by_another_lineage_for_successor(self) -> None:
        self.write_existing(
            predicate_id="global-reference", source="noir/zkc_next/src/main.nr"
        )
        self.write_existing(predicate_id="existing-lineage")
        result = self.run_helper(predicate_id="existing-lineage", version="2.0.0")
        self.assertEqual(result.returncode, 1)
        self.assertIn("global-reference", result.stderr)

    def test_allows_identity_reuse_for_new_lineage(self) -> None:
        self.write_existing(predicate_id="other-lineage", source="noir/zkc_next/src/main.nr",
                            encoder=self.encoder_path, proof_types=["zkc:proof:next:v1"])
        result = self.run_helper(predicate_id="new-lineage")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reports_required_supersedes_for_safe_same_lineage_entry(self) -> None:
        self.write_existing(predicate_id="lineage", version="1.0.0")
        result = self.run_helper(predicate_id="lineage", version="2.0.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["requiredActivationSupersedes"],
            "lineage@1.0.0",
        )

    def test_refuses_loose_or_mismatched_circuit_package(self) -> None:
        loose = self.root / "loose.nr"
        loose.write_text("fn main() {}\n")
        result = self.run_helper(source_path="loose.nr")
        self.assertEqual(result.returncode, 1)
        self.assertIn("circuit.sourcePath must be", result.stderr)

        manifest = self.root / "noir/zkc_next/Nargo.toml"
        original = manifest.read_text()
        manifest.write_text(original.replace('name = "zkc_next"', 'name = "wrong"'))
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match circuit", result.stderr)

    def test_refuses_unsafe_or_incomplete_dependency_closure(self) -> None:
        manifest = self.root / "noir/zkc_next/Nargo.toml"
        original = manifest.read_text()
        cases = (
            ('\n[dependencies]\nmissing = { path = "../missing" }\n', "directory is missing"),
            ('\n[dependencies]\noutside = { path = "../../../outside" }\n', "escapes the repository"),
        )
        for addition, expected in cases:
            with self.subTest(expected=expected):
                manifest.write_text(original + addition)
                result = self.run_helper()
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
        manifest.write_text(original)

        real_dependency = self.root / "noir/real_dep"
        real_dependency.mkdir()
        (real_dependency / "Nargo.toml").write_text(
            '[package]\nname = "real_dep"\ntype = "lib"\n'
        )
        (self.root / "noir/link_dep").symlink_to("real_dep", target_is_directory=True)
        manifest.write_text(
            original + '\n[dependencies]\nlinked = { path = "../link_dep" }\n'
        )
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("must not traverse a symlink", result.stderr)
        manifest.write_text(original)

        template = self.root / "manifest-template.toml"
        template.write_text(original)
        manifest.unlink()
        manifest.symlink_to("../../manifest-template.toml")
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("must not contain symlinks", result.stderr)


if __name__ == "__main__":
    unittest.main()
