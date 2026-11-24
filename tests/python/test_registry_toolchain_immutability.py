"""History checks protect build inputs without relying on artifact regeneration."""

from __future__ import annotations

import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_registry_immutability import REPO_ROOT, entry, guard, write_entry, write_v2_fixture


CONFIG = "noir/toolchains.json"
PINS = ".noir-version"


class RegistryToolchainImmutabilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.base = self.root / "base"
        self.current = self.root / "current"
        self.document = entry(source_path="noir/zkc_alpha/src/main.nr")
        write_entry(self.base, self.document)
        manifest = self.base / "noir/zkc_alpha/Nargo.toml"
        manifest.write_text('[package]\nname = "zkc_alpha"\ntype = "bin"\n')
        write_v2_fixture(self.base)
        self.config = json.loads((REPO_ROOT / CONFIG).read_text())
        self.config["packages"] = {"zkc_alpha": "historical", "zkc_beta": ["historical", "successor"]}
        self.config["probePackages"] = {}
        binding_path = next((self.base / "registry/predicates/beta/1.0.0/bindings").glob("*.json"))
        binding = json.loads(binding_path.read_text())
        binding["toolchain"].update(self.config["toolchains"]["historical"], id="historical")
        binding_path.write_text(json.dumps(binding))
        (self.base / CONFIG).write_text(json.dumps(self.config))
        shutil.copyfile(REPO_ROOT / PINS, self.base / PINS)
        shutil.copytree(self.base, self.current)

    def findings(self):
        return guard.check_immutability(
            guard.snapshot_from_directory(self.base),
            guard.snapshot_from_directory(self.current),
        )

    def write_config(self, config):
        (self.current / CONFIG).write_text(json.dumps(config))

    def test_unchanged_draft_entries_and_bindings_pass(self):
        self.assertEqual([], self.findings())

    def test_published_v1_and_v2_package_mapping_changes_fail(self):
        for package in self.config["packages"]:
            for replacement in ("successor", ["successor", "historical"], ["historical", "successor", "extra"], None):
                with self.subTest(package=package, replacement=replacement):
                    config = copy.deepcopy(self.config)
                    if replacement is None:
                        del config["packages"][package]
                    else:
                        config["packages"][package] = replacement
                    self.write_config(config)
                    self.assertIn("immutable package toolchain mapping", "\n".join(self.findings()))

    def test_binding_circuit_is_protected_independently_of_parent(self):
        binding_path = next((self.base / "registry/predicates/beta/1.0.0/bindings").glob("*.json"))
        binding = json.loads(binding_path.read_text())
        binding["circuit"] = "binding_only"
        for root in (self.base, self.current):
            (root / binding_path.relative_to(self.base)).write_text(json.dumps(binding))
            config = copy.deepcopy(self.config)
            config["packages"]["binding_only"] = "historical"
            (root / CONFIG).write_text(json.dumps(config))
        self.assertEqual([], self.findings())
        config["packages"]["binding_only"] = "successor"
        self.write_config(config)
        self.assertIn("binding_only", "\n".join(self.findings()))

    def test_used_lane_definition_cannot_change_or_disappear(self):
        for lane in ("historical", "successor"):
            for field in ("nargo", "noirc", "bb", None):
                with self.subTest(lane=lane, field=field):
                    config = copy.deepcopy(self.config)
                    if field is None:
                        del config["toolchains"][lane]
                    else:
                        config["toolchains"][lane][field] = "different"
                    self.write_config(config)
                    self.assertIn("immutable toolchain definition", "\n".join(self.findings()))

    def test_coordinated_lane_and_version_repin_cannot_hide_history_change(self):
        config = copy.deepcopy(self.config)
        config["toolchains"]["historical"]["nargo"] = "new-version"
        self.write_config(config)
        pins = (self.current / PINS).read_text().replace("1.0.0-beta.21", "new-version")
        (self.current / PINS).write_text(pins)
        findings = "\n".join(self.findings())
        self.assertIn("immutable toolchain definition", findings)
        self.assertIn("immutable toolchain version pin", findings)

    def test_duplicate_or_forward_referenced_pins_fail_closed(self):
        original = (self.current / PINS).read_text()
        for pins in (original + "NARGO_VERSION=1.0.0-beta.21\n",
                     "NARGO_VERSION=${HISTORICAL_NARGO_VERSION}\n" + original):
            with self.subTest(pins=pins):
                (self.current / PINS).write_text(pins)
                self.assertIn("current toolchain version pins are unreadable", "\n".join(self.findings()))

    def test_effective_version_pins_cannot_change_or_disappear(self):
        original = (self.base / PINS).read_text()
        keys = ("HISTORICAL_NARGO_VERSION", "HISTORICAL_BB_VERSION", "SUCCESSOR_NARGO_VERSION",
                "SUCCESSOR_BB_VERSION", "NARGO_VERSION", "BB_VERSION")
        for key in keys:
            for delete in (False, True):
                with self.subTest(key=key, delete=delete):
                    lines = [line for line in original.splitlines() if not line.startswith(key + "=")]
                    if not delete:
                        lines.append(key + "=different")
                    (self.current / PINS).write_text("\n".join(lines) + "\n")
                    self.assertIn("immutable toolchain version pin", "\n".join(self.findings()))

    def test_deleted_malformed_and_wrong_shape_config_fail_closed(self):
        for path in (CONFIG, PINS):
            original = (self.current / path).read_bytes()
            for payload in (None, b"[", b"[]"):
                with self.subTest(path=path, payload=payload):
                    target = self.current / path
                    if payload is None:
                        target.unlink(missing_ok=True)
                    else:
                        target.write_bytes(payload)
                    self.assertTrue(self.findings())
                    target.write_bytes(original)

    def test_new_package_lane_is_additive_without_repinning_published_inputs(self):
        config = copy.deepcopy(self.config)
        config["packages"]["new_package"] = "successor"
        self.write_config(config)
        write_entry(self.current, entry(
            predicate_id="gamma", proof_types=["zkc:proof:gamma:v1"],
            circuit_name="new_package", source_path="noir/new_package/src/main.nr",
            encoder="encoders/gamma.json",
        ))
        self.assertEqual([], self.findings())
        for package, assignment in self.config["packages"].items():
            self.assertEqual(json.dumps(assignment), json.dumps(config["packages"][package]))

    def test_pin_references_and_configuration_formatting_preserve_effective_inputs(self):
        pins = (self.current / PINS).read_text()
        pins = "\n".join(
            "NARGO_VERSION=${HISTORICAL_NARGO_VERSION}" if line.startswith("NARGO_VERSION=") else line
            for line in pins.splitlines()
        ) + "\n"
        (self.current / PINS).write_text(pins)
        config = copy.deepcopy(self.config)
        config["probePackages"] = {"successor": "zkc_alpha"}
        (self.current / CONFIG).write_text(json.dumps(config, sort_keys=True, indent=4))
        self.assertEqual([], self.findings())
        pins = pins.replace("HISTORICAL_NARGO_VERSION=1.0.0-beta.21", "HISTORICAL_NARGO_VERSION=different")
        (self.current / PINS).write_text(pins)
        self.assertIn("immutable toolchain version pin", "\n".join(self.findings()))

    def test_new_v2_binding_using_predeclared_lane_is_additive(self):
        directory = self.current / "registry/predicates/beta/1.0.0/bindings"
        binding = json.loads(next(directory.glob("*.json")).read_text())
        binding["bindingId"] = "sha256:" + "5" * 64
        binding["toolchain"].update(self.config["toolchains"]["successor"], id="successor")
        binding["artifactManifestKey"] = "beta@1.0.0/successor"
        binding["artifacts"] = {"acir": "artifacts/beta/successor/acir.json", "vk": "artifacts/beta/successor/vk"}
        for path in binding["artifacts"].values():
            target = self.current / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"new artifact\n")
        (directory / ("5" * 64 + ".json")).write_text(json.dumps(binding))
        self.assertEqual([], self.findings())

    def test_unused_lane_can_evolve_but_historical_inputs_stay_frozen(self):
        for root in (self.base, self.current):
            shutil.rmtree(root / "registry/predicates/beta")
        config = copy.deepcopy(self.config)
        config["toolchains"]["successor"]["nargo"] = "new-version"
        config["packages"]["new_package"] = "successor"
        self.write_config(config)
        pins = (self.current / PINS).read_text().replace("SUCCESSOR_NARGO_VERSION=1.0.0-beta.25",
                                                       "SUCCESSOR_NARGO_VERSION=new-version")
        (self.current / PINS).write_text(pins)
        self.assertEqual([], self.findings())

    def test_all_repository_published_package_mappings_are_frozen(self):
        base = guard.snapshot_from_directory(REPO_ROOT)
        config = json.loads((REPO_ROOT / CONFIG).read_text())
        packages = set()
        for item in base.entries.values():
            document = item.data
            if document.get("version") == guard.V2_ENTRY_VERSION:
                packages.add(document["source"]["circuit"])
                for path in guard._v2_binding_paths(base, item.path):
                    packages.add(json.loads(base.read_bytes(path))["circuit"])
            else:
                packages.add(document["circuit"]["name"])
        self.assertTrue(packages)
        for package in sorted(packages):
            with self.subTest(package=package):
                changed = copy.deepcopy(config)
                changed["packages"][package] = "tampered"
                current = copy.copy(base)
                current._read_bytes = lambda path: (
                    json.dumps(changed).encode() if path == CONFIG else base.read_bytes(path)
                )
                self.assertIn("immutable package toolchain mapping", "\n".join(guard.check_immutability(base, current)))

    def test_git_history_cli_rejects_lane_only_change(self):
        subprocess.run(["git", "init", "-q", str(self.current)], check=True)
        subprocess.run(["git", "add", "."], cwd=self.current, check=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                        "commit", "-qm", "published"], cwd=self.current, check=True)
        config = copy.deepcopy(self.config)
        config["packages"]["zkc_alpha"] = "successor"
        self.write_config(config)
        for extra in ([], ["--exact-base"]):
            result = subprocess.run(
                [sys.executable, str(REPO_ROOT / "registry/check_immutability.py"),
                 "--base-ref", "HEAD", *extra], cwd=self.current, text=True, capture_output=True,
            )
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)
            self.assertIn("immutable package toolchain mapping", result.stdout)


if __name__ == "__main__":
    unittest.main()
