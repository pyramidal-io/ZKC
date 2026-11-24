"""Focused tests for the merge-base registry immutability guard."""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "registry"))
import check_immutability as guard  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry(predicate_id="alpha", version="1.0.0", proof_types=None, source_path="circuits/alpha.nr",
          encoder="encoders/alpha.json", source=b"fn main() {}\n", circuit_name="zkc_alpha"):
    if proof_types is None:
        proof_types = ["zkc:proof:alpha:v1"]
    return {
        "version": "zkc:registry:predicate-entry:v1",
        "predicateId": predicate_id,
        "entryVersion": version,
        "title": "fixture",
        "author": {"name": "fixture"},
        "proofTypes": proof_types,
        "circuit": {
            "name": circuit_name,
            "scheme": "ultra_honk",
            "sourcePath": source_path,
            "sourceSha256": sha256(source),
            "acirHash": "sha256:" + "a" * 64,
            "vkHash": "0x" + "b" * 64,
            "vkSha256": "sha256:" + "c" * 64,
        },
        "publicInputEncoder": encoder,
        "review": {"status": "draft", "evidence": [], "reviewedAt": None},
        "activation": {"activatedAt": None, "supersedes": None},
    }


def write_entry(root: pathlib.Path, document: dict, source: bytes = b"fn main() {}\n") -> pathlib.Path:
    path = root / "registry" / "predicates" / document["predicateId"] / document["entryVersion"] / "entry.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2))
    source_path = root / document["circuit"]["sourcePath"]
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(source)
    encoder_path = root / document["publicInputEncoder"]
    encoder_path.parent.mkdir(parents=True, exist_ok=True)
    encoder_path.write_text("{}")
    return path


def binding_document(document: dict, version: int = 1) -> dict:
    """A complete semantic fixture whose every mutable field is security-relevant."""
    return {
        "$schema": f"https://zkc.dev/schemas/public-input-binding-v{version}.schema.json",
        "version": f"zkc:public-input-bindings:v{version}",
        "circuit": document["circuit"]["name"],
        "encoder": document["publicInputEncoder"],
        "predicateTypes": {document["proofTypes"][0]: 1},
        "bindings": [
            {
                "name": "value",
                "camelName": "value",
                "class": "bound",
                "source": "policy:trustedValues",
                "check": "member_of",
                "group": "trusted_value",
            },
            {
                "name": "claim_binding",
                "camelName": "claimBinding",
                "class": "derived",
                "from": ["param:requiredValue", "context:value"],
                "note": "Recompute the claim binding from the authenticated requirement and context.",
            },
            {
                "name": "output",
                "camelName": "output",
                "class": "free",
                "justification": "The circuit authenticates this intended public output before disclosure.",
            },
        ],
    }


def write_binding_contract(root: pathlib.Path, document: dict, version: int = 1) -> pathlib.Path:
    path = guard._binding_path(document["publicInputEncoder"])
    if path is None:
        raise AssertionError("binding fixture requires a canonical public-input encoder path")
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(binding_document(document, version), indent=2))
    schema = root / f"schemas/public-input-binding-v{version}.schema.json"
    schema.parent.mkdir(parents=True, exist_ok=True)
    schema.write_text(json.dumps({"title": f"binding schema v{version}"}, indent=2))
    return target


def write_v2_fixture(root: pathlib.Path, *, reviewed: bool = False) -> tuple[pathlib.Path, pathlib.Path]:
    source_path = "noir/zkc_beta/src/main.nr"
    encoder_path = "schemas/public-inputs/zkc_beta.json"
    sidecar_path = "schemas/public-input-bindings/zkc_beta.json"
    schema_path = "schemas/public-input-binding-v1.schema.json"
    provenance_path = "registry/toolchains/beta.json"
    files = {
        source_path: b"fn main() {}\n",
        encoder_path: b"{}\n",
        sidecar_path: b"{}\n",
        schema_path: b"{}\n",
        provenance_path: b'{"nargo":"1.0.0"}\n',
        "artifacts/beta/acir.json": b"acir\n",
        "artifacts/beta/vk": b"vk\n",
    }
    for relative, payload in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    pin = lambda path: {"path": path, "sha256": "sha256:" + sha256(files[path])}
    status = "reviewed" if reviewed else "draft"
    entry_document = {
        "version": guard.V2_ENTRY_VERSION,
        "predicateId": "beta",
        "entryVersion": "1.0.0",
        "title": "fixture",
        "author": {"name": "fixture"},
        "proofTypes": ["zkc:proof:beta:v1"],
        "sourceId": "sha256:" + "1" * 64,
        "source": {
            "circuit": "zkc_beta",
            "packageRoot": "noir/zkc_beta",
            "files": [pin(source_path)],
        },
        "publicInputContract": {
            "encoder": pin(encoder_path),
            "bindingSidecar": pin(sidecar_path),
            "bindingSchema": pin(schema_path),
        },
        "review": {"status": status, "evidence": [], "reviewedAt": None},
        "supersedes": None,
    }
    entry_path = root / "registry/predicates/beta/1.0.0/entry.json"
    entry_path.parent.mkdir(parents=True, exist_ok=True)
    entry_path.write_text(json.dumps(entry_document, indent=2))
    binding_document = {
        "version": "zkc:registry:artifact-binding:v1",
        "predicateId": "beta",
        "entryVersion": "1.0.0",
        "sourceId": entry_document["sourceId"],
        "bindingId": "sha256:" + "2" * 64,
        "circuit": "zkc_beta",
        "scheme": "ultra_honk",
        "toolchain": {
            "id": "fixture",
            "nargo": "1.0.0",
            "noirc": "1.0.0+fixture",
            "bb": "1.0.0",
            "provenance": pin(provenance_path),
        },
        "buildProfile": "release",
        "artifactManifestKey": "beta@1.0.0/fixture",
        "artifacts": {
            "acir": "artifacts/beta/acir.json",
            "vk": "artifacts/beta/vk",
        },
        "acirHash": "sha256:" + "3" * 64,
        "vkHash": "0x" + "4" * 64,
        "vkSha256": "sha256:" + sha256(files["artifacts/beta/vk"]),
        "review": {"status": status, "evidence": [], "reviewedAt": None},
        "activation": {"activatedAt": None, "supersedes": None},
    }
    binding_path = entry_path.parent / "bindings" / ("2" * 64 + ".json")
    binding_path.parent.mkdir(exist_ok=True)
    binding_path.write_text(json.dumps(binding_document, indent=2))
    return entry_path, binding_path


class RegistryImmutabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base_root = pathlib.Path(self.tmp.name) / "base"
        self.current_root = pathlib.Path(self.tmp.name) / "current"
        self.source = b"fn main() {}\n"
        self.base_entry = entry(source=self.source)
        write_entry(self.base_root, self.base_entry, self.source)
        write_entry(self.current_root, copy.deepcopy(self.base_entry), self.source)

    def findings(self):
        return guard.check_immutability(
            guard.snapshot_from_directory(self.base_root),
            guard.snapshot_from_directory(self.current_root),
        )

    def current_document(self):
        path = self.current_root / "registry/predicates/alpha/1.0.0/entry.json"
        return path, json.loads(path.read_text())

    def replace_current(self, document):
        path, _ = self.current_document()
        path.write_text(json.dumps(document, indent=2))

    def install_binding_contract(self, version: int = 1):
        document = entry(encoder="schemas/public-inputs/zkc_alpha.json")
        self.base_entry = copy.deepcopy(document)
        paths = []
        for root in (self.base_root, self.current_root):
            write_entry(root, copy.deepcopy(document), self.source)
            paths.append(write_binding_contract(root, document, version))
        return paths

    def install_v2(self, *, reviewed: bool = False):
        return (
            write_v2_fixture(self.base_root, reviewed=reviewed),
            write_v2_fixture(self.current_root, reviewed=reviewed),
        )

    def test_v2_source_binding_artifacts_and_provenance_are_immutable(self):
        (_base_entry, _base_binding), (current_entry, current_binding) = self.install_v2()
        source = self.current_root / "noir/zkc_beta/src/main.nr"
        source.write_bytes(b"fn main() { /* changed */ }\n")
        self.assertIn("immutable v2 protected file changed", "\n".join(self.findings()))
        source.write_bytes(b"fn main() {}\n")

        binding = json.loads(current_binding.read_text())
        binding["toolchain"]["bb"] = "2.0.0"
        current_binding.write_text(json.dumps(binding, indent=2))
        self.assertIn("immutable binding field 'toolchain' changed", "\n".join(self.findings()))
        write_v2_fixture(self.current_root)

        (self.current_root / "artifacts/beta/vk").write_bytes(b"changed\n")
        self.assertIn("immutable binding artifact changed", "\n".join(self.findings()))
        (self.current_root / "artifacts/beta/vk").write_bytes(b"vk\n")

        (self.current_root / "registry/toolchains/beta.json").write_bytes(b"changed\n")
        self.assertIn("immutable toolchain provenance changed", "\n".join(self.findings()))

        current_entry.unlink()
        self.assertIn("base registry entry was deleted", "\n".join(self.findings()))

    def test_v2_binding_deletion_and_lifecycle_regression_fail_closed(self):
        (_base_entry, _base_binding), (current_entry, current_binding) = self.install_v2(
            reviewed=True
        )
        current_binding.unlink()
        self.assertIn("committed artifact binding is missing", "\n".join(self.findings()))
        write_v2_fixture(self.current_root, reviewed=True)

        binding = json.loads(current_binding.read_text())
        binding["review"]["status"] = "draft"
        current_binding.write_text(json.dumps(binding, indent=2))
        self.assertIn("binding review/activation/deprecation transition is not monotonic", "\n".join(self.findings()))
        write_v2_fixture(self.current_root, reviewed=True)

        source = json.loads(current_entry.read_text())
        source["review"]["status"] = "draft"
        current_entry.write_text(json.dumps(source, indent=2))
        self.assertIn("source review/deprecation transition is not monotonic", "\n".join(self.findings()))

    def test_v2_additive_binding_cannot_reuse_published_artifact_paths(self):
        self.install_v2()
        original_path = self.current_root / "registry/predicates/beta/1.0.0/bindings" / (
            "2" * 64 + ".json"
        )
        binding = json.loads(original_path.read_text())
        binding["bindingId"] = "sha256:" + "5" * 64
        added = original_path.with_name("5" * 64 + ".json")
        added.write_text(json.dumps(binding, indent=2))
        self.assertIn("new binding reuses a previously published artifact path", "\n".join(self.findings()))

    def test_review_status_and_evidence_are_status_blind(self):
        for status in ("draft", "in_review", "self_attested", "reviewed", "deprecated"):
            with self.subTest(status=status):
                _, document = self.current_document()
                document["review"] = {
                    "status": status,
                    "evidence": [f"reviews/{status}.md"],
                    "reviewedAt": "2026-01-01T00:00:00Z",
                }
                document["activation"] = {
                    "activatedAt": "2026-01-02T00:00:00Z", "supersedes": "alpha@0.9.0"
                }
                document["deprecation"] = {"reason": "superseded", "deprecatedAt": "2026-01-03T00:00:00Z"}
                self.replace_current(document)
                self.assertEqual([], self.findings())

    def test_allowed_nonidentity_metadata_changes(self):
        _, document = self.current_document()
        document["version"] = "future-metadata-version"
        document["title"] = "renamed fixture"
        document["author"] = {"name": "new maintainer", "url": "https://example.test"}
        self.replace_current(document)
        self.assertEqual([], self.findings())

    def test_rejects_deletion_of_a_base_entry(self):
        (self.current_root / "registry/predicates/alpha/1.0.0/entry.json").unlink()
        self.assertIn("was deleted", "\n".join(self.findings()))

    def test_rejects_every_identity_field_and_complete_circuit_block(self):
        fields = {
            "predicateId": "other",
            "entryVersion": "1.0.1",
            "proofTypes": ["zkc:proof:other:v1"],
        }
        for field, value in fields.items():
            with self.subTest(field=field):
                _, document = self.current_document()
                document[field] = value
                self.replace_current(document)
                self.assertIn(f"'{field}' changed", "\n".join(self.findings()))
                self.replace_current(copy.deepcopy(self.base_entry))
        for circuit_field in self.base_entry["circuit"]:
            with self.subTest(circuit_field=circuit_field):
                _, document = self.current_document()
                document["circuit"][circuit_field] = "modified"
                self.replace_current(document)
                self.assertIn("'circuit' changed", "\n".join(self.findings()))
                self.replace_current(copy.deepcopy(self.base_entry))
        _, document = self.current_document()
        document["publicInputEncoder"] = "encoders/other.json"
        self.replace_current(document)
        self.assertIn("'publicInputEncoder' changed", "\n".join(self.findings()))

    def test_reports_malformed_proof_types_without_crashing(self):
        _, document = self.current_document()
        document["proofTypes"] = [{"not": "hashable"}]
        self.replace_current(document)
        output = "\n".join(self.findings())
        self.assertIn("current proofTypes must be an array of strings", output)
        self.assertIn("'proofTypes' changed", output)

    def test_rejects_coordinated_source_hash_repin(self):
        changed = b"fn main() { // coordinated repin }\n"
        _, document = self.current_document()
        document["circuit"]["sourceSha256"] = sha256(changed)
        self.replace_current(document)
        (self.current_root / "circuits/alpha.nr").write_bytes(changed)
        output = "\n".join(self.findings())
        self.assertIn("'circuit' changed", output)
        self.assertIn("source bytes changed", output)

    def test_rejects_missing_and_comment_only_changed_base_source(self):
        source_path = self.current_root / "circuits/alpha.nr"
        for replacement, expected in ((None, "source was deleted"), (b"fn main() {} // comment\n", "source bytes changed")):
            with self.subTest(replacement=replacement):
                if replacement is None:
                    source_path.unlink(missing_ok=True)
                else:
                    source_path.write_bytes(replacement)
                self.assertIn(expected, "\n".join(self.findings()))
                source_path.write_bytes(self.source)

    def test_rejects_package_manifest_local_dependency_and_encoder_edits(self):
        manifest = (
            '[package]\nname = "alpha"\ntype = "bin"\n\n'
            '[dependencies]\nshared = { path = "../deps/shared" }\n'
        )
        for root in (self.base_root, self.current_root):
            (root / "circuits/Nargo.toml").write_text(manifest)
            dependency = root / "deps/shared"
            (dependency / "src").mkdir(parents=True)
            (dependency / "Nargo.toml").write_text(
                '[package]\nname = "shared"\ntype = "lib"\n'
            )
            (dependency / "src/lib.nr").write_text("pub fn shared() {}\n")

        mutations = (
            ("circuits/Nargo.toml", manifest + "\n# changed\n", "Nargo.toml"),
            ("deps/shared/src/lib.nr", "pub fn shared() { 1 }\n", "deps/shared/src/lib.nr"),
            ("encoders/alpha.json", '{"changed": true}\n', "public-input encoder bytes changed"),
        )
        for relative, changed, expected in mutations:
            with self.subTest(path=relative):
                target = self.current_root / relative
                original = target.read_text()
                target.write_text(changed)
                self.assertIn(expected, "\n".join(self.findings()))
                target.write_text(original)

    def test_rejects_representative_binding_contract_semantic_mutations(self):
        _, current_path = self.install_binding_contract()
        original = current_path.read_text()

        def reclassify_as_free(document):
            cell = document["bindings"][0]
            cell.clear()
            cell.update(
                {
                    "name": "value",
                    "camelName": "value",
                    "class": "free",
                    "justification": (
                        "The prover chooses this value and the circuit authenticates its use."
                    ),
                }
            )

        cases = (
            ("class", reclassify_as_free),
            ("source", lambda document: document["bindings"][0].update(source="param:value")),
            ("check", lambda document: document["bindings"][0].update(check="policy_range")),
            ("group", lambda document: document["bindings"][0].update(group="other_group")),
            (
                "from",
                lambda document: document["bindings"][1].update(
                    {"from": ["public:value"]}
                ),
            ),
            ("note", lambda document: document["bindings"][1].update(note="Different recomputation")),
            (
                "predicateTypes",
                lambda document: document["predicateTypes"].update(
                    {self.base_entry["proofTypes"][0]: 2}
                ),
            ),
            (
                "justification",
                lambda document: document["bindings"][2].update(
                    justification="A different security argument now applies to this output."
                ),
            ),
        )
        for field, mutate in cases:
            with self.subTest(field=field):
                document = json.loads(original)
                mutate(document)
                current_path.write_text(json.dumps(document, indent=2))
                self.assertIn(
                    "immutable public-input binding sidecar bytes changed",
                    "\n".join(self.findings()),
                )
                current_path.write_text(original)

    def test_rejects_apparent_free_to_bound_tightening(self):
        _, current_path = self.install_binding_contract()
        document = json.loads(current_path.read_text())
        free_cell = document["bindings"][2]
        free_cell.clear()
        free_cell.update(
            {
                "name": "output",
                "camelName": "output",
                "class": "bound",
                "source": "context:output",
            }
        )
        current_path.write_text(json.dumps(document, indent=2))
        self.assertIn(
            "immutable public-input binding sidecar bytes changed",
            "\n".join(self.findings()),
        )

    def test_rejects_noncanonical_base_schema_selector(self):
        base_path, current_path = self.install_binding_contract()
        original = json.loads(base_path.read_text())
        cases = (
            ("$schema", "https://zkc.dev/schemas/public-input-binding-v999.schema.json"),
            ("version", "zkc:public-input-bindings:v999"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                document = copy.deepcopy(original)
                document[field] = value
                encoded = json.dumps(document, indent=2)
                base_path.write_text(encoded)
                current_path.write_text(encoded)
                self.assertIn(
                    "does not declare the supported canonical schema selector",
                    "\n".join(self.findings()),
                )
                base_path.write_text(json.dumps(original, indent=2))
                current_path.write_text(json.dumps(original, indent=2))

    def test_legacy_noncanonical_encoder_has_no_implicit_binding_sidecar(self):
        for root in (self.base_root, self.current_root):
            sidecar = root / "schemas/public-input-bindings/alpha.json"
            sidecar.parent.mkdir(parents=True, exist_ok=True)
            sidecar.write_text("base legacy metadata\n")
        (self.current_root / "schemas/public-input-bindings/alpha.json").write_text(
            "changed legacy metadata\n"
        )
        self.assertEqual([], self.findings())

    def test_rejects_binding_sidecar_deletion(self):
        _, current_path = self.install_binding_contract()
        current_path.unlink()
        self.assertIn(
            "immutable public-input binding sidecar was deleted",
            "\n".join(self.findings()),
        )

    def test_rejects_binding_schema_change_and_deletion(self):
        self.install_binding_contract()
        schema = self.current_root / "schemas/public-input-binding-v1.schema.json"
        original = schema.read_text()
        for replacement, expected in (
            (json.dumps({"title": "rewritten semantics"}), "schema bytes changed"),
            (None, "schema was deleted"),
        ):
            with self.subTest(expected=expected):
                if replacement is None:
                    schema.unlink()
                else:
                    schema.write_text(replacement)
                self.assertIn(expected, "\n".join(self.findings()))
                schema.write_text(original)

    def test_v2_binding_selector_and_schema_are_supported_and_immutable(self):
        self.install_binding_contract(version=2)
        self.assertEqual([], self.findings())
        schema = self.current_root / "schemas/public-input-binding-v2.schema.json"
        original = schema.read_text()
        schema.write_text(json.dumps({"title": "rewritten v2 semantics"}))
        self.assertIn("schema bytes changed", "\n".join(self.findings()))
        schema.write_text(original)

    def test_coordinated_review_artifact_edits_do_not_bypass_sidecar_pin(self):
        _, current_path = self.install_binding_contract()
        document = json.loads(current_path.read_text())
        document["bindings"][0]["source"] = "param:attackerChosenValue"
        current_path.write_text(json.dumps(document, indent=2))
        for relative in (
            "docs/zkc_public_input_classification.md",
            "tests/python/test_public_input_bindings.py",
        ):
            target = self.current_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("coordinated approval artifact rewrite\n")
        self.assertIn(
            "immutable public-input binding sidecar bytes changed",
            "\n".join(self.findings()),
        )

    def test_shared_binding_contract_is_compared_once(self):
        _, current_path = self.install_binding_contract()
        shared = entry(
            predicate_id="independent",
            proof_types=["zkc:proof:alpha:v1"],
            encoder="schemas/public-inputs/zkc_alpha.json",
        )
        for root in (self.base_root, self.current_root):
            write_entry(root, copy.deepcopy(shared), self.source)
        current_path.write_text(current_path.read_text() + "\n")
        output = "\n".join(self.findings())
        self.assertEqual(output.count("binding sidecar bytes changed"), 1, output)

    def test_permits_new_additive_binding_contract(self):
        self.install_binding_contract()
        successor_source = b"fn main_v2() {}\n"
        successor = entry(
            version="2.0.0",
            proof_types=["zkc:proof:alpha:v2"],
            source_path="circuits/alpha-v2.nr",
            encoder="schemas/public-inputs/zkc_alpha_v2.json",
            source=successor_source,
            circuit_name="zkc_alpha_v2",
        )
        successor["activation"]["supersedes"] = "alpha@1.0.0"
        write_entry(self.current_root, successor, successor_source)
        write_binding_contract(self.current_root, successor)
        self.assertEqual([], self.findings())

    def test_rejects_same_lineage_successor_reusing_base_contracts(self):
        cases = (
            ("proofTypes", lambda document: document.update(proofTypes=["zkc:proof:alpha:v1"]), "proofTypes"),
            ("sourcePath", lambda document: document["circuit"].update(sourcePath="circuits/alpha.nr"), "sourcePath"),
            ("encoder", lambda document: document.update(publicInputEncoder="encoders/alpha.json"), "publicInputEncoder"),
        )
        for name, mutate, expected in cases:
            with self.subTest(case=name):
                document = entry(version="2.0.0", proof_types=["zkc:proof:beta:v1"],
                                 source_path="circuits/beta.nr", encoder="encoders/beta.json")
                mutate(document)
                write_entry(self.current_root, document)
                self.assertIn(expected, "\n".join(self.findings()))
                entry_path = self.current_root / "registry/predicates/alpha/2.0.0"
                for child in sorted(entry_path.rglob("*"), reverse=True):
                    if child.is_file():
                        child.unlink()
                entry_path.rmdir()

    def test_permits_distinct_same_lineage_successor(self):
        successor = entry(version="2.0.0", proof_types=["zkc:proof:alpha:v2"],
                          source_path="circuits/alpha-v2.nr", encoder="encoders/alpha-v2.json",
                          source=b"fn main_v2() {}\n")
        successor["activation"]["supersedes"] = "alpha@1.0.0"
        write_entry(self.current_root, successor, b"fn main_v2() {}\n")
        self.assertEqual([], self.findings())

    def test_rejects_same_lineage_successor_without_immediate_supersedes(self):
        successor = entry(version="2.0.0", proof_types=["zkc:proof:alpha:v2"],
                          source_path="circuits/alpha-v2.nr", encoder="encoders/alpha-v2.json",
                          source=b"fn main_v2() {}\n")
        write_entry(self.current_root, successor, b"fn main_v2() {}\n")
        output = "\n".join(self.findings())
        self.assertIn("activation.supersedes", output)
        self.assertIn("alpha@1.0.0", output)

    def test_permits_independent_lineage_proof_type_overlap(self):
        independent = entry(predicate_id="independent", proof_types=["zkc:proof:alpha:v1"],
                            source_path="circuits/independent.nr", encoder="encoders/independent.json")
        write_entry(self.current_root, independent)
        self.assertEqual([], self.findings())

    def _synthetic_merge(self, mutate):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "fixture@example.test"],
            cwd=root,
            check=True,
        )
        document = entry()
        write_entry(root, document, self.source)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()

        subprocess.run(["git", "switch", "-qc", "feature"], cwd=root, check=True)
        mutate(root)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "feature"], cwd=root, check=True)

        subprocess.run(["git", "switch", "-qc", "queue", base_sha], cwd=root, check=True)
        (root / "queued-predecessor.txt").write_text("already in merge group\n")
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "queued predecessor"], cwd=root, check=True)
        queue_base = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "merge", "--no-ff", "-q", "-m", "synthetic merge group", "feature"],
            cwd=root,
            check=True,
        )
        return subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "registry/check_immutability.py"),
                "--base-ref",
                queue_base,
            ],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_cli_compares_synthetic_merge_group_with_payload_base(self):
        def mutate(root):
            (root / "circuits/alpha.nr").write_bytes(b"fn main() { // changed }\n")

        result = self._synthetic_merge(mutate)
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("source bytes changed", result.stdout)

    def test_cli_synthetic_merge_permits_lifecycle_metadata(self):
        def mutate(root):
            path = root / "registry/predicates/alpha/1.0.0/entry.json"
            document = json.loads(path.read_text())
            document["review"] = {
                "status": "in_review",
                "evidence": ["review underway"],
                "reviewedAt": None,
            }
            path.write_text(json.dumps(document, indent=2))

        result = self._synthetic_merge(mutate)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("no immutable registry changes", result.stdout)

    def test_cli_exact_push_base_detects_force_rewrite_deletion(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        fixture_root = pathlib.Path(temp.name)
        root = fixture_root / "author"
        remote = fixture_root / "remote.git"
        runner = fixture_root / "runner"
        root.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        subprocess.run(
            ["git", "--git-dir", str(remote), "config", "uploadpack.allowAnySHA1InWant", "true"],
            check=True,
        )
        subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "fixture@example.test"],
            cwd=root,
            check=True,
        )
        (root / "initial.txt").write_text("initial\n")
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=root, check=True)
        subprocess.run(["git", "branch", "-M", "main"], cwd=root, check=True)
        subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=root, check=True)
        subprocess.run(["git", "push", "-qu", "origin", "main"], cwd=root, check=True)
        initial_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()

        write_entry(root, entry(), self.source)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "publish entry"], cwd=root, check=True)
        subprocess.run(["git", "push", "-q", "origin", "main"], cwd=root, check=True)
        before_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()

        subprocess.run(["git", "switch", "-qC", "rewritten", initial_sha], cwd=root, check=True)
        (root / "replacement.txt").write_text("force-pushed replacement\n")
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "rewrite history"], cwd=root, check=True)
        subprocess.run(
            ["git", "push", "-q", "--force", "origin", "HEAD:main"],
            cwd=root,
            check=True,
        )
        subprocess.run(
            [
                "git", "clone", "-q", "--no-local", "--single-branch",
                "--branch", "main", str(remote), str(runner),
            ],
            check=True,
        )
        absent = subprocess.run(
            ["git", "cat-file", "-e", f"{before_sha}^{{commit}}"],
            cwd=runner,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        self.assertNotEqual(0, absent.returncode, "fresh checkout unexpectedly retained before-SHA")
        subprocess.run(
            ["git", "fetch", "-q", "--no-tags", "origin", before_sha],
            cwd=runner,
            check=True,
        )
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "registry/check_immutability.py"),
                "--base-ref",
                before_sha,
                "--exact-base",
            ],
            cwd=runner,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("base registry entry was deleted", result.stdout)
        self.assertIn("against exact base", result.stdout)


if __name__ == "__main__":
    unittest.main()
