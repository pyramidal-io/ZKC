"""Predicate registry governance tests (Freedom Safeguard 4).

Covers the acceptance criteria of the registry-governance requirement:
the SDK can determine whether a predicate is inspectable/reviewed, refuses
opaque and non-reviewed predicates by default, records explicit overrides,
and registry entries remain non-exclusive.
"""

import copy
import hashlib
import json
import logging
import pathlib
import shutil
import sys
import tempfile
import unittest

from _inventory import IS_PUBLIC_SNAPSHOT, expected_entries

import _path  # noqa: F401  (sys.path side effect)
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import KYC_PROOF_TYPE, issue_kyc_credential, trusted_test_issuer

from zkc_crypto import ProofContext
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    OpaquePredicateError,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationErrorCode,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "registry"))
import validate as registry_validate  # noqa: E402

MASTER_SEED = 0x5EED
FORBIDDEN_KEYS = registry_validate.FORBIDDEN_KEYS


def repo_registry() -> PredicateRegistry:
    return PredicateRegistry.from_repo(REPO_ROOT)


def make_temp_tree(mutate_entry=None, drop_registry=False) -> tempfile.TemporaryDirectory:
    """Copy the minimal repo surface a registry needs into a temp tree."""
    tmp = tempfile.TemporaryDirectory()
    root = pathlib.Path(tmp.name)
    for rel in (
        "registry",
        "schemas/public-inputs",
        "schemas/public-input-bindings",
        "artifacts/bindings",
    ):
        shutil.copytree(REPO_ROOT / rel, root / rel)
    shutil.copy2(
        REPO_ROOT / "schemas/public-input-binding-v1.schema.json",
        root / "schemas/public-input-binding-v1.schema.json",
    )
    (root / "noir").mkdir()
    shutil.copy2(REPO_ROOT / "noir/Nargo.toml", root / "noir/Nargo.toml")
    for circuit_dir in (REPO_ROOT / "noir").iterdir():
        src = circuit_dir / "src"
        if src.is_dir():
            shutil.copytree(src, root / "noir" / circuit_dir.name / "src")
            manifest = circuit_dir / "Nargo.toml"
            if manifest.is_file():
                shutil.copy2(manifest, root / "noir" / circuit_dir.name / "Nargo.toml")
    if drop_registry:
        shutil.rmtree(root / "registry" / "predicates")
    if mutate_entry is not None:
        for entry_path in (root / "registry" / "predicates").glob("*/*/entry.json"):
            entry = json.loads(entry_path.read_text())
            mutated = mutate_entry(entry, entry_path)
            if mutated is not None:
                entry_path.write_text(json.dumps(mutated, indent=2))
    return tmp


def make_request(registry_root=REPO_ROOT, proof_types=None, timestamp=1_700_000):
    context = ProofContext.verifier_session("did:zkc:verifier", 0xABCDEF, timestamp)
    proof_types = proof_types or [KYC_PROOF_TYPE]
    return ProofRequest(
        proof_types=proof_types,
        # Parameter blocks only for requested proof types: a block for an
        # unrequested type is refused before the opaque gate (spec 6.2.1).
        parameters={
            KYC_PROOF_TYPE: {
                "requiredLevel": 2,
                "requiredAttributes": [True, False, False, False, False],
            }
        } if KYC_PROOF_TYPE in proof_types else {},
        context=context,
        trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
    )


def make_client(registry, provider=None):
    return HolderClient.from_seed(
        MASTER_SEED, registry, StubBackend(), accumulator_provider=provider
    )


class RegistryValidationTests(unittest.TestCase):
    def test_repo_registry_is_valid(self):
        findings = registry_validate.validate_registry(REPO_ROOT)
        self.assertEqual(findings.errors, [], findings.errors)

    def test_repo_registry_validates_against_artifact_manifest_when_present(self):
        manifest = REPO_ROOT / "artifacts" / "build" / "manifest.json"
        if not manifest.is_file():
            self.skipTest("artifact manifest not generated locally")
        findings = registry_validate.validate_registry(REPO_ROOT, manifest)
        self.assertEqual(findings.errors, [], findings.errors)

    def test_rebind_binding_contract_successors_have_distinct_cryptographic_identities(self):
        """A new proof-type label is insufficient: successor proofs must not
        verify under the predecessor statement's ACIR or verification key.

        The manifest is the always-available, pinned record of those identities;
        the live Barretenberg counterpart cross-wires real proofs when the
        pinned toolchain is installed.
        """
        manifest = json.loads((REPO_ROOT / "artifacts" / "manifest.json").read_text())
        circuits = {entry["name"]: entry for entry in manifest["circuits"]}
        pairs = (
            ("zkc_credential_rebind", "zkc_credential_rebind_binding_v2"),
            ("zkc_credential_rebind_v2", "zkc_credential_rebind_v2_binding_v2"),
        )
        for predecessor, successor in pairs:
            with self.subTest(predecessor=predecessor, successor=successor):
                self.assertIn(predecessor, circuits)
                self.assertIn(successor, circuits)
                for identity in ("acirHash", "vkHash", "vkSha256"):
                    self.assertNotEqual(
                        circuits[predecessor][identity],
                        circuits[successor][identity],
                        f"{successor} reuses {predecessor}'s {identity}; "
                        "a separate package/proof type is not cryptographic identity separation",
                    )

    def test_all_circuit_proof_types_are_seeded(self):
        registry = repo_registry()
        published = set()
        for encoder in (REPO_ROOT / "schemas" / "public-inputs").glob("*.json"):
            published.update(json.loads(encoder.read_text())["proofTypes"])
        self.assertEqual(set(registry.proof_types()), published)

    def test_tampered_circuit_source_fails_validation(self):
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            source = root / "noir" / "zkc_kyc" / "src" / "main.nr"
            source.write_text(source.read_text() + "\n// tampered\n")
            findings = registry_validate.validate_registry(root)
            self.assertTrue(
                any("immutable" in error for error in findings.errors), findings.errors
            )

    def test_exclusivity_fields_are_rejected(self):
        for forbidden in ("canonical", "mandatory", "default"):
            def mutate(entry, path, key=forbidden):
                if entry["predicateId"] == "zkc-kyc":
                    entry[key] = True
                    return entry
                return None

            with make_temp_tree(mutate_entry=mutate) as tmp:
                findings = registry_validate.validate_registry(pathlib.Path(tmp))
                self.assertTrue(
                    any("Freedom Safeguard 1" in error for error in findings.errors),
                    f"{forbidden}: {findings.errors}",
                )

    def test_schema_defines_no_exclusivity_fields(self):
        schema = json.loads(
            (REPO_ROOT / "registry" / "schema" / "predicate-entry.schema.json").read_text()
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

        property_names = {key.lower() for key in keys_of(schema)}
        self.assertFalse(property_names & set(FORBIDDEN_KEYS))

    def test_multiple_entries_for_same_proof_type_are_allowed(self):
        # Predicate pluralism: a second, independent entry for an existing
        # proof type must validate cleanly (never a duplicate error).
        def clone(entry, path):
            return None

        with make_temp_tree(mutate_entry=clone) as tmp:
            root = pathlib.Path(tmp)
            original = json.loads(
                (root / "registry/predicates/zkc-kyc/1.0.0/entry.json").read_text()
            )
            duplicate = copy.deepcopy(original)
            duplicate["predicateId"] = "alt-kyc"
            duplicate["author"] = {"name": "Independent author"}
            target = root / "registry/predicates/alt-kyc/1.0.0/entry.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(duplicate, indent=2))
            findings = registry_validate.validate_registry(root)
            self.assertEqual(findings.errors, [], findings.errors)
            registry = PredicateRegistry.from_repo(root)
            entries = registry.resolve_all(KYC_PROOF_TYPE)
            self.assertEqual(
                sorted(e.predicate_id for e in entries),
                ["alt-kyc", "community-kyc", "zkc-kyc"],
            )

    def test_same_lineage_circuit_successor_cannot_reuse_selection_identity(self):
        # Both predecessors publish the v1 entry shape used by this mutation.
        # Keep the full private-source fixture and exercise the same invariant
        # against a published predecessor in the public snapshot.
        entry_version = "3.0.0" if IS_PUBLIC_SNAPSHOT else "5.0.0"
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            original = json.loads(
                (root / f"registry/predicates/zkc-kyc/{entry_version}/entry.json").read_text()
            )
            successor = copy.deepcopy(original)
            successor["entryVersion"] = "99.0.0"
            successor["activation"]["supersedes"] = (
                "zkc-kyc@4.0.0" if IS_PUBLIC_SNAPSHOT else f"zkc-kyc@{entry_version}"
            )
            target = root / "registry/predicates/zkc-kyc/99.0.0/entry.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(successor, indent=2))

            findings = registry_validate.validate_registry(root)
            joined = "\n".join(findings.errors)
            self.assertIn("distinct proof type", joined)
            self.assertIn("circuit source package", joined)
            self.assertIn("publicInputEncoder", joined)

    def test_same_lineage_circuit_successor_is_fully_additive(self):
        # Both predecessors publish the v1 entry shape used by this mutation.
        # Keep the full private-source fixture and exercise the same invariant
        # against a published predecessor in the public snapshot.
        entry_version = "3.0.0" if IS_PUBLIC_SNAPSHOT else "5.0.0"
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            original = json.loads(
                (root / f"registry/predicates/zkc-kyc/{entry_version}/entry.json").read_text()
            )
            successor = copy.deepcopy(original)
            successor["entryVersion"] = "99.0.0"
            successor["proofTypes"] = ["zkc:proof:kyc_registry_fixture:v1"]
            successor["circuit"]["name"] = "zkc_kyc_registry_fixture"
            successor["circuit"]["sourcePath"] = "noir/zkc_kyc_registry_fixture/src/main.nr"
            successor["publicInputEncoder"] = "schemas/public-inputs/zkc_kyc_registry_fixture.json"
            successor["activation"]["supersedes"] = (
                "zkc-kyc@4.0.0" if IS_PUBLIC_SNAPSHOT else f"zkc-kyc@{entry_version}"
            )

            old_source = root / original["circuit"]["sourcePath"]
            new_source = root / successor["circuit"]["sourcePath"]
            new_source.parent.mkdir(parents=True)
            new_source.write_bytes(old_source.read_bytes() + b"\n// additive registry fixture\n")
            (new_source.parents[1] / "Nargo.toml").write_text(
                '[package]\nname = "zkc_kyc_registry_fixture"\ntype = "bin"\n'
            )
            workspace = root / "noir/Nargo.toml"
            workspace.write_text(
                workspace.read_text().replace(
                    "\n]", '\n    "zkc_kyc_registry_fixture",\n]', 1
                )
            )
            successor["circuit"]["sourceSha256"] = hashlib.sha256(
                new_source.read_bytes()
            ).hexdigest()

            encoder = json.loads(
                (root / original["publicInputEncoder"]).read_text()
            )
            encoder["circuit"] = "zkc_kyc_registry_fixture"
            encoder["proofTypes"] = ["zkc:proof:kyc_registry_fixture:v1"]
            encoder_path = root / successor["publicInputEncoder"]
            encoder_path.write_text(json.dumps(encoder, indent=2))

            target = root / "registry/predicates/zkc-kyc/99.0.0/entry.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(successor, indent=2))

            findings = registry_validate.validate_registry(root)
            self.assertEqual(findings.errors, [], findings.errors)

    def test_validator_rejects_paths_outside_or_through_symlinks(self):
        def absolute_source(entry, path):
            if entry["predicateId"] == "zkc-kyc" and entry["entryVersion"] == "2.0.0":
                entry["circuit"]["sourcePath"] = "/etc/hosts"
                return entry
            return None

        with make_temp_tree(mutate_entry=absolute_source) as tmp:
            findings = registry_validate.validate_registry(pathlib.Path(tmp))
            self.assertTrue(
                any("repository-relative, not absolute" in error for error in findings.errors),
                findings.errors,
            )

        def traversing_encoder(entry, path):
            if entry["predicateId"] == "zkc-kyc" and entry["entryVersion"] == "2.0.0":
                entry["publicInputEncoder"] = "../outside.json"
                return entry
            return None

        with make_temp_tree(mutate_entry=traversing_encoder) as tmp:
            findings = registry_validate.validate_registry(pathlib.Path(tmp))
            self.assertTrue(
                any("normalized repository-relative path" in error for error in findings.errors),
                findings.errors,
            )

        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            entry_path = root / "registry/predicates/zkc-kyc/2.0.0/entry.json"
            document = json.loads(entry_path.read_text())
            source = root / document["circuit"]["sourcePath"]
            link = source.with_name("linked-main.nr")
            link.symlink_to(source.name)
            document["circuit"]["sourcePath"] = str(link.relative_to(root))
            entry_path.write_text(json.dumps(document, indent=2))
            findings = registry_validate.validate_registry(root)
            self.assertTrue(
                any("must not traverse a symlink" in error for error in findings.errors),
                findings.errors,
            )

    def test_validator_rejects_loose_or_mismatched_circuit_packages(self):
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            entry_path = root / "registry/predicates/zkc-kyc/2.0.0/entry.json"
            document = json.loads(entry_path.read_text())
            loose = root / "loose.nr"
            loose.write_text("fn main() {}\n")
            document["circuit"]["sourcePath"] = "loose.nr"
            document["circuit"]["sourceSha256"] = hashlib.sha256(
                loose.read_bytes()
            ).hexdigest()
            entry_path.write_text(json.dumps(document, indent=2))
            findings = registry_validate.validate_registry(root)
            self.assertTrue(
                any("circuit.sourcePath must be" in error for error in findings.errors),
                findings.errors,
            )

        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            manifest = root / "noir/zkc_kyc_v2/Nargo.toml"
            manifest.write_text(
                manifest.read_text().replace('name = "zkc_kyc_v2"', 'name = "wrong"')
            )
            findings = registry_validate.validate_registry(root)
            self.assertTrue(
                any("does not match circuit" in error for error in findings.errors),
                findings.errors,
            )

    def test_validator_rejects_unsafe_new_dependency_closures(self):
        cases = (
            ('missing = { path = "../missing" }', "directory is missing"),
            ('outside = { path = "../../../outside" }', "escapes the repository"),
        )
        for dependency, expected in cases:
            with self.subTest(expected=expected), make_temp_tree() as tmp:
                root = pathlib.Path(tmp)
                manifest = root / "noir/zkc_kyc_v2/Nargo.toml"
                manifest.write_text(
                    manifest.read_text() + f"\nmissing_fixture = {{ path = \"../missing\" }}\n"
                    if "missing" in dependency
                    else manifest.read_text() + "\noutside_fixture = { path = \"../../../outside\" }\n"
                )
                findings = registry_validate.validate_registry(root)
                self.assertTrue(
                    any(expected in error for error in findings.errors), findings.errors
                )

        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            real_dependency = root / "noir/real_dep"
            real_dependency.mkdir()
            (real_dependency / "Nargo.toml").write_text(
                '[package]\nname = "real_dep"\ntype = "lib"\n'
            )
            (root / "noir/link_dep").symlink_to("real_dep", target_is_directory=True)
            manifest = root / "noir/zkc_kyc_v2/Nargo.toml"
            manifest.write_text(
                manifest.read_text() + '\nlinked_fixture = { path = "../link_dep" }\n'
            )
            findings = registry_validate.validate_registry(root)
            self.assertTrue(
                any("must not traverse a symlink" in error for error in findings.errors),
                findings.errors,
            )

        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            manifest = root / "noir/zkc_kyc_v2/Nargo.toml"
            template = root / "manifest-template.toml"
            template.write_text(manifest.read_text())
            manifest.unlink()
            manifest.symlink_to("../../manifest-template.toml")
            findings = registry_validate.validate_registry(root)
            self.assertTrue(
                any("must not contain symlinks" in error for error in findings.errors),
                findings.errors,
            )

    def test_validator_rejects_malformed_encoder_shapes_without_crashing(self):
        malformed = ({}, [], [1], None, {"proofTypes": None})
        for encoder in malformed:
            with self.subTest(encoder=encoder), make_temp_tree() as tmp:
                root = pathlib.Path(tmp)
                path = root / "schemas/public-inputs/zkc_kyc_v2.json"
                path.write_text(json.dumps(encoder))
                findings = registry_validate.validate_registry(root)
                self.assertTrue(
                    any("public-input encoder" in error for error in findings.errors),
                    findings.errors,
                )

    def test_validator_reports_unhashable_proof_type_without_crashing(self):
        def mutate(entry, path):
            if entry["predicateId"] == "zkc-kyc" and entry["entryVersion"] == "2.0.0":
                entry["proofTypes"] = [{"not": "a string"}]
                return entry
            return None

        with make_temp_tree(mutate_entry=mutate) as tmp:
            findings = registry_validate.validate_registry(pathlib.Path(tmp))
            self.assertTrue(
                any("invalid proof type" in error for error in findings.errors),
                findings.errors,
            )

    def test_artifact_manifest_must_bind_encoder_path(self):
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            circuits = {}
            for entry_path in (root / "registry/predicates").glob("*/*/entry.json"):
                entry = json.loads(entry_path.read_text())
                if entry.get("version") != "zkc:registry:predicate-entry:v1":
                    continue
                circuit = entry["circuit"]
                circuits[circuit["name"]] = {
                    "name": circuit["name"],
                    "scheme": circuit["scheme"],
                    "acirHash": circuit["acirHash"],
                    "vkHash": circuit["vkHash"],
                    "vkSha256": circuit["vkSha256"],
                    "publicInputEncoder": entry["publicInputEncoder"],
                }
            circuits["zkc_kyc_v2"]["publicInputEncoder"] = "schemas/public-inputs/wrong.json"
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"circuits": list(circuits.values())}))
            findings = registry_validate.validate_registry(root, manifest)
            self.assertTrue(
                any(
                    "publicInputEncoder does not match the artifact manifest" in error
                    for error in findings.errors
                ),
                findings.errors,
            )

    def test_empty_artifact_manifest_cannot_disable_cross_checks(self):
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"circuits": []}))
            findings = registry_validate.validate_registry(root, manifest)
            self.assertTrue(
                any("circuits array must not be empty" in error for error in findings.errors),
                findings.errors,
            )
            self.assertTrue(
                any("is not in the artifact manifest" in error for error in findings.errors),
                findings.errors,
            )

    def test_supersedes_must_stay_within_one_predicate_lineage(self):
        def mutate(entry, path):
            if entry["predicateId"] == "zkc-kyc" and entry["entryVersion"] == "2.0.0":
                entry["activation"]["supersedes"] = "community-kyc@1.0.0"
                return entry
            return None

        with make_temp_tree(mutate_entry=mutate) as tmp:
            findings = registry_validate.validate_registry(pathlib.Path(tmp))
            self.assertTrue(
                any("same predicate lineage 'zkc-kyc'" in error for error in findings.errors),
                findings.errors,
            )

    def test_same_lineage_successor_must_supersede_immediate_predecessor(self):
        def mutate(entry, path):
            if entry["predicateId"] == "zkc-kyc" and entry["entryVersion"] == "2.0.0":
                entry["activation"]["supersedes"] = None
                return entry
            return None

        with make_temp_tree(mutate_entry=mutate) as tmp:
            findings = registry_validate.validate_registry(pathlib.Path(tmp))
            self.assertTrue(
                any(
                    "immediate predecessor 'zkc-kyc@1.0.0'" in error
                    for error in findings.errors
                ),
                findings.errors,
            )

    def test_unreviewed_entry_without_evidence_fails_when_marked_reviewed(self):
        def mutate(entry, path):
            if entry["predicateId"] == "zkc-kyc":
                entry["review"]["evidence"] = []
                return entry
            return None

        with make_temp_tree(mutate_entry=mutate) as tmp:
            findings = registry_validate.validate_registry(pathlib.Path(tmp))
            self.assertTrue(
                any("review evidence" in error for error in findings.errors),
                findings.errors,
            )

    def test_self_attested_entry_without_evidence_fails(self):
        # Self-attestation is only meaningful if it is written down publicly.
        def mutate(entry, path):
            if entry["predicateId"] == "zkc-kyc":
                entry["review"]["status"] = "self_attested"
                entry["review"]["evidence"] = []
                return entry
            return None

        with make_temp_tree(mutate_entry=mutate) as tmp:
            findings = registry_validate.validate_registry(pathlib.Path(tmp))
            self.assertTrue(
                any("review evidence" in error for error in findings.errors),
                findings.errors,
            )

    def test_self_attested_entry_may_not_carry_a_review_date(self):
        # A date on a self-attested entry would read as a review completion
        # date; there was no review to complete.
        def mutate(entry, path):
            if entry["predicateId"] == "zkc-kyc":
                entry["review"]["reviewedAt"] = "2026-06-11T00:00:00Z"
                return entry
            return None

        with make_temp_tree(mutate_entry=mutate) as tmp:
            findings = registry_validate.validate_registry(pathlib.Path(tmp))
            self.assertTrue(
                any("reviewedAt must be null" in error for error in findings.errors),
                findings.errors,
            )

    def test_shipped_entries_claim_no_independent_review(self):
        # Ground truth for the whole registry: not one entry claims
        # 'reviewed'. Flipping an entry to 'reviewed' must be accompanied by
        # real, publicly recorded independent review — this test is the
        # tripwire that forces that conversation.
        statuses = {}
        for entry_path in sorted(
            (REPO_ROOT / "registry/predicates").glob("*/*/entry.json")
        ):
            document = json.loads(entry_path.read_text())
            statuses[f"{document['predicateId']}@{document['entryVersion']}"] = document[
                "review"
            ]["status"]
        self.assertNotIn("reviewed", set(statuses.values()), statuses)
        self.assertEqual(
            {key for key, status in statuses.items() if status == "self_attested"},
            expected_entries({
                "community-kyc@1.0.0",
                "zkc-aggregation@1.0.0",
                # The issuer-authenticated rebind successors: implemented and
                # author-verified, with activation deliberately withheld.
                "zkc-credential-rebind@5.0.0",
                "zkc-credential-rebind@6.0.0",
                "zkc-jurisdiction@3.0.0",
                "zkc-jurisdiction@4.0.0",
                "zkc-kyc@1.0.0",
                "zkc-kyc@4.0.0",
                "zkc-remaining-predicates@7.0.0",
                "zkc-remaining-predicates@8.0.0",
            }),
            statuses,
        )
        self.assertEqual(
            {key for key, status in statuses.items() if status == "draft"},
            expected_entries({
                "community-kyc@2.0.0",
                "community-kyc@3.0.0",
                "zkc-aggregation@2.0.0",
                "zkc-aggregation@3.0.0",
                "zkc-credential-rebind@7.0.0",
                "zkc-credential-rebind@8.0.0",
                "zkc-credential-rebind@9.0.0",
                "zkc-jurisdiction@5.0.0",
                "zkc-jurisdiction@6.0.0",
                "zkc-jurisdiction@7.0.0",
                "zkc-jurisdiction@8.0.0",
                "zkc-kyc@2.0.0",
                "zkc-kyc@3.0.0",
                "zkc-kyc@5.0.0",
                "zkc-remaining-predicates@9.0.0",
                "zkc-remaining-predicates@10.0.0",
                "zkc-remaining-predicates@11.0.0",
                "zkc-remaining-predicates@12.0.0",
                "zkc-remaining-predicates@13.0.0",
                "zkc-remaining-predicates@14.0.0",
                "zkc-selective-disclosure@1.0.0",
                "zkc-selective-disclosure@2.0.0",
                "zkc-selective-disclosure@3.0.0",
                "zkc-selective-disclosure@4.0.0",
            }),
            statuses,
        )
        self.assertEqual(
            {key for key, status in statuses.items() if status == "deprecated"},
            expected_entries({
                # Unauthenticated credential-rebind lineage (security containment).
                "zkc-credential-rebind@1.0.0",
                "zkc-credential-rebind@2.0.0",
                "zkc-credential-rebind@3.0.0",
                "zkc-credential-rebind@4.0.0",
                "zkc-jurisdiction@1.0.0",
                "zkc-jurisdiction@2.0.0",
                "zkc-remaining-predicates@1.0.0",
                "zkc-remaining-predicates@2.0.0",
                "zkc-remaining-predicates@3.0.0",
                "zkc-remaining-predicates@4.0.0",
                # validFrom outside the signed digest (security review 2026-10-04).
                "zkc-remaining-predicates@5.0.0",
                "zkc-remaining-predicates@6.0.0",
            }),
            statuses,
        )


class RegistryLoaderTests(unittest.TestCase):
    def test_from_repo_uses_governed_registry(self):
        registry = repo_registry()
        # Two entry lineages serve the KYC proof type (predicate pluralism);
        # resolve() applies the documented holder-local deterministic
        # tie-break, resolve_all() returns both.
        self.assertEqual(
            [e.predicate_id for e in registry.resolve_all(KYC_PROOF_TYPE)],
            ["community-kyc", "zkc-kyc"],
        )
        entry = registry.resolve(KYC_PROOF_TYPE)
        self.assertEqual(entry.predicate_id, "community-kyc")
        self.assertEqual(
            registry.resolve(KYC_PROOF_TYPE, preferred_predicate_id="zkc-kyc").predicate_id,
            "zkc-kyc",
        )
        # Honest status: nothing in this repository has been independently
        # reviewed, so the shipped entries are self-attested — usable by
        # default (they publish review evidence), but NOT `reviewed`.
        self.assertEqual(entry.review_status, "self_attested")
        self.assertTrue(entry.inspectable)
        self.assertTrue(registry.inspectable(KYC_PROOF_TYPE))
        self.assertFalse(registry.reviewed(KYC_PROOF_TYPE))
        self.assertTrue(registry.usable_by_default(KYC_PROOF_TYPE))

        # Deprecated identities never resolve by default (fail closed);
        # inspecting them needs the explicit allow_unaccepted opt-in.
        self.assertIsNone(registry.resolve("zkc:proof:credential_rebind:v2"))
        linkable_successor = registry.resolve(
            "zkc:proof:credential_rebind:v2", allow_unaccepted=True
        )
        self.assertEqual(linkable_successor.predicate_id, "zkc-credential-rebind")
        self.assertEqual(linkable_successor.entry_version, "3.0.0")
        self.assertEqual(linkable_successor.circuit, "zkc_credential_rebind_binding_v2")
        authenticated_linkable = registry.resolve("zkc:proof:credential_rebind:v3")
        self.assertEqual(authenticated_linkable.entry_version, "5.0.0")
        self.assertEqual(authenticated_linkable.circuit, "zkc_credential_rebind_auth")
        self.assertTrue(authenticated_linkable.usable_by_default)
        authenticated_scoped = registry.resolve("zkc:proof:rebind:v4")
        self.assertEqual(authenticated_scoped.entry_version, "6.0.0")
        self.assertEqual(authenticated_scoped.circuit, "zkc_credential_rebind_auth_v2")
        self.assertTrue(authenticated_scoped.usable_by_default)
        # The deprecated lineage stays refused by the holder default.
        for deprecated in ("zkc:proof:credential_rebind:v1", "zkc:proof:rebind:v2"):
            self.assertIsNone(registry.resolve(deprecated), deprecated)
            self.assertFalse(
                registry.resolve(deprecated, allow_unaccepted=True).usable_by_default,
                deprecated,
            )

        scoped_successor = registry.resolve("zkc:proof:rebind:v3", allow_unaccepted=True)
        self.assertEqual(scoped_successor.predicate_id, "zkc-credential-rebind")
        self.assertEqual(scoped_successor.entry_version, "4.0.0")
        self.assertEqual(scoped_successor.circuit, "zkc_credential_rebind_v2_binding_v2")

    def test_legacy_encoder_scan_fallback(self):
        with make_temp_tree(drop_registry=True) as tmp:
            registry = PredicateRegistry.from_repo(pathlib.Path(tmp))
            entry = registry.resolve(KYC_PROOF_TYPE)
            self.assertIsNotNone(entry)
            self.assertEqual(entry.circuit, "zkc_kyc")

    def test_loader_excludes_hash_mismatched_entries_fail_closed(self):
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            source = root / "noir" / "zkc_kyc" / "src" / "main.nr"
            source.write_text(source.read_text() + "\n// tampered\n")
            registry = PredicateRegistry.from_registry_dir(root)
            self.assertIsNone(registry.resolve(KYC_PROOF_TYPE))
            self.assertFalse(registry.inspectable(KYC_PROOF_TYPE))

    def test_loader_excludes_registry_paths_outside_the_local_copy(self):
        def mutate(entry, path):
            if entry["predicateId"] == "zkc-kyc" and entry["entryVersion"] == "2.0.0":
                entry["circuit"]["sourcePath"] = "/etc/hosts"
                return entry
            return None

        with make_temp_tree(mutate_entry=mutate) as tmp:
            registry = PredicateRegistry.from_registry_dir(pathlib.Path(tmp))
            self.assertIsNone(registry.resolve("zkc:proof:kyc:v2"))

    def test_loader_excludes_invalid_or_malformed_encoders(self):
        for contents in ("{not json", json.dumps({}), json.dumps([{"truthy": True}])):
            with self.subTest(contents=contents), make_temp_tree() as tmp:
                root = pathlib.Path(tmp)
                (root / "schemas/public-inputs/zkc_kyc_v2.json").write_text(contents)
                registry = PredicateRegistry.from_registry_dir(root)
                self.assertIsNone(registry.resolve("zkc:proof:kyc:v2"))

    def test_loader_excludes_malformed_registry_metadata(self):
        mutations = (
            ("author", lambda document: document.update(author=[])),
            ("evidence", lambda document: document["review"].update(evidence=None)),
            ("predicateId", lambda document: document.update(predicateId=17)),
            ("entryVersion", lambda document: document.update(entryVersion={})),
        )
        for name, mutate in mutations:
            with self.subTest(field=name), make_temp_tree() as tmp:
                root = pathlib.Path(tmp)
                entry_path = root / "registry/predicates/zkc-kyc/2.0.0/entry.json"
                document = json.loads(entry_path.read_text())
                mutate(document)
                entry_path.write_text(json.dumps(document))
                registry = PredicateRegistry.from_registry_dir(root)
                self.assertIsNone(registry.resolve("zkc:proof:kyc:v2"))

    def test_unknown_predicate_is_not_inspectable_or_reviewed(self):
        registry = repo_registry()
        self.assertIsNone(registry.resolve("zkc:proof:secret-scoring:v1"))
        self.assertFalse(registry.inspectable("zkc:proof:secret-scoring:v1"))
        self.assertFalse(registry.reviewed("zkc:proof:secret-scoring:v1"))

    def test_resolve_prefers_stronger_assurance_holder_locally(self):
        # Preference ladder: reviewed > self_attested > everything else. Both
        # added lineages sort BEFORE the shipped ones, so a hit on the ladder
        # (not the alphabetical tie-break) is what selects the entry.
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            original = json.loads(
                (root / "registry/predicates/zkc-kyc/1.0.0/entry.json").read_text()
            )

            draft = copy.deepcopy(original)
            draft["predicateId"] = "aaa-draft-kyc"  # sorts first of all
            draft["review"]["status"] = "draft"
            draft["review"]["evidence"] = []
            draft["activation"]["activatedAt"] = None
            target = root / "registry/predicates/aaa-draft-kyc/1.0.0/entry.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(draft, indent=2))

            registry = PredicateRegistry.from_registry_dir(root)
            # With no `reviewed` entry present, self_attested wins over draft.
            resolved = registry.resolve(KYC_PROOF_TYPE)
            self.assertEqual(resolved.review_status, "self_attested")
            self.assertNotEqual(resolved.predicate_id, "aaa-draft-kyc")
            self.assertEqual(
                set(registry.statuses(KYC_PROOF_TYPE)), {"draft", "self_attested"}
            )
            self.assertEqual(len(registry.resolve_all(KYC_PROOF_TYPE)), 3)

            # Introduce an independently reviewed lineage: it now wins, even
            # though it still sorts after the self-attested ones would not.
            reviewed = copy.deepcopy(original)
            reviewed["predicateId"] = "aab-reviewed-kyc"
            reviewed["review"]["status"] = "reviewed"
            reviewed["review"]["reviewedAt"] = "2026-07-31T00:00:00Z"
            target = root / "registry/predicates/aab-reviewed-kyc/1.0.0/entry.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(reviewed, indent=2))
            registry = PredicateRegistry.from_registry_dir(root)
            self.assertEqual(
                registry.resolve(KYC_PROOF_TYPE).predicate_id, "aab-reviewed-kyc"
            )

            # Explicit holder-local preference can still pick any entry.
            preferred = registry.resolve(
                KYC_PROOF_TYPE, preferred_predicate_id="aaa-draft-kyc"
            )
            self.assertEqual(preferred.predicate_id, "aaa-draft-kyc")


def _unreviewed_kyc_tree():
    # Pluralism-aware: EVERY entry serving the KYC proof type must drop to a
    # status outside the holder's accepted set, otherwise another lineage's
    # usable entry still covers the type (which is exactly what pluralism is
    # for). `in_review` is outside DEFAULT_ACCEPTED_STATUSES.
    def mutate(entry, path):
        if KYC_PROOF_TYPE in entry["proofTypes"]:
            entry["review"]["status"] = "in_review"
            entry["review"]["reviewedAt"] = None
            entry["activation"]["activatedAt"] = None
            return entry
        return None

    return make_temp_tree(mutate_entry=mutate)


class HolderRefusalTests(unittest.TestCase):
    def _client_with_credential(self, registry):
        provider = LocalAccumulatorProvider()
        client = make_client(registry, provider=provider)
        client.store_credential(
            issue_kyc_credential(
                master_seed=MASTER_SEED,
                credential_id=42,
                expires_at=2_000_000,
                provider=provider,
            )
        )
        return client

    def test_opaque_predicate_refused_by_default(self):
        client = make_client(repo_registry())
        request = make_request(proof_types=["zkc:proof:secret-scoring:v1"])
        with self.assertRaises(OpaquePredicateError):
            generate_unauthenticated_linkable(client, request)
        # Refused before the Safeguard 6 opt-in is recorded: no record at all.
        self.assertEqual(client.override_log, [])

    def test_non_reviewed_predicate_refused_by_default(self):
        with _unreviewed_kyc_tree() as tmp:
            registry = PredicateRegistry.from_registry_dir(pathlib.Path(tmp))
            client = self._client_with_credential(registry)
            with self.assertRaises(OpaquePredicateError) as ctx:
                generate_unauthenticated_linkable(client, make_request())
            self.assertIn("in_review", str(ctx.exception))
            self.assertEqual(client.override_log, [])

    def test_non_reviewed_override_is_logged_and_recorded(self):
        with _unreviewed_kyc_tree() as tmp:
            registry = PredicateRegistry.from_registry_dir(pathlib.Path(tmp))
            client = self._client_with_credential(registry)
            with self.assertLogs("zkc.holder", level=logging.WARNING) as logs:
                envelope = generate_unauthenticated_linkable(client, make_request(), allow_opaque=True)
            self.assertEqual(envelope["version"], "zkc:proof:v1")
            self.assertTrue(
                any("OPAQUE PREDICATE OPT-IN" in line for line in logs.output)
            )
            self.assertEqual(
                [r["kind"] for r in client.override_log], ["UNAUTHENTICATED", "UNREVIEWED"]
            )
            record = client.override_log[1]
            self.assertEqual(record["proofType"], KYC_PROOF_TYPE)
            self.assertEqual(record["kind"], "UNREVIEWED")
            # Deterministic holder-local tie-break picks the first entry.
            self.assertEqual(record["predicateId"], "community-kyc")

    def test_opaque_override_is_recorded_before_capability_failure(self):
        from zkc_holder import BackendUnavailableError

        client = make_client(repo_registry())
        request = make_request(proof_types=["zkc:proof:secret-scoring:v1"])
        with self.assertLogs("zkc.holder", level=logging.WARNING):
            with self.assertRaises(BackendUnavailableError):
                generate_unauthenticated_linkable(client, request, allow_opaque=True)
        self.assertEqual(
            [r["kind"] for r in client.override_log], ["UNAUTHENTICATED", "OPAQUE"]
        )


class VerifierReviewStatusTests(unittest.TestCase):
    def _roundtrip(self, registry_root, accepted_review_statuses):
        registry = PredicateRegistry.from_repo(registry_root)
        provider = LocalAccumulatorProvider()
        client = make_client(registry, provider=provider)
        client.store_credential(
            issue_kyc_credential(
                master_seed=MASTER_SEED,
                credential_id=42,
                expires_at=2_000_000,
                provider=provider,
            )
        )
        # Generate against the registry as-is; override if non-reviewed so the
        # verifier-side policy is what decides.
        envelope = generate_unauthenticated_linkable(client, make_request(), allow_opaque=True)
        issuer = trusted_test_issuer()
        policy = VerifierTrustPolicy(
            issuers=(
                VerifierTrustedIssuer(
                    issuer_id=issuer.issuer_id,
                    public_key_x=issuer.public_key_x,
                    public_key_y=issuer.public_key_y,
                    proof_types=(KYC_PROOF_TYPE,),
                ),
            ),
            accepted_review_statuses=accepted_review_statuses,
        )
        verifier = ZKCVerifier(registry_root, policy, StubVerifyBackend())
        request = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 2,
                    "requiredAttributes": [True, False, False, False, False],
                }
            },
            context=ProofContext.verifier_session("did:zkc:verifier", 0xABCDEF, 1_700_000),
            accumulator_states={
                issuer.issuer_id: IssuerAccumulatorState(
                    current_epoch=provider.current_epoch(issuer.issuer_id),
                    roots=provider.roots(issuer.issuer_id),
                )
            },
        )
        return verifier.verify(envelope, request)

    def test_policy_requiring_reviewed_rejects_self_attested_repo_predicate(self):
        # The honest-status invariant: NO entry in this repository has been
        # independently reviewed, so a verifier that demands independent
        # review must reject this registry outright. If this test ever starts
        # passing "valid", either a genuine independent review landed (update
        # the entry to 'reviewed') or the gate has been weakened.
        result = self._roundtrip(REPO_ROOT, ("reviewed",))
        self.assertFalse(result.valid)
        self.assertIn(VerificationErrorCode.UNREVIEWED_PREDICATE, result.codes())

    def test_policy_accepting_self_attested_accepts_repo_predicate(self):
        # What the shipped example policy does (registry/verifiers/
        # example-exchange.json): accept self-attested entries explicitly,
        # because that is what this registry actually contains.
        result = self._roundtrip(REPO_ROOT, ("reviewed", "self_attested"))
        self.assertTrue(result.valid, result.to_dict())

    def test_policy_requiring_reviewed_rejects_unreviewed_predicate(self):
        with _unreviewed_kyc_tree() as tmp:
            result = self._roundtrip(pathlib.Path(tmp), ("reviewed",))
            self.assertFalse(result.valid)
            self.assertIn(VerificationErrorCode.UNREVIEWED_PREDICATE, result.codes())

    def test_policy_without_review_requirement_imposes_none(self):
        # Verifier-local choice: an empty accepted_review_statuses means no
        # review-status gate (only refuse-unknown applies globally).
        with _unreviewed_kyc_tree() as tmp:
            result = self._roundtrip(pathlib.Path(tmp), ())
            self.assertTrue(result.valid, result.to_dict())

    def test_policy_rejects_unknown_status_values(self):
        with self.assertRaises(ValueError):
            VerifierTrustPolicy(issuers=(), accepted_review_statuses=("blessed",))

    def test_verifier_exposes_registry_status(self):
        verifier = ZKCVerifier(
            REPO_ROOT, VerifierTrustPolicy(issuers=()), StubVerifyBackend()
        )
        self.assertEqual(
            verifier.predicate_review_statuses(KYC_PROOF_TYPE),
            ("self_attested", "self_attested"),  # one per serving entry
        )
        self.assertEqual(verifier.predicate_review_statuses("zkc:proof:nope:v1"), ())


if __name__ == "__main__":
    unittest.main()
