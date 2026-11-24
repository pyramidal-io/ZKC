"""Selector-free circuit identity is unique; discovery pluralism is preserved."""

import copy
import importlib.util
import itertools
import json
import pathlib
import shutil
import unittest
from unittest import mock

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from test_predicate_registry import (
    KYC_PROOF_TYPE, make_client, make_request, make_temp_tree as minimal_temp_tree, registry_validate,
)
from zkc_holder import ConstraintViolationError, OpaquePredicateError, PredicateRegistry
from zkc_registry.encoder_resolution import encoder_circuits
from zkc_verifier import StubVerifyBackend, VerificationKeyStore, VerifierTrustPolicy, ZKCVerifier
from zkc_verifier.errors import VerificationErrorCode as Code, VerificationResult

ROOT = pathlib.Path(__file__).resolve().parents[2]


def make_temp_tree(**kwargs):
    tmp = minimal_temp_tree(**kwargs)
    root = pathlib.Path(tmp.name)
    shutil.copy2(ROOT / "artifacts/manifest.json", root / "artifacts/manifest.json")
    return tmp


def add_duplicate(root, name="zkc_kyc_zz"):
    encoder_path = root / "schemas/public-inputs/zkc_kyc.json"
    encoder = json.loads(encoder_path.read_text())
    encoder["circuit"] = name
    (encoder_path.parent / f"{name}.json").write_text(json.dumps(encoder))
    shutil.copytree(root / "noir/zkc_kyc", root / "noir" / name)
    manifest = root / "noir" / name / "Nargo.toml"
    manifest.write_text(manifest.read_text().replace('name = "zkc_kyc"', f'name = "{name}"'))
    workspace = root / "noir/Nargo.toml"
    workspace.write_text(workspace.read_text().replace("members = [", f'members = ["{name}",', 1))
    entry = json.loads((root / "registry/predicates/zkc-kyc/1.0.0/entry.json").read_text())
    entry["predicateId"] = "aaa-kyc"
    entry["circuit"]["name"] = name
    entry["circuit"]["sourcePath"] = f"noir/{name}/src/main.nr"
    entry["publicInputEncoder"] = f"schemas/public-inputs/{name}.json"
    target = root / "registry/predicates/aaa-kyc/1.0.0/entry.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(entry))


class ProofTypeResolutionTests(unittest.TestCase):
    def test_cross_lineage_collision_fails_validation_holder_and_verifier(self):
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            add_duplicate(root)
            findings = registry_validate.validate_registry(root)
            self.assertTrue(any("duplicate" in e and KYC_PROOF_TYPE in e for e in findings.errors), findings.errors)
            registry = PredicateRegistry.from_repo(root)
            self.assertEqual(len(registry.resolve_all(KYC_PROOF_TYPE)), 3)
            self.assertIsNone(registry.resolve(KYC_PROOF_TYPE))
            self.assertIsNone(registry.resolve(KYC_PROOF_TYPE, "aaa-kyc"))
            # The ambiguous encoder map leaves no request-parameter contract,
            # so a parameterised request fails closed before the opaque gate;
            # a parameter-free request still reaches (and fails) that gate.
            with self.assertRaises(ConstraintViolationError):
                generate_unauthenticated_linkable(make_client(registry), make_request())
            bare = make_request()
            bare.parameters = {}
            with self.assertRaises(OpaquePredicateError):
                generate_unauthenticated_linkable(make_client(registry), bare)
            backend = mock.Mock(wraps=StubVerifyBackend())
            verifier = ZKCVerifier(root, VerifierTrustPolicy(issuers=()), backend)
            result = VerificationResult()
            self.assertIsNone(verifier._resolve_proof_artifact({"proofType": KYC_PROOF_TYPE}, result))
            self.assertIn(Code.UNKNOWN_PROOF_TYPE, [e.code for e in result.errors])
            backend.verify.assert_not_called()

    def test_encoder_validator_rejects_duplicate_before_per_encoder_checks(self):
        path = ROOT / "tests/vectors/validate_public_input_encoders.py"
        spec = importlib.util.spec_from_file_location("encoder_validator", path)
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            add_duplicate(root)
            with mock.patch.object(validator, "ROOT", root), self.assertRaisesRegex(
                AssertionError, "duplicate selector-free proof type"
            ):
                validator.main()

    def test_unregistered_duplicate_and_legacy_scan_also_fail_closed(self):
        for drop_registry in (False, True):
            with self.subTest(drop_registry=drop_registry), make_temp_tree(drop_registry=drop_registry) as tmp:
                root = pathlib.Path(tmp)
                encoder = root / "schemas/public-inputs/zkc_kyc.json"
                # Even a second file claiming the same circuit is ambiguous.
                shutil.copy2(encoder, encoder.with_name("duplicate.json"))
                registry = PredicateRegistry.from_repo(root)
                self.assertIsNone(registry.resolve(KYC_PROOF_TYPE))
                verifier = ZKCVerifier(root, VerifierTrustPolicy(issuers=()), StubVerifyBackend())
                self.assertNotIn(KYC_PROOF_TYPE, verifier._circuit_by_proof_type)

    def test_all_glob_orders_have_identical_circuit_and_vk_selection(self):
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            add_duplicate(root)
            original = pathlib.Path.glob
            encoders = list(original(root / "schemas/public-inputs", "*.json"))
            affected = [p for p in encoders if p.stem in ("zkc_kyc", "zkc_kyc_zz", "zkc_kyc_v2")]
            rest = [p for p in encoders if p not in affected]
            maps = []
            for permutation in itertools.permutations(affected):
                def shuffled(path, pattern):
                    if path == root / "schemas/public-inputs" and pattern == "*.json":
                        return iter([*permutation, *rest])
                    return original(path, pattern)
                store = mock.Mock()
                real_store = VerificationKeyStore.from_repo(root)
                for method in (
                    "vk_hash", "legacy_vk_identity", "binding_vk_candidates",
                    "has_binding_for_circuit", "binding_evidence",
                ):
                    getattr(store, method).side_effect = getattr(real_store, method)
                store.lookup.return_value = b"fixture-key"
                backend = mock.Mock(is_production=True)
                with mock.patch.object(pathlib.Path, "glob", shuffled):
                    verifier = ZKCVerifier(root, VerifierTrustPolicy(issuers=()), backend, vk_store=store)
                    result = VerificationResult()
                    self.assertIsNone(verifier._resolve_proof_artifact({"proofType": KYC_PROOF_TYPE}, result))
                    store.lookup.assert_not_called()
                    self.assertEqual(
                        verifier._resolve_proof_artifact({"proofType": "zkc:proof:kyc:v2"}, VerificationResult())[0],
                        "zkc_kyc_v2",
                    )
                    store.lookup.assert_called_once_with("zkc_kyc_v2")
                    maps.append(verifier._circuit_by_proof_type)
            self.assertTrue(all(mapping == maps[0] for mapping in maps))

    def test_exact_v2_selection_survives_selector_free_collision(self):
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            encoder_path = root / "schemas/public-inputs/zkc_kyc_v2.json"
            encoder = json.loads(encoder_path.read_text())
            encoder["circuit"] = "unrelated_v2"
            (encoder_path.parent / "unrelated_v2.json").write_text(json.dumps(encoder))
            proof_type = "zkc:proof:kyc:v2"
            registry = PredicateRegistry.from_repo(root)
            self.assertIsNone(registry.resolve(proof_type))
            bindings = registry.bindings_for("zkc-kyc", "4.0.0", proof_type)
            self.assertEqual(len(bindings), 2)
            verifier = ZKCVerifier(root, VerifierTrustPolicy(issuers=()), StubVerifyBackend())
            for binding in bindings:
                resolved = registry.resolve_binding(proof_type, binding.selector)
                self.assertEqual(resolved.binding, binding)
                result = VerificationResult()
                self.assertEqual(
                    verifier._resolve_proof_artifact(
                        {"proofType": proof_type, "bindingSelector": binding.selector}, result
                    )[0],
                    "zkc_kyc_v2",
                )
                self.assertEqual(result.errors, [])

    def test_collision_rejects_an_honest_envelope_before_backend(self):
        from test_verifier import VerifierTestBase
        fixture = VerifierTestBase()
        fixture.setUp()
        with make_temp_tree() as tmp:
            root = pathlib.Path(tmp)
            add_duplicate(root)
            backend = mock.Mock(wraps=StubVerifyBackend())
            verifier = ZKCVerifier(root, fixture.make_verifier()._trust_policy, backend)
            result = verifier.verify(copy.deepcopy(fixture.envelope), fixture.make_request())
            self.assertFalse(result.valid)
            self.assertIn(Code.UNKNOWN_PROOF_TYPE, result.codes())
            backend.verify.assert_not_called()
        control = fixture.make_verifier().verify(fixture.envelope, fixture.make_request())
        self.assertTrue(control.valid, control.to_dict())

    def test_shared_encoder_listings_and_unique_types_keep_working(self):
        registry = PredicateRegistry.from_repo(ROOT)
        self.assertEqual(len(registry.resolve_all(KYC_PROOF_TYPE)), 2)
        self.assertEqual(registry.resolve(KYC_PROOF_TYPE).circuit, "zkc_kyc")
        verifier = ZKCVerifier(ROOT, VerifierTrustPolicy(issuers=()), StubVerifyBackend())
        self.assertEqual(verifier._circuit_by_proof_type[KYC_PROOF_TYPE], "zkc_kyc")
        circuits, errors = encoder_circuits(ROOT)
        self.assertEqual(errors, ())
        self.assertEqual(circuits[KYC_PROOF_TYPE], "zkc_kyc")


if __name__ == "__main__":
    unittest.main()
