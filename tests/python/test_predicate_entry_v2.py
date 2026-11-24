"""Predicate-entry v2 source identity and exact artifact-binding selection."""

import copy
import dataclasses
import json
import unittest

import _path  # noqa: F401
from _path import REPO_ROOT

from zkc_crypto import field_to_hex
from zkc_crypto.apr import apr_digest_from_dict, sign_apr, verify_apr_signature
from zkc_holder import BindingResolutionError, PredicateRegistry
from zkc_registry.predicate_v2 import (
    binding_id,
    parse_request_selectors,
    request_extension,
    source_id,
)


PREDICATE_ID = "zkc-kyc"
ENTRY_VERSION = "4.0.0"
PROOF_TYPE = "zkc:proof:kyc:v2"


def _documents():
    root = REPO_ROOT / "registry/predicates" / PREDICATE_ID / ENTRY_VERSION
    source = json.loads((root / "entry.json").read_text(encoding="utf-8"))
    bindings = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((root / "bindings").glob("*.json"))
    ]
    return source, bindings


def _unsigned_apr():
    return {
        "request": {
            "proofTypes": ["zkc:proof:kyc:v1"],
            "parameters": {"zkc:proof:kyc:v1": {"requiredLevel": 2}},
            "context": {
                "profile": "zkc:context:verifier-session:v1",
                "verifierId": "verifier.example",
                "sessionId": field_to_hex(123),
                "timestamp": 1_700_000,
            },
        },
        "verifierId": "verifier.example",
        "nonce": field_to_hex(456),
        "issuedAt": 1_700_000,
        "expiresAt": 1_703_600,
    }


class IdentityTests(unittest.TestCase):
    def test_committed_source_and_binding_ids_are_canonical(self):
        source, bindings = _documents()
        self.assertEqual(source_id(source), source["sourceId"])
        self.assertEqual(len(bindings), 2)
        for binding in bindings:
            self.assertEqual(binding_id(binding), binding["bindingId"])
        binding_dir = REPO_ROOT / "registry/predicates" / PREDICATE_ID / ENTRY_VERSION / "bindings"
        self.assertEqual(
            {path.stem for path in binding_dir.glob("*.json")},
            {item["bindingId"].removeprefix("sha256:") for item in bindings},
        )

    def test_one_source_has_two_distinct_active_toolchain_bindings(self):
        source, bindings = _documents()
        self.assertEqual({item["sourceId"] for item in bindings}, {source["sourceId"]})
        self.assertEqual({item["toolchain"]["id"] for item in bindings}, {"historical", "successor"})
        self.assertEqual(len({item["bindingId"] for item in bindings}), 2)
        self.assertEqual(len({item["vkHash"] for item in bindings}), 2)
        self.assertTrue(all(item["activation"]["activatedAt"] for item in bindings))

    def test_manifest_indexes_both_exact_binding_tuples(self):
        manifest = json.loads((REPO_ROOT / "artifacts/manifest.json").read_text())
        tuples = {
            (item["predicateId"], item["entryVersion"], item["bindingId"])
            for item in manifest["bindings"]
        }
        _source, bindings = _documents()
        self.assertEqual(
            tuples,
            {(PREDICATE_ID, ENTRY_VERSION, item["bindingId"]) for item in bindings},
        )


class ResolutionTests(unittest.TestCase):
    def setUp(self):
        self.registry = PredicateRegistry.from_repo(REPO_ROOT)
        self.bindings = self.registry.bindings_for(PREDICATE_ID, ENTRY_VERSION, PROOF_TYPE)

    def test_legacy_selector_free_resolution_is_frozen(self):
        # The only entry is draft: default resolution fails closed, and only
        # an explicit allow_unaccepted inspection returns the frozen entry.
        self.assertIsNone(self.registry.resolve(PROOF_TYPE))
        entry = self.registry.resolve(PROOF_TYPE, allow_unaccepted=True)
        self.assertEqual((entry.predicate_id, entry.entry_version), (PREDICATE_ID, "2.0.0"))

    def test_each_exact_selector_resolves_without_a_default(self):
        self.assertEqual(len(self.bindings), 2)
        for binding in self.bindings:
            resolved = self.registry.resolve_binding(PROOF_TYPE, binding.selector)
            self.assertEqual(resolved.binding, binding)
            self.assertEqual(resolved.source.source_id, binding.source_id)
        with self.assertRaisesRegex(BindingResolutionError, "not registered"):
            self.registry.resolve_binding(
                PROOF_TYPE,
                {
                    "predicateId": PREDICATE_ID,
                    "entryVersion": ENTRY_VERSION,
                    "bindingId": "sha256:" + "0" * 64,
                },
            )

    def test_malformed_crosswired_inactive_deprecated_and_disallowed_fail_closed(self):
        selected = self.bindings[0]
        resolved = self.registry.resolve_binding(PROOF_TYPE, selected.selector)
        cases = (
            (
                PredicateRegistry([resolved.source], [selected]),
                {**selected.selector, "extra": True},
                {},
                "malformed",
            ),
            (
                PredicateRegistry([resolved.source], [selected]),
                selected.selector,
                {"allowed_binding_ids": ("sha256:" + "f" * 64,)},
                "disallowed",
            ),
            (
                PredicateRegistry(
                    [resolved.source], [dataclasses.replace(selected, activated_at=None)]
                ),
                selected.selector,
                {},
                "inactive",
            ),
            (
                PredicateRegistry(
                    [resolved.source],
                    [dataclasses.replace(selected, review_status="deprecated")],
                ),
                selected.selector,
                {},
                "deprecated",
            ),
        )
        for registry, selector, kwargs, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(BindingResolutionError) as caught:
                registry.resolve_binding(PROOF_TYPE, selector, **kwargs)
            self.assertEqual(caught.exception.reason, reason)

        crosswired = dataclasses.replace(selected, source_id="sha256:" + "e" * 64)
        registry = PredicateRegistry([resolved.source], [crosswired])
        with self.assertRaises(BindingResolutionError) as caught:
            registry.resolve_binding(PROOF_TYPE, crosswired.selector)
        self.assertEqual(caught.exception.reason, "cross_wired")


class AuthenticatedSelectorTests(unittest.TestCase):
    def test_selector_extension_is_closed_and_round_trips(self):
        binding = PredicateRegistry.from_repo(REPO_ROOT).bindings_for(
            PREDICATE_ID, ENTRY_VERSION, PROOF_TYPE
        )[0]
        selectors = {"zkc:proof:kyc:v1": binding.selector}
        extension = request_extension(selectors)
        self.assertEqual(
            parse_request_selectors(extension, ["zkc:proof:kyc:v1"]), selectors
        )
        bad = copy.deepcopy(extension)
        bad["zkc:request:binding-selectors:v1"]["unexpected"] = True
        with self.assertRaises(ValueError):
            parse_request_selectors(bad, ["zkc:proof:kyc:v1"])

    def test_legacy_apr_digest_is_unchanged_and_extension_is_authenticated(self):
        unsigned = _unsigned_apr()
        self.assertEqual(
            apr_digest_from_dict(unsigned),
            0x2D048CBAF7A0646482B57E982E44ADA483471C1F10B29D540FC52890B56A1884,
        )
        binding = PredicateRegistry.from_repo(REPO_ROOT).bindings_for(
            PREDICATE_ID, ENTRY_VERSION, PROOF_TYPE
        )[0]
        unsigned["request"]["extensions"] = request_extension(
            {"zkc:proof:kyc:v1": binding.selector}
        )
        signed = sign_apr(unsigned, 12345)
        self.assertTrue(verify_apr_signature(signed))
        tampered = copy.deepcopy(signed)
        tampered["request"]["extensions"]["zkc:request:binding-selectors:v1"][
            "selectors"
        ][0]["bindingId"] = "sha256:" + "0" * 64
        self.assertFalse(verify_apr_signature(tampered))


if __name__ == "__main__":
    unittest.main()
