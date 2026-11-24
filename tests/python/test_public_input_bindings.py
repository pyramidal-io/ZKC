"""Per-predicate public-input classification contract (punch-list P4).

Covers the acceptance criteria of the P4 requirement: every encoder public
input carries a bound/derived/free classification in its name-keyed sidecar,
every 'free' field carries a written justification, the CI gate fails on any
unclassified field, the snake_case <-> camelCase name map round-trips, and
circuits selecting their meaning via a public predicate_type publish an exact
proof-type -> predicate_type map.
"""

import contextlib
import copy
import io
import json
import pathlib
import re
import sys
import unittest

from _inventory import expected_circuits

import _path  # noqa: F401  (sys.path side effect)

from zkc_crypto import PublicInputBindings

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS_DIR = REPO_ROOT / "tests" / "vectors"
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

import validate_public_input_encoders as gate  # noqa: E402

ENCODER_DIR = REPO_ROOT / "schemas" / "public-inputs"
BINDING_DIR = REPO_ROOT / "schemas" / "public-input-bindings"
SPECIFICATION = REPO_ROOT / "docs" / "zkc_specification.md"


def load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


class GatePassesOnCommittedContractTest(unittest.TestCase):
    def test_every_committed_encoder_and_classification_validates(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(), 0)

    def test_every_encoder_has_a_classification_sidecar(self):
        encoders = {path.name for path in ENCODER_DIR.glob("*.json")}
        bindings = {path.name for path in BINDING_DIR.glob("*.json")}
        self.assertEqual(encoders, bindings)

    def test_every_free_field_is_justified_in_writing(self):
        for path in sorted(BINDING_DIR.glob("*.json")):
            for entry in load(path)["bindings"]:
                if entry["class"] == "free":
                    self.assertGreaterEqual(
                        len(entry["justification"].strip()),
                        gate.MIN_JUSTIFICATION_CHARS,
                        f"{path.name}: {entry['name']}",
                    )

    def test_remaining_predicates_versions_agree_on_names_not_offsets(self):
        v1 = [e["name"] for e in load(ENCODER_DIR / "zkc_remaining_predicates.json")["publicInputs"]]
        v2 = [
            e["name"]
            for e in load(ENCODER_DIR / "zkc_remaining_predicates_v2.json")["publicInputs"]
        ]
        # v1 orders (predicate_type, set_root); v2 reverses them — binding by
        # offset would silently compare the wrong fields.
        self.assertLess(v1.index("predicate_type"), v1.index("set_root"))
        self.assertLess(v2.index("set_root"), v2.index("predicate_type"))

    def test_remaining_predicates_set_root_is_bound_not_preimage_derived(self):
        for name in (
            "zkc_remaining_predicates.json",
            "zkc_remaining_predicates_v2.json",
            "zkc_remaining_predicates_v3.json",
            "zkc_remaining_predicates_v4.json",
            "zkc_remaining_predicates_v5.json",
            "zkc_remaining_predicates_v6.json",
            "zkc_remaining_predicates_v7.json",
            "zkc_remaining_predicates_v8.json",
        ):
            doc = load(BINDING_DIR / name)
            by_name = {entry["name"]: entry for entry in doc["bindings"]}
            self.assertEqual(by_name["set_root"]["class"], "bound", name)
            claim_from = by_name["claim_binding"]["from"]
            self.assertNotIn("public:set_root", claim_from, name)


# Golden classification table: the ratified class of EVERY public input. This
# remains useful current-state and documentation consistency evidence, while
# registry/check_immutability.py independently byte-protects every committed
# sidecar and its canonical schema against coordinated history rewrites. Keep
# this table in sync with docs/zkc_public_input_classification.md §5.
RATIFIED_CLASSES = {
    "zkc_kyc": {
        "holder_commitment": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_kyc_v2": {
        "presentation_pseudonym": "bound",
        "scope_id": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_jurisdiction": {
        "holder_commitment": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "jurisdiction_set_root": "bound",
        "membership_type": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_jurisdiction_v2": {
        "presentation_pseudonym": "bound",
        "scope_id": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "jurisdiction_set_root": "bound",
        "membership_type": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_jurisdiction_v3": {
        "holder_commitment": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "jurisdiction_set_root": "bound",
        "membership_type": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_jurisdiction_v4": {
        "presentation_pseudonym": "bound",
        "scope_id": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "jurisdiction_set_root": "bound",
        "membership_type": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_remaining_predicates": {
        "holder_commitment": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "predicate_type": "bound",
        "set_root": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_remaining_predicates_v2": {
        "presentation_pseudonym": "bound",
        "scope_id": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "set_root": "bound",
        "predicate_type": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_remaining_predicates_v3": {
        "holder_commitment": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "predicate_type": "bound",
        "set_root": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_remaining_predicates_v4": {
        "presentation_pseudonym": "bound",
        "scope_id": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "set_root": "bound",
        "predicate_type": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_remaining_predicates_v5": {
        "holder_commitment": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "predicate_type": "bound",
        "set_root": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_remaining_predicates_v6": {
        "presentation_pseudonym": "bound",
        "scope_id": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "set_root": "bound",
        "predicate_type": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_selective_disclosure_v1": {
        "presentation_pseudonym": "bound",
        "scope_id": "bound",
        "claim_binding": "derived",
        "proof_context": "bound",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "timestamp": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
        "credential_attribute_count": "free",
        "disclosure_count": "derived",
        "disclosed_flags": "bound",
        "disclosed_attributes": "free",
    },
    "zkc_credential_rebind": {
        "old_holder_commitment": "bound",
        "new_holder_commitment": "free",
        "credential_id": "free",
        "issuer_id_hash": "free",
        "schema_id_hash": "free",
        "proof_context": "bound",
        "timestamp": "bound",
        "claim_binding": "derived",
    },
    "zkc_credential_rebind_v2": {
        "old_presentation_pseudonym": "bound",
        "new_presentation_pseudonym": "free",
        "scope_id": "bound",
        "credential_id": "free",
        "issuer_id_hash": "free",
        "schema_id_hash": "free",
        "proof_context": "bound",
        "timestamp": "bound",
        "claim_binding": "derived",
    },
    "zkc_credential_rebind_binding_v2": {
        "old_holder_commitment": "bound",
        "new_holder_commitment": "free",
        "credential_id": "free",
        "issuer_id_hash": "free",
        "schema_id_hash": "free",
        "proof_context": "bound",
        "timestamp": "bound",
        "claim_binding": "derived",
    },
    "zkc_credential_rebind_v2_binding_v2": {
        "old_presentation_pseudonym": "bound",
        "new_presentation_pseudonym": "free",
        "scope_id": "bound",
        "credential_id": "free",
        "issuer_id_hash": "free",
        "schema_id_hash": "free",
        "proof_context": "bound",
        "timestamp": "bound",
        "claim_binding": "derived",
    },
    "zkc_credential_rebind_auth": {
        "old_holder_commitment": "bound",
        "new_holder_commitment": "free",
        "credential_id": "free",
        "issuer_id_hash": "bound",
        "schema_id_hash": "free",
        "proof_context": "bound",
        "timestamp": "bound",
        "claim_binding": "derived",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_credential_rebind_auth_v2": {
        "old_presentation_pseudonym": "bound",
        "new_presentation_pseudonym": "free",
        "scope_id": "bound",
        "credential_id": "free",
        "issuer_id_hash": "bound",
        "schema_id_hash": "free",
        "proof_context": "bound",
        "timestamp": "bound",
        "claim_binding": "derived",
        "accumulator_root": "bound",
        "accumulator_epoch": "bound",
        "current_epoch": "bound",
        "issuer_public_key_x": "bound",
        "issuer_public_key_y": "bound",
    },
    "zkc_aggregation": {
        "aggregation_commitment": "derived",
        "aggregated_claim_binding": "derived",
        "holder_commitment": "bound",
        "context": "bound",
        "num_proofs": "bound",
        "input_proof_commitments": "derived",
    },
    "zkc_aggregation_v2": {
        "aggregation_commitment": "derived",
        "aggregated_claim_binding": "derived",
        "presentation_pseudonym": "bound",
        "scope_id": "bound",
        "context": "bound",
        "num_proofs": "bound",
        "input_proof_commitments": "derived",
    },
}

# v7/v8 deliberately preserve the v5/v6 public ABIs; only the private issuer
# digest changes to authenticate validFrom.
RATIFIED_CLASSES["zkc_remaining_predicates_v7"] = dict(
    RATIFIED_CLASSES["zkc_remaining_predicates_v5"]
)
RATIFIED_CLASSES["zkc_remaining_predicates_v8"] = dict(
    RATIFIED_CLASSES["zkc_remaining_predicates_v6"]
)

# The beta.25 artifact successors deliberately preserve their predecessors'
# public ABI and binding classification. Their distinct circuit and proof-type
# identities bind the toolchain change without rewriting ratified history.
RATIFIED_ALIAS_OF = {
    "zkc_community_kyc_v2": "zkc_kyc",
    "zkc_kyc_v3": "zkc_kyc_v2",
    "zkc_aggregation_v3": "zkc_aggregation_v2",
    "zkc_credential_rebind_auth_v3": "zkc_credential_rebind_auth_v2",
    "zkc_jurisdiction_v5": "zkc_jurisdiction_v4",
    "zkc_remaining_predicates_v9": "zkc_remaining_predicates_v8",
    "zkc_remaining_predicates_v10": "zkc_remaining_predicates_v9",
    "zkc_selective_disclosure_v2": "zkc_selective_disclosure_v1",
}
for successor, predecessor in RATIFIED_ALIAS_OF.items():
    RATIFIED_CLASSES[successor] = dict(RATIFIED_CLASSES[predecessor])

if (BINDING_DIR / "zkc_selective_disclosure_v3.json").is_file():
    RATIFIED_CLASSES["zkc_selective_disclosure_v3"] = {
        **RATIFIED_CLASSES["zkc_selective_disclosure_v2"], "layout_id": "bound",
    }

if (BINDING_DIR / "zkc_jurisdiction_v6.json").is_file():
    RATIFIED_CLASSES["zkc_jurisdiction_v6"] = {
        **RATIFIED_CLASSES["zkc_jurisdiction_v5"],
        "code_space_id": "bound", "required_verification_method": "bound",
    }

if (BINDING_DIR / "zkc_remaining_predicates_v11.json").is_file():
    RATIFIED_CLASSES["zkc_remaining_predicates_v11"] = {
        **RATIFIED_CLASSES["zkc_remaining_predicates_v10"], "code_space_id": "bound",
    }

for successor, predecessor in {
    "zkc_community_kyc_v3": "zkc_community_kyc_v2",
    "zkc_credential_rebind_auth_linkable_v2": "zkc_credential_rebind_auth",
    "zkc_credential_rebind_auth_v4": "zkc_credential_rebind_auth_v3",
    "zkc_jurisdiction_v7": "zkc_jurisdiction_v3",
    "zkc_jurisdiction_v8": "zkc_jurisdiction_v6",
    "zkc_kyc_v4": "zkc_kyc_v3",
    "zkc_remaining_predicates_v12": "zkc_remaining_predicates_v7",
    "zkc_remaining_predicates_v13": "zkc_remaining_predicates_v10",
    "zkc_remaining_predicates_v14": "zkc_remaining_predicates_v11",
    "zkc_selective_disclosure_v4": "zkc_selective_disclosure_v3",
}.items():
    if (BINDING_DIR / f"{successor}.json").is_file():
        RATIFIED_ALIAS_OF[successor] = predecessor
        RATIFIED_CLASSES[successor] = dict(RATIFIED_CLASSES[predecessor])

CLASS_LETTER = {"bound": "B", "derived": "D", "free": "F"}


class RatifiedClassificationPinTest(unittest.TestCase):
    def test_sidecars_match_the_ratified_golden_table(self):
        sidecar_circuits = {path.stem for path in BINDING_DIR.glob("*.json")}
        self.assertEqual(sidecar_circuits, expected_circuits(set(RATIFIED_CLASSES)))
        for circuit in sorted(expected_circuits(set(RATIFIED_CLASSES))):
            expected = RATIFIED_CLASSES[circuit]
            doc = load(BINDING_DIR / f"{circuit}.json")
            actual = {entry["name"]: entry["class"] for entry in doc["bindings"]}
            self.assertEqual(actual, expected, circuit)

    def test_ratified_doc_tables_match_the_sidecars(self):
        text = (REPO_ROOT / "docs" / "zkc_public_input_classification.md").read_text()
        for circuit in sorted(expected_circuits(set(RATIFIED_CLASSES))):
            expected = RATIFIED_CLASSES[circuit]
            if circuit in RATIFIED_ALIAS_OF:
                row = f"| `{circuit}` | `{RATIFIED_ALIAS_OF[circuit]}` |"
                self.assertIn(row, text, circuit)
                continue
            heading = f"### `{circuit}`"
            self.assertIn(heading, text, circuit)
            section = text.split(heading, 1)[1].split("\n### ")[0]
            for name, binding_class in expected.items():
                row = f"| `{name}` |"
                self.assertIn(row, section, f"{circuit}: {name} missing from doc table")
                row_line = next(
                    line for line in section.splitlines() if row in line
                )
                self.assertIn(
                    f"**{CLASS_LETTER[binding_class]}**",
                    row_line,
                    f"{circuit}: {name} class drifted between sidecar and doc",
                )


class ConditionalRequestPinContractTest(unittest.TestCase):
    EXPECTED_REBIND_PINS = {
        "issuer_id_hash": "param:issuerIdHash",
        "schema_id_hash": "param:schemaIdHash",
    }
    V2_STEMS = (
        "zkc_credential_rebind_binding_v2",
        "zkc_credential_rebind_v2_binding_v2",
    )
    V2_SELECTOR = (
        "zkc:public-input-bindings:v2",
        "https://zkc.dev/schemas/public-input-binding-v2.schema.json",
    )

    def setUp(self):
        self.schema = load(REPO_ROOT / "schemas" / "public-input-binding-v1.schema.json")
        self.encoder = load(ENCODER_DIR / "zkc_credential_rebind.json")
        self.binding = load(BINDING_DIR / "zkc_credential_rebind.json")
        self.where = "zkc_credential_rebind.json"
        self.schemas = {
            (
                "zkc:public-input-bindings:v1",
                "https://zkc.dev/schemas/public-input-binding-v1.schema.json",
            ): self.schema,
            self.V2_SELECTOR: load(
                REPO_ROOT / "schemas" / "public-input-binding-v2.schema.json"
            ),
        }

    def v2_contract(self, stem: str):
        encoder = copy.deepcopy(self.encoder)
        encoder["circuit"] = stem
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            entry.pop("pinnedBy", None)
        binding["version"], binding["$schema"] = self.V2_SELECTOR
        binding["circuit"] = stem
        binding["encoder"] = f"schemas/public-inputs/{stem}.json"
        for entry in binding["bindings"]:
            if entry["name"] in self.EXPECTED_REBIND_PINS:
                entry["pinnedBy"] = self.EXPECTED_REBIND_PINS[entry["name"]]
        return binding, encoder, f"{stem}.json"

    def test_v1_rejects_pinned_by(self):
        binding = copy.deepcopy(self.binding)
        next(entry for entry in binding["bindings"] if entry["name"] == "issuer_id_hash")[
            "pinnedBy"
        ] = "param:issuerIdHash"
        with self.assertRaises(AssertionError) as ctx:
            gate.validate_binding_document(binding, self.encoder, self.schemas, self.where)
        self.assertIn("only admitted under v2", str(ctx.exception))

    def test_selector_dispatch_rejects_mixed_or_unknown_pairs(self):
        binding, encoder, where = self.v2_contract(self.V2_STEMS[0])
        cases = (
            ("version", "zkc:public-input-bindings:v1"),
            (
                "$schema",
                "https://zkc.dev/schemas/public-input-binding-v1.schema.json",
            ),
            ("version", "zkc:public-input-bindings:v999"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                malformed = copy.deepcopy(binding)
                malformed[field] = value
                self.check_rejects(
                    malformed, encoder, where, "supported canonical selector"
                )

    def test_v2_contracts_admit_the_rebind_pins_for_both_successors(self):
        for stem in self.V2_STEMS:
            with self.subTest(stem=stem):
                binding, encoder, where = self.v2_contract(stem)
                gate.validate_binding_document(binding, encoder, self.schemas, where)
                actual = {
                    entry["name"]: entry["pinnedBy"]
                    for entry in binding["bindings"]
                    if "pinnedBy" in entry
                }
                self.assertEqual(actual, self.EXPECTED_REBIND_PINS)

    def test_successor_sidecars_publish_v2_selector_and_ratified_pins(self):
        for stem in self.V2_STEMS:
            with self.subTest(stem=stem):
                document = load(BINDING_DIR / f"{stem}.json")
                self.assertEqual(
                    (document["version"], document["$schema"]), self.V2_SELECTOR
                )
                actual = {
                    entry["name"]: entry["pinnedBy"]
                    for entry in document["bindings"]
                    if "pinnedBy" in entry
                }
                self.assertEqual(actual, self.EXPECTED_REBIND_PINS)

    def test_runtime_pin_api_requires_encoder_metadata(self):
        binding, _, _ = self.v2_contract(self.V2_STEMS[0])
        bindings = PublicInputBindings(binding)
        with self.assertRaisesRegex(ValueError, "require encoder metadata"):
            bindings.conditional_pins()

    def test_runtime_rejects_noncanonical_camel_name_even_if_pin_matches(self):
        binding, _, _ = self.v2_contract(self.V2_STEMS[0])
        entry = next(
            entry for entry in binding["bindings"] if entry["name"] == "issuer_id_hash"
        )
        entry["camelName"] = "issuerFilter"
        entry["pinnedBy"] = "param:issuerFilter"
        with self.assertRaisesRegex(ValueError, "mechanical conversion 'issuerIdHash'"):
            PublicInputBindings(binding)

    def test_runtime_rejects_mixed_or_unknown_selector_pairs(self):
        binding, _, _ = self.v2_contract(self.V2_STEMS[0])
        cases = (
            ("version", "zkc:public-input-bindings:v1"),
            (
                "$schema",
                "https://zkc.dev/schemas/public-input-binding-v1.schema.json",
            ),
            ("version", "zkc:public-input-bindings:v999"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                malformed = copy.deepcopy(binding)
                malformed[field] = value
                with self.assertRaisesRegex(ValueError, "supported canonical selector pair"):
                    PublicInputBindings(malformed)

    def test_runtime_v1_rejects_conditional_pins(self):
        binding = copy.deepcopy(self.binding)
        next(entry for entry in binding["bindings"] if entry["name"] == "issuer_id_hash")[
            "pinnedBy"
        ] = "param:issuerIdHash"
        with self.assertRaisesRegex(ValueError, "only admitted by the binding-v2 selector"):
            PublicInputBindings(binding)

    def test_runtime_rejects_non_object_document_cleanly(self):
        with self.assertRaisesRegex(ValueError, "must be a JSON object"):
            PublicInputBindings([])

    def check_rejects(self, binding, encoder, where, fragment):
        with self.assertRaises(AssertionError) as ctx:
            gate.validate_binding_document(binding, encoder, self.schemas, where)
        self.assertIn(fragment, str(ctx.exception))

    def test_pin_must_target_its_own_camel_case_request_parameter(self):
        binding, encoder, where = self.v2_contract(self.V2_STEMS[0])
        next(entry for entry in binding["bindings"] if entry["name"] == "issuer_id_hash")[
            "pinnedBy"
        ] = "param:schemaIdHash"
        self.check_rejects(binding, encoder, where, "must equal 'param:issuerIdHash'")

    def test_pin_is_only_valid_for_free_fields(self):
        binding, encoder, where = self.v2_contract(self.V2_STEMS[0])
        entry = next(entry for entry in binding["bindings"] if entry["name"] == "proof_context")
        entry["pinnedBy"] = "param:proofContext"
        self.check_rejects(binding, encoder, where, "only valid on free fields")

    def test_pin_requires_a_scalar_field_public_input(self):
        binding, encoder, where = self.v2_contract(self.V2_STEMS[0])
        entry = next(entry for entry in binding["bindings"] if entry["name"] == "timestamp")
        entry.clear()
        entry.update(
            {
                "name": "timestamp",
                "camelName": "timestamp",
                "class": "free",
                "pinnedBy": "param:timestamp",
                "justification": "This deliberately malformed fixture tests that conditional pins cannot target integer public inputs.",
            }
        )
        self.check_rejects(binding, encoder, where, "requires a scalar Field public input")

    def test_undeclared_entry_key_fails_even_with_the_minimal_schema_validator(self):
        binding, encoder, where = self.v2_contract(self.V2_STEMS[0])
        next(entry for entry in binding["bindings"] if entry["name"] == "issuer_id_hash")[
            "unexpectedRule"
        ] = True
        self.check_rejects(binding, encoder, where, "undeclared binding entry key(s) ['unexpectedRule']")

    def test_undeclared_document_key_fails_even_with_the_minimal_schema_validator(self):
        binding, encoder, where = self.v2_contract(self.V2_STEMS[0])
        binding["unexpectedRule"] = True
        self.check_rejects(binding, encoder, where, "undeclared binding document key(s) ['unexpectedRule']")

    def test_malformed_pin_reference_fails_schema_validation(self):
        binding, encoder, where = self.v2_contract(self.V2_STEMS[0])
        next(entry for entry in binding["bindings"] if entry["name"] == "issuer_id_hash")[
            "pinnedBy"
        ] = "policy:issuerIdHash"
        with self.assertRaises(SystemExit):
            gate.validate_binding_document(binding, encoder, self.schemas, where)


class SpecificationWireNameTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.specification = SPECIFICATION.read_text()

    def section(self, start: str, end: str) -> str:
        self.assertIn(start, self.specification)
        self.assertIn(end, self.specification)
        return self.specification.split(start, 1)[1].split(end, 1)[0]

    def test_section_seven_envelope_mappings_match_encoder_names(self):
        sections = {
            ("### 7.1 KYC Proof Circuit", "### 7.2 Jurisdiction Proof Circuit"):
                "zkc_kyc",
            ("### 7.2 Jurisdiction Proof Circuit", "### 7.2a Remaining Predicate Profiles"):
                "zkc_jurisdiction",
        }
        for (start, end), circuit in sections.items():
            with self.subTest(circuit=circuit):
                mappings = re.findall(
                    r"`publicInputs\.\{([^}]*)\}`", self.section(start, end)
                )
                self.assertEqual(len(mappings), 1, circuit)
                documented = [name.strip() for name in mappings[0].split(",")]
                encoded = [
                    entry["name"]
                    for entry in load(ENCODER_DIR / f"{circuit}.json")["publicInputs"]
                ]
                self.assertEqual(documented, encoded, circuit)

    def test_verification_algorithm_uses_encoder_public_input_names(self):
        algorithm = self.section(
            "### 6.2 Verification Algorithm", "### 6.3 Integration Patterns"
        )
        accessed = re.findall(
            r"individualProof\.publicInputs\.([A-Za-z_][A-Za-z0-9_]*)", algorithm
        )
        expected = {"proof_context", "accumulator_epoch", "accumulator_root"}
        self.assertEqual(set(accessed), expected)
        for path in ENCODER_DIR.glob("*.json"):
            if path.stem.startswith(("zkc_aggregation", "zkc_credential_rebind")):
                continue
            encoder_names = {entry["name"] for entry in load(path)["publicInputs"]}
            self.assertLessEqual(expected, encoder_names, path.stem)

    def test_specification_defines_encoder_declared_wire_names(self):
        self.assertIn(
            "canonical wire key for each encoder-declared public input is exactly "
            "the snake_case `name` entry",
            self.specification,
        )


class GateRejectsBrokenClassificationsTest(unittest.TestCase):
    def setUp(self):
        self.schema = load(REPO_ROOT / "schemas" / "public-input-binding-v1.schema.json")
        self.encoder = load(ENCODER_DIR / "zkc_remaining_predicates.json")
        self.binding = load(BINDING_DIR / "zkc_remaining_predicates.json")
        self.where = "zkc_remaining_predicates.json"

    def check_rejects(self, binding, fragment):
        with self.assertRaises(AssertionError) as ctx:
            gate.validate_binding_document(binding, self.encoder, self.schema, self.where)
        self.assertIn(fragment, str(ctx.exception))

    def test_valid_document_passes(self):
        gate.validate_binding_document(self.binding, self.encoder, self.schema, self.where)

    def test_non_object_binding_fails_schema_validation(self):
        with self.assertRaises(SystemExit):
            gate.validate_binding_document([], self.encoder, self.schema, self.where)

    def test_schema_and_version_selectors_must_be_the_canonical_v1_pair(self):
        cases = (
            ("$schema", None),
            ("$schema", "https://zkc.dev/schemas/public-input-binding-v999.schema.json"),
            ("version", "zkc:public-input-bindings:v999"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                binding = copy.deepcopy(self.binding)
                if value is None:
                    binding.pop(field)
                else:
                    binding[field] = value
                self.check_rejects(binding, "supported canonical selector")

    def test_unclassified_field_fails(self):
        binding = copy.deepcopy(self.binding)
        binding["bindings"] = [
            entry for entry in binding["bindings"] if entry["name"] != "set_root"
        ]
        self.check_rejects(binding, "unclassified public input(s) ['set_root']")

    def test_classification_for_unknown_field_fails(self):
        binding = copy.deepcopy(self.binding)
        binding["bindings"].append(
            {
                "name": "ghost_field",
                "camelName": "ghostField",
                "class": "bound",
                "source": "context:value",
            }
        )
        self.check_rejects(binding, "unknown public input(s) ['ghost_field']")

    def test_duplicate_classification_fails(self):
        binding = copy.deepcopy(self.binding)
        binding["bindings"].append(copy.deepcopy(binding["bindings"][0]))
        self.check_rejects(binding, "duplicate classification")

    def test_free_without_justification_fails(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "set_root":
                entry.clear()
                entry.update({"name": "set_root", "camelName": "setRoot", "class": "free"})
        self.check_rejects(binding, "written justification")

    def test_short_justification_fails(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "set_root":
                entry.clear()
                entry.update(
                    {
                        "name": "set_root",
                        "camelName": "setRoot",
                        "class": "free",
                        "justification": "prover-chosen",
                    }
                )
        self.check_rejects(binding, "written justification")

    def test_unknown_class_fails_schema_validation(self):
        binding = copy.deepcopy(self.binding)
        binding["bindings"][0]["class"] = "optional"
        with self.assertRaises(SystemExit):
            gate.validate_binding_document(binding, self.encoder, self.schema, self.where)

    def test_bound_without_structured_source_fails(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "proof_context":
                entry["source"] = "checked against the request somehow"
        self.check_rejects(binding, "structured")

    def test_derived_without_from_fails(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "claim_binding":
                entry.pop("from")
        self.check_rejects(binding, "'from' list")

    def test_derived_public_reference_must_name_a_real_field(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "claim_binding":
                entry["from"] = ["public:no_such_field"]
        self.check_rejects(binding, "does not name another")

    def test_camel_name_drift_fails(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "set_root":
                entry["camelName"] = "jurisdictionSetRoot"
        self.check_rejects(binding, "mechanical conversion")

    def test_bound_source_must_not_self_reference(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "proof_context":
                entry["source"] = "public:proof_context — compared against itself"
        self.check_rejects(binding, "does not name another public input")

    def test_bound_source_dangling_map_reference_fails(self):
        binding = load(BINDING_DIR / "zkc_kyc.json")
        encoder = load(ENCODER_DIR / "zkc_kyc.json")
        for entry in binding["bindings"]:
            if entry["name"] == "proof_context":
                entry["source"] = "map:predicateTypes[proofType] — but no map is published"
        with self.assertRaises(AssertionError) as ctx:
            gate.validate_binding_document(binding, encoder, self.schema, "zkc_kyc.json")
        self.assertIn("no predicateTypes map", str(ctx.exception))

    def test_derived_without_recomputation_note_fails(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "claim_binding":
                entry.pop("note")
        self.check_rejects(binding, "exact recomputation")

    def test_padded_justification_fails(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "set_root":
                entry.clear()
                entry.update(
                    {
                        "name": "set_root",
                        "camelName": "setRoot",
                        "class": "free",
                        "justification": "." * 80,
                    }
                )
        self.check_rejects(binding, "written justification")

    def test_check_kind_only_on_bound_fields(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "claim_binding":
                entry["check"] = "equals"
        self.check_rejects(binding, "only valid on bound fields")

    def test_permuted_predicate_type_map_fails(self):
        binding = copy.deepcopy(self.binding)
        binding["predicateTypes"]["zkc:proof:source:v1"] = 3
        binding["predicateTypes"]["zkc:proof:tax:v1"] = 2
        self.check_rejects(binding, "declares")

    def test_free_predicate_type_selector_fails(self):
        binding = copy.deepcopy(self.binding)
        for entry in binding["bindings"]:
            if entry["name"] == "predicate_type":
                entry.clear()
                entry.update(
                    {
                        "name": "predicate_type",
                        "camelName": "predicateType",
                        "class": "free",
                        "justification": "The prover selects which predicate profile it "
                        "proves; this verifier treats all four profiles as interchangeable.",
                    }
                )
        self.check_rejects(binding, "predicate_type must be class 'bound'")

    def test_missing_predicate_type_map_fails(self):
        binding = copy.deepcopy(self.binding)
        binding.pop("predicateTypes")
        # Even with the selector's own map reference neutralized, a circuit
        # exposing predicate_type may not omit the map.
        for entry in binding["bindings"]:
            if entry["name"] == "predicate_type":
                entry["source"] = "param:predicateType — placeholder for this test"
        self.check_rejects(binding, "proof-type -> predicate_type map")

    def test_missing_predicate_type_map_also_breaks_selector_reference(self):
        binding = copy.deepcopy(self.binding)
        binding.pop("predicateTypes")
        self.check_rejects(binding, "publishes no predicateTypes map")

    def test_predicate_type_map_must_cover_proof_types_exactly(self):
        binding = copy.deepcopy(self.binding)
        binding["predicateTypes"].pop("zkc:proof:sanctions:v1")
        self.check_rejects(binding, "predicateTypes keys")

    def test_predicate_type_map_values_must_be_distinct(self):
        binding = copy.deepcopy(self.binding)
        binding["predicateTypes"]["zkc:proof:sanctions:v1"] = 1
        self.check_rejects(binding, "distinct")

    def test_orphan_predicate_type_map_fails(self):
        schema = self.schema
        encoder = load(ENCODER_DIR / "zkc_kyc.json")
        binding = load(BINDING_DIR / "zkc_kyc.json")
        binding["predicateTypes"] = {"zkc:proof:kyc:v1": 1}
        with self.assertRaises(AssertionError) as ctx:
            gate.validate_binding_document(binding, encoder, schema, "zkc_kyc.json")
        self.assertIn("no predicate_type input", str(ctx.exception))

    def test_snake_to_camel_matches_request_vocabulary(self):
        self.assertEqual(gate.snake_to_camel("jurisdiction_set_root"), "jurisdictionSetRoot")
        self.assertEqual(gate.snake_to_camel("set_root"), "setRoot")
        self.assertEqual(gate.snake_to_camel("issuer_public_key_x"), "issuerPublicKeyX")
        self.assertEqual(gate.snake_to_camel("timestamp"), "timestamp")


class PublicInputBindingsApiTest(unittest.TestCase):
    def setUp(self):
        self.bindings = PublicInputBindings.for_circuit(REPO_ROOT, "zkc_remaining_predicates")

    def test_name_keyed_access(self):
        self.assertEqual(self.bindings.circuit, "zkc_remaining_predicates")
        self.assertEqual(self.bindings.binding_class("set_root"), "bound")
        self.assertEqual(self.bindings.binding_class("claim_binding"), "derived")
        self.assertIn("param:setRoot", self.bindings.entry("set_root")["source"])
        with self.assertRaises(ValueError):
            self.bindings.entry("no_such_field")

    def test_name_map_round_trips(self):
        for name in self.bindings.names:
            self.assertEqual(self.bindings.snake_name(self.bindings.camel_name(name)), name)
        self.assertEqual(self.bindings.camel_name("set_root"), "setRoot")
        self.assertEqual(self.bindings.snake_name("setRoot"), "set_root")
        with self.assertRaises(ValueError):
            self.bindings.snake_name("set_root")  # snake spelling is not a camelName

    def test_predicate_type_map(self):
        self.assertEqual(self.bindings.predicate_type_for("zkc:proof:accreditation:v1"), 1)
        self.assertEqual(self.bindings.predicate_type_for("zkc:proof:sanctions:v1"), 4)
        with self.assertRaises(ValueError):
            self.bindings.predicate_type_for("zkc:proof:kyc:v1")
        kyc = PublicInputBindings.for_circuit(REPO_ROOT, "zkc_kyc")
        with self.assertRaises(ValueError):
            kyc.predicate_type_for("zkc:proof:kyc:v1")

    def test_v1_v2_profile_maps_share_meanings(self):
        v2 = PublicInputBindings.for_circuit(REPO_ROOT, "zkc_remaining_predicates_v2")
        v1_by_family = {
            proof_type.split(":")[2]: value
            for proof_type, value in self.bindings.predicate_types.items()
        }
        v2_by_family = {
            proof_type.split(":")[2]: value for proof_type, value in v2.predicate_types.items()
        }
        self.assertEqual(v1_by_family, v2_by_family)

    def test_duplicate_names_rejected(self):
        document = json.loads(
            (BINDING_DIR / "zkc_remaining_predicates.json").read_text()
        )
        document["bindings"].append(copy.deepcopy(document["bindings"][0]))
        with self.assertRaises(ValueError):
            PublicInputBindings(document)

    def test_every_circuit_loads(self):
        for path in sorted(BINDING_DIR.glob("*.json")):
            bindings = PublicInputBindings.load(path)
            self.assertTrue(bindings.names)


if __name__ == "__main__":
    unittest.main()
