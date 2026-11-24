#!/usr/bin/env python3
"""Validate committed public input encoder definitions against circuit source.

For every encoder in schemas/public-inputs/<circuit>.json this script parses
the `pub` parameters of the circuit's main() signature straight from the Noir
source and checks that the encoder declares the exact same names, types,
order, flattened field-element counts, and offsets. It also structurally
validates each encoder against schemas/public-input-encoder-v1.schema.json.

It additionally gates the request-binding classification contract: every
encoder public input MUST carry a bound/derived/free classification in the
name-keyed sidecar schemas/public-input-bindings/<circuit>.json (the encoder
bytes themselves are registry-immutable), every 'free' field MUST carry a
written justification, and a circuit selecting its meaning via a public
predicate_type MUST publish its proof-type -> predicate_type map. Any
unclassified field in a new or changed encoder fails this script, and CI.

This is the toolchain-free consistency check (no nargo required); CI
additionally cross-checks the encoders against the compiled ABI via
scripts/build_artifact_manifest.py.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENCODER_DIR = ROOT / "schemas" / "public-inputs"
ENCODER_SCHEMA = ROOT / "schemas" / "public-input-encoder-v1.schema.json"
BINDING_DIR = ROOT / "schemas" / "public-input-bindings"
BINDING_SCHEMAS = {
    (
        "zkc:public-input-bindings:v1",
        "https://zkc.dev/schemas/public-input-binding-v1.schema.json",
    ): ROOT / "schemas" / "public-input-binding-v1.schema.json",
    (
        "zkc:public-input-bindings:v2",
        "https://zkc.dev/schemas/public-input-binding-v2.schema.json",
    ): ROOT / "schemas" / "public-input-binding-v2.schema.json",
}
BINDING_V2_SELECTOR = (
    "zkc:public-input-bindings:v2",
    "https://zkc.dev/schemas/public-input-binding-v2.schema.json",
)
NOIR_DIR = ROOT / "noir"

BINDING_CLASSES = ("bound", "derived", "free")
BOUND_CHECK_KINDS = ("equals", "member_of", "policy_range")
ALLOWED_BINDING_DOCUMENT_KEYS = frozenset(
    {"$schema", "version", "circuit", "encoder", "predicateTypes", "bindings"}
)
ALLOWED_BINDING_ENTRY_KEYS = frozenset(
    {
        "name",
        "camelName",
        "class",
        "source",
        "check",
        "group",
        "from",
        "justification",
        "note",
    }
)
ALLOWED_BINDING_ENTRY_KEYS_V2 = ALLOWED_BINDING_ENTRY_KEYS | {"pinnedBy"}
# A structured reference the P1 request-binding chokepoint can parse: where
# the verifier's expected value (bound) or recomputation inputs (derived)
# come from. `source` may continue with prose after the leading reference.
REFERENCE_PREFIX_RE = re.compile(r"^(context|param|envelope|policy|map|public):[A-Za-z0-9_.\[\]]+")
FROM_REFERENCE_RE = re.compile(r"^(context|param|envelope|policy|map|public):[A-Za-z0-9_.\[\]]+$")
PREDICATE_CONSTANT_RE = re.compile(r"\bpub\s+global\s+(PREDICATE_[A-Z_]+)\s*:\s*u8\s*=\s*(\d+)")
PREDICATE_TYPE_MAP_REFERENCE = "map:predicateTypes[proofType]"
MIN_JUSTIFICATION_CHARS = 40
MIN_JUSTIFICATION_WORDS = 8
JUSTIFICATION_WORD_RE = re.compile(r"[A-Za-z]{2,}")

sys.path.insert(0, str(ROOT / "python"))
from zkc_registry.encoder_resolution import encoder_circuits  # noqa: E402

sys.path.insert(0, str(ROOT / "scripts"))
from build_artifact_manifest import validate_schema  # noqa: E402


def strip_comments(source: str) -> str:
    return re.sub(r"//[^\n]*", "", source)


def extract_main_signature(source: str) -> str:
    source = strip_comments(source)
    match = re.search(r"\bfn\s+main\s*\(", source)
    if not match:
        raise AssertionError("no main() found")
    depth = 0
    for i in range(match.end() - 1, len(source)):
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
            if depth == 0:
                return source[match.end() : i]
    raise AssertionError("unbalanced parentheses in main() signature")


def split_parameters(signature: str) -> list:
    parameters = []
    depth = 0
    current = []
    for char in signature:
        if char in "([<":
            depth += 1
        elif char in ")]>":
            depth -= 1
        if char == "," and depth == 0:
            parameters.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    tail = "".join(current).strip()
    if tail:
        parameters.append(tail)
    return parameters


def field_elements(noir_type: str) -> int:
    noir_type = noir_type.strip()
    array = re.fullmatch(r"\[(.+);\s*(\d+)\]", noir_type)
    if array:
        return int(array.group(2)) * field_elements(array.group(1))
    if noir_type in ("Field", "bool") or re.fullmatch(r"[ui]\d+", noir_type):
        return 1
    raise AssertionError(f"unsupported Noir type for public inputs: {noir_type!r}")


def normalize_type(noir_type: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"\s*([;\[\]])\s*", r"\1", noir_type.strip())).replace(
        ";", "; "
    )


def public_inputs_from_source(circuit: str) -> list:
    source = (NOIR_DIR / circuit / "src" / "main.nr").read_text()
    inputs = []
    offset = 0
    for parameter in split_parameters(extract_main_signature(source)):
        name, _, type_part = parameter.partition(":")
        type_part = type_part.strip()
        if not type_part.startswith("pub "):
            continue
        noir_type = normalize_type(type_part[len("pub ") :])
        elements = field_elements(noir_type)
        inputs.append(
            {
                "index": len(inputs),
                "offset": offset,
                "name": name.strip(),
                "abiType": noir_type,
                "fieldElements": elements,
            }
        )
        offset += elements
    if not inputs:
        raise AssertionError(f"{circuit}: no pub parameters found in main()")
    return inputs


def snake_to_camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.capitalize() for part in rest)


def check_reference(reference: str, encoder_names, self_name: str, has_map: bool, cell: str) -> None:
    """Resolve a structured reference: public: must name another field of the
    same circuit, map: must point at a published predicateTypes map."""
    prefix, _, target = reference.partition(":")
    if prefix == "public" and (target == self_name or target not in encoder_names):
        raise AssertionError(
            f"{cell}: reference {reference!r} does not name another public input"
        )
    if prefix == "map":
        if reference != PREDICATE_TYPE_MAP_REFERENCE:
            raise AssertionError(
                f"{cell}: unknown map reference {reference!r}; only "
                f"{PREDICATE_TYPE_MAP_REFERENCE!r} exists"
            )
        if not has_map:
            raise AssertionError(
                f"{cell}: reference {reference!r} but the document publishes no predicateTypes map"
            )


def predicate_constants_from_source(circuit: str) -> dict:
    """Parse `pub global PREDICATE_<NAME>: u8 = N;` constants from the circuit."""
    source = strip_comments((NOIR_DIR / circuit / "src" / "main.nr").read_text())
    return {name: int(value) for name, value in PREDICATE_CONSTANT_RE.findall(source)}


def validate_binding_document(binding: dict, encoder: dict, schemas: dict, where: str) -> None:
    """Gate the bound/derived/free classification sidecar for one encoder.

    Fails on any unclassified public input, any classification for a field the
    encoder does not declare, a 'free' field without a written justification,
    a malformed structured reference, a camelName that drifts from the
    mechanical snake_case conversion, or a public predicate_type selector
    without an exact proof-type -> predicate_type map.
    """
    # Keep the direct-schema calling convention used by focused unit tests
    # while production callers dispatch over the complete selector map.
    schema_documents = (
        schemas
        if all(isinstance(key, tuple) for key in schemas)
        else {
            (
                "zkc:public-input-bindings:v1",
                "https://zkc.dev/schemas/public-input-binding-v1.schema.json",
            ): schemas
        }
    )
    if not isinstance(binding, dict):
        validate_schema(binding, next(iter(schema_documents.values())), where)
        raise AssertionError(f"{where}: binding document must be an object")
    selector = (binding.get("version"), binding.get("$schema"))
    schema = schema_documents.get(selector)
    if schema is None:
        raise AssertionError(
            f"{where}: version/$schema must be a supported canonical selector, got {selector!r}"
        )
    validate_schema(binding, schema, where)

    undeclared_document_keys = sorted(set(binding) - ALLOWED_BINDING_DOCUMENT_KEYS)
    if undeclared_document_keys:
        # build_artifact_manifest.validate_schema intentionally implements only
        # a small JSON-Schema subset and ignores additionalProperties. Keep the
        # complete sidecar vocabulary closed even when this lightweight gate is
        # the only validator available.
        raise AssertionError(
            f"{where}: undeclared binding document key(s) {undeclared_document_keys}"
        )

    circuit = encoder["circuit"]
    if binding["circuit"] != circuit:
        raise AssertionError(f"{where}: binding circuit {binding['circuit']!r} != encoder circuit {circuit!r}")
    expected_encoder_path = f"schemas/public-inputs/{circuit}.json"
    if binding["encoder"] != expected_encoder_path:
        raise AssertionError(
            f"{where}: encoder reference {binding['encoder']!r} != {expected_encoder_path!r}"
        )

    encoder_names = [entry["name"] for entry in encoder["publicInputs"]]
    encoder_entries = {entry["name"]: entry for entry in encoder["publicInputs"]}
    binding_names = [entry["name"] for entry in binding["bindings"]]
    duplicates = sorted({name for name in binding_names if binding_names.count(name) > 1})
    if duplicates:
        raise AssertionError(f"{where}: duplicate classification for {duplicates}")
    unclassified = [name for name in encoder_names if name not in binding_names]
    if unclassified:
        raise AssertionError(
            f"{where}: unclassified public input(s) {unclassified}; every encoder "
            "field MUST be classified bound/derived/free"
        )
    unknown = [name for name in binding_names if name not in encoder_names]
    if unknown:
        raise AssertionError(f"{where}: classification for unknown public input(s) {unknown}")

    predicate_types = binding.get("predicateTypes")
    has_map = isinstance(predicate_types, dict) and bool(predicate_types)

    seen_camel: dict = {}
    for entry in binding["bindings"]:
        name = entry["name"]
        cell = f"{where}: {name}"
        if "pinnedBy" in entry and selector != BINDING_V2_SELECTOR:
            raise AssertionError(f"{cell}: 'pinnedBy' is only admitted under v2 binding contracts")
        allowed_entry_keys = (
            ALLOWED_BINDING_ENTRY_KEYS_V2
            if selector == BINDING_V2_SELECTOR
            else ALLOWED_BINDING_ENTRY_KEYS
        )
        undeclared_keys = sorted(set(entry) - allowed_entry_keys)
        if undeclared_keys:
            # build_artifact_manifest.validate_schema intentionally implements
            # only a small JSON-Schema subset and ignores additionalProperties.
            # Enforce the sidecar's closed entry vocabulary here, in the gate
            # that every committed sidecar traverses.
            raise AssertionError(f"{cell}: undeclared binding entry key(s) {undeclared_keys}")
        camel = entry["camelName"]
        if camel != snake_to_camel(name):
            raise AssertionError(
                f"{cell}: camelName {camel!r} != mechanical conversion {snake_to_camel(name)!r}"
            )
        if camel in seen_camel:
            raise AssertionError(f"{cell}: camelName {camel!r} already used by {seen_camel[camel]!r}")
        seen_camel[camel] = name

        binding_class = entry["class"]
        if binding_class not in BINDING_CLASSES:
            raise AssertionError(f"{cell}: unknown class {binding_class!r}")
        if binding_class != "bound" and ("check" in entry or "group" in entry):
            raise AssertionError(f"{cell}: 'check'/'group' are only valid on bound fields")
        if "pinnedBy" in entry:
            expected_pin = f"param:{camel}"
            if binding_class != "free":
                raise AssertionError(f"{cell}: 'pinnedBy' is only valid on free fields")
            if entry["pinnedBy"] != expected_pin:
                raise AssertionError(
                    f"{cell}: pinnedBy {entry['pinnedBy']!r} must equal {expected_pin!r}"
                )
            encoder_entry = encoder_entries[name]
            if encoder_entry["abiType"] != "Field" or encoder_entry["fieldElements"] != 1:
                raise AssertionError(
                    f"{cell}: 'pinnedBy' requires a scalar Field public input, got "
                    f"{encoder_entry['abiType']!r}"
                )
        if binding_class == "bound":
            source = entry.get("source", "")
            match = REFERENCE_PREFIX_RE.match(source)
            if not match:
                raise AssertionError(
                    f"{cell}: bound field needs a 'source' starting with a structured "
                    f"reference (context:/param:/envelope:/policy:/map:), got {source!r}"
                )
            check_reference(match.group(0), encoder_names, name, has_map, cell)
            if entry.get("check", "equals") not in BOUND_CHECK_KINDS:
                raise AssertionError(
                    f"{cell}: unknown check kind {entry['check']!r}; expected one of "
                    f"{BOUND_CHECK_KINDS}"
                )
            if "from" in entry or "justification" in entry:
                raise AssertionError(f"{cell}: bound field must not carry 'from'/'justification'")
        elif binding_class == "derived":
            from_refs = entry.get("from")
            if not isinstance(from_refs, list) or not from_refs:
                raise AssertionError(f"{cell}: derived field needs a non-empty 'from' list")
            for reference in from_refs:
                if not isinstance(reference, str) or not FROM_REFERENCE_RE.match(reference):
                    raise AssertionError(f"{cell}: malformed 'from' reference {reference!r}")
                check_reference(reference, encoder_names, name, has_map, cell)
            # The exact recomputation (including interior hashing of the
            # referenced values) is part of the contract, not optional prose.
            if len(entry.get("note", "").strip()) < MIN_JUSTIFICATION_CHARS:
                raise AssertionError(
                    f"{cell}: derived field needs a 'note' stating the exact recomputation "
                    f"(at least {MIN_JUSTIFICATION_CHARS} characters)"
                )
            if "source" in entry or "justification" in entry:
                raise AssertionError(f"{cell}: derived field must not carry 'source'/'justification'")
        else:  # free
            justification = entry.get("justification", "")
            if (
                len(justification.strip()) < MIN_JUSTIFICATION_CHARS
                or len(JUSTIFICATION_WORD_RE.findall(justification)) < MIN_JUSTIFICATION_WORDS
            ):
                raise AssertionError(
                    f"{cell}: free field needs a written justification of at least "
                    f"{MIN_JUSTIFICATION_CHARS} characters and {MIN_JUSTIFICATION_WORDS} words"
                )
            if "source" in entry or "from" in entry:
                raise AssertionError(f"{cell}: free field must not carry 'source'/'from'")

    has_predicate_type = "predicate_type" in binding_names
    if has_predicate_type:
        if not has_map:
            raise AssertionError(
                f"{where}: circuit exposes predicate_type but publishes no "
                "proof-type -> predicate_type map"
            )
        proof_types = set(encoder.get("proofTypes", []))
        if set(predicate_types) != proof_types:
            raise AssertionError(
                f"{where}: predicateTypes keys {sorted(predicate_types)} != encoder "
                f"proofTypes {sorted(proof_types)}"
            )
        values = list(predicate_types.values())
        if any(type(value) is not int or value < 1 for value in values):
            raise AssertionError(f"{where}: predicateTypes values must be integers >= 1")
        if len(set(values)) != len(values):
            raise AssertionError(
                f"{where}: predicateTypes values must be distinct (per-meaning domain separation)"
            )

        # The map's values are the P2 per-meaning selectors; they must equal
        # the PREDICATE_* constants the circuit itself dispatches on, matched
        # by the proof type's family token, so a permuted or renumbered map
        # can never land with green CI.
        constants = predicate_constants_from_source(circuit)
        if not constants:
            raise AssertionError(
                f"{where}: no PREDICATE_* constants found in {circuit} source to "
                "ratify predicateTypes against"
            )
        for proof_type, value in predicate_types.items():
            family = proof_type.split(":")[2].upper()
            matches = [
                constant
                for constant in constants
                if family in constant.split("_")
            ]
            if len(matches) != 1:
                raise AssertionError(
                    f"{where}: proof type {proof_type!r} matches {len(matches)} "
                    f"PREDICATE_* constants in {circuit} source: {sorted(matches)}"
                )
            if value != constants[matches[0]]:
                raise AssertionError(
                    f"{where}: predicateTypes[{proof_type!r}] = {value} but "
                    f"{circuit} declares {matches[0]} = {constants[matches[0]]}"
                )

        # A published map with a prover-chosen selector is self-contradictory:
        # the selector must be pinned to the map.
        selector = next(entry for entry in binding["bindings"] if entry["name"] == "predicate_type")
        if selector["class"] != "bound" or not selector.get("source", "").startswith(
            PREDICATE_TYPE_MAP_REFERENCE
        ):
            raise AssertionError(
                f"{where}: predicate_type must be class 'bound' with source "
                f"{PREDICATE_TYPE_MAP_REFERENCE!r}"
            )
    elif predicate_types is not None:
        raise AssertionError(
            f"{where}: predicateTypes map present but the circuit has no predicate_type input"
        )


def main() -> int:
    _, resolution_errors = encoder_circuits(ROOT)
    if resolution_errors:
        raise AssertionError("; ".join(resolution_errors))
    schema = json.loads(ENCODER_SCHEMA.read_text())
    binding_schemas = {
        selector: json.loads(path.read_text()) for selector, path in BINDING_SCHEMAS.items()
    }
    encoder_paths = sorted(ENCODER_DIR.glob("*.json"))
    if not encoder_paths:
        raise AssertionError(f"no encoder definitions found in {ENCODER_DIR}")

    orphan_bindings = sorted(
        path.name
        for path in BINDING_DIR.glob("*.json")
        if not (ENCODER_DIR / path.name).is_file()
    )
    if orphan_bindings:
        raise AssertionError(
            f"binding classification(s) without a matching encoder: {orphan_bindings}"
        )

    for encoder_path in encoder_paths:
        encoder = json.loads(encoder_path.read_text())
        validate_schema(encoder, schema, encoder_path.name)

        circuit = encoder["circuit"]
        if encoder_path.stem != circuit:
            raise AssertionError(f"{encoder_path.name}: file name must match circuit {circuit!r}")

        expected = public_inputs_from_source(circuit)
        declared = [
            {
                "index": entry["index"],
                "offset": entry["offset"],
                "name": entry["name"],
                "abiType": entry["abiType"],
                "fieldElements": entry["fieldElements"],
            }
            for entry in encoder["publicInputs"]
        ]
        if declared != expected:
            raise AssertionError(
                f"{encoder_path.name} does not match {circuit} main() signature:\n"
                f"  encoder: {json.dumps(declared)}\n"
                f"  source:  {json.dumps(expected)}"
            )
        total = sum(entry["fieldElements"] for entry in expected)
        if encoder["totalFieldElements"] != total:
            raise AssertionError(
                f"{encoder_path.name}: totalFieldElements is "
                f"{encoder['totalFieldElements']}, source flattens to {total}"
            )

        binding_path = BINDING_DIR / encoder_path.name
        if not binding_path.is_file():
            raise AssertionError(
                f"{encoder_path.name}: unclassified public inputs — no binding "
                f"classification at {binding_path.relative_to(ROOT)}"
            )
        binding = json.loads(binding_path.read_text())
        validate_binding_document(binding, encoder, binding_schemas, binding_path.name)

        print(f"validated {encoder_path.relative_to(ROOT)} against {circuit} main()")
        print(f"validated {binding_path.relative_to(ROOT)} classification")
    return 0


if __name__ == "__main__":
    sys.exit(main())
