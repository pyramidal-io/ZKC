"""Public-input encoding per schemas/public-inputs/*.json.

Turns the JSON `publicInputs` object of a zkc:proof:v1 proof entry into the
flat field-element byte string barretenberg consumes (`bb verify -i`):
declaration order, one 32-byte big-endian element per field, booleans as 0/1,
unsigned integers zero-extended, `[u8; N]` one byte per element.

`PublicInputBindings` loads the name-keyed request-binding classification
sidecar (schemas/public-input-bindings/<circuit>.json): the bound/derived/free
class per field, the snake_case <-> camelCase name map, optional conditional
request pins, and — for circuits whose meaning is selected by a public
predicate_type — the proof-type -> predicate_type map. Consumers bind by NAME,
never by offset: v1/v2 encoders order the same names differently.
"""

from __future__ import annotations

import json
import pathlib
import re

from .field import FIELD_MODULUS, hex_to_field

__all__ = ["PublicInputBindings", "PublicInputEncoder"]


_PUBLIC_INPUT_BINDING_SELECTORS = {
    (
        "zkc:public-input-bindings:v1",
        "https://zkc.dev/schemas/public-input-binding-v1.schema.json",
    ): 1,
    (
        "zkc:public-input-bindings:v2",
        "https://zkc.dev/schemas/public-input-binding-v2.schema.json",
    ): 2,
}


def _snake_to_camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.capitalize() for part in rest)


class PublicInputEncoder:
    def __init__(self, encoder_document: dict):
        self._document = encoder_document
        self.circuit = encoder_document["circuit"]
        self.proof_types = tuple(encoder_document["proofTypes"])
        self.total_field_elements = encoder_document["totalFieldElements"]
        self._inputs = encoder_document["publicInputs"]

    @classmethod
    def load(cls, path) -> "PublicInputEncoder":
        return cls(json.loads(pathlib.Path(path).read_text()))

    def field_elements(self, public_inputs: dict) -> list:
        """Encode the JSON public-input object into ordered field elements."""
        elements = []
        for entry in self._inputs:
            name = entry["name"]
            abi_type = entry["abiType"]
            if name not in public_inputs:
                raise ValueError(f"public input '{name}' missing")
            value = public_inputs[name]
            if abi_type == "Field":
                elements.append(hex_to_field(value))
            elif abi_type.startswith("u") and abi_type[1:].isdigit():
                bits = int(abi_type[1:])
                if type(value) is not int:
                    raise ValueError(f"public input '{name}' must be an integer for {abi_type}")
                if not 0 <= value < (1 << bits):
                    raise ValueError(f"public input '{name}' out of range for {abi_type}")
                elements.append(value)
            elif abi_type == "bool":
                if not isinstance(value, bool):
                    raise ValueError(f"public input '{name}' must be a boolean")
                elements.append(1 if value else 0)
            elif abi_type.startswith("[u8;"):
                expected_length = int(abi_type.rstrip("]").split(";")[1])
                if not isinstance(value, str) or not value.startswith("0x"):
                    raise ValueError(f"public input '{name}' must be 0x-prefixed hex bytes")
                data = bytes.fromhex(value[2:])
                if len(data) != expected_length:
                    raise ValueError(
                        f"public input '{name}' must be {expected_length} bytes, got {len(data)}"
                    )
                elements.extend(data)
            elif (array := re.fullmatch(r"\[(bool|Field);\s*(\d+)\]", abi_type)):
                element_type = array.group(1)
                expected_length = int(array.group(2))
                if not isinstance(value, list) or len(value) != expected_length:
                    raise ValueError(
                        f"public input '{name}' must contain exactly "
                        f"{expected_length} {element_type} values"
                    )
                for index, item in enumerate(value):
                    if element_type == "bool":
                        if type(item) is not bool:
                            raise ValueError(
                                f"public input '{name}[{index}]' must be a boolean"
                            )
                        elements.append(1 if item else 0)
                    else:
                        try:
                            elements.append(hex_to_field(item))
                        except (TypeError, ValueError) as exc:
                            raise ValueError(
                                f"public input '{name}[{index}]' must be a field element"
                            ) from exc
            else:
                raise ValueError(f"unsupported abiType '{abi_type}' for '{name}'")
        if len(elements) != self.total_field_elements:
            raise ValueError(
                f"encoded {len(elements)} field elements, encoder declares "
                f"{self.total_field_elements}"
            )
        return elements

    def encode_bytes(self, public_inputs: dict) -> bytes:
        """Flat 32-byte big-endian concatenation (bb public_inputs format)."""
        output = bytearray()
        for element in self.field_elements(public_inputs):
            if not 0 <= element < FIELD_MODULUS:
                raise ValueError("encoded element is not a canonical field element")
            output.extend(element.to_bytes(32, "big"))
        return bytes(output)


class PublicInputBindings:
    """Name-keyed view of one circuit's binding-classification document."""

    def __init__(self, binding_document: dict):
        if not isinstance(binding_document, dict):
            raise ValueError("public-input binding document must be a JSON object")
        selector = (binding_document.get("version"), binding_document.get("$schema"))
        if selector not in _PUBLIC_INPUT_BINDING_SELECTORS:
            raise ValueError(
                "public-input binding document does not declare a supported canonical "
                f"selector pair: {selector!r}"
            )
        self._document = binding_document
        self._selector_version = _PUBLIC_INPUT_BINDING_SELECTORS[selector]
        self.circuit = binding_document["circuit"]
        self.predicate_types = dict(binding_document.get("predicateTypes", {}))
        self._scalar_field_names = None
        self._by_name: dict = {}
        self._name_by_camel: dict = {}
        for entry in binding_document["bindings"]:
            name = entry["name"]
            camel = entry["camelName"]
            if self._selector_version == 1 and "pinnedBy" in entry:
                raise ValueError(
                    f"conditional pin for '{name}' is only admitted by the binding-v2 selector"
                )
            expected_camel = _snake_to_camel(name)
            if camel != expected_camel:
                raise ValueError(
                    f"binding camelName '{camel}' for '{name}' must equal "
                    f"mechanical conversion '{expected_camel}'"
                )
            if name in self._by_name:
                raise ValueError(f"duplicate binding classification for '{name}'")
            if camel in self._name_by_camel:
                raise ValueError(f"duplicate camelName '{camel}'")
            self._by_name[name] = entry
            self._name_by_camel[camel] = name

    @classmethod
    def load(cls, path) -> "PublicInputBindings":
        return cls(json.loads(pathlib.Path(path).read_text()))

    @classmethod
    def for_circuit(cls, root, circuit: str) -> "PublicInputBindings":
        root = pathlib.Path(root)
        bindings = cls.load(root / "schemas" / "public-input-bindings" / f"{circuit}.json")
        if bindings.circuit != circuit:
            raise ValueError(
                f"binding sidecar for '{circuit}' declares circuit '{bindings.circuit}'"
            )
        expected_encoder = f"schemas/public-inputs/{circuit}.json"
        if bindings._document.get("encoder") != expected_encoder:
            raise ValueError(
                f"binding sidecar for '{circuit}' does not declare encoder '{expected_encoder}'"
            )
        encoder_document = json.loads((root / expected_encoder).read_text())
        if encoder_document.get("circuit") != circuit:
            raise ValueError(f"encoder document for '{circuit}' declares another circuit")
        bindings._scalar_field_names = {
            entry.get("name")
            for entry in encoder_document.get("publicInputs", [])
            if entry.get("abiType") == "Field" and entry.get("fieldElements") == 1
        }
        return bindings

    @property
    def names(self) -> tuple:
        return tuple(self._by_name)

    def entry(self, name: str) -> dict:
        if name not in self._by_name:
            raise ValueError(f"no binding classification for public input '{name}'")
        return self._by_name[name]

    def binding_class(self, name: str) -> str:
        return self.entry(name)["class"]

    def camel_name(self, name: str) -> str:
        return self.entry(name)["camelName"]

    def snake_name(self, camel_name: str) -> str:
        if camel_name not in self._name_by_camel:
            raise ValueError(f"no public input with camelName '{camel_name}'")
        return self._name_by_camel[camel_name]

    def predicate_type_for(self, proof_type: str) -> int:
        if not self.predicate_types:
            raise ValueError(f"{self.circuit} publishes no proof-type -> predicate_type map")
        if proof_type not in self.predicate_types:
            raise ValueError(f"no predicate type for proof type '{proof_type}'")
        return self.predicate_types[proof_type]

    def request_parameters(self) -> frozenset:
        """Every request parameter this sidecar structurally references.

        Read only from the schema's structured reference positions: the
        leading reference of a ``source`` string, each ``from`` reference, and
        a ``pinnedBy`` rule. Free-text notes and justifications are never
        parsed. A ``param:`` reference that is not exactly one camel-case
        name is rejected rather than truncated, so a malformed sidecar cannot
        silently shrink or widen a closed request-parameter set.
        """
        names = set()

        def add(reference: str, where: str, *, leading: bool) -> None:
            if not isinstance(reference, str) or not reference.startswith("param:"):
                return
            match = (
                re.match(r"param:([a-z][a-zA-Z0-9]*)(?![A-Za-z0-9_.\[\]])", reference)
                if leading
                else re.fullmatch(r"param:([a-z][a-zA-Z0-9]*)", reference)
            )
            if match is None:
                raise ValueError(f"malformed param: reference in {where}: {reference!r}")
            names.add(match.group(1))

        for name, entry in self._by_name.items():
            add(entry.get("source"), f"'{name}'.source", leading=True)
            for reference in entry.get("from", ()) or ():
                add(reference, f"'{name}'.from", leading=False)
            if "pinnedBy" in entry:
                add(entry["pinnedBy"], f"'{name}'.pinnedBy", leading=False)
        return frozenset(names)

    def conditional_pins(self) -> tuple[tuple[str, str], ...]:
        """Return optional public-input -> request-parameter pin rules.

        ``pinnedBy`` is deliberately a small declarative vocabulary rather than
        a verifier-local table of field names.  A pin may only be declared for
        a ``free`` input and must point at that input's own canonical camel-case
        request spelling.  Treating even a syntactically plausible but
        non-canonical rule as invalid avoids silently accepting a sidecar whose
        contract the runtime does not understand.
        """
        pins = []
        parameters = set()
        for name, entry in self._by_name.items():
            if "pinnedBy" not in entry:
                continue
            if self._scalar_field_names is None:
                raise ValueError(
                    "conditional pins require encoder metadata; use PublicInputBindings.for_circuit"
                )
            pinned_by = entry["pinnedBy"]
            if not isinstance(pinned_by, str):
                raise ValueError(f"conditional pin for '{name}' must be a string")
            match = re.fullmatch(r"param:([a-z][a-zA-Z0-9]*)", pinned_by)
            if match is None:
                raise ValueError(f"conditional pin for '{name}' is not a param: reference")
            parameter = match.group(1)
            if entry.get("class") != "free":
                raise ValueError(f"conditional pin for '{name}' must classify the input as free")
            if self._scalar_field_names is not None and name not in self._scalar_field_names:
                raise ValueError(f"conditional pin for '{name}' must target a scalar Field input")
            if parameter != entry.get("camelName"):
                raise ValueError(
                    f"conditional pin for '{name}' must name its camelName '{entry.get('camelName')}'"
                )
            if parameter in parameters:
                raise ValueError(f"duplicate conditional pin parameter '{parameter}'")
            parameters.add(parameter)
            pins.append((name, parameter))
        return tuple(pins)
