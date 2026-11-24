#!/usr/bin/env python3
"""Print the immutable identity pins for a prospective registry entry.

This is deliberately a read-only preflight helper.  It never creates an entry
or changes any repository file; callers copy the JSON fragment into a reviewed
entry document after the checks succeed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from noir_package import NoirPackageError, inspect_circuit_package


ROOT = Path(__file__).resolve().parents[1]
PREDICATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CIRCUIT_RE = re.compile(r"^zkc_[a-z0-9_]+$")
PROOF_TYPE_RE = re.compile(r"^zkc:proof:[a-z0-9._-]+:v[0-9]+$")
ARTIFACT_PIN_RES = {
    "acirHash": re.compile(r"^sha256:[0-9a-f]{64}$"),
    "vkHash": re.compile(r"^0x[0-9a-f]{64}$"),
    "vkSha256": re.compile(r"^sha256:[0-9a-f]{64}$"),
}


class PinError(Exception):
    """An actionable preflight failure."""


def safe_repo_file(root: Path, value: str, label: str) -> tuple[Path, str]:
    """Return an existing regular file below *root*, retaining a stable path."""
    path = Path(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not value
        or value == "."
        or "\\" in value
        or "\x00" in value
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise PinError(f"{label} must be a safe repository-relative path: {value!r}")
    candidate = root / path
    cursor = root
    for part in path.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise PinError(f"{label} must not traverse a symlink: {value!r}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        raise PinError(f"{label} must resolve inside --root: {value!r}") from None
    if not resolved.is_file():
        raise PinError(f"{label} is not a file: {value!r}")
    return resolved, path.as_posix()


def source_package_reference(root: Path, source_path: str) -> str:
    """Identify the nearest Noir package, or fall back to the source file."""
    path = Path(source_path)
    for parent in path.parents:
        if parent == Path("."):
            break
        if (root / parent / "Nargo.toml").is_file():
            return parent.as_posix()
    return path.as_posix()


def load_json(path: Path, label: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PinError(f"{label} is not valid JSON ({path}): {exc}") from None
    if not isinstance(data, dict):
        raise PinError(f"{label} must contain a JSON object: {path}")
    return data


def existing_entries(root: Path) -> list[tuple[Path, dict]]:
    predicates = root / "registry" / "predicates"
    if not predicates.exists():
        return []
    if not predicates.is_dir():
        raise PinError("registry/predicates is not a directory")
    entries = []
    for entry_path in sorted(predicates.glob("*/*/entry.json")):
        relative = entry_path.relative_to(root).as_posix()
        safe_path, _ = safe_repo_file(root, relative, "existing registry entry")
        entries.append((safe_path, load_json(safe_path, "existing registry entry")))
    return entries


def pins_from_manifest(manifest: dict, circuit: str, encoder_path: str) -> dict:
    circuits = manifest.get("circuits")
    if not isinstance(circuits, list):
        raise PinError("artifact manifest must contain a circuits array")
    matches = [item for item in circuits if isinstance(item, dict) and item.get("name") == circuit]
    if not matches:
        raise PinError(f"artifact manifest has no circuit entry for {circuit!r}")
    if len(matches) != 1:
        raise PinError(f"artifact manifest has multiple circuit entries for {circuit!r}")
    item = matches[0]
    if item.get("scheme") != "ultra_honk":
        raise PinError(
            f"artifact manifest circuit {circuit!r} does not use ultra_honk"
        )
    if item.get("publicInputEncoder") != encoder_path:
        raise PinError(
            "artifact manifest publicInputEncoder does not match --public-input-encoder "
            f"({item.get('publicInputEncoder')!r} != {encoder_path!r})"
        )
    pins = {}
    for key, pattern in ARTIFACT_PIN_RES.items():
        value = item.get(key)
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise PinError(
                f"artifact manifest circuit {circuit!r} has an invalid or missing {key}"
            )
        pins[key] = value
    return pins


def validate_encoder(encoder: dict, circuit: str) -> list[str]:
    if encoder.get("version") != "zkc:public-inputs:v1":
        raise PinError("public-input encoder has an unsupported or missing version")
    if encoder.get("circuit") != circuit:
        raise PinError(
            f"public-input encoder circuit {encoder.get('circuit')!r} does not match "
            f"--circuit {circuit!r}"
        )
    if encoder.get("proofSystem") != "ultra_honk":
        raise PinError("public-input encoder proofSystem must be 'ultra_honk'")
    if encoder.get("curve") != "BN254":
        raise PinError("public-input encoder curve must be 'BN254'")
    encoding = encoder.get("encoding")
    encoding_keys = ("fieldElement", "order", "booleans", "integers", "byteArrays")
    if not isinstance(encoding, dict) or not all(
        isinstance(encoding.get(key), str) and encoding[key] for key in encoding_keys
    ):
        raise PinError("public-input encoder encoding profile is incomplete")
    proof_types = encoder.get("proofTypes")
    if not isinstance(proof_types, list) or not proof_types or not all(
        isinstance(item, str) and PROOF_TYPE_RE.fullmatch(item) for item in proof_types
    ):
        raise PinError(
            "public-input encoder must contain a non-empty array of valid proofTypes"
        )
    if len(set(proof_types)) != len(proof_types):
        raise PinError("public-input encoder proofTypes must not contain duplicates")
    public_inputs = encoder.get("publicInputs")
    if not isinstance(public_inputs, list) or not public_inputs:
        raise PinError("public-input encoder publicInputs must be a non-empty array")
    next_offset = 0
    for index, item in enumerate(public_inputs):
        if not isinstance(item, dict):
            raise PinError(f"public-input encoder publicInputs[{index}] must be an object")
        if (
            not isinstance(item.get("index"), int)
            or isinstance(item.get("index"), bool)
            or item["index"] != index
        ):
            raise PinError(
                f"public-input encoder publicInputs[{index}].index must equal {index}"
            )
        if (
            not isinstance(item.get("offset"), int)
            or isinstance(item.get("offset"), bool)
            or item["offset"] != next_offset
        ):
            raise PinError(
                f"public-input encoder publicInputs[{index}].offset must equal {next_offset}"
            )
        if not isinstance(item.get("name"), str) or not re.fullmatch(
            r"[a-z][a-z0-9_]*", item["name"]
        ):
            raise PinError(
                f"public-input encoder publicInputs[{index}].name is invalid"
            )
        if not isinstance(item.get("abiType"), str) or not item["abiType"]:
            raise PinError(
                f"public-input encoder publicInputs[{index}].abiType must be a string"
            )
        elements = item.get("fieldElements")
        if not isinstance(elements, int) or isinstance(elements, bool) or elements < 1:
            raise PinError(
                f"public-input encoder publicInputs[{index}].fieldElements "
                "must be a positive integer"
            )
        next_offset += elements
        if not isinstance(item.get("description"), str):
            raise PinError(
                f"public-input encoder publicInputs[{index}].description must be a string"
            )
    total = encoder.get("totalFieldElements")
    if not isinstance(total, int) or isinstance(total, bool) or total != next_offset:
        raise PinError(
            "public-input encoder totalFieldElements must equal the flattened "
            f"public input size {next_offset}"
        )
    return proof_types


def build_fragment(args: argparse.Namespace) -> dict:
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise PinError(f"--root is not a directory: {root}")
    if not PREDICATE_ID_RE.fullmatch(args.predicate_id):
        raise PinError(f"--predicate-id is invalid: {args.predicate_id!r}")
    if not SEMVER_RE.fullmatch(args.entry_version):
        raise PinError(f"--entry-version must be MAJOR.MINOR.PATCH: {args.entry_version!r}")
    if not CIRCUIT_RE.fullmatch(args.circuit):
        raise PinError(f"--circuit is invalid: {args.circuit!r}")

    source_file, source_path = safe_repo_file(root, args.source_path, "--source-path")
    try:
        package = inspect_circuit_package(root, args.circuit, source_path)
    except NoirPackageError as exc:
        raise PinError(f"invalid circuit package: {exc}") from None
    encoder_file, encoder_path = safe_repo_file(
        root, args.public_input_encoder, "--public-input-encoder"
    )
    manifest_file, _ = safe_repo_file(root, args.manifest, "--manifest")
    encoder = load_json(encoder_file, "public-input encoder")
    proof_types = validate_encoder(encoder, args.circuit)

    manifest = load_json(manifest_file, "artifact manifest")
    artifact_pins = pins_from_manifest(manifest, args.circuit, encoder_path)
    entry_path = f"registry/predicates/{args.predicate_id}/{args.entry_version}/entry.json"
    prospective = root / entry_path
    if prospective.exists():
        raise PinError(
            f"prospective entry already exists: {entry_path}; published entries are immutable"
        )

    entries = existing_entries(root)
    lineage = [
        (path, entry)
        for path, entry in entries
        if entry.get("predicateId", path.parent.parent.name) == args.predicate_id
    ]
    required_supersedes = None
    if lineage:
        lineage_versions = []
        for path, entry in lineage:
            version = entry.get("entryVersion", path.parent.name)
            if isinstance(version, str) and SEMVER_RE.fullmatch(version):
                lineage_versions.append((tuple(int(part) for part in version.split(".")), version))
        if not lineage_versions:
            raise PinError(f"existing predicate lineage {args.predicate_id!r} has no valid versions")
        latest_key, latest_version = max(lineage_versions)
        proposed_key = tuple(int(part) for part in args.entry_version.split("."))
        if proposed_key <= latest_key:
            raise PinError(
                f"--entry-version must be newer than committed {latest_version!r} "
                f"in lineage {args.predicate_id!r}"
            )
        required_supersedes = f"{args.predicate_id}@{latest_version}"

        # A same-lineage replacement must start with package and encoder paths
        # that no committed entry already references. Independent new
        # lineages remain free to reuse an existing implementation.
        candidate_package = package.package_root
        for path, entry in entries:
            where = path.relative_to(root).as_posix()
            circuit = entry.get("circuit") if isinstance(entry.get("circuit"), dict) else {}
            existing_source = circuit.get("sourcePath")
            if isinstance(existing_source, str) and source_package_reference(
                root, existing_source
            ) == candidate_package:
                raise PinError(
                    f"{where} already references source package {candidate_package!r}; "
                    "a new version in this lineage needs a new source package"
                )
            if entry.get("publicInputEncoder") == encoder_path:
                raise PinError(
                    f"{where} already references publicInputEncoder {encoder_path!r}; "
                    "a new version in this lineage needs a new encoder path"
                )

        for path, entry in lineage:
            where = path.relative_to(root).as_posix()
            circuit = entry.get("circuit") if isinstance(entry.get("circuit"), dict) else {}
            if circuit.get("name") == args.circuit:
                raise PinError(
                    f"{where} already uses circuit name {args.circuit!r}; "
                    "a new version in this lineage needs a new artifact identity"
                )
            old_proof_types = entry.get("proofTypes", [])
            if isinstance(old_proof_types, list):
                overlap = sorted(set(proof_types).intersection(old_proof_types))
                if overlap:
                    raise PinError(
                        f"{where} already uses proofTypes {overlap}; "
                        "proofTypes must be disjoint across versions in one lineage"
                    )

    fragment = {
        "entryPath": entry_path,
        "predicateId": args.predicate_id,
        "entryVersion": args.entry_version,
        "proofTypes": proof_types,
        "circuit": {
            "name": args.circuit,
            "scheme": "ultra_honk",
            "sourcePath": source_path,
            "sourceSha256": hashlib.sha256(source_file.read_bytes()).hexdigest(),
            **artifact_pins,
        },
        "publicInputEncoder": encoder_path,
    }
    if required_supersedes is not None:
        fragment["requiredActivationSupersedes"] = required_supersedes
    return fragment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predicate-id", required=True)
    parser.add_argument("--entry-version", required=True)
    parser.add_argument("--circuit", required=True)
    parser.add_argument("--source-path", required=True)
    parser.add_argument("--public-input-encoder", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--root", default=str(ROOT), help="repository root (default: helper's root)")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build_fragment(args), indent=2, sort_keys=True))
        return 0
    except PinError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
