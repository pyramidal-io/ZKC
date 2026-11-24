#!/usr/bin/env python3
"""Build the reproducible ZKC circuit artifact manifest.

Invoked by scripts/generate_artifacts.sh. For every mapped bin package this
script:

  1. compiles it in a toolchain-specific copy of the single Noir workspace
  2. copies the compiled ACIR artifact into artifacts/build/<circuit>/
  3. runs the mapped `bb write_vk` to produce the verification key + vk hash
  4. extracts the flattened public input order from the compiled ABI
  5. cross-checks it against the committed encoder definition in
     schemas/public-inputs/<circuit>.json (when present)
  6. emits one combined artifacts/build/manifest.json and validates it against
     artifacts/manifest.schema.json

Standard library only. Binary paths are explicit and their versions are checked
against noir/toolchains.json and .noir-version before compilation starts.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

from noir_toolchains import (
    ToolchainError,
    load_config,
    package_toolchains,
    parse_binary_assignments,
    stage_and_compile,
    verify_binaries,
    workspace_bin_packages,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOIR_DIR = ROOT / "noir"
BUILD_DIR = ROOT / "artifacts" / "build"
MANIFEST_SCHEMA = ROOT / "artifacts" / "manifest.schema.json"
ENCODER_DIR = ROOT / "schemas" / "public-inputs"
NOIR_VERSION_FILE = ROOT / ".noir-version"
TOOLCHAIN_CONFIG = NOIR_DIR / "toolchains.json"
SPEC_VERSION = "0.2.5"


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def abi_type_to_string(abi_type: dict) -> str:
    kind = abi_type["kind"]
    if kind == "field":
        return "Field"
    if kind == "boolean":
        return "bool"
    if kind == "integer":
        prefix = "u" if abi_type["sign"] == "unsigned" else "i"
        return f"{prefix}{abi_type['width']}"
    if kind == "array":
        return f"[{abi_type_to_string(abi_type['type'])}; {abi_type['length']}]"
    fail(f"unsupported ABI type kind for public inputs: {kind}")
    return ""


def abi_type_field_elements(abi_type: dict) -> int:
    if abi_type["kind"] == "array":
        return abi_type["length"] * abi_type_field_elements(abi_type["type"])
    return 1


def flatten_public_inputs(abi: dict) -> list:
    inputs = []
    offset = 0
    for parameter in abi["parameters"]:
        if parameter["visibility"] != "public":
            continue
        elements = abi_type_field_elements(parameter["type"])
        inputs.append(
            {
                "index": len(inputs),
                "offset": offset,
                "name": parameter["name"],
                "abiType": abi_type_to_string(parameter["type"]),
                "fieldElements": elements,
            }
        )
        offset += elements
    if abi.get("return_type") is not None:
        fail("circuits with return values are not supported by the encoder profile")
    return inputs


def check_encoder(circuit: str, abi_inputs: list, require_encoder: bool):
    encoder_path = ENCODER_DIR / f"{circuit}.json"
    if not encoder_path.exists():
        if require_encoder:
            fail(f"missing public input encoder {encoder_path.relative_to(ROOT)}")
        print(f"  warning: no public input encoder committed for {circuit}")
        return None
    encoder = json.loads(encoder_path.read_text())
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
    if declared != abi_inputs:
        fail(
            f"{encoder_path.relative_to(ROOT)} does not match the compiled ABI of {circuit}:\n"
            f"  encoder:  {json.dumps(declared)}\n"
            f"  compiled: {json.dumps(abi_inputs)}"
        )
    total = sum(entry["fieldElements"] for entry in abi_inputs)
    if encoder["totalFieldElements"] != total:
        fail(
            f"{encoder_path.relative_to(ROOT)} totalFieldElements is "
            f"{encoder['totalFieldElements']}, compiled ABI flattens to {total}"
        )
    return str(encoder_path.relative_to(ROOT))


def validate_schema(instance, schema, path: str = "$") -> None:
    """Minimal JSON-Schema subset validator (type/const/pattern/required/
    properties/items/minItems/minimum) sufficient for the ZKC schemas."""
    if "const" in schema:
        if instance != schema["const"]:
            fail(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    expected_type = schema.get("type")
    if expected_type is not None:
        type_map = {
            "object": dict,
            "array": list,
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "null": type(None),
        }
        allowed = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(
            isinstance(instance, type_map[t]) and not (t == "integer" and isinstance(instance, bool))
            for t in allowed
        ):
            fail(f"{path}: expected type {expected_type}, got {type(instance).__name__}")
    if isinstance(instance, str) and "pattern" in schema:
        if not re.search(schema["pattern"], instance):
            fail(f"{path}: {instance!r} does not match pattern {schema['pattern']!r}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            fail(f"{path}: {instance} is below minimum {schema['minimum']}")
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                fail(f"{path}: missing required property {key!r}")
        for key, subschema in schema.get("properties", {}).items():
            if key in instance:
                validate_schema(instance[key], subschema, f"{path}.{key}")
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            fail(f"{path}: expected at least {schema['minItems']} items")
        if "items" in schema:
            for i, item in enumerate(instance):
                validate_schema(item, schema["items"], f"{path}[{i}]")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_binding_records() -> list[dict]:
    records = []
    for path in sorted((ROOT / "registry" / "predicates").glob("*/*/bindings/*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            fail(f"cannot read artifact binding {path.relative_to(ROOT)}: {exc}")
        if not isinstance(value, dict):
            fail(f"artifact binding must be an object: {path.relative_to(ROOT)}")
        records.append(value)
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-encoders",
        action="store_true",
        help="fail when a bin circuit has no committed public input encoder",
    )
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=TOOLCHAIN_CONFIG,
        help="package-to-toolchain build configuration",
    )
    parser.add_argument(
        "--nargo",
        action="append",
        default=[],
        metavar="TOOLCHAIN=PATH",
        help="nargo binary for a configured toolchain (repeat for every toolchain)",
    )
    parser.add_argument(
        "--bb",
        action="append",
        default=[],
        metavar="TOOLCHAIN=PATH",
        help="bb binary for a configured toolchain (repeat for every toolchain)",
    )
    parser.add_argument("--cache-root", type=pathlib.Path, required=True)
    parser.add_argument("--output-root", type=pathlib.Path, required=True)
    args = parser.parse_args()

    if shutil.which("git") is None:
        fail("git is not on PATH")
    try:
        config = load_config(args.config, NOIR_DIR, NOIR_VERSION_FILE)
        nargo_bins = parse_binary_assignments(args.nargo, "--nargo")
        bb_bins = parse_binary_assignments(args.bb, "--bb")
        verified = verify_binaries(config, nargo_bins, bb_bins)
    except (ToolchainError, OSError, subprocess.CalledProcessError) as error:
        fail(str(error))

    git_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout.strip()

    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True)

    try:
        compiled_artifacts = stage_and_compile(
            root=ROOT,
            source_noir_dir=NOIR_DIR,
            cache_root=args.cache_root.absolute(),
            output_root=args.output_root.absolute(),
            config=config,
            verified=verified,
        )
    except (ToolchainError, OSError, subprocess.CalledProcessError) as error:
        fail(str(error))

    binding_records = load_binding_records()
    bindings_by_build = {}
    for binding in binding_records:
        key = (binding.get("circuit"), binding.get("toolchain", {}).get("id"))
        bindings_by_build.setdefault(key, []).append(binding)

    circuits = []
    bindings = []
    for package in workspace_bin_packages(NOIR_DIR):
        name = package["name"]
        lanes = package_toolchains(config, name)
        for lane_index, toolchain_id in enumerate(lanes):
            print(f"processing {name} [{toolchain_id}] ...")
            toolchain = config["toolchains"][toolchain_id]
            artifact_key = name if len(lanes) == 1 else (name, toolchain_id)
            artifact_path = compiled_artifacts[artifact_key]
            if not artifact_path.exists():
                fail(f"mapped build output is missing: {artifact_path}")
            artifact = json.loads(artifact_path.read_text())
            if artifact["noir_version"] != toolchain["noirc"]:
                fail(
                    f"{name} was compiled with noir {artifact['noir_version']}, "
                    f"expected {toolchain['noirc']}"
                )

            build_key = name if lane_index == 0 else f"bindings/{name}/{toolchain_id}"
            circuit_dir = BUILD_DIR / build_key
            circuit_dir.mkdir(parents=True)
            shutil.copy(artifact_path, circuit_dir / f"{name}.json")
            bb_result = subprocess.run(
                [
                    str(verified[toolchain_id]["bb_bin"]),
                    "write_vk",
                    "-b",
                    str(artifact_path),
                    "-o",
                    str(circuit_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "HOME": str(args.cache_root.resolve() / toolchain_id)},
            )
            if bb_result.returncode != 0:
                fail(
                    f"{toolchain_id} bb write_vk failed for {name} "
                    f"(exit {bb_result.returncode}):\n"
                    f"stdout:\n{bb_result.stdout}\nstderr:\n{bb_result.stderr}"
                )

            abi_inputs = flatten_public_inputs(artifact["abi"])
            encoder_ref = check_encoder(name, abi_inputs, args.require_encoders)
            generated = {
                "acirHash": "sha256:" + sha256_hex(base64.b64decode(artifact["bytecode"])),
                "vkHash": "0x" + (circuit_dir / "vk_hash").read_bytes().hex(),
                "vkSha256": "sha256:" + sha256_hex((circuit_dir / "vk").read_bytes()),
            }
            build_artifacts = {
                "acir": f"artifacts/build/{build_key}/{name}.json",
                "vk": f"artifacts/build/{build_key}/vk",
            }
            if lane_index == 0:
                circuits.append(
                    {
                        "name": name,
                        "packageVersion": package["version"],
                        "description": package["description"],
                        "scheme": "ultra_honk",
                        "toolchain": toolchain,
                        **generated,
                        "publicInputEncoder": encoder_ref,
                        "publicInputs": abi_inputs,
                        "artifacts": build_artifacts,
                    }
                )
            for binding in bindings_by_build.get((name, toolchain_id), []):
                expected_toolchain = {key: binding["toolchain"][key] for key in ("nargo", "noirc", "bb")}
                if expected_toolchain != toolchain:
                    fail(
                        f"binding {binding['bindingId']} toolchain disagrees with lane "
                        f"{toolchain_id}: {expected_toolchain} != {toolchain}"
                    )
                for field, value in generated.items():
                    if binding[field] != value:
                        fail(
                            f"binding {binding['bindingId']} {field} disagrees with rebuilt output "
                            f"({binding[field]} != {value})"
                        )
                bindings.append(
                    {
                        **{
                            field: binding[field]
                            for field in (
                                "predicateId", "entryVersion", "sourceId", "bindingId",
                                "circuit", "scheme", "toolchain", "buildProfile",
                                "artifactManifestKey", "acirHash", "vkHash", "vkSha256",
                            )
                        },
                        "artifacts": build_artifacts,
                    }
                )

    historical = config["toolchains"]["historical"]
    manifest = {
        "version": "zkc:artifacts:v2",
        # Preserve the v1 top-level provenance for existing consumers. Circuit
        # provenance is authoritative for mixed-toolchain builds.
        "toolchain": historical,
        "source": {"gitCommit": git_commit, "specVersion": SPEC_VERSION},
        "circuits": circuits,
        "bindings": sorted(bindings, key=lambda item: item["artifactManifestKey"]),
    }
    validate_schema(manifest, json.loads(MANIFEST_SCHEMA.read_text()))

    manifest_path = BUILD_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {manifest_path.relative_to(ROOT)} ({len(circuits)} circuits)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
