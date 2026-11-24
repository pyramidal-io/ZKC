#!/usr/bin/env python3
"""Publish or verify the committed ZKC circuit artifact set.

`scripts/generate_artifacts.sh` writes the reproducible build output to
`artifacts/build/` (gitignored). This script maintains the COMMITTED copy that
ships in the repository so a fresh checkout can resolve verification keys
without a local Noir toolchain:

  artifacts/manifest.json          committed manifest (build manifest with
                                   artifact paths rewritten to the committed
                                   layout)
  artifacts/<circuit>/<circuit>.json  committed ACIR artifact in CANONICAL
                                   form: noir_version, hash, abi, bytecode.
                                   nargo's debug_symbols/file_map are
                                   machine-dependent (they embed local source
                                   paths), so they are stripped — the
                                   canonical form leaks no local paths. Its
                                   first-published top-level `hash` is retained
                                   when only nargo's workspace metadata drifts;
                                   ABI and bytecode remain exact. The manifest's
                                   acirHash covers the decoded bytecode and is
                                   unaffected.
  artifacts/<circuit>/vk              committed UltraHonk verification key
                                   (bb write_vk output, byte-stable)

Modes:
  publish (default)  copy the build artifacts into the committed layout and
                     write artifacts/manifest.json. Idempotent: when the
                     committed set already matches, nothing is rewritten (the
                     recorded source.gitCommit is preserved).
  --check            fail (exit 1) unless the committed set matches the fresh
                     build. `source.gitCommit` and nargo's workspace-dependent
                     top-level ACIR `hash` metadata are excluded; ACIR bytecode,
                     ABI, Noir version, VKs, and manifest pins remain exact.

Standard library only; requires a prior `scripts/generate_artifacts.sh` run.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import subprocess
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from build_artifact_manifest import validate_schema  # noqa: E402


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def committed_artifact_paths(name: str) -> dict:
    return {
        "acir": f"artifacts/{name}/{name}.json",
        "vk": f"artifacts/{name}/vk",
    }


def committed_binding_artifact_paths(binding: dict) -> dict:
    base = (
        f"artifacts/bindings/{binding['predicateId']}/{binding['entryVersion']}/"
        f"{binding['toolchain']['id']}"
    )
    return {"acir": f"{base}/{binding['circuit']}.json", "vk": f"{base}/vk"}


CANONICAL_ACIR_FIELDS = ("noir_version", "hash", "abi", "bytecode")


def canonical_acir_bytes(build_acir_path: pathlib.Path) -> bytes:
    """The committed, platform-stable serialization of a nargo ACIR artifact.

    Only the canonical fields are kept — nargo's debug_symbols/file_map embed
    machine-local source paths and differ between build hosts.
    """
    try:
        artifact = json.loads(build_acir_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"build ACIR artifact is unreadable: {build_acir_path}: {exc}")
    missing = [field for field in CANONICAL_ACIR_FIELDS if field not in artifact]
    if missing:
        fail(f"{build_acir_path} is missing ACIR artifact field(s): {', '.join(missing)}")
    canonical = {field: artifact[field] for field in CANONICAL_ACIR_FIELDS}
    return (json.dumps(canonical, indent=2) + "\n").encode("utf-8")


def compatible_acir_bytes(expected_bytes: bytes, committed_bytes: bytes) -> bool:
    """True when canonical ACIR bytes differ only in nargo's package hash.

    Nargo derives the top-level ``hash`` from workspace/package metadata, so
    adding an unrelated workspace member can change it while the ABI and ACIR
    bytecode remain identical.  Preserve a circuit's first-published metadata
    value in that narrow case.  Both documents must still use the exact
    canonical key order and serialization; extra fields or any other byte
    change fail closed.
    """
    if committed_bytes == expected_bytes:
        return True
    try:
        expected = json.loads(expected_bytes.decode("utf-8"))
        committed = json.loads(committed_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(expected, dict) or not isinstance(committed, dict):
        return False
    if tuple(expected) != CANONICAL_ACIR_FIELDS or tuple(committed) != CANONICAL_ACIR_FIELDS:
        return False
    if type(expected["hash"]) is not str or type(committed["hash"]) is not str:
        return False
    expected_with_committed_hash = dict(expected)
    expected_with_committed_hash["hash"] = committed["hash"]
    canonical = (json.dumps(expected_with_committed_hash, indent=2) + "\n").encode("utf-8")
    return canonical == committed_bytes


def artifact_bytes_match(committed_rel: str, expected: bytes, actual: bytes) -> bool:
    if committed_rel.endswith(".json"):
        return compatible_acir_bytes(expected, actual)
    return expected == actual


def published_manifest(build_manifest: dict) -> dict:
    """The build manifest with artifact paths rewritten to the committed layout."""
    manifest = copy.deepcopy(build_manifest)
    for circuit in manifest.get("circuits", []):
        circuit["artifacts"] = committed_artifact_paths(circuit["name"])
    for binding in manifest.get("bindings", []):
        binding["artifacts"] = committed_binding_artifact_paths(binding)
    return manifest


def comparable(manifest: dict) -> dict:
    """Compare effective provenance, including legacy inherited toolchains.

    Older manifests record one toolchain at the top level. A newly generated
    per-circuit declaration of that same toolchain must not force a rewrite
    of historical artifacts. Normalize inheritance, never discard provenance:
    any differing explicit nargo, noirc, or bb pin still fails comparison.
    """
    stripped = copy.deepcopy(manifest)
    if isinstance(stripped.get("source"), dict):
        stripped["source"].pop("gitCommit", None)
    for circuit in stripped.get("circuits", []):
        if "toolchain" not in circuit:
            circuit["toolchain"] = copy.deepcopy(stripped.get("toolchain"))
    return stripped


def load_manifest(path: pathlib.Path, label: str) -> dict:
    if not path.is_file():
        fail(f"{label} manifest not found: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} manifest is unreadable: {path}: {exc}")
    if not isinstance(manifest, dict):
        fail(f"{label} manifest must contain a JSON object: {path}")
    return manifest


def describe_differences(expected: dict, actual: dict, path: str = "$") -> list:
    """Human-readable paths at which two JSON values differ."""
    if type(expected) is not type(actual):
        return [f"{path}: {type(expected).__name__} != {type(actual).__name__}"]
    if isinstance(expected, dict):
        differences = []
        for key in sorted(set(expected) | set(actual)):
            if key not in actual:
                differences.append(f"{path}.{key}: missing from the committed manifest")
            elif key not in expected:
                differences.append(f"{path}.{key}: not present in the regenerated manifest")
            else:
                differences.extend(describe_differences(expected[key], actual[key], f"{path}.{key}"))
        return differences
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return [f"{path}: length {len(expected)} != {len(actual)}"]
        differences = []
        for index, (left, right) in enumerate(zip(expected, actual)):
            differences.extend(describe_differences(left, right, f"{path}[{index}]"))
        return differences
    if expected != actual:
        return [f"{path}: {expected!r} != {actual!r}"]
    return []


def expected_artifact_files(root: pathlib.Path, build_manifest: dict) -> list:
    """(committed_path, expected_bytes) for every published artifact file.

    Verification keys are published byte-for-byte; ACIR artifacts are
    published in canonical form (see canonical_acir_bytes).
    """
    files = []
    for circuit in build_manifest["circuits"]:
        name = circuit["name"]
        committed = committed_artifact_paths(name)
        build_acir = root / circuit["artifacts"]["acir"]
        build_vk = root / circuit["artifacts"]["vk"]
        if not build_acir.is_file():
            fail(f"build artifact is missing: {circuit['artifacts']['acir']}")
        if not build_vk.is_file():
            fail(f"build artifact is missing: {circuit['artifacts']['vk']}")
        files.append((committed["acir"], canonical_acir_bytes(build_acir)))
        files.append((committed["vk"], build_vk.read_bytes()))
    for binding in build_manifest.get("bindings", []):
        committed = committed_binding_artifact_paths(binding)
        build_acir = root / binding["artifacts"]["acir"]
        build_vk = root / binding["artifacts"]["vk"]
        if not build_acir.is_file():
            fail(f"binding build artifact is missing: {binding['artifacts']['acir']}")
        if not build_vk.is_file():
            fail(f"binding build artifact is missing: {binding['artifacts']['vk']}")
        files.append((committed["acir"], canonical_acir_bytes(build_acir)))
        files.append((committed["vk"], build_vk.read_bytes()))
    return files


def check(root: pathlib.Path, build_manifest: dict, committed_path: pathlib.Path) -> int:
    expected = published_manifest(build_manifest)
    committed = load_manifest(committed_path, "committed")

    problems = []
    differences = describe_differences(comparable(expected), comparable(committed))
    if differences:
        problems.append(
            f"{committed_path.relative_to(root)} does not match the regenerated build manifest:"
        )
        problems.extend(f"  {item}" for item in differences)

    for committed_rel, expected_bytes in expected_artifact_files(root, build_manifest):
        committed_file = root / committed_rel
        if not committed_file.is_file():
            problems.append(f"committed artifact is missing: {committed_rel}")
        elif not artifact_bytes_match(
            committed_rel, expected_bytes, committed_file.read_bytes()
        ):
            problems.append(
                f"committed artifact differs from the regenerated build: {committed_rel}"
            )

    if problems:
        print("Committed artifact set is OUT OF SYNC with the pinned-toolchain build:")
        for problem in problems:
            print(f"- {problem}")
        print("Regenerate and republish: scripts/generate_artifacts.sh --require-encoders "
              "&& python3 scripts/publish_artifacts.py")
        return 1
    print(f"Committed artifact set matches the regenerated build ({len(build_manifest['circuits'])} circuits).")
    return 0


def publish(root: pathlib.Path, build_manifest: dict, committed_path: pathlib.Path) -> int:
    manifest = published_manifest(build_manifest)
    artifact_files = expected_artifact_files(root, build_manifest)

    if committed_path.is_file():
        try:
            existing = json.loads(committed_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            existing = None
        if (
            isinstance(existing, dict)
            and comparable(existing) == comparable(manifest)
            and all(
                (root / committed_rel).is_file()
                and artifact_bytes_match(
                    committed_rel,
                    expected_bytes,
                    (root / committed_rel).read_bytes(),
                )
                for committed_rel, expected_bytes in artifact_files
            )
        ):
            print(f"{committed_path.relative_to(root)} is already up to date.")
            return 0

    git_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, cwd=root
    ).stdout.strip()
    manifest["source"]["gitCommit"] = git_commit

    schema_path = root / "artifacts" / "manifest.schema.json"
    validate_schema(manifest, json.loads(schema_path.read_text(encoding="utf-8")))

    for committed_rel, expected_bytes in artifact_files:
        destination = root / committed_rel
        if destination.is_file() and artifact_bytes_match(
            committed_rel, expected_bytes, destination.read_bytes()
        ):
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(expected_bytes)

    committed_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {committed_path.relative_to(root)} "
        f"({len(manifest['circuits'])} circuits, source commit {git_commit[:12]})"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed artifact set matches the regenerated build",
    )
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=SCRIPT_DIR.parent,
        help="repository root (tests only; defaults to this checkout)",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    build_manifest_path = root / "artifacts" / "build" / "manifest.json"
    if not build_manifest_path.is_file():
        fail(
            f"{build_manifest_path} not found - run scripts/generate_artifacts.sh "
            "(pinned toolchain, see .noir-version) first"
        )
    build_manifest = load_manifest(build_manifest_path, "build")
    committed_path = root / "artifacts" / "manifest.json"

    if args.check:
        return check(root, build_manifest, committed_path)
    return publish(root, build_manifest, committed_path)


if __name__ == "__main__":
    sys.exit(main())
