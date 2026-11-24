#!/usr/bin/env python3
"""Prevent mutation of committed predicate-registry identities and bytes.

For pull requests and merge groups, this checker compares the merge-base Git
*tree* with the current working tree. For a default-branch push audit,
``--exact-base`` compares the event's exact before-tree so a force rewrite
cannot erase an entry by moving the merge base behind its publication. Both
modes cover committed changes and the uncommitted checkout that CI validates,
without trusting review or activation metadata.

Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import posixpath
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from typing import Callable, Optional


ENTRY_PREFIX = "registry/predicates"
IDENTITY_FIELDS = ("predicateId", "entryVersion", "proofTypes", "circuit", "publicInputEncoder")
V2_ENTRY_VERSION = "zkc:registry:predicate-entry:v2"
V2_IDENTITY_FIELDS = (
    "predicateId", "entryVersion", "proofTypes", "sourceId", "source",
    "publicInputContract", "supersedes", "adoptsV1",
)
V2_BINDING_IMMUTABLE_FIELDS = (
    "version", "predicateId", "entryVersion", "sourceId", "bindingId", "circuit",
    "scheme", "toolchain", "buildProfile", "artifactManifestKey", "artifacts",
    "acirHash", "vkHash", "vkSha256",
)
PUBLIC_INPUT_ENCODER_DIR = pathlib.PurePosixPath("schemas/public-inputs")
PUBLIC_INPUT_BINDING_DIR = pathlib.PurePosixPath("schemas/public-input-bindings")
BINDING_SCHEMA_SELECTORS = {
    (
        "zkc:public-input-bindings:v1",
        "https://zkc.dev/schemas/public-input-binding-v1.schema.json",
    ): "schemas/public-input-binding-v1.schema.json",
    (
        "zkc:public-input-bindings:v2",
        "https://zkc.dev/schemas/public-input-binding-v2.schema.json",
    ): "schemas/public-input-binding-v2.schema.json",
}


@dataclass
class EntrySnapshot:
    """One entry as read from a tree, keyed by its repository-relative path."""

    path: str
    data: object


@dataclass
class RegistrySnapshot:
    """Entries and a byte reader for either a directory or a Git tree."""

    entries: dict[str, EntrySnapshot]
    errors: list[str]
    _read_bytes: Callable[[str], Optional[bytes]]
    _list_files: Callable[[str], list[str]]

    def read_bytes(self, path: str) -> Optional[bytes]:
        return self._read_bytes(path)

    def list_files(self, path: str) -> list[str]:
        return self._list_files(path)


def _entry_paths_from_directory(root: pathlib.Path) -> list[str]:
    predicates = root / ENTRY_PREFIX
    if not predicates.is_dir():
        return []
    return sorted(path.relative_to(root).as_posix() for path in predicates.rglob("entry.json"))


def _decode_entries(
    paths: list[str], read_bytes: Callable[[str], Optional[bytes]]
) -> RegistrySnapshot:
    entries: dict[str, EntrySnapshot] = {}
    errors: list[str] = []
    for path in paths:
        raw = read_bytes(path)
        if raw is None:
            errors.append(f"{path}: entry disappeared while being read")
            continue
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"{path}: cannot parse JSON ({exc})")
            data = None
        entries[path] = EntrySnapshot(path=path, data=data)
    return RegistrySnapshot(
        entries=entries,
        errors=errors,
        _read_bytes=read_bytes,
        _list_files=lambda _path: [],
    )


def snapshot_from_directory(root: pathlib.Path | str) -> RegistrySnapshot:
    """Read registry entries from a checkout directory.

    This is intentionally public so unit tests and other local checks can use
    exactly the same comparison semantics as the CI command.
    """
    root_path = pathlib.Path(root)

    def read_bytes(path: str) -> Optional[bytes]:
        candidate = root_path / path
        try:
            if candidate.is_symlink():
                return None
            return candidate.read_bytes()
        except OSError:
            return None

    def list_files(path: str) -> list[str]:
        candidate = root_path / path
        if candidate.is_symlink() or candidate.is_file():
            return [path]
        if not candidate.is_dir():
            return []
        return sorted(
            child.relative_to(root_path).as_posix()
            for child in candidate.rglob("*")
            if child.is_symlink() or child.is_file()
        )

    snapshot = _decode_entries(_entry_paths_from_directory(root_path), read_bytes)
    snapshot._list_files = list_files
    return snapshot


def _run_git(arguments: list[str], cwd: pathlib.Path) -> bytes:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(detail or " ".join(arguments))
    return completed.stdout


def snapshot_from_git_tree(repo_root: pathlib.Path | str, treeish: str) -> RegistrySnapshot:
    """Read registry entries and source bytes from an immutable Git tree."""
    repo = pathlib.Path(repo_root)
    listing = _run_git(
        ["git", "ls-tree", "-r", "-z", "--name-only", treeish, "--", ENTRY_PREFIX], repo
    )
    paths = [
        item.decode("utf-8", "surrogateescape")
        for item in listing.split(b"\0")
        if item and item.endswith(b"/entry.json")
    ]

    def read_bytes(path: str) -> Optional[bytes]:
        try:
            return _run_git(["git", "show", f"{treeish}:{path}"], repo)
        except RuntimeError:
            return None

    def list_files(path: str) -> list[str]:
        listing = _run_git(
            ["git", "ls-tree", "-r", "-z", "--name-only", treeish, "--", path], repo
        )
        return sorted(
            item.decode("utf-8", "surrogateescape")
            for item in listing.split(b"\0")
            if item
        )

    snapshot = _decode_entries(sorted(paths), read_bytes)
    snapshot._list_files = list_files
    return snapshot


def _entry_object(snapshot: RegistrySnapshot, path: str, side: str, findings: list[str]) -> Optional[dict]:
    entry = snapshot.entries.get(path)
    if entry is None:
        findings.append(f"{path}: base registry entry was deleted; publish a new entry version instead")
        return None
    if not isinstance(entry.data, dict):
        findings.append(f"{path}: {side} registry entry is not a readable JSON object")
        return None
    return entry.data


def _value(entry: dict, field: str):
    """Preserve the distinction between a missing field and a JSON null."""
    return entry.get(field, _MISSING)


_MISSING = object()


def _source_path(entry: dict) -> Optional[str]:
    circuit = entry.get("circuit")
    if isinstance(circuit, dict) and isinstance(circuit.get("sourcePath"), str):
        return circuit["sourcePath"]
    return None


def _binding_path(encoder: object) -> Optional[str]:
    """Derive the verifier-contract sidecar for a canonical encoder path.

    Existing entry documents predate binding sidecars, so the association is
    deliberately derived instead of backfilled into their immutable identity.
    The current contract requires matching filenames in the two schema
    directories; non-canonical legacy encoder paths have no implicit sidecar.
    """
    if not isinstance(encoder, str):
        return None
    path = pathlib.PurePosixPath(encoder)
    if path.parent != PUBLIC_INPUT_ENCODER_DIR or path.suffix != ".json":
        return None
    return (PUBLIC_INPUT_BINDING_DIR / path.name).as_posix()


def _binding_schema_path(binding_bytes: bytes) -> Optional[str]:
    """Resolve the supported canonical schema selected by a binding sidecar."""
    try:
        document = json.loads(binding_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    return BINDING_SCHEMA_SELECTORS.get((document.get("version"), document.get("$schema")))


def _package_root(snapshot: RegistrySnapshot, source_path: str) -> Optional[str]:
    """Return the nearest Noir package containing ``source_path``."""
    path = pathlib.PurePosixPath(source_path)
    if path.is_absolute() or ".." in path.parts:
        return None
    for parent in path.parents:
        if parent == pathlib.PurePosixPath("."):
            break
        manifest = f"{parent.as_posix()}/Nargo.toml"
        if snapshot.read_bytes(manifest) is not None:
            return parent.as_posix()
    return None


def _local_dependencies(
    snapshot: RegistrySnapshot,
    package_root: str,
    where: str,
    findings: list[str],
) -> list[str]:
    manifest_path = f"{package_root}/Nargo.toml"
    raw = snapshot.read_bytes(manifest_path)
    if raw is None:
        findings.append(f"{where}: base package manifest is missing: {manifest_path}")
        return []
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        findings.append(f"{where}: cannot parse base package manifest {manifest_path}: {exc}")
        return []

    roots = []
    for table_name in ("dependencies", "dev-dependencies"):
        dependencies = document.get(table_name, {})
        if not isinstance(dependencies, dict):
            continue
        for dependency in dependencies.values():
            if not isinstance(dependency, dict) or not isinstance(dependency.get("path"), str):
                continue
            resolved = posixpath.normpath(
                posixpath.join(package_root, dependency["path"])
            )
            if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
                findings.append(
                    f"{where}: local dependency escapes the repository: "
                    f"{package_root}/{dependency['path']}"
                )
                continue
            if snapshot.read_bytes(f"{resolved}/Nargo.toml") is None:
                findings.append(
                    f"{where}: local dependency package is missing: {resolved}"
                )
                continue
            roots.append(resolved)
    return roots


def _package_closure(
    snapshot: RegistrySnapshot,
    package_root: str,
    where: str,
    findings: list[str],
) -> set[str]:
    closure = set()
    pending = [package_root]
    while pending:
        current = pending.pop()
        if current in closure:
            continue
        closure.add(current)
        pending.extend(_local_dependencies(snapshot, current, where, findings))
    return closure


def _compare_package(
    base: RegistrySnapshot,
    current: RegistrySnapshot,
    package_root: str,
    where: str,
    findings: list[str],
) -> None:
    base_files = set(base.list_files(package_root))
    current_files = set(current.list_files(package_root))
    for path in sorted(base_files - current_files):
        findings.append(
            f"{where}: immutable circuit package file was deleted: {path}"
        )
    for path in sorted(current_files - base_files):
        findings.append(
            f"{where}: immutable circuit package gained a file: {path}; "
            "publish a new source package instead"
        )
    for path in sorted(base_files & current_files):
        base_bytes = base.read_bytes(path)
        current_bytes = current.read_bytes(path)
        if base_bytes is None:
            findings.append(f"{where}: base circuit package file is unreadable: {path}")
        elif current_bytes is None:
            findings.append(f"{where}: immutable circuit package file is unreadable: {path}")
        elif base_bytes != current_bytes:
            findings.append(
                f"{where}: immutable circuit package bytes changed at {path}; "
                "publish a new source package instead"
            )


def _semver_key(value: object) -> Optional[tuple[int, int, int]]:
    if not isinstance(value, str):
        return None
    parts = value.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _json_file(snapshot: RegistrySnapshot, path: str, findings: list[str], label: str):
    raw = snapshot.read_bytes(path)
    if raw is None:
        findings.append(f"{path}: {label} is missing")
        return None
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        findings.append(f"{path}: {label} is not valid JSON")
        return None
    return value if isinstance(value, dict) else None


def _v2_binding_paths(snapshot: RegistrySnapshot, entry_path: str) -> list[str]:
    version_dir = posixpath.dirname(entry_path)
    return [
        path
        for path in snapshot.list_files(f"{version_dir}/bindings")
        if path.endswith(".json")
    ]


def _version_pins(snapshot: RegistrySnapshot, side: str, findings: list[str]) -> dict[str, str]:
    """Resolve the build loader's KEY=value/earlier-key-reference pin syntax."""
    raw = snapshot.read_bytes(".noir-version")
    values: dict[str, str] = {}
    try:
        if raw is None:
            raise ValueError("file is missing or unreadable")
        for line in raw.decode("utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if not separator or key in values:
                raise ValueError(f"invalid or duplicate pin {key!r}")

            def replace(match: re.Match[str]) -> str:
                referenced = match.group(1)
                if referenced not in values:
                    raise ValueError(f"undefined or forward pin {referenced!r}")
                return values[referenced]

            values[key] = re.sub(r"\$\{([A-Z][A-Z0-9_]*)\}", replace, value)
    except (UnicodeDecodeError, ValueError) as exc:
        findings.append(f".noir-version: {side} toolchain version pins are unreadable ({exc})")
    return values


def _compare_toolchain_inputs(
    base: RegistrySnapshot, current: RegistrySnapshot, findings: list[str]
) -> None:
    """Freeze published package assignments and their effective compiler inputs.

    Compare selected values, not the whole configuration: new packages and
    unused lanes may evolve without repinning any committed build identity.
    Bases predating the explicit package map have no mapping to compare.
    """
    config_path = "noir/toolchains.json"
    if base.read_bytes(config_path) is None or not base.entries:
        return
    packages: set[str] = set()
    for path, snapshot in base.entries.items():
        entry = snapshot.data
        if not isinstance(entry, dict):
            continue
        if entry.get("version") == V2_ENTRY_VERSION:
            source = entry.get("source", {})
            if isinstance(source, dict) and isinstance(source.get("circuit"), str):
                packages.add(source["circuit"])
            for binding_path in _v2_binding_paths(base, path):
                binding = _json_file(base, binding_path, findings, "base artifact binding")
                if isinstance(binding, dict) and isinstance(binding.get("circuit"), str):
                    packages.add(binding["circuit"])
        else:
            circuit = entry.get("circuit", {})
            if isinstance(circuit, dict) and isinstance(circuit.get("name"), str):
                packages.add(circuit["name"])
    if not packages:
        return

    configs = []
    for side, snapshot in (("base", base), ("current", current)):
        config = _json_file(snapshot, config_path, findings, f"{side} toolchain configuration")
        if not isinstance(config, dict) or not all(
            isinstance(config.get(key), dict) for key in ("packages", "toolchains")
        ) or config.get("version") != "zkc:noir-toolchains:v1":
            findings.append(f"{config_path}: {side} toolchain configuration has an unsupported shape/version")
            return
        configs.append(config)
    old, new = configs
    lanes: set[str] = set()
    for package in sorted(packages):
        assignment = old["packages"].get(package)
        selected = [assignment] if isinstance(assignment, str) else assignment
        if not isinstance(selected, list) or not selected or not all(
            isinstance(lane, str) and lane for lane in selected
        ) or len(set(selected)) != len(selected):
            findings.append(f"{config_path}: base package toolchain mapping is invalid: {package}")
            continue
        if assignment != new["packages"].get(package):
            findings.append(
                f"{config_path}: immutable package toolchain mapping changed or was deleted: "
                f"{package}; retain the committed lanes and publish an additive package instead"
            )
        lanes.update(selected)

    pin_keys: set[str] = set()
    for lane in sorted(lanes):
        definition = old["toolchains"].get(lane)
        if not isinstance(definition, dict) or set(definition) != {"nargo", "noirc", "bb"} or not all(
            isinstance(value, str) and value for value in definition.values()
        ):
            findings.append(f"{config_path}: base toolchain definition is invalid: {lane}")
        if definition != new["toolchains"].get(lane):
            findings.append(f"{config_path}: immutable toolchain definition changed or was deleted: {lane}")
        if lane not in ("historical", "successor"):
            findings.append(f"{config_path}: unsupported base toolchain pin resolution: {lane}")
            continue
        pin_keys.update((f"{lane.upper()}_NARGO_VERSION", f"{lane.upper()}_BB_VERSION"))
        if lane == "historical":
            pin_keys.update(("NARGO_VERSION", "BB_VERSION"))
    old_pins = _version_pins(base, "base", findings)
    new_pins = _version_pins(current, "current", findings)
    for key in sorted(pin_keys):
        if not old_pins.get(key):
            findings.append(f".noir-version: base toolchain version pin is missing: {key}")
        elif old_pins[key] != new_pins.get(key):
            findings.append(f".noir-version: immutable toolchain version pin changed or was deleted: {key}")


def _lifecycle_transition_allowed(base: dict, current: dict) -> bool:
    order = {"draft": 0, "in_review": 1, "self_attested": 2, "reviewed": 3, "deprecated": 4}
    base_review = base.get("review", {})
    current_review = current.get("review", {})
    if order.get(current_review.get("status"), -1) < order.get(base_review.get("status"), -1):
        return False
    base_activation = base.get("activation", {})
    current_activation = current.get("activation", {})
    old_time = base_activation.get("activatedAt")
    new_time = current_activation.get("activatedAt")
    if old_time is not None and new_time != old_time:
        return False
    old_supersedes = base_activation.get("supersedes")
    new_supersedes = current_activation.get("supersedes")
    if old_supersedes is not None and new_supersedes != old_supersedes:
        return False
    if "deprecation" in base and current.get("deprecation") != base.get("deprecation"):
        return False
    return True


def check_immutability(base: RegistrySnapshot, current: RegistrySnapshot) -> list[str]:
    """Return actionable findings for mutations from ``base`` to ``current``.

    Review evidence, status, activation, and deprecation are intentionally not
    compared. The original source package and its local dependency closure,
    encoder, associated verifier-contract sidecar, and the sidecar's canonical
    schema are byte-compared even if a change edits every current-state pin or
    review artifact in coordination.
    """
    findings = [f"base snapshot: {error}" for error in base.errors]
    findings.extend(f"current snapshot: {error}" for error in current.errors)
    _compare_toolchain_inputs(base, current, findings)
    base_predicate_ids: set[str] = set()
    base_proof_types: dict[str, set[object]] = {}
    base_versions: dict[str, set[str]] = {}
    base_source_paths: set[str] = set()
    base_package_roots: set[str] = set()
    base_encoders: set[str] = set()
    compared_packages: set[str] = set()
    compared_loose_sources: set[str] = set()
    compared_encoders: set[str] = set()
    compared_bindings: set[str] = set()
    binding_schemas: dict[str, str] = {}
    current_versions: dict[str, list[tuple[tuple[int, int, int], str]]] = {}

    for current_snapshot in current.entries.values():
        if not isinstance(current_snapshot.data, dict):
            continue
        current_proof_types = current_snapshot.data.get("proofTypes")
        if not isinstance(current_proof_types, list) or not all(
            isinstance(item, str) for item in current_proof_types
        ):
            findings.append(
                f"{current_snapshot.path}: current proofTypes must be an array of strings"
            )
        predicate_id = current_snapshot.data.get("predicateId")
        version = current_snapshot.data.get("entryVersion")
        version_key = _semver_key(version)
        if isinstance(predicate_id, str) and isinstance(version, str) and version_key:
            current_versions.setdefault(predicate_id, []).append((version_key, version))

    for path, base_entry_snapshot in sorted(base.entries.items()):
        if not isinstance(base_entry_snapshot.data, dict):
            continue
        base_entry = base_entry_snapshot.data
        if base_entry.get("version") == V2_ENTRY_VERSION:
            current_entry = _entry_object(current, path, "current", findings)
            if current_entry is not None:
                for field in V2_IDENTITY_FIELDS:
                    if base_entry.get(field) != current_entry.get(field):
                        findings.append(
                            f"{path}: immutable v2 source identity field '{field}' changed; "
                            "publish a semantic source successor instead"
                        )
                if not _lifecycle_transition_allowed(base_entry, current_entry):
                    findings.append(
                        f"{path}: source review/deprecation transition is not monotonic"
                    )
            protected_pins = []
            source = base_entry.get("source", {})
            if isinstance(source, dict) and isinstance(source.get("files"), list):
                protected_pins.extend(source["files"])
            contract = base_entry.get("publicInputContract", {})
            if isinstance(contract, dict):
                protected_pins.extend(contract.values())
            for pin in protected_pins:
                protected = pin.get("path") if isinstance(pin, dict) else None
                if not isinstance(protected, str):
                    findings.append(f"{path}: malformed base v2 protected-file pin")
                    continue
                before = base.read_bytes(protected)
                after = current.read_bytes(protected)
                if before is None:
                    findings.append(f"{path}: base v2 protected file is missing: {protected}")
                elif after is None:
                    findings.append(f"{path}: immutable v2 protected file was deleted: {protected}")
                elif before != after:
                    findings.append(f"{path}: immutable v2 protected file changed: {protected}")

            base_binding_paths = _v2_binding_paths(base, path)
            current_binding_paths = set(_v2_binding_paths(current, path))
            base_artifact_paths = set()
            for binding_path in base_binding_paths:
                base_binding = _json_file(base, binding_path, findings, "base artifact binding")
                if base_binding is None:
                    continue
                current_binding = _json_file(
                    current, binding_path, findings, "committed artifact binding"
                )
                if current_binding is None:
                    continue
                for field in V2_BINDING_IMMUTABLE_FIELDS:
                    if base_binding.get(field) != current_binding.get(field):
                        findings.append(
                            f"{binding_path}: immutable binding field '{field}' changed; "
                            "publish a new child binding instead"
                        )
                if not _lifecycle_transition_allowed(base_binding, current_binding):
                    findings.append(
                        f"{binding_path}: binding review/activation/deprecation transition "
                        "is not monotonic"
                    )
                artifacts = base_binding.get("artifacts", {})
                for artifact_path in artifacts.values() if isinstance(artifacts, dict) else ():
                    if not isinstance(artifact_path, str):
                        continue
                    base_artifact_paths.add(artifact_path)
                    before = base.read_bytes(artifact_path)
                    after = current.read_bytes(artifact_path)
                    if before is None:
                        findings.append(
                            f"{binding_path}: base binding artifact is missing: {artifact_path}"
                        )
                    elif after is None:
                        findings.append(
                            f"{binding_path}: immutable binding artifact was deleted: {artifact_path}"
                        )
                    elif before != after:
                        findings.append(
                            f"{binding_path}: immutable binding artifact changed: {artifact_path}"
                        )
                provenance = base_binding.get("toolchain", {}).get("provenance", {})
                provenance_path = provenance.get("path") if isinstance(provenance, dict) else None
                if isinstance(provenance_path, str):
                    before = base.read_bytes(provenance_path)
                    after = current.read_bytes(provenance_path)
                    if before != after:
                        findings.append(
                            f"{binding_path}: immutable toolchain provenance changed: {provenance_path}"
                        )

            for binding_path in sorted(current_binding_paths - set(base_binding_paths)):
                binding = _json_file(current, binding_path, findings, "new artifact binding")
                if binding is None:
                    continue
                artifacts = binding.get("artifacts", {})
                for artifact_path in artifacts.values() if isinstance(artifacts, dict) else ():
                    if artifact_path in base_artifact_paths or base.read_bytes(artifact_path) is not None:
                        findings.append(
                            f"{binding_path}: new binding reuses a previously published artifact path "
                            f"{artifact_path!r}"
                        )
            continue
        predicate_id = base_entry.get("predicateId")
        if isinstance(predicate_id, str):
            base_predicate_ids.add(predicate_id)
            version = base_entry.get("entryVersion")
            if isinstance(version, str):
                base_versions.setdefault(predicate_id, set()).add(version)
            proof_types = base_entry.get("proofTypes")
            if isinstance(proof_types, list):
                base_proof_types.setdefault(predicate_id, set()).update(
                    item for item in proof_types if isinstance(item, str)
                )
                if not all(isinstance(item, str) for item in proof_types):
                    findings.append(f"{path}: base proofTypes contains a non-string value")
        source_path = _source_path(base_entry)
        if source_path is not None:
            base_source_paths.add(source_path)
            package_root = _package_root(base, source_path)
            if package_root is not None:
                base_package_roots.add(package_root)
        else:
            package_root = None
        encoder = base_entry.get("publicInputEncoder")
        if isinstance(encoder, str):
            base_encoders.add(encoder)

        current_entry = _entry_object(current, path, "current", findings)
        if current_entry is not None:
            for field in IDENTITY_FIELDS:
                if _value(base_entry, field) != _value(current_entry, field):
                    findings.append(
                        f"{path}: immutable identity field '{field}' changed; "
                        "publish a new entry version instead"
                    )

        # Source identity is the complete direct package plus every local Noir
        # dependency package reachable from its base Nargo.toml. This detects
        # manifest/dependency edits as well as coordinated main.nr/hash repins.
        if source_path is not None:
            if package_root is not None:
                closure = _package_closure(base, package_root, path, findings)
                for closure_root in sorted(closure):
                    if closure_root not in compared_packages:
                        _compare_package(base, current, closure_root, path, findings)
                        compared_packages.add(closure_root)
            elif source_path not in compared_loose_sources:
                base_bytes = base.read_bytes(source_path)
                current_bytes = current.read_bytes(source_path)
                if base_bytes is None:
                    findings.append(f"{path}: base circuit source is missing: {source_path}")
                elif current_bytes is None:
                    findings.append(
                        f"{path}: immutable circuit source was deleted: {source_path}; "
                        "publish a new source package instead"
                    )
                elif base_bytes != current_bytes:
                    findings.append(
                        f"{path}: immutable circuit source bytes changed at {source_path}; "
                        "publish a new source package instead"
                    )
                compared_loose_sources.add(source_path)

        if isinstance(encoder, str) and encoder not in compared_encoders:
            base_bytes = base.read_bytes(encoder)
            current_bytes = current.read_bytes(encoder)
            if base_bytes is None:
                findings.append(f"{path}: base public-input encoder is missing: {encoder}")
            elif current_bytes is None:
                findings.append(f"{path}: immutable public-input encoder was deleted: {encoder}")
            elif base_bytes != current_bytes:
                findings.append(f"{path}: immutable public-input encoder bytes changed: {encoder}")
            compared_encoders.add(encoder)

        # The binding-sidecar path is canonically derived from the immutable
        # encoder. Encoders outside the canonical schemas/public-inputs
        # directory remain unaffected. Once a base tree contains the associated
        # sidecar, its complete bytes and the canonical schema selected by its
        # exact supported version/$schema pair are immutable verifier-contract
        # state.
        binding_path = _binding_path(encoder)
        if binding_path is not None and binding_path not in compared_bindings:
            base_bytes = base.read_bytes(binding_path)
            if base_bytes is not None:
                current_bytes = current.read_bytes(binding_path)
                if current_bytes is None:
                    findings.append(
                        f"{path}: immutable public-input binding sidecar was deleted: "
                        f"{binding_path}; publish a new additive contract identity instead"
                    )
                elif base_bytes != current_bytes:
                    findings.append(
                        f"{path}: immutable public-input binding sidecar bytes changed: "
                        f"{binding_path}; publish a new additive contract identity instead"
                    )
                schema_path = _binding_schema_path(base_bytes)
                if schema_path is None:
                    findings.append(
                        f"{path}: base public-input binding sidecar does not declare the "
                        f"supported canonical schema selector: {binding_path}"
                    )
                else:
                    binding_schemas.setdefault(schema_path, path)
            compared_bindings.add(binding_path)

    for schema_path, path in sorted(binding_schemas.items()):
        base_bytes = base.read_bytes(schema_path)
        current_bytes = current.read_bytes(schema_path)
        if base_bytes is None:
            findings.append(
                f"{path}: base public-input binding schema is missing: {schema_path}"
            )
        elif current_bytes is None:
            findings.append(
                f"{path}: immutable public-input binding schema was deleted: {schema_path}"
            )
        elif base_bytes != current_bytes:
            findings.append(
                f"{path}: immutable public-input binding schema bytes changed: {schema_path}; "
                "retain v1 and publish a new additive contract identity instead; future "
                "schema versions require explicit admission support"
            )

    # A successor may extend a lineage, but it cannot silently replace its
    # predecessor's proof-type contract, source, or encoder.  Independent
    # lineages remain free to overlap in proof types.
    for path, current_entry_snapshot in sorted(current.entries.items()):
        if path in base.entries or not isinstance(current_entry_snapshot.data, dict):
            continue
        entry = current_entry_snapshot.data
        predicate_id = entry.get("predicateId")
        if not isinstance(predicate_id, str) or predicate_id not in base_predicate_ids:
            continue
        if entry.get("version") == V2_ENTRY_VERSION:
            version = entry.get("entryVersion")
            version_key = _semver_key(version)
            base_keys = [
                (_semver_key(base_version), base_version)
                for base_version in base_versions.get(predicate_id, set())
            ]
            valid_base_keys = [item for item in base_keys if item[0] is not None]
            if version_key is not None and valid_base_keys:
                latest_base_key, latest_base_version = max(valid_base_keys)
                if version_key <= latest_base_key:
                    findings.append(
                        f"{path}: new v2 entryVersion {version!r} is not newer than "
                        f"committed {latest_base_version!r}"
                    )
                expected = f"{predicate_id}@{latest_base_version}"
                if entry.get("supersedes") != expected:
                    findings.append(
                        f"{path}: v2 successor must name immediate predecessor {expected!r}"
                    )
            proof_types = entry.get("proofTypes", [])
            overlap = set(item for item in proof_types if isinstance(item, str)) & base_proof_types.get(
                predicate_id, set()
            )
            if overlap and not isinstance(entry.get("adoptsV1"), str):
                findings.append(
                    f"{path}: v2 proof-type reuse {sorted(overlap)!r} requires an exact adoptsV1 record"
                )
            continue
        proof_types = entry.get("proofTypes")
        if isinstance(proof_types, list):
            overlap = sorted(
                {item for item in proof_types if isinstance(item, str)}
                & base_proof_types.get(predicate_id, set()),
                key=repr,
            )
            if overlap:
                findings.append(
                    f"{path}: new entry reuses base lineage proofTypes {overlap!r} for "
                    f"predicateId '{predicate_id}'; use distinct proof types"
                )
        source_path = _source_path(entry)
        if source_path in base_source_paths:
            findings.append(
                f"{path}: new entry reuses base-referenced circuit sourcePath '{source_path}'; "
                "use a new source path"
            )
        if source_path is not None:
            package_root = _package_root(current, source_path)
            if package_root in base_package_roots:
                findings.append(
                    f"{path}: new entry reuses base-referenced circuit package "
                    f"'{package_root}'; use a new source package"
                )
        encoder = entry.get("publicInputEncoder")
        if encoder in base_encoders:
            findings.append(
                f"{path}: new entry reuses base-referenced publicInputEncoder {encoder!r}; "
                "use a new encoder"
            )

        version = entry.get("entryVersion")
        version_key = _semver_key(version)
        base_keys = [
            (_semver_key(base_version), base_version)
            for base_version in base_versions.get(predicate_id, set())
        ]
        valid_base_keys = [item for item in base_keys if item[0] is not None]
        if version_key is not None and valid_base_keys:
            latest_base_key, latest_base_version = max(valid_base_keys)
            if version_key <= latest_base_key:
                findings.append(
                    f"{path}: new same-lineage entryVersion {version!r} is not newer "
                    f"than committed {latest_base_version!r}"
                )
            predecessors = [
                item for item in current_versions.get(predicate_id, []) if item[0] < version_key
            ]
            if predecessors:
                _, predecessor = max(predecessors)
                expected = f"{predicate_id}@{predecessor}"
                activation = entry.get("activation")
                actual = activation.get("supersedes") if isinstance(activation, dict) else None
                if actual != expected:
                    findings.append(
                        f"{path}: same-lineage successor must set activation.supersedes "
                        f"to its immediate predecessor {expected!r} (observed {actual!r})"
                    )
    return findings


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-ref",
        required=True,
        help="CI-provided Git ref used as, or to derive, the comparison base",
    )
    parser.add_argument(
        "--exact-base",
        action="store_true",
        help="compare the supplied base tree exactly (required for push before-SHAs)",
    )
    args = parser.parse_args(argv)
    try:
        repo_root = pathlib.Path(
            _run_git(["git", "rev-parse", "--show-toplevel"], pathlib.Path.cwd())
            .decode("utf-8", "replace")
            .strip()
        )
        if args.exact_base:
            if not args.base_ref.strip("0"):
                raise RuntimeError("the push before-SHA is all zeroes; no exact base tree exists")
            comparison_base = _run_git(
                ["git", "rev-parse", "--verify", f"{args.base_ref}^{{commit}}"],
                repo_root,
            ).decode("ascii").strip()
        else:
            comparison_base = _run_git(
                ["git", "merge-base", args.base_ref, "HEAD"], repo_root
            ).decode("ascii").strip()
        base = snapshot_from_git_tree(repo_root, comparison_base)
        current = snapshot_from_directory(repo_root)
    except RuntimeError as exc:
        print(f"Registry immutability check could not establish its Git base: {exc}", file=sys.stderr)
        return 2

    findings = check_immutability(base, current)
    if findings:
        label = "exact base" if args.exact_base else "merge base"
        print(
            f"Registry immutability check: {len(findings)} finding(s) "
            f"against {label} {comparison_base}."
        )
        for finding in findings:
            print(f"- {finding}")
        return 1
    label = "exact base" if args.exact_base else "merge base"
    print(
        "Registry immutability check: no immutable registry changes "
        f"against {label} {comparison_base}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
