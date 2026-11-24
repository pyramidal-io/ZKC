#!/usr/bin/env python3
"""Safe, standard-library inspection of ZKC Noir package closures."""

from __future__ import annotations

import pathlib
import posixpath
import tomllib
from dataclasses import dataclass


class NoirPackageError(ValueError):
    """A circuit package cannot be safely and reproducibly inspected."""


@dataclass(frozen=True)
class NoirPackageInspection:
    package_root: str
    closure: tuple[str, ...]


def _relative_parts(value: str, label: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise NoirPackageError(f"{label} must be a normalized repository-relative path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise NoirPackageError(f"{label} must be a normalized repository-relative path")
    return path.parts


def _safe_node(root: pathlib.Path, relative: str, label: str) -> pathlib.Path:
    parts = _relative_parts(relative, label)
    candidate = root.joinpath(*parts)
    cursor = root
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise NoirPackageError(f"{label} must not traverse a symlink: {relative}")
    try:
        candidate.resolve(strict=False).relative_to(root.resolve())
    except (OSError, ValueError):
        raise NoirPackageError(f"{label} escapes the repository: {relative}") from None
    return candidate


def _manifest(root: pathlib.Path, package_root: str) -> dict:
    manifest_path = f"{package_root}/Nargo.toml"
    candidate = _safe_node(root, manifest_path, "Noir package manifest")
    if not candidate.is_file():
        raise NoirPackageError(f"Noir package manifest is missing: {manifest_path}")
    try:
        document = tomllib.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise NoirPackageError(f"cannot parse Noir package manifest {manifest_path}: {exc}") from None
    package = document.get("package")
    if not isinstance(package, dict):
        raise NoirPackageError(f"Noir package manifest has no [package] table: {manifest_path}")
    if not isinstance(package.get("name"), str) or not package["name"]:
        raise NoirPackageError(f"Noir package manifest has no package name: {manifest_path}")
    if package.get("type") not in ("bin", "lib"):
        raise NoirPackageError(
            f"Noir package manifest type must be 'bin' or 'lib': {manifest_path}"
        )
    return document


def _dependency_root(package_root: str, value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise NoirPackageError(
            f"local dependency path in {package_root}/Nargo.toml must be a non-empty POSIX path"
        )
    path = pathlib.PurePosixPath(value)
    if path.is_absolute():
        raise NoirPackageError(
            f"local dependency escapes the repository: {package_root}/{value}"
        )
    if posixpath.normpath(value) != value:
        raise NoirPackageError(
            f"local dependency path is not normalized: {package_root}/{value}"
        )
    resolved = posixpath.normpath(posixpath.join(package_root, value))
    if resolved in ("", ".", "..") or resolved.startswith("../") or resolved.startswith("/"):
        raise NoirPackageError(
            f"local dependency escapes the repository: {package_root}/{value}"
        )
    _relative_parts(resolved, "local dependency package")
    return resolved


def _assert_regular_tree(root: pathlib.Path, package_root: str) -> None:
    package_dir = _safe_node(root, package_root, "Noir package")
    if not package_dir.is_dir():
        raise NoirPackageError(f"Noir package directory is missing: {package_root}")
    for child in package_dir.rglob("*"):
        relative = child.relative_to(root).as_posix()
        if child.is_symlink():
            raise NoirPackageError(f"Noir package must not contain symlinks: {relative}")
        if not child.is_dir() and not child.is_file():
            raise NoirPackageError(f"Noir package contains a non-regular path: {relative}")


def inspect_circuit_package(
    repo_root: pathlib.Path | str,
    circuit_name: str,
    source_path: str,
) -> NoirPackageInspection:
    """Validate the workspace circuit package and all local dependencies.

    ZKC artifacts are compiled from ``noir/<package>/src/main.nr`` workspace
    bin packages. Requiring that exact binding prevents an entry from borrowing
    artifact hashes while pinning an unrelated loose file.
    """
    root = pathlib.Path(repo_root)
    expected_root = f"noir/{circuit_name}"
    expected_source = f"{expected_root}/src/main.nr"
    if source_path != expected_source:
        raise NoirPackageError(
            f"circuit.sourcePath must be {expected_source!r} for circuit {circuit_name!r}"
        )
    source = _safe_node(root, source_path, "circuit.sourcePath")
    if not source.is_file():
        raise NoirPackageError(f"circuit source is missing: {source_path}")

    workspace_path = _safe_node(root, "noir/Nargo.toml", "Noir workspace manifest")
    if not workspace_path.is_file():
        raise NoirPackageError("Noir workspace manifest is missing: noir/Nargo.toml")
    try:
        workspace_document = tomllib.loads(workspace_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise NoirPackageError(f"cannot parse Noir workspace manifest: {exc}") from None
    workspace = workspace_document.get("workspace")
    members = workspace.get("members") if isinstance(workspace, dict) else None
    if not isinstance(members, list) or circuit_name not in members:
        raise NoirPackageError(
            f"circuit package {circuit_name!r} is not a member of noir/Nargo.toml"
        )

    closure: set[str] = set()
    pending = [expected_root]
    while pending:
        package_root = pending.pop()
        if package_root in closure:
            continue
        _assert_regular_tree(root, package_root)
        document = _manifest(root, package_root)
        package = document["package"]
        if package_root == expected_root:
            if package["name"] != circuit_name:
                raise NoirPackageError(
                    f"{package_root}/Nargo.toml package name {package['name']!r} "
                    f"does not match circuit {circuit_name!r}"
                )
            if package["type"] != "bin":
                raise NoirPackageError(
                    f"circuit package {package_root} must have package type 'bin'"
                )
        closure.add(package_root)
        for table_name in ("dependencies", "dev-dependencies"):
            dependencies = document.get(table_name, {})
            if not isinstance(dependencies, dict):
                raise NoirPackageError(
                    f"[{table_name}] must be a table in {package_root}/Nargo.toml"
                )
            for dependency in dependencies.values():
                if isinstance(dependency, dict) and "path" in dependency:
                    pending.append(_dependency_root(package_root, dependency["path"]))

    return NoirPackageInspection(expected_root, tuple(sorted(closure)))
