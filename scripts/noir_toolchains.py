#!/usr/bin/env python3
"""Fail-closed loading and execution of ZKC's per-package Noir toolchains."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile


CONFIG_VERSION = "zkc:noir-toolchains:v1"
REQUIRED_TOOLCHAINS = ("historical", "successor")
TOOL_FIELDS = ("nargo", "noirc", "bb")


class ToolchainError(ValueError):
    """Raised when build configuration or an installed toolchain fails closed."""


def package_toolchains(config: dict, package_name: str) -> tuple[str, ...]:
    """Configured build lanes for a package, primary/legacy lane first."""
    value = config["packages"][package_name]
    return (value,) if isinstance(value, str) else tuple(value)


def read_version_file(path: pathlib.Path) -> dict[str, str]:
    """Read KEY=value pins and resolve references to earlier keys."""
    values: dict[str, str] = {}
    reference = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ToolchainError(f"{path}: invalid pin line {raw_line!r}")
        key = key.strip()
        value = value.strip()
        if key in values:
            raise ToolchainError(f"{path}: duplicate pin {key}")

        def replace(match: re.Match[str]) -> str:
            referenced = match.group(1)
            if referenced not in values:
                raise ToolchainError(
                    f"{path}: {key} references undefined or forward pin {referenced}"
                )
            return values[referenced]

        values[key] = reference.sub(replace, value)
    return values


def workspace_bin_packages(noir_dir: pathlib.Path) -> list[dict[str, str | None]]:
    members_text = (noir_dir / "Nargo.toml").read_text()
    members = re.findall(r'"([a-z0-9_]+)"', members_text)
    packages: list[dict[str, str | None]] = []
    for member in members:
        manifest_path = noir_dir / member / "Nargo.toml"
        if not manifest_path.is_file():
            raise ToolchainError(f"workspace member has no manifest: {manifest_path}")
        manifest = manifest_path.read_text()
        if not re.search(r'^type\s*=\s*"bin"', manifest, re.MULTILINE):
            continue
        description = re.search(r'^description\s*=\s*"([^"]*)"', manifest, re.MULTILINE)
        version = re.search(r'^version\s*=\s*"([^"]*)"', manifest, re.MULTILINE)
        packages.append(
            {
                "name": member,
                "description": description.group(1) if description else "",
                "version": version.group(1) if version else None,
            }
        )
    if not packages:
        raise ToolchainError("no bin packages found in Noir workspace")
    return packages


def load_config(
    config_path: pathlib.Path, noir_dir: pathlib.Path, version_file: pathlib.Path
) -> dict:
    config = json.loads(config_path.read_text())
    if config.get("version") != CONFIG_VERSION:
        raise ToolchainError(
            f"{config_path}: version must be {CONFIG_VERSION!r}"
        )
    toolchains = config.get("toolchains")
    packages = config.get("packages")
    probes = config.get("probePackages", {})
    if not isinstance(toolchains, dict) or not isinstance(packages, dict):
        raise ToolchainError(f"{config_path}: toolchains and packages must be objects")
    if not isinstance(probes, dict):
        raise ToolchainError(f"{config_path}: probePackages must be an object")
    if set(toolchains) != set(REQUIRED_TOOLCHAINS):
        raise ToolchainError(
            f"{config_path}: toolchains must be exactly {list(REQUIRED_TOOLCHAINS)}"
        )
    for toolchain_id, definition in toolchains.items():
        if not isinstance(definition, dict) or set(definition) != set(TOOL_FIELDS):
            raise ToolchainError(
                f"{config_path}: toolchain {toolchain_id!r} must contain exactly "
                f"{list(TOOL_FIELDS)}"
            )
        if not all(isinstance(definition[field], str) and definition[field] for field in TOOL_FIELDS):
            raise ToolchainError(f"{config_path}: {toolchain_id} tool pins must be strings")

    workspace_names = [package["name"] for package in workspace_bin_packages(noir_dir)]
    missing = sorted(set(workspace_names) - set(packages))
    extra = sorted(set(packages) - set(workspace_names))
    if missing or extra:
        raise ToolchainError(
            f"{config_path}: package mapping must exactly cover workspace bin packages; "
            f"missing={missing}, extra={extra}"
        )
    invalid = []
    for name, assignment in packages.items():
        lanes = (assignment,) if isinstance(assignment, str) else assignment
        if (
            not isinstance(lanes, (list, tuple))
            or not lanes
            or len(set(lanes)) != len(lanes)
            or any(not isinstance(item, str) or item not in toolchains for item in lanes)
        ):
            invalid.append(name)
    if invalid:
        raise ToolchainError(f"{config_path}: packages reference unknown toolchains: {invalid}")
    for toolchain_id, package_name in probes.items():
        if toolchain_id not in toolchains or package_name not in workspace_names:
            raise ToolchainError(
                f"{config_path}: invalid probe {toolchain_id!r} -> {package_name!r}"
            )
    used_toolchains = {
        toolchain_id
        for package_name in packages
        for toolchain_id in package_toolchains(config, package_name)
    }
    for toolchain_id in toolchains:
        if toolchain_id not in used_toolchains and toolchain_id not in probes:
            raise ToolchainError(
                f"{config_path}: unused toolchain {toolchain_id!r} needs a probePackage"
            )

    pins = read_version_file(version_file)
    expected = {
        "historical": ("HISTORICAL_NARGO_VERSION", "HISTORICAL_BB_VERSION"),
        "successor": ("SUCCESSOR_NARGO_VERSION", "SUCCESSOR_BB_VERSION"),
    }
    for toolchain_id, (nargo_pin, bb_pin) in expected.items():
        for key in (nargo_pin, bb_pin):
            if key not in pins:
                raise ToolchainError(f"{version_file}: missing {key}")
        definition = toolchains[toolchain_id]
        if definition["nargo"] != pins[nargo_pin] or definition["bb"] != pins[bb_pin]:
            raise ToolchainError(
                f"{config_path}: {toolchain_id} pins disagree with {version_file}"
            )
    if pins.get("NARGO_VERSION") != toolchains["historical"]["nargo"]:
        raise ToolchainError(f"{version_file}: NARGO_VERSION must alias the historical pin")
    if pins.get("BB_VERSION") != toolchains["historical"]["bb"]:
        raise ToolchainError(f"{version_file}: BB_VERSION must alias the historical pin")
    return config


def parse_binary_assignments(values: list[str], option: str) -> dict[str, pathlib.Path]:
    assignments: dict[str, pathlib.Path] = {}
    for value in values:
        toolchain_id, separator, raw_path = value.partition("=")
        if not separator or not toolchain_id or not raw_path:
            raise ToolchainError(f"{option} expects TOOLCHAIN=PATH, got {value!r}")
        if toolchain_id in assignments:
            raise ToolchainError(f"{option}: duplicate assignment for {toolchain_id}")
        resolved = shutil.which(raw_path)
        if resolved is None:
            raise ToolchainError(f"{option}: executable not found: {raw_path}")
        assignments[toolchain_id] = pathlib.Path(resolved).resolve()
    return assignments


def tool_version(command: list[str], pattern: str) -> str:
    completed = subprocess.run(command, capture_output=True, text=True, check=True)
    output = completed.stdout + completed.stderr
    match = re.search(pattern, output)
    if not match:
        raise ToolchainError(f"could not parse version from {' '.join(command)}: {output!r}")
    return match.group(1)


def nargo_versions(binary: pathlib.Path, lane: str) -> dict[str, str]:
    output = subprocess.run(
        [str(binary), "--version"], capture_output=True, text=True, check=True
    ).stdout
    nargo = re.search(r"nargo version = ([^\s]+)", output)
    noirc = re.search(r"noirc version = ([^\s]+)", output)
    if not nargo or not noirc:
        raise ToolchainError(f"could not parse {lane} nargo version")
    return {"nargo": nargo.group(1), "noirc": noirc.group(1)}


def verify_binaries(
    config: dict,
    nargo_bins: dict[str, pathlib.Path],
    bb_bins: dict[str, pathlib.Path],
) -> dict[str, dict[str, str | pathlib.Path]]:
    expected_ids = set(config["toolchains"])
    if set(nargo_bins) != expected_ids or set(bb_bins) != expected_ids:
        raise ToolchainError(
            "binary assignments must exactly cover configured toolchains; "
            f"nargo={sorted(nargo_bins)}, bb={sorted(bb_bins)}, expected={sorted(expected_ids)}"
        )
    verified: dict[str, dict[str, str | pathlib.Path]] = {}
    for toolchain_id, pins in config["toolchains"].items():
        observed = {
            **nargo_versions(nargo_bins[toolchain_id], toolchain_id),
            "bb": tool_version([str(bb_bins[toolchain_id]), "--version"], r"([0-9][^\s]*)\s*$"),
        }
        if observed != pins:
            raise ToolchainError(
                f"{toolchain_id} binary versions do not match config: "
                f"expected={pins}, observed={observed}"
            )
        verified[toolchain_id] = {
            **observed,
            "nargo_bin": nargo_bins[toolchain_id],
            "bb_bin": bb_bins[toolchain_id],
        }
    return verified


def stage_and_compile(
    *,
    root: pathlib.Path,
    source_noir_dir: pathlib.Path,
    cache_root: pathlib.Path,
    output_root: pathlib.Path,
    config: dict,
    verified: dict[str, dict[str, str | pathlib.Path]],
) -> dict[object, pathlib.Path]:
    """Compile mapped packages in exact workspace copies with isolated targets/caches."""
    for source_path in source_noir_dir.rglob("*"):
        if source_path.is_symlink():
            raise ToolchainError(f"refusing to stage symlinked Noir source: {source_path}")
    for build_root in (cache_root, output_root):
        if build_root.is_symlink():
            raise ToolchainError(f"build root must not be a symlink: {build_root}")
    cache_root = cache_root.resolve()
    output_root = output_root.resolve()
    source_noir_dir = source_noir_dir.resolve()
    if (
        cache_root == output_root
        or cache_root in output_root.parents
        or output_root in cache_root.parents
    ):
        raise ToolchainError("cache-root and output-root must be distinct and non-overlapping")
    for controlled_root in (cache_root, output_root):
        if (
            controlled_root == source_noir_dir
            or source_noir_dir in controlled_root.parents
            or controlled_root in source_noir_dir.parents
        ):
            raise ToolchainError(
                f"build root must not contain or be inside Noir source: {controlled_root}"
            )

    # Preserve the v1 package-name key for single-lane callers.  Only a
    # genuinely multi-lane package needs the explicit (package, toolchain)
    # key, so adding a second binding does not break existing consumers.
    compiled: dict[object, pathlib.Path] = {}
    packages_by_toolchain = {
        toolchain_id: [
            name
            for name in config["packages"]
            if toolchain_id in package_toolchains(config, name)
        ]
        for toolchain_id in config["toolchains"]
    }
    output_root.mkdir(parents=True, exist_ok=True)
    for toolchain_id in config["toolchains"]:
        lane_dir = pathlib.Path(
            tempfile.mkdtemp(prefix=f"{toolchain_id}-", dir=output_root)
        )
        staged_noir = lane_dir / "workspace" / "noir"
        cache_home = cache_root / toolchain_id
        if cache_home.is_symlink():
            raise ToolchainError(f"toolchain cache home must not be a symlink: {cache_home}")
        cache_home.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            source_noir_dir,
            staged_noir,
            symlinks=True,
            ignore=shutil.ignore_patterns("target", "Prover.toml", "Verifier.toml", ".DS_Store"),
        )
        package_names = packages_by_toolchain[toolchain_id]
        probe = config.get("probePackages", {}).get(toolchain_id)
        if not package_names and probe:
            package_names = [probe]
        if not package_names:
            raise ToolchainError(
                f"toolchain {toolchain_id!r} has no mapped package or probePackage"
            )
        child_env = os.environ.copy()
        # Nargo has no cache-root flag in beta.21/beta.25 and always uses
        # $HOME/nargo. Scope HOME to this child process; the caller's environment
        # and actual user home are never modified.
        child_env["HOME"] = str(cache_home)
        for name in package_names:
            print(f"==> [{toolchain_id}] nargo compile --package {name}")
            subprocess.run(
                [str(verified[toolchain_id]["nargo_bin"]), "compile", "--package", name],
                cwd=staged_noir,
                env=child_env,
                check=True,
            )
            artifact = staged_noir / "target" / f"{name}.json"
            if not artifact.is_file():
                raise ToolchainError(f"{toolchain_id} did not emit {artifact}")
            if toolchain_id in package_toolchains(config, name):
                lanes = package_toolchains(config, name)
                compiled[name if len(lanes) == 1 else (name, toolchain_id)] = artifact

        dep_dir = cache_home / "nargo" / "github.com" / "noir-lang" / "poseidon" / "v0.3.0"
        integrity_script = root / "scripts" / "check-poseidon-source-integrity.sh"
        for extra in ([], ["--self-test"]):
            subprocess.run(
                [str(integrity_script), "--dep-dir", str(dep_dir), *extra],
                check=True,
            )

    expected_packages = set()
    for name in config["packages"]:
        lanes = package_toolchains(config, name)
        expected_packages.update(
            {name} if len(lanes) == 1 else {(name, toolchain_id) for toolchain_id in lanes}
        )
    if set(compiled) != expected_packages:
        raise ToolchainError(
            f"compiled package set mismatch: missing={sorted(expected_packages - set(compiled))}, "
            f"extra={sorted(set(compiled) - expected_packages)}"
        )
    return compiled


def check_workspace(root: pathlib.Path, nargo_bins: dict[str, pathlib.Path]) -> None:
    """Check and test every circuit with its pinned compiler lanes."""
    noir_dir = root / "noir"
    config = load_config(noir_dir / "toolchains.json", noir_dir, root / ".noir-version")
    if set(nargo_bins) != set(REQUIRED_TOOLCHAINS):
        raise ToolchainError(f"--nargo must provide exactly {list(REQUIRED_TOOLCHAINS)}")
    for lane, pins in config["toolchains"].items():
        expected = {name: pins[name] for name in ("nargo", "noirc")}
        observed = nargo_versions(nargo_bins[lane], lane)
        if observed != expected:
            raise ToolchainError(
                f"{lane} compiler versions do not match config: "
                f"expected={expected}, observed={observed}"
            )

    integrity = ["bash", str(root / "scripts" / "check-poseidon-source-integrity.sh")]
    subprocess.run([str(nargo_bins["historical"]), "fmt", "--check"], cwd=noir_dir, check=True)
    subprocess.run(integrity, cwd=root, check=True)

    for lane in REQUIRED_TOOLCHAINS:
        packages = [
            name for name in config["packages"] if lane in package_toolchains(config, name)
        ]
        if not packages:
            packages = [config["probePackages"][lane]]
        for command in ("check", "test"):
            for name in packages:
                print(f"==> [{lane}] nargo {command} --package {name}", flush=True)
                subprocess.run(
                    [str(nargo_bins[lane]), command, "--package", name], cwd=noir_dir, check=True
                )
            subprocess.run(integrity, cwd=root, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Format-check and test the pinned Noir workspace.")
    parser.add_argument(
        "--nargo", action="append", required=True, metavar="LANE=PATH",
        help="Nargo executable for each of historical and successor",
    )
    args = parser.parse_args()
    try:
        nargo_bins = parse_binary_assignments(args.nargo, "--nargo")
        check_workspace(pathlib.Path(__file__).resolve().parents[1], nargo_bins)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Noir workspace check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
