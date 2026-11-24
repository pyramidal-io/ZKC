#!/usr/bin/env python3
"""Validate the exact public-source policy from one committed Git tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys


REPORT_FORMAT = "zkc:public-allowlist-report:v1"
REGULAR_MODES = {"100644", "100755"}
CANONICAL_SPECIFICATION = "docs/zkc_specification.md"
SPEC_VERSION_RE = re.compile(r"^\*\*Version:\*\*\s+([^\s]+)$", re.MULTILINE)
GLOB_METACHARACTERS = frozenset("*?[]{}")
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class PolicyError(ValueError):
    """A malformed or unsafe public-source policy."""


def run_git(root: pathlib.Path, *arguments: str) -> str:
    """Run a Git plumbing command and normalize command failures."""

    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or "Git command failed"
        raise OSError(message) from exc
    return completed.stdout


def parse_policy(contents: str) -> tuple[str, ...]:
    """Parse one flat, default-deny exact-file policy."""

    paths: list[str] = []
    seen: set[str] = set()
    for line in contents.splitlines():
        path = line.strip()
        if not path or path.startswith("#"):
            continue
        components = path.split("/")
        if (
            path.startswith("/")
            or "\\" in path
            or path.endswith("/")
            or bool(GLOB_METACHARACTERS.intersection(path))
            or any(component in {".", "..", ".git"} for component in components)
        ):
            raise PolicyError(f"unsafe allowlist entry: {path}")
        if path in seen:
            raise PolicyError(f"duplicate allowlist entry: {path}")
        seen.add(path)
        paths.append(path)
    return tuple(paths)


def resolve_commit(root: pathlib.Path, revision: str) -> str:
    """Resolve a revision to one immutable commit object ID."""

    if COMMIT_SHA_RE.fullmatch(revision) is None:
        raise PolicyError("revision must be a full commit SHA")
    return run_git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").strip()


def read_blob(root: pathlib.Path, commit: str, path: str) -> str:
    """Read a UTF-8 blob from the resolved commit, never from the worktree."""

    return run_git(root, "show", f"{commit}:{path}")


def tracked_files(root: pathlib.Path, commit: str) -> dict[str, str]:
    """Return committed paths and modes from the exact source tree."""

    entries = run_git(root, "ls-tree", "-r", "-z", "--full-tree", commit)
    tracked: dict[str, str] = {}
    for entry in entries.split("\0"):
        if not entry:
            continue
        metadata, path = entry.split("\t", 1)
        mode, _object_type, _object_id = metadata.split(" ", 2)
        tracked[path] = mode
    return tracked


def build_report(root: pathlib.Path, revision: str) -> dict[str, object]:
    """Build a deterministic allowlist report from one committed source tree."""

    commit = resolve_commit(root, revision)
    tracked = tracked_files(root, commit)
    inventory = parse_policy(read_blob(root, commit, "PUBLIC_ALLOWLIST"))
    if "PUBLIC_ALLOWLIST" not in inventory:
        raise PolicyError("PUBLIC_ALLOWLIST must include itself")
    for path in inventory:
        if path not in tracked:
            raise PolicyError(f"allowlist entry is not tracked at the source revision: {path}")
        if tracked[path] not in REGULAR_MODES:
            raise PolicyError(f"non-regular allowlist entry: {path} (mode {tracked[path]})")
    specification_mode = tracked.get(CANONICAL_SPECIFICATION)
    if specification_mode not in REGULAR_MODES:
        raise PolicyError(
            "non-regular canonical specification: "
            f"{CANONICAL_SPECIFICATION} (mode {specification_mode})"
        )
    match = SPEC_VERSION_RE.search(read_blob(root, commit, CANONICAL_SPECIFICATION))
    if match is None:
        raise PolicyError("docs/zkc_specification.md has no canonical version header")
    ordered = sorted(inventory)
    return {
        "format": REPORT_FORMAT,
        "revision": commit,
        "zkc_version": match.group(1),
        "inventory_count": len(ordered),
        "inventory_sha256": hashlib.sha256(("\n".join(ordered) + "\n").encode()).hexdigest(),
        "inventory": ordered,
    }


def main(argv: list[str] | None = None) -> int:
    """Write the deterministic JSON report or one concise failure."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--revision", required=True)
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    arguments = parser.parse_args(argv)
    try:
        report = build_report(arguments.root, arguments.revision)
    except (OSError, UnicodeError, PolicyError) as exc:
        print(f"public allowlist validation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
