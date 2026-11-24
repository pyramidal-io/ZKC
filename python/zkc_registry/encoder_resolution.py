"""Shared selector-free encoder resolution, independent of discovery ranking."""

from __future__ import annotations

import json
import pathlib


def encoder_circuits(repo_root) -> tuple[dict, tuple]:
    """Return only unique proofType -> circuit claims, plus validation errors.

    Count documents, not distinct circuit names: a copied encoder is a second
    claim too. Registry listings sharing the one encoder do not create claims.
    Exact v2 binding selectors are resolved separately and never use this map.
    """
    root = pathlib.Path(repo_root)
    claims = {}
    errors = []
    for path in (root / "schemas/public-inputs").glob("*.json"):
        where = path.relative_to(root).as_posix()
        try:
            encoder = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            errors.append(f"{where}: unreadable public-input encoder")
            continue
        if not isinstance(encoder, dict) or not isinstance(encoder.get("proofTypes"), list):
            errors.append(f"{where}: malformed public-input encoder")
            continue
        circuit = encoder.get("circuit")
        for proof_type in encoder["proofTypes"]:
            if isinstance(proof_type, str):
                claims.setdefault(proof_type, []).append((where, circuit))
    mapping = {}
    for proof_type, candidates in sorted(claims.items()):
        if len(candidates) != 1:
            paths = sorted(path for path, _ in candidates)
            errors.append(
                f"duplicate selector-free proof type {proof_type!r} in encoders {paths}"
            )
        else:
            path, circuit = candidates[0]
            if isinstance(circuit, str) and path == f"schemas/public-inputs/{circuit}.json":
                mapping[proof_type] = circuit
            else:
                errors.append(f"{path}: encoder filename must match its circuit")
    return mapping, tuple(sorted(errors))
