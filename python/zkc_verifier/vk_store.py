"""Verification-key lookup via the reproducible artifact manifest.

The committed manifest (`artifacts/manifest.json`, maintained by
`scripts/publish_artifacts.py` and drift-gated in CI against a pinned-toolchain
rebuild) ships with the repository, so a fresh checkout resolves verification
keys without a local Noir toolchain. `scripts/generate_artifacts.sh` produces
the equivalent build manifest (`artifacts/build/manifest.json`) plus
per-circuit `vk` files (UltraHonk, `bb write_vk`). The store resolves a
circuit name to its verification key and cross-checks the manifest's pinned
sha256 before returning it — a swapped or corrupted vk fails closed.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Optional

__all__ = ["VerificationKeyStore"]


class VerificationKeyStore:
    def __init__(self, manifest_path, base_dir=None):
        self._manifest_path = pathlib.Path(manifest_path)
        # Artifact paths inside a manifest are repository-relative. The
        # default base derivation assumes the generated layout
        # (<root>/artifacts/build/manifest.json); pass base_dir explicitly for
        # any other location, e.g. the committed <root>/artifacts/manifest.json.
        self._base_dir = (
            pathlib.Path(base_dir)
            if base_dir is not None
            else self._manifest_path.parent.parent.parent
        )
        self._circuits = None
        self._bindings = None
        self._binding_rows = None

    @classmethod
    def from_repo(cls, repo_root) -> "VerificationKeyStore":
        """Prefer the committed manifest; fall back to a local build."""
        root = pathlib.Path(repo_root)
        committed = root / "artifacts" / "manifest.json"
        if committed.is_file():
            return cls(committed, base_dir=root)
        return cls(root / "artifacts" / "build" / "manifest.json", base_dir=root)

    def available(self) -> bool:
        return self._manifest_path.is_file()

    def _load(self) -> dict:
        if self._circuits is None:
            manifest = json.loads(self._manifest_path.read_text())
            self._circuits = {entry["name"]: entry for entry in manifest["circuits"]}
            self._binding_rows = tuple(manifest.get("bindings", []))
            self._bindings = {
                (
                    entry["predicateId"],
                    entry["entryVersion"],
                    entry["bindingId"],
                ): entry
                for entry in self._binding_rows
            }
        return self._circuits

    def legacy_vk_identity(self, circuit: str) -> tuple:
        """The circuit row's (VK digest, VK hash, ACIR digest) pins.

        A pin the row omits is None: a minimal manifest needs only
        ``vkSha256`` and ``artifacts.vk`` for :meth:`lookup`. Raises
        ValueError when a present pin is malformed.
        """
        if not self.available():
            return None, None, None
        entry = self._load().get(circuit)
        if entry is None:
            return None, None, None
        pins = []
        for key, prefix, length in (
            ("vkSha256", "sha256:", 64), ("vkHash", "0x", 64), ("acirHash", "sha256:", 64)
        ):
            value = entry.get(key)
            if value is not None and not (
                isinstance(value, str)
                and value.startswith(prefix)
                and len(value) == len(prefix) + length
                and all(c in "0123456789abcdef" for c in value[len(prefix):])
            ):
                raise ValueError(f"malformed {key} pin for circuit {circuit}")
            pins.append(value)
        return tuple(pins)

    def binding_vk_candidates(self, vk_sha256, vk_hash) -> tuple:
        """Every manifest binding sharing a present VK pin, before policy filtering."""
        if not self.available():
            return ()
        self._load()
        return tuple(
            entry
            for entry in self._binding_rows
            if (vk_sha256 is not None and entry.get("vkSha256") == vk_sha256)
            or (vk_hash is not None and entry.get("vkHash") == vk_hash)
        )

    def has_binding_for_circuit(self, circuit: str) -> bool:
        """Whether any manifest binding declares this legacy circuit name."""
        if not self.available():
            return False
        self._load()
        return any(entry.get("circuit") == circuit for entry in self._binding_rows)

    def _binding(self, selector: dict):
        self._load()
        try:
            key = (
                selector["predicateId"],
                selector["entryVersion"],
                selector["bindingId"],
            )
        except (KeyError, TypeError):
            return None
        return self._bindings.get(key)

    def lookup(self, circuit: str) -> Optional[bytes]:
        """Verification key bytes for a circuit; None when unknown.

        Raises ValueError when the on-disk vk does not match the manifest's
        pinned sha256 (fail closed on tampering).
        """
        if not self.available():
            return None
        entry = self._load().get(circuit)
        if entry is None:
            return None
        vk_path = self._base_dir / entry["artifacts"]["vk"]
        if not vk_path.is_file():
            return None
        expected = entry.get("vkSha256")
        if not isinstance(expected, str):
            raise ValueError(f"verification key for {circuit} has no manifest sha256 pin")
        vk_bytes = vk_path.read_bytes()
        actual = "sha256:" + hashlib.sha256(vk_bytes).hexdigest()
        if actual != expected:
            raise ValueError(
                f"verification key for {circuit} does not match manifest pin "
                f"({actual} != {expected})"
            )
        return vk_bytes

    def vk_hash(self, circuit: str) -> Optional[bytes]:
        """Manifest-pinned UltraHonk verification-key hash for a circuit.

        Returns the 32 `bb write_vk` vk-hash bytes, or None when the manifest
        (or the circuit, or a well-formed pin) is unavailable — callers MUST
        fail closed on None.
        """
        if not self.available():
            return None
        entry = self._load().get(circuit)
        if entry is None:
            return None
        value = entry.get("vkHash")
        if not isinstance(value, str) or not value.startswith("0x"):
            return None
        try:
            raw = bytes.fromhex(value[2:])
        except ValueError:
            return None
        return raw if len(raw) == 32 else None

    def lookup_binding(self, selector: dict) -> Optional[bytes]:
        """VK bytes for one exact v2 binding tuple, with pin verification."""
        if not self.available():
            return None
        entry = self._binding(selector)
        if entry is None:
            return None
        vk_path = self._base_dir / entry["artifacts"]["vk"]
        if not vk_path.is_file():
            return None
        vk_bytes = vk_path.read_bytes()
        actual = "sha256:" + hashlib.sha256(vk_bytes).hexdigest()
        if actual != entry["vkSha256"]:
            raise ValueError(
                f"verification key for binding {entry['bindingId']} does not match "
                f"manifest pin ({actual} != {entry['vkSha256']})"
            )
        return vk_bytes

    def binding_vk_hash(self, selector: dict) -> Optional[bytes]:
        entry = self._binding(selector) if self.available() else None
        if entry is None:
            return None
        value = entry.get("vkHash")
        if not isinstance(value, str) or not value.startswith("0x"):
            return None
        try:
            raw = bytes.fromhex(value[2:])
        except ValueError:
            return None
        return raw if len(raw) == 32 else None

    def binding_evidence(self, selector: dict) -> Optional[dict]:
        entry = self._binding(selector) if self.available() else None
        if entry is None:
            return None
        return {
            key: entry[key]
            for key in (
                "predicateId", "entryVersion", "sourceId", "bindingId",
                "circuit", "toolchain", "buildProfile", "artifactManifestKey",
                "acirHash", "vkHash", "vkSha256",
            )
        }
