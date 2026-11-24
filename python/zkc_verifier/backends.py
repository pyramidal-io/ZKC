"""Proof-verification backends.

* `BBVerifyBackend` — production path: UltraHonk verification via `bb verify`
  with the manifest-pinned verification key and encoder-derived public
  inputs. REJECTS stub proofs unconditionally.
* `StubVerifyBackend` — test path, clearly non-production: accepts only
  `zkc:stub:v1:…` payloads and recomputes the deterministic stub digest from
  the public inputs. No cryptographic soundness.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile

from zkc_crypto import PublicInputEncoder
from zkc_crypto.stub import STUB_PROOF_PREFIX, stub_proof_payload

__all__ = ["VerifyBackend", "StubVerifyBackend", "BBVerifyBackend"]


class VerifyBackend:
    name = "abstract"
    is_production = False

    def verify(self, circuit: str, proof: str, public_inputs: dict, vk_bytes) -> bool:
        """True only when the proof verifies. MUST fail closed."""
        raise NotImplementedError


class StubVerifyBackend(VerifyBackend):
    name = "stub"
    is_production = False

    def verify(self, circuit: str, proof: str, public_inputs: dict, vk_bytes) -> bool:
        if not isinstance(proof, str) or not proof.startswith(STUB_PROOF_PREFIX):
            return False
        return proof == stub_proof_payload(circuit, public_inputs)


class BBVerifyBackend(VerifyBackend):
    name = "bb"
    is_production = True

    def __init__(self, repo_root, bb: str = "bb"):
        self._root = pathlib.Path(repo_root)
        self._bb = bb

    @classmethod
    def available(cls, bb: str = "bb") -> bool:
        return shutil.which(bb) is not None

    def verify(self, circuit: str, proof: str, public_inputs: dict, vk_bytes) -> bool:
        if not isinstance(proof, str) or not proof.startswith("0x"):
            # Stub payloads and any other non-binary proof NEVER verify on
            # the production path.
            return False
        if not vk_bytes:
            return False
        try:
            proof_bytes = bytes.fromhex(proof[2:])
        except ValueError:
            return False
        encoder_path = self._root / "schemas" / "public-inputs" / f"{circuit}.json"
        if not encoder_path.is_file():
            return False
        try:
            encoded_inputs = PublicInputEncoder.load(encoder_path).encode_bytes(public_inputs)
        except ValueError:
            return False
        with tempfile.TemporaryDirectory(prefix="zkc-verify-") as scratch:
            scratch_path = pathlib.Path(scratch)
            (scratch_path / "vk").write_bytes(vk_bytes)
            (scratch_path / "proof").write_bytes(proof_bytes)
            (scratch_path / "public_inputs").write_bytes(encoded_inputs)
            result = subprocess.run(
                [
                    self._bb, "verify",
                    "-k", str(scratch_path / "vk"),
                    "-p", str(scratch_path / "proof"),
                    "-i", str(scratch_path / "public_inputs"),
                ],
                capture_output=True,
                text=True,
            )
        return result.returncode == 0
