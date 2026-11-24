"""Canonical AFP-KDC v1.0.1 master-seed encoding.

The KDC seed is always exactly 32 secret bytes. AFP-KDC v1.0.1 maps those
bytes to a circuit field by interpreting them as an unsigned big-endian
integer and reducing modulo the BN254 scalar modulus. That reduction has
intentional, versioned aliases; byte-domain derivations must therefore use
the original 32 bytes, never the reduced field element.
"""

from __future__ import annotations

import re
import secrets

from .poseidon2 import FIELD_MODULUS

__all__ = [
    "MASTER_SEED_BYTES",
    "MASTER_SEED_PROFILE",
    "generate_master_seed",
    "master_seed_to_bytes",
    "master_seed_to_field",
    "master_seed_to_hex",
]

MASTER_SEED_BYTES = 32
MASTER_SEED_PROFILE = "afp-kdc:master-seed:v1.0.1"
_MAX_MASTER_SEED = 1 << (8 * MASTER_SEED_BYTES)
_CANONICAL_HEX = re.compile(r"0x[0-9a-f]{64}\Z")


def master_seed_to_bytes(master_seed: int | bytes | str) -> bytes:
    """Return the canonical 32 seed bytes, rejecting ambiguous encodings.

    ``bytes`` is the normative SDK representation. A non-negative 256-bit
    ``int`` remains accepted by the Python reference for compatibility and is
    encoded big-endian with leading zeroes. Canonical lowercase ``0x`` hex is
    accepted by local SDK APIs. Seeds never belong in proof requests or APRs.
    """
    if isinstance(master_seed, bytes):
        if len(master_seed) != MASTER_SEED_BYTES:
            raise ValueError("master seed must be exactly 32 bytes")
        return master_seed
    if type(master_seed) is int:
        if not 0 <= master_seed < _MAX_MASTER_SEED:
            raise ValueError("master seed integer must be unsigned and fit in 256 bits")
        return master_seed.to_bytes(MASTER_SEED_BYTES, "big")
    if isinstance(master_seed, str):
        if not _CANONICAL_HEX.fullmatch(master_seed):
            raise ValueError("master seed hex must be canonical lowercase 0x plus 64 digits")
        return bytes.fromhex(master_seed[2:])
    raise TypeError("master seed must be bytes, a 256-bit integer, or canonical hex")


def master_seed_to_hex(master_seed: int | bytes | str) -> str:
    """Return canonical lowercase ``0x``-prefixed seed hex."""
    return "0x" + master_seed_to_bytes(master_seed).hex()


def master_seed_to_field(master_seed: int | bytes | str) -> int:
    """Map a seed to the AFP-KDC v1.0.1 Poseidon2 input field element."""
    return int.from_bytes(master_seed_to_bytes(master_seed), "big") % FIELD_MODULUS


def generate_master_seed() -> bytes:
    """Generate a full-entropy 256-bit seed without truncation or reduction."""
    return secrets.token_bytes(MASTER_SEED_BYTES)
