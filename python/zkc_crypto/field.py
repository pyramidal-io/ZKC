"""BN254 scalar field encoding helpers shared by the ZKC Python packages.

Standard library only.
"""

from __future__ import annotations

import hashlib
import re

from .poseidon2 import FIELD_MODULUS

__all__ = [
    "FIELD_MODULUS",
    "canonical_hex_to_field",
    "field_to_hex",
    "hex_to_field",
    "derive_domain",
    "string_to_field",
]

_CANONICAL_FIELD_HEX = re.compile(r"0x[0-9a-f]{64}")


def field_to_hex(value: int) -> str:
    """Canonical 0x-prefixed 32-byte lowercase big-endian hex of a field element."""
    if not 0 <= value < FIELD_MODULUS:
        raise ValueError("value is not a canonical BN254 scalar field element")
    return "0x" + value.to_bytes(32, "big").hex()


def hex_to_field(value: str) -> int:
    """Parse a 0x-prefixed hex field element; fail closed on malformed input.

    This parser is lenient: ``int(x, 16)`` also accepts surrounding
    whitespace, ``_`` separators, uppercase digits and short forms. Digest
    code that must reproduce legacy values relies on that; any closed wire
    format must use ``canonical_hex_to_field`` instead.
    """
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"expected 0x-prefixed hex field element, got {type(value).__name__}")
    parsed = int(value, 16)
    if parsed >= FIELD_MODULUS:
        raise ValueError("hex value is not a canonical BN254 scalar field element")
    return parsed


def canonical_hex_to_field(value: str) -> int:
    """Parse exactly the form ``field_to_hex`` produces; fail closed.

    The only accepted form is ``0x`` plus 64 lowercase hex digits (32
    big-endian bytes) below the field modulus. The pattern is matched before
    any decoding, so two implementations cannot read one string as two
    different values or accept an alias of a signed value.
    """
    if type(value) is not str or _CANONICAL_FIELD_HEX.fullmatch(value) is None:
        raise ValueError("expected a canonical field element: 0x plus 64 lowercase hex digits")
    parsed = int(value[2:], 16)
    if parsed >= FIELD_MODULUS:
        raise ValueError("hex value is not a canonical BN254 scalar field element")
    return parsed


def derive_domain(tag: str) -> int:
    """Canonical ZKA/KDC domain separator derivation.

    domain = Blake2b-512("ZKA-Domain-{tag}") interpreted little-endian, mod Fr.
    Reproduces the pinned constants in noir/zkc_lib/src/lib.nr (verified
    against DOMAIN_ZKC_CREDENTIAL / DOMAIN_ZKC_BINDING / DOMAIN_ZKC_CLAIM).
    """
    digest = hashlib.blake2b(f"ZKA-Domain-{tag}".encode(), digest_size=64).digest()
    return int.from_bytes(digest, "little") % FIELD_MODULUS


def string_to_field(value: str) -> int:
    """Reference encoding of an arbitrary identifier string to a field element.

    string_to_field(s) = Blake2b-512("ZKC-String-" + s) little-endian mod Fr.
    Used where the spec leaves identifier encoding deployment-defined (proof
    context fields, proof-type tags in aggregation). Mirrors the domain
    derivation so the construction stays auditable in one place.
    """
    digest = hashlib.blake2b(b"ZKC-String-" + value.encode(), digest_size=64).digest()
    return int.from_bytes(digest, "little") % FIELD_MODULUS
