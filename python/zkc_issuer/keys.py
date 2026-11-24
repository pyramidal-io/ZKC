"""Issuer signing key generation, loading, and digest signing.

Reuses the shared stdlib secp256k1 ECDSA implementation in
``zkc_crypto.ecdsa_secp256k1`` (the same construction as
``tools/zkc_test_issuer.py``: RFC 6979 deterministic nonces, canonical low-s).

This is reference/sandbox tooling: production issuers keep signing keys in
audited cryptographic modules (HSMs). Private scalars never appear in
``repr``/logs and are only serialized through the explicit
``to_private_dict`` escape hatch.
"""

from __future__ import annotations

import datetime
import hashlib
import secrets
from dataclasses import dataclass, field

from zkc_crypto import digest_to_message_bytes, parse_attribute_layout_id
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes, sign, verify

__all__ = ["SIGNATURE_SCHEME_ECDSA_SECP256K1", "TEST_ISSUER_SEED", "IssuerSigningKey"]

SIGNATURE_SCHEME_ECDSA_SECP256K1 = "ECDSA_SECP256K1"

# Well-known TEST-ONLY seed shared with tools/zkc_test_issuer.py and the Noir
# circuit fixtures. The derived key is PUBLIC knowledge.
TEST_ISSUER_SEED = b"zkc-test-issuer-v1"


def _parse_rfc3339(value: str) -> int:
    return int(datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


@dataclass(frozen=True)
class IssuerSigningKey:
    """An issuer ECDSA secp256k1 signing key with a validity window.

    ``attribute_layout_id`` pins the one layout this exact public key attests
    for legacy attribute sets. Bind it only after verifying the signing key's
    historical legacy layout, or provision fresh key material.
    """

    key_id: str
    private_key: int = field(repr=False)
    not_before: str = "2026-01-01T00:00:00Z"
    not_after: str = "2027-01-01T00:00:00Z"
    scheme: str = SIGNATURE_SCHEME_ECDSA_SECP256K1
    attribute_layout_id: str | None = None

    def __post_init__(self):
        if self.scheme != SIGNATURE_SCHEME_ECDSA_SECP256K1:
            raise ValueError(f"unsupported signature scheme: {self.scheme}")
        if not self.key_id:
            raise ValueError("key_id must be non-empty")
        if not 1 <= self.private_key < N:
            raise ValueError("private key out of range for secp256k1")
        if _parse_rfc3339(self.not_before) >= _parse_rfc3339(self.not_after):
            raise ValueError("key validity window is empty (notBefore >= notAfter)")
        if self.attribute_layout_id is not None:
            parse_attribute_layout_id(self.attribute_layout_id)

    # --- construction -----------------------------------------------------

    @classmethod
    def generate(cls, key_id: str, **kwargs) -> "IssuerSigningKey":
        """Generate a fresh random signing key (CSPRNG)."""
        return cls(key_id=key_id, private_key=secrets.randbelow(N - 1) + 1, **kwargs)

    @classmethod
    def from_seed(cls, seed: bytes, key_id: str, **kwargs) -> "IssuerSigningKey":
        """Deterministic key derivation — TEST/SANDBOX ONLY (key = sha256(seed) mod n)."""
        private_key = int.from_bytes(hashlib.sha256(seed).digest(), "big") % N
        if private_key == 0:  # pragma: no cover — astronomically unlikely
            raise ValueError("seed derives a zero scalar; pick another seed")
        return cls(key_id=key_id, private_key=private_key, **kwargs)

    @classmethod
    def test_issuer(cls, key_id: str = "sandbox-2026-01", **kwargs) -> "IssuerSigningKey":
        """The well-known PUBLIC test issuer key (tools/zkc_test_issuer.py)."""
        return cls.from_seed(TEST_ISSUER_SEED, key_id=key_id, **kwargs)

    @classmethod
    def from_private_dict(cls, data: dict) -> "IssuerSigningKey":
        """Load a key from its private serialization (see to_private_dict)."""
        return cls(
            key_id=data["keyId"],
            private_key=int(data["privateKey"], 16),
            not_before=data["notBefore"],
            not_after=data["notAfter"],
            scheme=data.get("scheme", SIGNATURE_SCHEME_ECDSA_SECP256K1),
            attribute_layout_id=data.get("attributeLayoutId"),
        )

    # --- public material --------------------------------------------------

    def public_key_coordinates(self):
        """(x, y) 32-byte big-endian public key coordinates."""
        return public_key_bytes(self.private_key)

    def public_key_hex(self) -> str:
        """0x-prefixed concatenated x||y hex, as published in issuer metadata."""
        x, y = self.public_key_coordinates()
        return "0x" + x.hex() + y.hex()

    def metadata_entry(self) -> dict:
        """The signingKeys[] entry for issuer metadata (public material only)."""
        entry = {
            "keyId": self.key_id,
            "scheme": self.scheme,
            "publicKey": self.public_key_hex(),
            "notBefore": self.not_before,
            "notAfter": self.not_after,
        }
        if self.attribute_layout_id is not None:
            entry["attributeLayoutId"] = self.attribute_layout_id
        return entry

    # --- signing ------------------------------------------------------------

    def is_valid_at(self, timestamp: int) -> bool:
        return _parse_rfc3339(self.not_before) <= timestamp < _parse_rfc3339(self.not_after)

    def sign_digest(self, digest: int) -> bytes:
        """Sign a credential digest (field element); returns r||s (64 bytes)."""
        message = digest_to_message_bytes(digest)
        signature = sign(message, self.private_key)
        x, y = self.public_key_coordinates()
        if not verify(x, y, signature, message):  # pragma: no cover — self-check
            raise RuntimeError("issuer signature self-verification failed")
        return signature

    # --- explicit private serialization (key loading/storage) ---------------

    def to_private_dict(self) -> dict:
        """Serialize INCLUDING the private scalar. Handle with care; never log."""
        entry = {
            "keyId": self.key_id,
            "scheme": self.scheme,
            "privateKey": f"{self.private_key:064x}",
            "notBefore": self.not_before,
            "notAfter": self.not_after,
        }
        if self.attribute_layout_id is not None:
            entry["attributeLayoutId"] = self.attribute_layout_id
        return entry
