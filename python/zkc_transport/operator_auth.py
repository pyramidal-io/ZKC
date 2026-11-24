"""Signed operator requests for the issuer admin router (stdlib-only).

Issuer operator mutations (revoke, renew) never share a listener with the
holder-facing issuer stages. They live on ``IssuerAdminServer``, which
admits a request only when it carries a valid signature by a pinned operator
key. A credential identifier is public (every active one is a published
accumulator leaf, see docs/zkc_metadata_leakage_threat_model.md section
1.10), so knowing one never authorizes anything.

Request signature
-----------------
The client sends four headers:

* ``X-ZKC-Operator-Key``       — the pinned operator key id
* ``X-ZKC-Operator-Timestamp`` — unix seconds, decimal digits
* ``X-ZKC-Operator-Nonce``     — 32 lowercase hex characters (128 random bits)
* ``X-ZKC-Operator-Signature`` — ``0x`` + 128 lowercase hex (``r || s``, low-s)

The signature is ECDSA secp256k1 over the SHA-256 of this transcript::

    "ZKC-OPERATOR-REQUEST" 0x00 0x01
    text(issuerId) text(keyId) text(method) text(requestTarget)
    u64(timestamp) nonce[16] sha256(body)[32]

where ``text(x)`` is a 4-byte big-endian length followed by the UTF-8 bytes.
The transcript binds the audience (issuer id), the signer, the method, the
exact request target, the time, a single-use nonce and the exact body bytes.

The server refuses a request when a header is missing, repeated or
malformed, when the key is not pinned, when the timestamp is more than
``max_clock_skew_seconds`` from its clock, when the signature does not verify
(high-s twins included), or when the ``(keyId, nonce)`` pair was already
accepted inside the replay window. A nonce is recorded only after its
signature verifies, so forged requests cannot consume an operator's nonces.

This is reference code. Operator keys belong in an HSM or a signing service;
``OperatorKey`` holds a raw scalar for tests and local tooling only.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import struct
import threading
from dataclasses import dataclass, field
from typing import Mapping

from zkc_crypto.ecdsa_secp256k1 import N, P, public_key_bytes, sign, verify

__all__ = [
    "OPERATOR_KEY_HEADER",
    "OPERATOR_NONCE_HEADER",
    "OPERATOR_REQUEST_DOMAIN",
    "OPERATOR_SIGNATURE_HEADER",
    "OPERATOR_TIMESTAMP_HEADER",
    "OperatorAuthenticator",
    "OperatorKey",
    "operator_request_digest",
]

OPERATOR_REQUEST_DOMAIN = b"ZKC-OPERATOR-REQUEST\x00\x01"
OPERATOR_KEY_HEADER = "X-ZKC-Operator-Key"
OPERATOR_TIMESTAMP_HEADER = "X-ZKC-Operator-Timestamp"
OPERATOR_NONCE_HEADER = "X-ZKC-Operator-Nonce"
OPERATOR_SIGNATURE_HEADER = "X-ZKC-Operator-Signature"
_AUTH_HEADERS = (
    OPERATOR_KEY_HEADER,
    OPERATOR_TIMESTAMP_HEADER,
    OPERATOR_NONCE_HEADER,
    OPERATOR_SIGNATURE_HEADER,
)

_KEY_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_TIMESTAMP = re.compile(r"[0-9]{1,20}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_SIGNATURE = re.compile(r"0x[0-9a-f]{128}")
_PUBLIC_KEY = re.compile(r"0x[0-9a-f]{128}")
_METHOD = re.compile(r"[A-Z]{1,16}")


def _text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def operator_request_digest(
    *,
    issuer_id: str,
    key_id: str,
    method: str,
    request_target: str,
    timestamp: int,
    nonce: bytes,
    body: bytes,
) -> bytes:
    """SHA-256 of the canonical signed-request transcript (32 bytes)."""
    if type(timestamp) is not int or not 0 <= timestamp < 2**64:
        raise ValueError("timestamp must be a u64 integer")
    if type(nonce) is not bytes or len(nonce) != 16:
        raise ValueError("nonce must be exactly 16 bytes")
    if type(body) is not bytes:
        raise ValueError("body must be bytes")
    for name, value in (("issuer_id", issuer_id), ("key_id", key_id),
                        ("method", method), ("request_target", request_target)):
        if type(value) is not str or not value:
            raise ValueError(f"{name} must be a non-empty string")
    transcript = b"".join((
        OPERATOR_REQUEST_DOMAIN,
        _text(issuer_id),
        _text(key_id),
        _text(method),
        _text(request_target),
        struct.pack(">Q", timestamp),
        nonce,
        hashlib.sha256(body).digest(),
    ))
    return hashlib.sha256(transcript).digest()


@dataclass(frozen=True)
class OperatorKey:
    """An operator ECDSA secp256k1 request-signing key (reference tooling)."""

    key_id: str
    private_key: int = field(repr=False)

    def __post_init__(self):
        if type(self.key_id) is not str or not _KEY_ID.fullmatch(self.key_id):
            raise ValueError("operator key id must be 1-128 characters of [A-Za-z0-9._:-]")
        if type(self.private_key) is not int or not 1 <= self.private_key < N:
            raise ValueError("operator private key out of range for secp256k1")

    @classmethod
    def generate(cls, key_id: str) -> "OperatorKey":
        """A fresh random operator key (CSPRNG)."""
        return cls(key_id=key_id, private_key=secrets.randbelow(N - 1) + 1)

    @classmethod
    def from_seed(cls, seed: bytes, key_id: str) -> "OperatorKey":
        """Deterministic derivation: TEST ONLY (key = sha256(seed) mod n)."""
        private_key = int.from_bytes(hashlib.sha256(seed).digest(), "big") % N
        return cls(key_id=key_id, private_key=private_key)

    def public_key_hex(self) -> str:
        """``0x`` + x||y hex, the form ``OperatorAuthenticator`` pins."""
        x, y = public_key_bytes(self.private_key)
        return "0x" + x.hex() + y.hex()

    def sign_request(
        self,
        *,
        issuer_id: str,
        method: str,
        request_target: str,
        body: bytes,
        timestamp: int,
        nonce: bytes = None,
    ) -> dict:
        """Return the four authentication headers for one request."""
        if nonce is None:
            nonce = secrets.token_bytes(16)
        digest = operator_request_digest(
            issuer_id=issuer_id,
            key_id=self.key_id,
            method=method,
            request_target=request_target,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        return {
            OPERATOR_KEY_HEADER: self.key_id,
            OPERATOR_TIMESTAMP_HEADER: str(timestamp),
            OPERATOR_NONCE_HEADER: nonce.hex(),
            OPERATOR_SIGNATURE_HEADER: "0x" + sign(digest, self.private_key).hex(),
        }


def _pinned_public_key(value) -> tuple:
    if type(value) is not str or not _PUBLIC_KEY.fullmatch(value):
        raise ValueError("operator public key must be 0x + 128 lowercase hex (x||y)")
    raw = bytes.fromhex(value[2:])
    x, y = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    if x >= P or y >= P or (y * y - (x * x * x + 7)) % P != 0:
        raise ValueError("operator public key is not a secp256k1 curve point")
    return raw[:32], raw[32:]


class OperatorAuthenticator:
    """Verifies signed operator requests against pinned public keys.

    ``operator_keys`` maps key id to ``0x`` + x||y public key hex. The set is
    fixed at construction; it must be non-empty. ``authenticate`` returns
    the accepted key id (the operator principal) or ``None``. Every refusal
    looks the same to the caller.
    """

    def __init__(
        self,
        issuer_id: str,
        operator_keys: Mapping[str, str],
        clock,
        max_clock_skew_seconds: int = 60,
        max_tracked_nonces: int = 100_000,
    ):
        if type(issuer_id) is not str or not issuer_id:
            raise ValueError("issuer_id must be a non-empty string")
        if not callable(clock):
            raise ValueError("clock must be callable")
        if type(max_clock_skew_seconds) is not int or not 1 <= max_clock_skew_seconds <= 600:
            raise ValueError("max_clock_skew_seconds must be between 1 and 600")
        if type(max_tracked_nonces) is not int or max_tracked_nonces < 1:
            raise ValueError("max_tracked_nonces must be a positive integer")
        if not isinstance(operator_keys, Mapping) or not operator_keys:
            raise ValueError("at least one pinned operator key is required")
        keys = {}
        seen = set()
        for key_id, public_key in operator_keys.items():
            if type(key_id) is not str or not _KEY_ID.fullmatch(key_id):
                raise ValueError("operator key id must be 1-128 characters of [A-Za-z0-9._:-]")
            coordinates = _pinned_public_key(public_key)
            if coordinates in seen:
                raise ValueError("operator public keys must be distinct")
            seen.add(coordinates)
            keys[key_id] = coordinates
        self._issuer_id = issuer_id
        self._keys = keys
        self._clock = clock
        self._skew = max_clock_skew_seconds
        self._max_nonces = max_tracked_nonces
        # (key id, nonce) -> last unix second at which the timestamp check
        # could still admit it; after that the timestamp check refuses it.
        self._seen_nonces: dict = {}
        # Highest clock reading seen; a nonce is forgotten only once this
        # passes its window, so a clock step backwards cannot revive it.
        self._high_water = 0
        self._lock = threading.Lock()

    @property
    def issuer_id(self) -> str:
        return self._issuer_id

    @staticmethod
    def _single_header(headers, name: str):
        values = headers.get_all(name) if hasattr(headers, "get_all") else None
        if values is None:
            value = headers.get(name)
            values = [] if value is None else [value]
        if len(values) != 1 or type(values[0]) is not str:
            return None
        return values[0]

    def authenticate(self, method: str, request_target: str, headers, body: bytes):
        """Return the operator key id for a valid request, else ``None``."""
        values = [self._single_header(headers, name) for name in _AUTH_HEADERS]
        if any(value is None for value in values):
            return None
        key_id, timestamp_text, nonce_hex, signature_hex = values
        if (
            type(method) is not str or not _METHOD.fullmatch(method)
            or type(request_target) is not str or not request_target.startswith("/")
            or type(body) is not bytes
            or not _KEY_ID.fullmatch(key_id)
            or not _TIMESTAMP.fullmatch(timestamp_text)
            or not _NONCE.fullmatch(nonce_hex)
            or not _SIGNATURE.fullmatch(signature_hex)
        ):
            return None
        coordinates = self._keys.get(key_id)
        if coordinates is None:
            return None
        timestamp = int(timestamp_text)
        if timestamp >= 2**64:
            return None
        try:
            now = int(self._clock())
        except Exception:
            return None
        if abs(now - timestamp) > self._skew:
            return None
        nonce = bytes.fromhex(nonce_hex)
        replay_key = (key_id, nonce)
        with self._lock:
            if timestamp + self._skew < self._high_water:
                return None  # its nonce may already be forgotten
            if replay_key in self._seen_nonces:
                return None  # cheap early refusal; rechecked below
        digest = operator_request_digest(
            issuer_id=self._issuer_id,
            key_id=key_id,
            method=method,
            request_target=request_target,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        if not verify(coordinates[0], coordinates[1], bytes.fromhex(signature_hex[2:]), digest):
            return None
        with self._lock:
            self._high_water = max(self._high_water, now)
            if timestamp + self._skew < self._high_water:
                return None
            # Forget nonces whose windows the high-water clock has passed.
            for stale in [
                k for k, until in self._seen_nonces.items() if until < self._high_water
            ]:
                del self._seen_nonces[stale]
            if replay_key in self._seen_nonces:
                return None
            if len(self._seen_nonces) >= self._max_nonces:
                return None  # fail closed rather than forget a live nonce
            self._seen_nonces[replay_key] = timestamp + self._skew
        return key_id
