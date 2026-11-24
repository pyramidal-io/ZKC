"""Minimal secp256k1 ECDSA (verify + deterministic sign) for ZKC tooling.

Same construction as tools/zkc_test_issuer.py (RFC 6979 nonces, canonical
low-s). Verification enforces the same low-s rule as signing and as the
Barretenberg in-circuit verifier (``s < (n + 1) / 2``, i.e. ``s <= n // 2``):
the high-s twin ``(r, n - s)`` of a valid signature is rejected, so no party
without the private key can mint a second valid encoding of a signed message
(spec section 2.4.1).

Standard library only. This is reference/test tooling — production issuers
use audited cryptographic libraries; ZKC holders never sign credential
digests (issuers do) and never need a signing key here.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = ["P", "N", "HALF_N", "GX", "GY", "sign", "verify", "public_key_bytes"]

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
# Largest accepted ``s``. N is odd, so ``s <= N // 2`` is exactly the
# Barretenberg secp256k1 bound ``s < (N + 1) / 2``.
HALF_N = N // 2


def _inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _rfc6979_k(digest: bytes, private_key: int) -> int:
    x = private_key.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(digest: bytes, private_key: int) -> bytes:
    """Deterministic ECDSA over a 32-byte digest; r||s, canonical low-s."""
    if len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    z = int.from_bytes(digest, "big")
    while True:
        k = _rfc6979_k(digest, private_key)
        point = _mul(k, (GX, GY))
        r = point[0] % N
        s = _inv(k, N) * (z + r * private_key) % N
        if s > HALF_N:
            s = N - s
        if r != 0 and s != 0:
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        digest = hashlib.sha256(digest).digest()  # pragma: no cover


def verify(public_key_x: bytes, public_key_y: bytes, signature: bytes, digest: bytes) -> bool:
    """Verify a low-s r||s signature over a 32-byte digest. Fail closed.

    Rejects ``s > HALF_N``: every caller (epoch announcements, APRs,
    receipts, delegation tokens, audit bundles, issuer credentials) gets the
    same non-malleable acceptance set as the circuit verifier.
    """
    if len(signature) != 64 or len(digest) != 32:
        return False
    if len(public_key_x) != 32 or len(public_key_y) != 32:
        return False
    x = int.from_bytes(public_key_x, "big")
    y = int.from_bytes(public_key_y, "big")
    if x >= P or y >= P or (y * y - (x * x * x + 7)) % P != 0:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < N and 1 <= s <= HALF_N):
        return False
    z = int.from_bytes(digest, "big")
    w = _inv(s, N)
    u1 = z * w % N
    u2 = r * w % N
    point = _add(_mul(u1, (GX, GY)), _mul(u2, (x, y)))
    return point is not None and point[0] % N == r


def public_key_bytes(private_key: int):
    """(x, y) 32-byte big-endian coordinates of the public key."""
    point = _mul(private_key, (GX, GY))
    return point[0].to_bytes(32, "big"), point[1].to_bytes(32, "big")
