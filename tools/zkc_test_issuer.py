#!/usr/bin/env python3
"""Deterministic TEST-ONLY secp256k1 issuer for ZKC circuit fixtures.

Generates the well-known ZKC test issuer keypair and ECDSA signatures over
32-byte credential digests, formatted as Noir `[u8; 32]` / `[u8; 64]` array
literals for use in circuit tests.

THE PRIVATE KEY BELOW IS PUBLIC AND FOR TEST FIXTURES ONLY. It is derived
deterministically from a published seed string; never use it for anything
other than test vectors.

Usage:
    python3 tools/zkc_test_issuer.py pubkey
    python3 tools/zkc_test_issuer.py sign 0x<64-hex-digest> [0x<digest> ...]
    python3 tools/zkc_test_issuer.py selftest

Standard library only (python3.9+). Signing uses deterministic nonces
(RFC 6979-style HMAC-SHA256 derivation) so output is reproducible.
"""

from __future__ import annotations

import hashlib
import hmac
import sys

# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# TEST-ONLY private key: int(sha256("zkc-test-issuer-v1")) mod n
TEST_ISSUER_SEED = b"zkc-test-issuer-v1"
PRIVATE_KEY = int.from_bytes(hashlib.sha256(TEST_ISSUER_SEED).digest(), "big") % N


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
    """Deterministic nonce per RFC 6979 (SHA-256, qlen = 256)."""
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


def sign(digest: bytes, private_key: int = PRIVATE_KEY) -> bytes:
    if len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    z = int.from_bytes(digest, "big")
    while True:
        k = _rfc6979_k(digest, private_key)
        point = _mul(k, (GX, GY))
        r = point[0] % N
        s = _inv(k, N) * (z + r * private_key) % N
        if s > N // 2:  # canonical low-s form
            s = N - s
        if r != 0 and s != 0:
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        digest = hashlib.sha256(digest).digest()  # pragma: no cover


def verify(public_key, signature: bytes, digest: bytes) -> bool:
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    # Low-s only, matching the Noir/Barretenberg verifier (s < (n + 1) / 2).
    if not (1 <= r < N and 1 <= s <= N // 2):
        return False
    z = int.from_bytes(digest, "big")
    w = _inv(s, N)
    u1 = z * w % N
    u2 = r * w % N
    point = _add(_mul(u1, (GX, GY)), _mul(u2, public_key))
    return point is not None and point[0] % N == r


def public_key(private_key: int = PRIVATE_KEY):
    return _mul(private_key, (GX, GY))


def noir_u8_array(data: bytes) -> str:
    return "[" + ", ".join(str(b) for b in data) + "]"


def selftest() -> None:
    # 1. Sign/verify roundtrip with the test issuer key.
    digest = hashlib.sha256(b"zkc-selftest").digest()
    pub = public_key()
    assert verify(pub, sign(digest), digest), "sign/verify roundtrip failed"
    assert not verify(pub, sign(digest), hashlib.sha256(b"other").digest()), (
        "tampered digest must not verify"
    )
    # 2. Verify the checked-in zkc_issuer_sig KAT signature, proving this
    #    implementation agrees with the Noir secp256k1 verifier.
    kat_x = bytes(
        [137, 81, 38, 98, 181, 144, 46, 180, 102, 61, 191, 66, 140, 98, 244, 92, 229, 44,
         211, 23, 36, 201, 121, 32, 86, 185, 98, 216, 108, 62, 37, 26]
    )
    kat_y = bytes(
        [34, 85, 29, 119, 46, 134, 16, 31, 56, 87, 20, 235, 116, 171, 39, 5, 122, 99, 146,
         254, 158, 5, 185, 45, 152, 119, 236, 243, 137, 31, 179, 114]
    )
    kat_digest = bytes(
        [219, 230, 201, 83, 210, 164, 56, 223, 229, 121, 220, 109, 44, 226, 5, 186, 73, 118,
         161, 46, 56, 46, 45, 182, 179, 179, 208, 119, 134, 28, 37, 110]
    )
    kat_signature = bytes(
        [127, 242, 233, 19, 129, 223, 126, 197, 228, 106, 54, 18, 192, 184, 118, 140, 152,
         55, 241, 255, 40, 185, 103, 179, 102, 150, 220, 48, 226, 220, 176, 143, 19, 107,
         60, 33, 245, 230, 34, 119, 197, 192, 86, 17, 119, 230, 92, 52, 135, 208, 246, 154,
         147, 76, 98, 39, 55, 114, 112, 220, 49, 36, 226, 246]
    )
    kat_pub = (int.from_bytes(kat_x, "big"), int.from_bytes(kat_y, "big"))
    assert verify(kat_pub, kat_signature, kat_digest), "zkc_issuer_sig KAT must verify"
    print("selftest passed")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("pubkey", "sign", "selftest"):
        print(__doc__)
        return 1
    command = sys.argv[1]
    if command == "selftest":
        selftest()
        return 0
    pub = public_key()
    x_bytes = pub[0].to_bytes(32, "big")
    y_bytes = pub[1].to_bytes(32, "big")
    if command == "pubkey":
        print("issuer_public_key_x:", noir_u8_array(x_bytes))
        print("issuer_public_key_y:", noir_u8_array(y_bytes))
        return 0
    for argument in sys.argv[2:]:
        digest = bytes.fromhex(argument.removeprefix("0x").rjust(64, "0"))
        signature = sign(digest)
        assert verify(pub, signature, digest)
        print(f"digest {argument}:")
        print("  signature:", noir_u8_array(signature))
    return 0


if __name__ == "__main__":
    sys.exit(main())
