"""Holder signing keys for Disclosure Receipts and audit authorizations
(spec §5.6, §5.9.3; docs/zkc_audit_disclosure.md).

A holder signs two kinds of portable evidence: the Disclosure Receipt
(``holderSignature``) and the audit-bundle authorization record
(``holderAuthorizationKey``). Each document carries its signer's public key.
A carried key proves only that whoever holds its private key signed the
document. It never identifies the holder. A relying party anchors the key by
comparing it with an expected key that it obtained from the holder through a
channel it trusts (:func:`holder_key_matches`), and compares the response
handle with the handle it associated with that key. Fresh keys cannot be
anchored by a third party.

Keys are scoped so that they add no linking handle beyond the active
presentation profile's own handle:

* linkable receipt (authenticated APR): one stable key per verifier identity;
* scoped receipt: one stable key per ``scopeId``;
* anonymous receipt, refusal receipt, and every unauthenticated answer: a
  fresh key per receipt, derived from a random 32-byte nonce that is never
  stored plus the receipt's own digest, so two such receipts never share a
  key and nobody (the holder included) can derive the key again;
* audit authorization: one stable key per ``auditorKeyId``.

Every derivation starts from the exact 32 master-seed bytes (never the reduced
field element) and uses HMAC-SHA512 with explicit ASCII domain tags and
length-prefixed inputs. A derived private key exists only in the signing call
frame; the SDK never logs, serializes or stores it.

Standard library only.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from .ecdsa_secp256k1 import N, public_key_bytes
from .master_seed import master_seed_to_bytes
from .poseidon2 import FIELD_MODULUS

__all__ = [
    "RECEIPT_KEY_DOMAIN",
    "AUDIT_AUTHORIZATION_ROOT_DOMAIN",
    "AUDIT_AUTHORIZATION_KEY_DOMAIN",
    "RECEIPT_KEY_NONCE_BYTES",
    "derive_linkable_receipt_key",
    "derive_scoped_receipt_key",
    "derive_fresh_receipt_key",
    "derive_audit_authorization_root",
    "derive_audit_authorization_key",
    "holder_public_key",
    "holder_key_bytes",
    "holder_key_matches",
]

RECEIPT_KEY_DOMAIN = "zkc/receipt-key:v2"
AUDIT_AUTHORIZATION_ROOT_DOMAIN = "zkc/audit-authorization-root:v2"
AUDIT_AUTHORIZATION_KEY_DOMAIN = "zkc/audit-authorization-key:v2"
RECEIPT_KEY_NONCE_BYTES = 32

_HEX_COORDINATE = re.compile(r"0x[0-9a-fA-F]{64}\Z")
_LINKABLE_LABEL = b"linkable-verifier"
_SCOPED_LABEL = b"scoped"
_FRESH_LABEL = b"fresh"


def _frame(*parts: bytes) -> bytes:
    """Length-prefix every input (u32 big-endian) so no two tuples collide."""
    return b"".join(len(part).to_bytes(4, "big") + part for part in parts)


def _derive_scalar(key: bytes, domain: str, *parts: bytes) -> int:
    """HMAC-SHA512(key, frame(domain, *parts)) mapped into [1, n-1].

    The 512-bit output reduced modulo n-1 has negligible bias."""
    raw = hmac.new(key, _frame(domain.encode("ascii"), *parts), hashlib.sha512).digest()
    return int.from_bytes(raw, "big") % (N - 1) + 1


def _field_bytes(value: int, name: str) -> bytes:
    if type(value) is not int or not 0 <= value < FIELD_MODULUS:
        raise ValueError(f"{name} must be an exact field element")
    return value.to_bytes(32, "big")


def derive_linkable_receipt_key(master_seed: int | bytes | str, verifier_identity: int) -> int:
    """Stable linkable-profile receipt key for one authenticated verifier.

    ``verifier_identity`` is ``H("zkc/verifier-id:v1", sec1(aprSignerKey))``
    (spec §5.9.1). Two verifiers derive unrelated keys."""
    return _derive_scalar(
        master_seed_to_bytes(master_seed),
        RECEIPT_KEY_DOMAIN,
        _LINKABLE_LABEL,
        _field_bytes(verifier_identity, "verifier identity"),
    )


def derive_scoped_receipt_key(master_seed: int | bytes | str, scope_id: int) -> int:
    """Stable scoped-profile receipt key for one ``scopeId`` (spec §5.9.1).

    The scope already binds the verifier identity, scope policy and rotation
    epoch, so the key is stable within a scope and unrelated across scopes."""
    scope = _field_bytes(scope_id, "scope id")
    if scope_id == 0:
        raise ValueError("scope id 0 is the anonymous sentinel")
    return _derive_scalar(
        master_seed_to_bytes(master_seed), RECEIPT_KEY_DOMAIN, _SCOPED_LABEL, scope
    )


def _derive_fresh_receipt_key_kat(
    master_seed: int | bytes | str, nonce: bytes, receipt_digest: int
) -> int:
    """Fresh-key derivation with an explicit nonce: known-answer tests only."""
    if type(nonce) is not bytes or len(nonce) != RECEIPT_KEY_NONCE_BYTES:
        raise ValueError("receipt key nonce must be exactly 32 bytes")
    return _derive_scalar(
        master_seed_to_bytes(master_seed),
        RECEIPT_KEY_DOMAIN,
        _FRESH_LABEL,
        nonce,
        _field_bytes(receipt_digest, "receipt digest"),
    )


def derive_fresh_receipt_key(master_seed: int | bytes | str, receipt_digest: int) -> int:
    """Fresh one-receipt key from the seed, a random 32-byte nonce and the
    receipt's own digest.

    ``receipt_digest`` is ``receipt_digest_from_dict`` of the receipt being
    signed (spec 5.6, computable before signing). A new random nonce is drawn
    and discarded, so the key can never be derived again. Mixing in the digest
    means that even a repeated RNG output (for example after a VM snapshot is
    cloned) cannot give two different receipts the same key."""
    return _derive_fresh_receipt_key_kat(
        master_seed, secrets.token_bytes(RECEIPT_KEY_NONCE_BYTES), receipt_digest
    )


def derive_audit_authorization_root(master_seed: int | bytes | str) -> bytes:
    """64-byte audit-authorization root: HMAC-SHA512(seed, frame(root domain)).

    An exporter keeps this root instead of the seed. The root yields only
    audit-authorization keys."""
    return hmac.new(
        master_seed_to_bytes(master_seed),
        _frame(AUDIT_AUTHORIZATION_ROOT_DOMAIN.encode("ascii")),
        hashlib.sha512,
    ).digest()


def derive_audit_authorization_key(authorization_root: bytes, auditor_key_id: str) -> int:
    """Stable per-auditor authorization key over the exact UTF-8 bytes of
    ``auditorKeyId`` as it appears in the authorization record."""
    if type(authorization_root) is not bytes or len(authorization_root) != 64:
        raise ValueError("audit authorization root must be exactly 64 bytes")
    if not isinstance(auditor_key_id, str) or not auditor_key_id:
        raise ValueError("auditor key id must be a non-empty string")
    return _derive_scalar(
        authorization_root,
        AUDIT_AUTHORIZATION_KEY_DOMAIN,
        auditor_key_id.encode("utf-8"),
    )


def holder_public_key(private_key: int) -> dict:
    """The ``{"x", "y"}`` wire form of a holder signing key's public point."""
    x, y = public_key_bytes(private_key)
    return {"x": "0x" + x.hex(), "y": "0x" + y.hex()}


def _coordinate(value, name: str) -> bytes:
    if not isinstance(value, str) or not _HEX_COORDINATE.match(value):
        raise ValueError(f"holder key {name} must be 0x plus 64 hex digits")
    return bytes.fromhex(value[2:])


def holder_key_bytes(key) -> bytes:
    """Exact 64-byte ``x || y`` of a ``{"x", "y"}`` holder key; ValueError otherwise."""
    if not isinstance(key, dict) or set(key) != {"x", "y"}:
        raise ValueError("holder key must be an object with exactly x and y")
    return _coordinate(key["x"], "x") + _coordinate(key["y"], "y")


def holder_key_matches(carried, expected) -> bool:
    """Constant-time comparison of a document-carried key with the caller's
    expected key.

    ``expected`` is trusted caller input: a malformed expected key raises
    ValueError. A malformed carried key is a mismatch (fail closed)."""
    expected_bytes = holder_key_bytes(expected)
    try:
        carried_bytes = holder_key_bytes(carried)
    except ValueError:
        return False
    return hmac.compare_digest(carried_bytes, expected_bytes)
