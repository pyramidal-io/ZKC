"""Exact code-space transcripts for the additive jurisdiction-v6/set-v11 circuits.

Identifiers use the case-sensitive ZKC string-to-field encoding. All host
integers are canonical; no coercion or modular reduction is accepted here.
Leaf bounds include exclusion sentinels 0 and 65535. Credential admission
and approved codebook membership remain the caller's responsibility.
"""

from __future__ import annotations

from .field import string_to_field
from .poseidon2 import canonical_integer, poseidon3, poseidon4

_KINDS = frozenset({"jurisdiction", "source", "tax", "sanctions"})
_CREDENTIAL_TYPES = frozenset({
    "zkc:cred:jurisdiction:v2", "zkc:cred:source:v3",
    "zkc:cred:tax:v3", "zkc:cred:sanctions:v3",
})


def _kind(kind: str) -> str:
    if not isinstance(kind, str) or kind not in _KINDS:
        raise ValueError("unknown case-sensitive set family")
    return kind


def _space(code_space_id: int) -> int:
    value = canonical_integer(code_space_id, name="code_space_id")
    if value == 0:
        raise ValueError("code_space_id must be nonzero")
    return value


def code_space_leaf(kind: str, code_space_id: int, code: int, claim_type: int | None = None) -> int:
    """Hash one real or sentinel leaf under its exact family and space."""
    kind = _kind(kind)
    space = _space(code_space_id)
    code = canonical_integer(code, 65536, name="code")
    domain = string_to_field(f"zkc:set-leaf:{kind}:v1")
    if kind == "jurisdiction":
        claim_type = canonical_integer(claim_type, 3, name="claim_type")
        return poseidon4(domain, space, code, claim_type)
    if claim_type is not None:
        raise ValueError("claim_type is only defined for jurisdiction")
    return poseidon3(domain, space, code)


def bind_code_space_digest(credential_type: str, code_space_id: int, predecessor_digest: int) -> int:
    """Wrap the unchanged predecessor credential digest in its new schema."""
    if not isinstance(credential_type, str) or credential_type not in _CREDENTIAL_TYPES:
        raise ValueError("unknown code-space credential schema")
    return poseidon3(string_to_field(credential_type), _space(code_space_id),
                     canonical_integer(predecessor_digest, name="predecessor_digest"))


def bind_code_space_statement(kind: str, code_space_id: int, predecessor_binding: int,
                              required_verification_method: int = 0) -> int:
    """Bind the old statement to the space and optional signed method."""
    kind = _kind(kind)
    space = _space(code_space_id)
    old = canonical_integer(predecessor_binding, name="predecessor_binding")
    method = canonical_integer(required_verification_method, 5, name="required_verification_method")
    domain = string_to_field(f"zkc:set-binding:{kind}:v1")
    if kind == "jurisdiction":
        return poseidon4(domain, space, old, method)
    if method != 0:
        raise ValueError("required_verification_method is only defined for jurisdiction")
    return poseidon3(domain, space, old)
