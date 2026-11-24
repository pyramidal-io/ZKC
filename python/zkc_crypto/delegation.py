"""Holder-controlled delegation of scoped, non-custodial proving (spec §5.3–§5.4).

``delegateViewing`` (spec §5.4) lets a holder authorize a named *principal* (a
delegate / agent identified by a public key) to exercise a :class:`ViewingScope`
— a set of proof types bound to **one** context value, **one** predicate source
(verifier), and **one** expiry (spec §5.3, property 3). The holder mints a
:class:`DelegationToken`: a capability signed by the holder that carries only
public material (no ``masterSeed``, no credential-binding keys, no witness
plaintext — spec §5.3 non-custodial mandate).

The delegate proves through a :class:`DelegatedProver`, constructed with only the
token + holder-issued *viewing-limited material*. It is provably seedless: it
holds no :class:`~zkc_holder.HolderClient`, master seed, or binding key, and it
**fails closed** on any request that diverges from the delegated scope (spec §5.3
property 5: reject if context, predicate source, proof type, or expiry differ).

The reference realizes the "holder-controlled execution environment" option of
spec §5.3 property 2: the holder pre-authorizes the in-scope proof material in its
own (seed-custodying) environment, and the delegate exercises that capability
within scope. The seed never crosses the delegation boundary.
"""

from __future__ import annotations

import dataclasses
import hashlib
import unicodedata

from .ecdsa_secp256k1 import N, public_key_bytes, sign, verify
from .kdc import derive_holder_commitment_from_seed
from .master_seed import master_seed_to_bytes
from .poseidon2 import canonical_integer

# Domain separation: the delegation signing key is distinct from the holder's
# receipt and audit-authorization keys (``zkc_crypto.holder_keys``) and from
# any other key derived from the seed.
_DELEGATION_KEY_DOMAIN = b"ZKC-Delegation-Key"
# Token digest v2 (spec §5.4 "Delegation token digest"): every field is
# length-prefixed, the proof-type list carries an explicit count, and the
# reviewed request commitment is a field of the same transcript. The v1
# transcript (NUL-terminated strings, no count, request commitment folded in
# by a second hash) was not injective and is no longer produced or accepted.
DELEGATION_TOKEN_DIGEST_VERSION = 2
_TOKEN_DIGEST_DOMAIN_V2 = b"zkc/delegation-token:v2\0"
_U32_LIMIT = 1 << 32
# Unicode General Categories refused in delegated identifiers: every "Other"
# category (Cc controls incl. NUL, Cf format/invisible incl. zero-width and
# bidi controls, Cs surrogates, Co private use, Cn unassigned) plus the line
# and paragraph separators Zl/Zp.
FORBIDDEN_IDENTIFIER_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def delegation_authorization_digest(
    token_digest: bytes, request_digest: bytes, authorization_nonce: bytes,
) -> bytes:
    """Principal proof of possession for one exact holder-reviewed capability."""
    if any(type(value) is not bytes or len(value) != 32
           for value in (token_digest, request_digest, authorization_nonce)):
        raise DelegationError("delegation authorization requires exact digests")
    return hashlib.sha256(
        b"zkc/delegation-principal-authorization:v1\0"
        + token_digest + request_digest + authorization_nonce
    ).digest()


class DelegationError(Exception):
    """Raised when a delegation is malformed, out of scope, or fails closed."""


@dataclasses.dataclass(frozen=True)
class ViewingScope:
    """The bounds of a delegation (spec §5.3 property 3).

    Scoped to a fixed set of ``proof_types``, a single ``context_value``, a
    single predicate source (``verifier_id``), one ``expires_at``, and a use
    budget (``max_uses`` defaults to 1 — spec §5.3 "one proof request").
    """

    proof_types: tuple
    context_value: int
    verifier_id: str
    expires_at: int
    max_uses: int = 1

    def normalized_types(self) -> tuple:
        """Distinct proof types, ordered by their UTF-8 bytes (digest order)."""
        return tuple(sorted(set(self.proof_types), key=lambda item: item.encode("utf-8")))

    def covers(self, proof_type: str, context_value: int, verifier_id: str, now: int) -> bool:
        """Whether a single request falls inside this scope (fail-closed check)."""
        # Exact ``str`` only: a subclass could override ``__eq__`` to match.
        if type(proof_type) is not str or type(verifier_id) is not str:
            return False
        try:
            canonical_integer(context_value, name="delegation request context")
            canonical_integer(now, 1 << 64, name="delegation request time")
            _validate_scope_integers(self)
            validate_scope_identifiers(self)
        except (ValueError, DelegationError):
            return False
        return (
            proof_type in self.proof_types
            and context_value == self.context_value
            and verifier_id == self.verifier_id
            and now <= self.expires_at
        )


def _validate_scope_integers(scope: ViewingScope) -> None:
    canonical_integer(scope.context_value, name="delegation context")
    canonical_integer(scope.expires_at, 1 << 64, name="delegation expiry")
    canonical_integer(scope.max_uses, 1 << 32, name="delegation max_uses")
    if scope.max_uses < 1:
        raise ValueError("delegation max_uses must be in [1, 2^32)")


def validate_delegation_identifier(value, *, name: str) -> bytes:
    """Return the UTF-8 bytes of a proof type or verifier id, or fail closed.

    The value must be a nonempty ``str`` with no code point in
    :data:`FORBIDDEN_IDENTIFIER_CATEGORIES`, so NUL, other controls, and
    invisible format characters (zero-width joiners, bidi overrides) cannot
    be signed in a scope, and must encode to fewer than 2**32 bytes.
    """
    if type(value) is not str or not value:
        raise DelegationError(f"{name} must be a nonempty string")
    for character in value:
        if unicodedata.category(character) in FORBIDDEN_IDENTIFIER_CATEGORIES:
            raise DelegationError(
                f"{name} contains a control, format, separator, or unassigned "
                f"character (U+{ord(character):04X})"
            )
    encoded = value.encode("utf-8")
    if len(encoded) >= _U32_LIMIT:
        raise DelegationError(f"{name} is too long")
    return encoded


def validate_scope_identifiers(scope: ViewingScope) -> None:
    """Fail closed on a scope whose identifiers could not be signed under v2."""
    if type(scope.proof_types) is not tuple or not scope.proof_types:
        raise DelegationError("viewing scope proof types must be a nonempty tuple")
    if len(scope.proof_types) >= _U32_LIMIT:
        raise DelegationError("viewing scope names too many proof types")
    for proof_type in scope.proof_types:
        validate_delegation_identifier(proof_type, name="delegation proof type")
    validate_delegation_identifier(scope.verifier_id, name="delegation verifier id")


def _field(value: bytes) -> bytes:
    """``u32be(len(value)) || value``: the v2 framing of every field."""
    if len(value) >= _U32_LIMIT:
        raise DelegationError("delegation transcript field is too long")
    return len(value).to_bytes(4, "big") + value


def delegation_token_transcript_v2(
    principal_key_x: bytes,
    principal_key_y: bytes,
    scope: ViewingScope,
    holder_commitment: int,
    issued_at: int,
    nonce: int,
    request_digest: bytes = b"",
) -> bytes:
    """Exact v2 preimage of the token digest (spec §5.4).

    ``domain || F(px) || F(py) || u32be(n) || F(t_1) .. F(t_n) || F(ctx) ||
    F(verifier) || F(expiry) || F(max_uses) || F(holder) || F(issued_at) ||
    F(nonce) || F(request_digest)`` where ``F(v) = u32be(len(v)) || v``,
    ``t_i`` are the distinct proof types in UTF-8 byte order, integers are
    fixed-width big-endian (u256 scalars, u64 times, u32 ``max_uses``), and
    ``request_digest`` is empty (inspection-only token) or 32 bytes.
    """
    try:
        _validate_scope_integers(scope)
        canonical_integer(holder_commitment, name="holder commitment")
        canonical_integer(issued_at, 1 << 64, name="delegation issuance")
        canonical_integer(nonce, name="delegation nonce")
    except ValueError as exc:
        raise DelegationError(str(exc)) from exc
    validate_scope_identifiers(scope)
    if any(type(key) is not bytes or len(key) != 32
           for key in (principal_key_x, principal_key_y)):
        raise DelegationError("delegation principal key coordinates are invalid")
    if type(request_digest) is not bytes or len(request_digest) not in (0, 32):
        raise DelegationError("delegation request commitment is invalid")
    return _frame_transcript_v2(
        principal_key_x,
        principal_key_y,
        [item.encode("utf-8") for item in scope.normalized_types()],
        scope.context_value,
        scope.verifier_id.encode("utf-8"),
        scope.expires_at,
        scope.max_uses,
        holder_commitment,
        issued_at,
        nonce,
        request_digest,
    )


def _frame_transcript_v2(
    principal_key_x: bytes,
    principal_key_y: bytes,
    proof_types: list,
    context_value: int,
    verifier_id: bytes,
    expires_at: int,
    max_uses: int,
    holder_commitment: int,
    issued_at: int,
    nonce: int,
    request_digest: bytes,
) -> bytes:
    """Pure v2 framing over already-validated, already-normalized fields.

    Kept separate from the character policy so the framing alone is injective
    (tests exercise it with NUL and other control bytes): the character ban is
    defence in depth for what a holder can be shown and asked to sign.
    """
    if len(proof_types) >= _U32_LIMIT:
        raise DelegationError("viewing scope names too many proof types")
    return b"".join((
        _TOKEN_DIGEST_DOMAIN_V2,
        _field(principal_key_x),
        _field(principal_key_y),
        len(proof_types).to_bytes(4, "big"),
        *(_field(item) for item in proof_types),
        _field(context_value.to_bytes(32, "big")),
        _field(verifier_id),
        _field(expires_at.to_bytes(8, "big")),
        _field(max_uses.to_bytes(4, "big")),
        _field(holder_commitment.to_bytes(32, "big")),
        _field(issued_at.to_bytes(8, "big")),
        _field(nonce.to_bytes(32, "big")),
        _field(request_digest),
    ))


@dataclasses.dataclass(frozen=True)
class DelegationToken:
    """A holder-signed capability authorizing ``principal`` to exercise ``scope``.

    Carries only public material: the principal's public key, the scope, the
    holder commitment, freshness fields, the holder's delegation public key, and
    the signature. No seed or binding key is ever present. The holder-key
    coordinates are untrusted wire metadata until a holder consumer anchors
    them to a delegation key resolved from its authenticated local state.
    """

    principal_key_x: bytes
    principal_key_y: bytes
    scope: ViewingScope
    holder_commitment: int
    issued_at: int
    nonce: int
    holder_key_x: bytes
    holder_key_y: bytes
    signature: bytes
    # Empty means an inspection-only token. Holder-side authorization requires
    # a 32-byte reviewed request commitment, signed as a digest field.
    request_digest: bytes = b""
    # Digest version the signature covers. Only v2 exists; any other value
    # (including the retired v1) fails closed in ``digest``.
    digest_version: int = DELEGATION_TOKEN_DIGEST_VERSION

    def digest(self) -> bytes:
        if (type(self.digest_version) is not int
                or self.digest_version != DELEGATION_TOKEN_DIGEST_VERSION):
            raise DelegationError("unsupported delegation token digest version")
        return hashlib.sha256(delegation_token_transcript_v2(
            self.principal_key_x,
            self.principal_key_y,
            self.scope,
            self.holder_commitment,
            self.issued_at,
            self.nonce,
            self.request_digest,
        )).digest()

    def verify_signature(self) -> bool:
        """Check token self-consistency under its token-carried public key.

        This does not authenticate a holder and MUST NOT authorize generation
        or release of holder-controlled material. Holder consumers use
        ``HolderClient.authorize_delegated_material``, which verifies under the
        delegation key derived from that holder's authenticated local seed.
        """
        try:
            return verify(self.holder_key_x, self.holder_key_y, self.signature, self.digest())
        except (AttributeError, DelegationError, TypeError, ValueError, OverflowError):
            return False


def derive_delegation_signing_key(master_seed: int | bytes | str) -> int:
    """Domain-separated secp256k1 delegation key, derived from the seed.

    Uses its own domain, so the delegation key cannot be confused with a
    receipt key (``zkc_crypto.holder_keys``) or the seed.
    """
    raw = hashlib.blake2b(
        _DELEGATION_KEY_DOMAIN + master_seed_to_bytes(master_seed), digest_size=64
    ).digest()
    return (int.from_bytes(raw, "big") % (N - 1)) + 1


def mint_delegation_token(
    *,
    master_seed: int | bytes | str,
    holder_commitment: int,
    principal_key_x: bytes,
    principal_key_y: bytes,
    scope: ViewingScope,
    issued_at: int,
    nonce: int,
    request_digest: bytes = b"",
) -> DelegationToken:
    """Mint + sign a :class:`DelegationToken` (the seed stays with the caller).

    Canonicalizes ``master_seed`` once, then derives both the delegation signing
    key and serialized holder commitment from those same seed bytes. Fails
    closed on an empty, already-expired, or zero-use scope, or when the exact
    integer ``holder_commitment`` is inconsistent with the master seed, and
    on a proof type or verifier id that is empty or carries a control, format,
    separator, or unassigned character (see :func:`validate_delegation_identifier`).
    """
    if type(scope) is not ViewingScope:
        raise DelegationError("viewing scope representation is invalid")
    if not scope.proof_types:
        raise DelegationError("viewing scope must name at least one proof type")
    validate_scope_identifiers(scope)
    try:
        _validate_scope_integers(scope)
        canonical_integer(issued_at, 1 << 64, name="delegation issuance")
        canonical_integer(nonce, name="delegation nonce")
    except ValueError as exc:
        raise DelegationError(str(exc)) from exc
    if scope.expires_at <= issued_at:
        raise DelegationError("viewing scope expiry must be after issuance")
    if scope.max_uses < 1:
        raise DelegationError("viewing scope max_uses must be >= 1")

    seed_bytes = master_seed_to_bytes(master_seed)
    expected_holder_commitment = derive_holder_commitment_from_seed(seed_bytes)
    if type(holder_commitment) is not int:
        raise DelegationError("holder commitment must be an integer")
    if holder_commitment != expected_holder_commitment:
        raise DelegationError("holder commitment does not match master seed")

    signing_key = derive_delegation_signing_key(seed_bytes)
    holder_key_x, holder_key_y = public_key_bytes(signing_key)
    digest = hashlib.sha256(delegation_token_transcript_v2(
        principal_key_x,
        principal_key_y,
        scope,
        expected_holder_commitment,
        issued_at,
        nonce,
        request_digest,
    )).digest()
    signature = sign(digest, signing_key)
    return DelegationToken(
        principal_key_x=bytes(principal_key_x),
        principal_key_y=bytes(principal_key_y),
        scope=scope,
        holder_commitment=expected_holder_commitment,
        issued_at=issued_at,
        nonce=nonce,
        holder_key_x=holder_key_x,
        holder_key_y=holder_key_y,
        signature=signature,
        request_digest=request_digest,
        digest_version=DELEGATION_TOKEN_DIGEST_VERSION,
    )


class DelegatedProver:
    """Non-custodial delegate (spec §5.3).

    Constructed with only a :class:`DelegationToken`, the principal's private key
    (to prove it is the named delegate), and holder-issued *viewing-limited
    material* (``{proof_type: envelope}``). It holds no master seed, holder
    client, or binding key, and fails closed outside the delegated scope.
    Token signature verification here establishes token self-consistency only;
    the holder must already have authorized ``material`` through its local-key
    anchor before releasing it to this object.
    """

    def __init__(self, token: DelegationToken, principal_private_key: int, material: dict):
        if not token.verify_signature():
            raise DelegationError("delegation token signature is invalid")
        principal_x, principal_y = public_key_bytes(principal_private_key)
        if principal_x != token.principal_key_x or principal_y != token.principal_key_y:
            raise DelegationError("principal key does not match the delegation token")
        self._token = token
        # Only viewing-limited material for the scoped proof types is retained.
        self._material = {
            proof_type: material[proof_type]
            for proof_type in token.scope.proof_types
            if proof_type in material
        }
        self._uses = 0

    @property
    def remaining_uses(self) -> int:
        return max(0, self._token.scope.max_uses - self._uses)

    def prove(self, proof_type: str, context_value: int, verifier_id: str, *, now: int) -> dict:
        """Exercise the capability for one in-scope request; fail closed otherwise.

        Rejects (spec §5.3 property 5) a token whose signature no longer verifies,
        an exhausted use budget, an expired token, or a request whose proof type,
        context value, or predicate source falls outside the delegated scope.
        """
        token = self._token
        if not token.verify_signature():
            raise DelegationError("delegation token signature is invalid")
        if self._uses >= token.scope.max_uses:
            raise DelegationError("delegation token use budget exhausted")
        try:
            canonical_integer(now, 1 << 64, name="delegation request time")
        except ValueError as exc:
            raise DelegationError(str(exc)) from exc
        if now > token.scope.expires_at:
            raise DelegationError("delegation token has expired")
        if not token.scope.covers(proof_type, context_value, verifier_id, now):
            raise DelegationError(
                f"request out of delegated scope (proof_type={proof_type}, "
                f"verifier_id={verifier_id})"
            )
        if proof_type not in self._material:
            raise DelegationError(f"no viewing-limited material authorized for {proof_type}")
        self._uses += 1
        return self._material[proof_type]
