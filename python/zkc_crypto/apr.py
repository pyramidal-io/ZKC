"""Authenticated Proof Request (APR) and holder-custodied Disclosure Receipt
(spec §5.5, §5.6 — verifier accountability, Safeguard 6).

This module is the single source of truth for the verifier-accountability
artifacts in the reference stack:

* the **purposeTag** / purpose-bound context preimage (re-exported from
  :mod:`zkc_crypto.context`),
* the **APR digest** a verifier signs to bind itself to a demand, and
* the **Disclosure Receipt digest** a holder signs to retain self-contained,
  third-party-verifiable evidence of what was asked and answered.

Both artifacts sign a 32-byte Poseidon2 field digest with the reference
secp256k1 ECDSA primitive (Ed25519 is spec-permitted but the reference stack
signs with secp256k1, mirroring the issuer/credential signing path). No issuer,
registry, or operator participates in verification. A third party checks the
verifier key carried with the APR and anchors the holder key itself: the holder
key carried with a receipt is self-asserted (spec §5.6.1).

The reference request fixtures flatten the spec's nested
`request.requirements.context` (TS interface, §5.2) to `request.context`; the
bound context value is identical either way. The non-field request members
commit into the field preimage as: `proofTypes` via a domain-tagged,
length-bound Poseidon2 hash, and `parameters` via `string_to_field` of its
canonical (sorted-key, no-whitespace) JSON serialization.

Standard library only.
"""

from __future__ import annotations

import json
import time

from .context import (
    PURPOSE_BOUND_PROFILE,
    VERIFIER_SESSION_PROFILE,
    ProofContext,
)
from .digests import digest_to_message_bytes
from .ecdsa_secp256k1 import public_key_bytes, sign, verify
from .field import derive_domain, field_to_hex, hex_to_field, string_to_field
from .holder_keys import holder_key_bytes, holder_key_matches
from .poseidon2 import canonical_integer, hash_fields
from .presentation import derive_scope_id, derive_verifier_identity
from zkc_registry.predicate_v2 import parse_request_selectors

__all__ = [
    "DOMAIN_ZKC_APR",
    "DOMAIN_ZKC_RECEIPT",
    "SUPPORTED_SIGNATURE_SCHEMES",
    "REFERENCE_SIGNATURE_SCHEME",
    "SESSION_SCOPE_POLICY",
    "context_value_from_fixture",
    "recompute_purpose_bound_context",
    "apr_digest_from_dict",
    "apr_signer_pubkey",
    "sign_apr",
    "verify_apr_signature",
    "apr_freshness",
    "VERIFICATION_CONTEXT_EXTENSION",
    "LEGACY_MAX_PROOF_AGE",
    "canonical_request_context",
    "verification_context_extension",
    "receipt_digest_from_dict",
    "sign_receipt",
    "verify_receipt",
]

DOMAIN_ZKC_APR = derive_domain("zkc/apr")
DOMAIN_ZKC_APR_EXTENSIONS = derive_domain("zkc/apr/extensions:v1")
DOMAIN_ZKC_RECEIPT = derive_domain("zkc/receipt")
VERIFICATION_CONTEXT_EXTENSION = "zkc:request:verification-context:v1"
LEGACY_MAX_PROOF_AGE = 3600

# The spec permits ECDSA_SECP256K1 or Ed25519; the reference stack signs and
# verifies under secp256k1 (the same curve as issuer/credential signatures).
SUPPORTED_SIGNATURE_SCHEMES = ("ECDSA_SECP256K1", "Ed25519")
REFERENCE_SIGNATURE_SCHEME = "ECDSA_SECP256K1"


def _validate_signed_request_parameter_keys(apr: dict) -> None:
    """Reject ambiguous APR parameter tables before signing.

    Every signed proof type owns exactly one parameter block.  Extra keys can
    otherwise become meaningful after presentation-profile translation, while
    missing keys leave the signed request structurally incomplete.
    """
    try:
        request = apr["request"]
    except (KeyError, TypeError) as exc:
        raise ValueError("APR request must be an object") from exc
    if not isinstance(request, dict):
        raise ValueError("APR request must be an object")

    proof_types = request.get("proofTypes")
    if (
        not isinstance(proof_types, list)
        or any(not isinstance(proof_type, str) or not proof_type for proof_type in proof_types)
    ):
        raise ValueError("APR request proofTypes must be an array of non-empty strings")
    if len(set(proof_types)) != len(proof_types):
        raise ValueError("APR request proofTypes must not contain duplicates")

    parameters = request.get("parameters", {})
    if not isinstance(parameters, dict):
        raise ValueError("APR request parameters must be an object")
    expected = set(proof_types)
    actual = set(parameters)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {missing}")
        if extra:
            details.append(f"extra {extra}")
        raise ValueError(
            "APR request parameter keys must exactly match proofTypes"
            + (f": {', '.join(details)}" if details else "")
        )
    parse_request_selectors(request.get("extensions"), proof_types)


# ---------------------------------------------------------------------------
# Context value reconstruction (profile-aware)
# ---------------------------------------------------------------------------

def context_value_from_fixture(context_fixture: dict) -> int:
    """Reconstruct a context `value` from its structured fixture form.

    Mirrors the reference profile constructions in :mod:`zkc_crypto.context`.
    For an opaque (deployment-defined) profile the value is taken as-is."""
    canonical_integer(context_fixture["timestamp"], 1 << 64, name="context timestamp")
    if "sessionId" in context_fixture:
        canonical_integer(hex_to_field(context_fixture["sessionId"]), name="context sessionId")
    profile = context_fixture["profile"]
    if profile == PURPOSE_BOUND_PROFILE:
        return ProofContext.purpose_bound(
            context_fixture["verifierId"],
            hex_to_field(context_fixture["sessionId"]),
            context_fixture["purpose"],
            context_fixture["timestamp"],
        ).value
    if profile == VERIFIER_SESSION_PROFILE:
        return ProofContext.verifier_session(
            context_fixture["verifierId"],
            hex_to_field(context_fixture["sessionId"]),
            context_fixture["timestamp"],
        ).value
    return hex_to_field(context_fixture["value"])


def recompute_purpose_bound_context(apr: dict) -> int:
    """Verifier-side `recomputePurposeBoundContext(apr)` (spec §6.2 step 0).

    The verifier recomputes the bound context value from the APR's own request
    context so PURPOSE_MISMATCH catches a proof bound under a different
    purpose."""
    return context_value_from_fixture(apr["request"]["context"])


def canonical_request_context(raw: dict) -> dict:
    """Closed, type-strict context metadata for authenticated agreement.

    Legacy fixtures may omit the derived value and purposeTag. Supplied
    derived fields must agree; unknown metadata is never silently discarded.
    Opaque profiles require an additional signed context extension at the
    holder and verifier because the legacy APR digest covers only their value.
    """
    if not isinstance(raw, dict):
        raise ValueError("request context must be an object")
    profile = raw.get("profile")
    if not isinstance(profile, str) or not profile:
        raise ValueError("context profile must be a non-empty string")
    if type(raw.get("timestamp")) is not int or raw["timestamp"] <= 0:
        raise ValueError("context timestamp must be a positive integer")
    known = profile in (VERIFIER_SESSION_PROFILE, PURPOSE_BOUND_PROFILE)
    allowed = {"profile", "value", "timestamp", "verifierId", "sessionId"}
    if profile == PURPOSE_BOUND_PROFILE:
        allowed |= {"purpose", "purposeTag"}
    if set(raw) - allowed:
        raise ValueError("unknown context metadata")
    if known or "verifierId" in raw or "sessionId" in raw:
        if not isinstance(raw.get("verifierId"), str) or not raw["verifierId"]:
            raise ValueError("context verifierId must be a non-empty string")
        session = hex_to_field(raw["sessionId"])
    else:
        session = 0
    if profile == PURPOSE_BOUND_PROFILE:
        if not isinstance(raw.get("purpose"), str):
            raise ValueError("context purpose must be a string")
        context = ProofContext.purpose_bound(raw["verifierId"], session, raw["purpose"], raw["timestamp"])
    elif known:
        context = ProofContext.verifier_session(raw["verifierId"], session, raw["timestamp"])
    else:
        context = ProofContext(profile, hex_to_field(raw["value"]), raw["timestamp"], raw.get("verifierId", ""), session)
    if "value" in raw and hex_to_field(raw["value"]) != context.value:
        raise ValueError("context value does not reconstruct")
    if "purposeTag" in raw and hex_to_field(raw["purposeTag"]) != context.purpose_tag:
        raise ValueError("context purposeTag does not reconstruct")
    return context.to_metadata()


def verification_context_extension(context: ProofContext, max_proof_age: int = LEGACY_MAX_PROOF_AGE) -> dict:
    """Extension to merge into request.extensions BEFORE signing an APR."""
    if type(max_proof_age) is not int or max_proof_age < 0:
        raise ValueError("maxProofAge must be a non-negative integer")
    return {VERIFICATION_CONTEXT_EXTENSION: {
        "context": canonical_request_context(context.to_metadata()),
        "maxProofAge": max_proof_age,
    }}


# ---------------------------------------------------------------------------
# Field commitments to the structured (non-field) request members
# ---------------------------------------------------------------------------

def _commit_proof_types(proof_types) -> int:
    fields = [string_to_field(proof_type) for proof_type in proof_types]
    # Domain-tag and length-bind so [] and a single-element list never collide
    # with a bare field value.
    return hash_fields([DOMAIN_ZKC_APR, len(fields), *fields], len(fields) + 2, strict=True)


def _commit_parameters(parameters) -> int:
    canonical = json.dumps(
        parameters,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return string_to_field(canonical)


def _commit_presentation(presentation) -> int:
    """Commit the optional `request.presentation` block into the APR digest.

    This helper is called only when the ``presentation`` key is present.  Its
    canonical JSON therefore binds a present ``null`` distinctly from an
    absent key; the latter retains the original eight-field digest for legacy
    APR signatures.  A present block commits to its canonical (sorted-key,
    no-whitespace) JSON so the signed request binds the requested profile,
    scope policy, and rotation policy verbatim."""
    canonical = json.dumps(
        presentation,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hash_fields([DOMAIN_ZKC_APR, string_to_field(canonical)], 2, strict=True)


def _commit_extensions(extensions) -> int:
    """Domain-separated commitment to versioned request extensions."""
    canonical = json.dumps(
        extensions,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hash_fields([DOMAIN_ZKC_APR_EXTENSIONS, string_to_field(canonical)], 2, strict=True)


# ---------------------------------------------------------------------------
# Authenticated Proof Request (spec §5.5)
# ---------------------------------------------------------------------------

def apr_digest_from_dict(apr: dict) -> int:
    """Poseidon2 digest the verifier signs (spec §5.5).

    Covers H("zkc/apr", verifierId, proofTypes, parameters,
             request.requirements.context.value, nonce, issuedAt, expiresAt
             [, presentation] [, extensions]).
    Independent of the signature field, so it is identical before signing and
    at verification.

    The optional `request.presentation` block (design §5.1) is covered ONLY
    when present, appended as a 9th commitment. An APR without a presentation
    block keeps the original 8-element digest byte-for-byte — `hash_fields`
    binds the message length into its IV, so an 8-element digest never collides
    with a 9-element one, and legacy (presentation-less) APR signatures remain
    valid."""
    request = apr["request"]
    context_value = context_value_from_fixture(request["context"])
    fields = [
        DOMAIN_ZKC_APR,
        string_to_field(apr["verifierId"]),
        _commit_proof_types(list(request["proofTypes"])),
        _commit_parameters(request.get("parameters", {})),
        context_value,
        hex_to_field(apr["nonce"]),
        canonical_integer(apr["issuedAt"], 1 << 64, name="issuedAt"),
        canonical_integer(apr["expiresAt"], 1 << 64, name="expiresAt"),
    ]
    if "presentation" in request:
        fields.append(_commit_presentation(request["presentation"]))
    if "extensions" in request:
        fields.append(_commit_extensions(request["extensions"]))
    return hash_fields(fields, len(fields), strict=True)


def apr_signer_pubkey(apr: dict) -> bytes:
    """SEC1 compressed public key of the APR signer (design §2 input).

    Returns the 33-byte `0x02/0x03 || x` encoding of the verifier key carried
    in the APR signature, so a holder can derive `verifier_identity` from the
    *authenticated* signer without trusting any wire-supplied identity. Raises
    ValueError if the APR carries no verifier key."""
    try:
        key = apr["signature"]["verifierKey"]
        key_x = bytes.fromhex(key["x"].removeprefix("0x"))
        key_y = bytes.fromhex(key["y"].removeprefix("0x"))
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("APR carries no verifier public key") from exc
    if len(key_x) != 32 or len(key_y) != 32:
        raise ValueError("APR verifier key coordinates must be 32 bytes each")
    prefix = 0x02 if (key_y[-1] & 1) == 0 else 0x03
    return bytes([prefix]) + key_x


# The session scope policy (spec 5.9.1): a scope unique to ONE authenticated
# request's own context value. Every proof answering that request shares one
# pseudonym -- which the circuits derive from the holder's binding key, so the
# answers are bound to one holder -- while two sessions with distinct contexts
# (and two verifiers) derive unrelated scopes and therefore unlinkable
# pseudonyms. A verifier reusing one context gains no more than the
# "verifier" scope already gives it. The derived
# label prefix is reserved so no APR can name another session's scope.
SESSION_SCOPE_POLICY = "session"
_SESSION_SCOPE_PREFIX = "session:"


def scope_from_apr_presentation(apr: dict, block: dict, timestamp: int) -> int:
    """scope_id for an authenticated APR's presentation block (design §2).

    The SINGLE shared derivation for both sides of the protocol — the holder
    (``zkc_holder.client._resolve_presentation``) and the verifier
    (``zkc_verifier.verifier._recompute_scope``) — so the two can never
    drift: ``rotation_epoch = floor(shared-context-timestamp /
    rotationEpochSeconds)``, ``verifier_identity`` from the authenticated APR
    signer key, then ``scope_id = H("zkc/scope:v1", verifier_identity,
    scopePolicy, rotation_epoch)``. Raises ValueError on any invalid field;
    callers map it to their own error surface (``HolderError`` /
    ``SCOPE_MISMATCH``)."""
    scope_policy = block.get("scopePolicy")
    if not isinstance(scope_policy, str) or not scope_policy:
        raise ValueError("APR scopePolicy must be a non-empty string")
    if scope_policy.startswith(_SESSION_SCOPE_PREFIX):
        raise ValueError("APR scopePolicy prefix 'session:' is reserved")
    if scope_policy == SESSION_SCOPE_POLICY:
        context_value = context_value_from_fixture(apr["request"]["context"])
        scope_policy = _SESSION_SCOPE_PREFIX + "0x" + format(context_value, "064x")
    rotation_epoch_seconds = int(block.get("rotationEpochSeconds", 0) or 0)
    if rotation_epoch_seconds < 0:
        raise ValueError("rotationEpochSeconds must be non-negative")
    rotation_epoch = (
        timestamp // rotation_epoch_seconds if rotation_epoch_seconds > 0 else 0
    )
    verifier_identity = derive_verifier_identity(apr_signer_pubkey(apr))
    return derive_scope_id(verifier_identity, scope_policy, rotation_epoch)


def sign_apr(apr_unsigned: dict, verifier_private_key: int,
             scheme: str = REFERENCE_SIGNATURE_SCHEME) -> dict:
    """Attach a verifier signature over the APR digest (spec §5.5)."""
    if scheme not in SUPPORTED_SIGNATURE_SCHEMES:
        raise ValueError(f"unsupported APR signature scheme: {scheme}")
    _validate_signed_request_parameter_keys(apr_unsigned)
    digest = digest_to_message_bytes(apr_digest_from_dict(apr_unsigned))
    value = sign(digest, verifier_private_key)
    key_x, key_y = public_key_bytes(verifier_private_key)
    signed = dict(apr_unsigned)
    signed["signature"] = {
        "scheme": scheme,
        "value": "0x" + value.hex(),
        "verifierKey": {"x": "0x" + key_x.hex(), "y": "0x" + key_y.hex()},
    }
    return signed


def verify_apr_signature(apr: dict) -> bool:
    """True iff the APR carries a valid verifier signature. Fail closed."""
    try:
        signature = apr["signature"]
        if signature["scheme"] != REFERENCE_SIGNATURE_SCHEME:
            return False
        digest = digest_to_message_bytes(apr_digest_from_dict(apr))
        key = signature["verifierKey"]
        return verify(
            bytes.fromhex(key["x"].removeprefix("0x")),
            bytes.fromhex(key["y"].removeprefix("0x")),
            bytes.fromhex(signature["value"].removeprefix("0x")),
            digest,
        )
    except (AttributeError, KeyError, ValueError, TypeError):
        return False


def apr_freshness(apr: dict, now: int | None = None, seen_nonces=()) -> tuple:
    """(`fresh: bool`, `reason: str`): expiry + nonce-replay check (spec §5.5).

    Nonces must use field_to_hex's lowercase, 32-byte padded wire encoding,
    matching verifier admission. `seen_nonces` is a caller-owned container of
    already-observed canonical nonce strings; this check does not populate it.
    A reused nonce is a replay. Omitted ``now`` reads the wall clock. An explicit time
    is a trusted caller-owned u64 Unix timestamp, never derived from the APR.
    """
    try:
        issued_at = canonical_integer(apr["issuedAt"], 1 << 64, name="issuedAt")
        expires_at = canonical_integer(apr["expiresAt"], 1 << 64, name="expiresAt")
        now = canonical_integer(int(time.time()) if now is None else now, 1 << 64, name="now")
        nonce = apr["nonce"]
        nonce_value = canonical_integer(hex_to_field(nonce), name="APR nonce")
        if nonce != field_to_hex(nonce_value):
            return False, "APR nonce must use canonical field encoding"
    except (KeyError, TypeError, ValueError, OverflowError):
        return False, "malformed APR freshness fields"
    if expires_at <= issued_at:
        return False, "APR expiresAt must be after issuedAt"
    if now > expires_at:
        return False, "APR expired"
    if nonce in seen_nonces:
        return False, "APR nonce already seen (replay)"
    return True, ""


# ---------------------------------------------------------------------------
# Disclosure Receipt (spec §5.6)
# ---------------------------------------------------------------------------

def receipt_digest_from_dict(receipt: dict) -> int:
    """Poseidon2 digest the holder signs (spec §5.6).

    Covers H("zkc/receipt", apr, outcome, response), where `apr` binds the
    verifier-signed demand verbatim (its digest and signature) so the receipt
    is non-repudiable against that exact request."""
    apr = receipt["apr"]
    apr_digest = apr_digest_from_dict(apr)
    # Bind the verifier signature verbatim so the receipt commits to the signed
    # demand, not merely the demand preimage.
    signature_commitment = string_to_field(apr["signature"]["value"])

    response = receipt.get("response")
    if response is None:
        response_commitment = 0
    elif "holderCommitment" in response:
        # v1 / linkable receipt shape — digest is byte-identical to before.
        response_commitment = hash_fields(
            [
                hex_to_field(response["holderCommitment"]),
                hex_to_field(response["contextValue"]),
                _commit_proof_types(list(response["answeredProofTypes"])),
            ],
            3,
            strict=True,
        )
    else:
        # v2 receipt shapes (design §5.3): the response binds ONLY the active
        # profile's handle. Anonymous carries no handle (sentinel 0); scoped
        # carries the presentation pseudonym + scope. The global commitment is
        # absent from a v2 receipt.
        handle = hex_to_field(response["presentationPseudonym"]) if "presentationPseudonym" in response else 0
        scope = hex_to_field(response["scopeId"]) if "scopeId" in response else 0
        response_commitment = hash_fields(
            [
                handle,
                scope,
                hex_to_field(response["contextValue"]),
                _commit_proof_types(list(response["answeredProofTypes"])),
            ],
            4,
            strict=True,
        )
    return hash_fields(
        [
            DOMAIN_ZKC_RECEIPT,
            apr_digest,
            signature_commitment,
            string_to_field(receipt["outcome"]),
            response_commitment,
        ],
        5,
        strict=True,
    )


def sign_receipt(receipt_unsigned: dict, holder_private_key: int,
                 scheme: str = REFERENCE_SIGNATURE_SCHEME) -> dict:
    """Attach a holder signature over the receipt digest (spec §5.6).

    The holder signs under a profile-scoped key (spec §5.6.1,
    :mod:`zkc_crypto.holder_keys`) whose public half is conveyed with the
    receipt. The carried key is not a trust anchor: :func:`verify_receipt`
    requires the relying party's own expected holder key."""
    if scheme not in SUPPORTED_SIGNATURE_SCHEMES:
        raise ValueError(f"unsupported receipt signature scheme: {scheme}")
    digest = digest_to_message_bytes(receipt_digest_from_dict(receipt_unsigned))
    value = sign(digest, holder_private_key)
    key_x, key_y = public_key_bytes(holder_private_key)
    signed = dict(receipt_unsigned)
    signed["holderSignature"] = {
        "scheme": scheme,
        "value": "0x" + value.hex(),
        "holderKey": {"x": "0x" + key_x.hex(), "y": "0x" + key_y.hex()},
    }
    return signed


def verify_receipt(receipt: dict, *, expected_holder_key: dict = None) -> dict:
    """Third-party Disclosure Receipt verification (spec §5.6, §5.6.1).

    Returns a structured result. ``aprValid`` alone proves the demand ("the
    holder of verifier key K asked X"). ``holderValid`` proves only that the
    key carried in ``holderSignature.holderKey`` signed this receipt; that key
    is self-asserted, so anyone can sign a receipt under a key of their own.
    ``holderKeyAnchored`` is true only when the carried key equals
    ``expected_holder_key``, a key the relying party obtained from the holder
    through a channel it trusts (never from the receipt, the APR signer, or
    any other party). An answered receipt MUST also bind
    ``response.contextValue`` to the APR's context value.

    ``valid`` requires all four. Without ``expected_holder_key`` a receipt is
    never valid (fail closed). ``holderKeyAnchored`` is reported only when the
    holder signature is valid. A malformed ``expected_holder_key`` raises
    ValueError. No issuer, registry, or operator participates.

    Anchoring the key does not anchor the response handle: the relying party
    MUST also compare ``response.holderCommitment`` (or
    ``presentationPseudonym`` + ``scopeId``) with the handle it associated
    with the anchored key. Fresh-key receipts (anonymous, refused,
    unauthenticated) cannot be anchored by a third party at all; for them only
    ``aprValid`` and ``contextBound`` carry third-party meaning."""
    if expected_holder_key is not None:
        holder_key_bytes(expected_holder_key)
    result = {
        "aprValid": verify_apr_signature(receipt.get("apr", {})),
        "holderValid": False,
        "holderKeyAnchored": False,
        "contextBound": True,
    }
    try:
        signature = receipt["holderSignature"]
        if signature["scheme"] == REFERENCE_SIGNATURE_SCHEME:
            digest = digest_to_message_bytes(receipt_digest_from_dict(receipt))
            key = signature["holderKey"]
            result["holderValid"] = verify(
                bytes.fromhex(key["x"].removeprefix("0x")),
                bytes.fromhex(key["y"].removeprefix("0x")),
                bytes.fromhex(signature["value"].removeprefix("0x")),
                digest,
            )
            # Anchoring is reported only for a key that actually signed this
            # receipt; a matching key with a bad signature anchors nothing.
            if result["holderValid"] and expected_holder_key is not None:
                result["holderKeyAnchored"] = holder_key_matches(key, expected_holder_key)
    except (AttributeError, KeyError, ValueError, TypeError):
        result["holderValid"] = False
        result["holderKeyAnchored"] = False

    if receipt.get("outcome") == "answered":
        try:
            response = receipt["response"]
            expected = context_value_from_fixture(receipt["apr"]["request"]["context"])
            result["contextBound"] = hex_to_field(response["contextValue"]) == expected
        except (KeyError, ValueError, TypeError):
            result["contextBound"] = False

    result["valid"] = (
        result["aprValid"]
        and result["holderValid"]
        and result["holderKeyAnchored"]
        and result["contextBound"]
    )
    return result
