"""ZKC reference verifier (spec §6.2).

Collects ALL applicable structured errors (it does not stop at the first
failure, except when the envelope is malformed and nothing else can be
trusted). Fail closed: anything unparseable, unknown, or unverifiable is a
rejection, never a pass.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import logging
import pathlib
import re
import threading
from collections.abc import Mapping, MutableSet
from dataclasses import dataclass, field, replace

from zkc_crypto import (
    ANONYMOUS_PROFILE,
    CANONICAL_SET_EXCLUSION,
    CANONICAL_SET_INCLUSION,
    CANONICAL_SET_MAX_REQUEST_CODES,
    CANONICAL_SET_PARAM,
    CANONICAL_SET_PARAM_KEYS,
    JURISDICTION_CANONICAL_SET_PARAM,
    FIELD_MODULUS,
    LINKABLE_PROFILE,
    PURPOSE_BOUND_PROFILE,
    SCOPED_PROFILE,
    CanonicalCodeSet,
    CanonicalSetError,
    EnvelopeError,
    ProofContext,
    PublicInputBindings,
    apr_freshness,
    apr_signer_pubkey,
    compute_attribute_flags_hash,
    compute_claim_binding_2,
    compute_claim_binding_3,
    compute_claim_binding_4,
    compute_selective_disclosure_binding,
    compute_selective_disclosure_binding_v3,
    field_to_hex,
    hex_to_field,
    parse_attribute_layout_id,
    recompute_purpose_bound_context,
    scope_from_apr_presentation,
    string_to_field,
    validate_compliance_proof_v1,
    validate_compliance_proof_v2,
    verify_apr_signature,
)
from zkc_holder.aggregation import (
    aggregate_commitments,
    aggregated_claim_binding,
    commitment_for_envelope_proof,
)
from zkc_holder.predicates import (
    MEMBERSHIP_TYPE_EXCLUSION,
    MEMBERSHIP_TYPE_INCLUSION,
    PROFILE_PROOF_TYPES,
    family_for_v1_proof_type,
    legacy_presentation_proof_type_for_verification,
    resolve_presentation_proof_type_for_request,
)
from zkc_holder.registry import BindingResolutionError, PredicateRegistry
from zkc_registry.containment import matches_containment_identity
from zkc_registry.encoder_resolution import encoder_circuits
from zkc_registry.predicate_v2 import parse_request_selectors, selector_key
from zkc_crypto.request_parameters import (
    request_parameter_contracts,
    unknown_request_parameters,
)
from zkc_crypto.apr import (
    LEGACY_MAX_PROOF_AGE,
    VERIFICATION_CONTEXT_EXTENSION,
    canonical_request_context,
)
from zkc_crypto.code_space_requests import resolve_code_space_request
from zkc_crypto.code_spaces import CODE_SPACE_PROOF_TO_KIND
from zkc_crypto.code_space_transcripts import bind_code_space_statement
from zkc_crypto.credential_id_successors import NONZERO_CREDENTIAL_PROOF_PREDECESSORS

from .backends import VerifyBackend
from .errors import VerificationErrorCode as Code
from .errors import VerificationResult
from .errors import VerificationWarningCode as WarningCode
from .trust_policy import VerifierTrustPolicy, _is_authenticated_accumulator_state
from .vk_store import VerificationKeyStore

__all__ = ["VerificationRequest", "ZKCVerifier"]

logger = logging.getLogger("zkc.verifier")
_APR_NONCE_LOCK = threading.Lock()

KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
COMMUNITY_KYC_V2_PROOF_TYPE = "zkc:proof:community_kyc:v2"
REBIND_PROOF_TYPE = "zkc:proof:credential_rebind:v1"
REBIND_BINDING_V2_PROOF_TYPE = "zkc:proof:credential_rebind:v2"

# v2 (presentation-profile) proof types. The v2 rebind/aggregate proof types
# drop the ``credential_``/``aggregation`` prefix used by v1 — they match the
# v2 public-input encoders (schemas/public-inputs/zkc_credential_rebind_v2.json →
# ``zkc:proof:rebind:v2``; …/zkc_aggregation_v2.json → ``zkc:proof:aggregate:v2``).
KYC_V2_PROOF_TYPE = "zkc:proof:kyc:v2"
KYC_V3_PROOF_TYPE = "zkc:proof:kyc:v3"
REBIND_V2_PROOF_TYPE = "zkc:proof:rebind:v2"
REBIND_V2_BINDING_V2_PROOF_TYPE = "zkc:proof:rebind:v3"

# Issuer-authenticated credential-rebind successors (spec section 7.4, ADR 0004):
# the only rebind statements that authenticate the credential they migrate.
REBIND_AUTH_PROOF_TYPE = "zkc:proof:credential_rebind:v3"
REBIND_AUTH_V2_PROOF_TYPE = "zkc:proof:rebind:v4"
REBIND_AUTH_V3_PROOF_TYPE = "zkc:proof:rebind:v5"
AGGREGATE_V2_PROOF_TYPE = "zkc:proof:aggregate:v2"
AGGREGATE_V3_PROOF_TYPE = "zkc:proof:aggregate:v3"
SELECTIVE_DISCLOSURE_PROOF_TYPE = "zkc:proof:selective_disclosure:v1"
SELECTIVE_DISCLOSURE_V2_PROOF_TYPE = "zkc:proof:selective_disclosure:v2"
SELECTIVE_DISCLOSURE_V3_PROOF_TYPE = "zkc:proof:selective_disclosure:v3"
_LAYOUT_BOUND_DISCLOSURE_PROOF_TYPES = frozenset(
    (SELECTIVE_DISCLOSURE_V3_PROOF_TYPE, "zkc:proof:selective_disclosure:v4")
)
SELECTIVE_DISCLOSURE_PROOF_TYPES = frozenset(
    (SELECTIVE_DISCLOSURE_PROOF_TYPE, SELECTIVE_DISCLOSURE_V2_PROOF_TYPE)
) | _LAYOUT_BOUND_DISCLOSURE_PROOF_TYPES

JURISDICTION_PROOF_TYPE = "zkc:proof:jurisdiction:v1"
JURISDICTION_V2_PROOF_TYPE = "zkc:proof:jurisdiction:v2"
JURISDICTION_V3_PROOF_TYPE = "zkc:proof:jurisdiction:v3"
JURISDICTION_V4_PROOF_TYPE = "zkc:proof:jurisdiction:v4"
JURISDICTION_V5_PROOF_TYPE = "zkc:proof:jurisdiction:v5"
ACCREDITATION_PROOF_TYPE = "zkc:proof:accreditation:v1"
ACCREDITATION_V2_PROOF_TYPE = "zkc:proof:accreditation:v2"
SOURCE_PROOF_TYPE = "zkc:proof:source:v1"
SOURCE_V2_PROOF_TYPE = "zkc:proof:source:v2"
TAX_PROOF_TYPE = "zkc:proof:tax:v1"
TAX_V2_PROOF_TYPE = "zkc:proof:tax:v2"
SANCTIONS_PROOF_TYPE = "zkc:proof:sanctions:v1"
SANCTIONS_V2_PROOF_TYPE = "zkc:proof:sanctions:v2"
ACCREDITATION_V3_PROOF_TYPE = "zkc:proof:accreditation:v3"
ACCREDITATION_V4_PROOF_TYPE = "zkc:proof:accreditation:v4"
SOURCE_V3_PROOF_TYPE = "zkc:proof:source:v3"
SOURCE_V4_PROOF_TYPE = "zkc:proof:source:v4"
TAX_V3_PROOF_TYPE = "zkc:proof:tax:v3"
TAX_V4_PROOF_TYPE = "zkc:proof:tax:v4"
SANCTIONS_V3_PROOF_TYPE = "zkc:proof:sanctions:v3"
SANCTIONS_V4_PROOF_TYPE = "zkc:proof:sanctions:v4"
ACCREDITATION_V5_PROOF_TYPE = "zkc:proof:accreditation:v5"
ACCREDITATION_V6_PROOF_TYPE = "zkc:proof:accreditation:v6"
SOURCE_V5_PROOF_TYPE = "zkc:proof:source:v5"
SOURCE_V6_PROOF_TYPE = "zkc:proof:source:v6"
TAX_V5_PROOF_TYPE = "zkc:proof:tax:v5"
TAX_V6_PROOF_TYPE = "zkc:proof:tax:v6"
SANCTIONS_V5_PROOF_TYPE = "zkc:proof:sanctions:v5"
SANCTIONS_V6_PROOF_TYPE = "zkc:proof:sanctions:v6"
ACCREDITATION_V7_PROOF_TYPE = "zkc:proof:accreditation:v7"
ACCREDITATION_V8_PROOF_TYPE = "zkc:proof:accreditation:v8"
SOURCE_V7_PROOF_TYPE = "zkc:proof:source:v7"
SOURCE_V8_PROOF_TYPE = "zkc:proof:source:v8"
TAX_V7_PROOF_TYPE = "zkc:proof:tax:v7"
TAX_V8_PROOF_TYPE = "zkc:proof:tax:v8"
SANCTIONS_V7_PROOF_TYPE = "zkc:proof:sanctions:v7"
SANCTIONS_V8_PROOF_TYPE = "zkc:proof:sanctions:v8"
ACCREDITATION_V9_PROOF_TYPE = "zkc:proof:accreditation:v9"
ACCREDITATION_V10_PROOF_TYPE = "zkc:proof:accreditation:v10"
SOURCE_V9_PROOF_TYPE = "zkc:proof:source:v9"
SOURCE_V10_PROOF_TYPE = "zkc:proof:source:v10"
TAX_V9_PROOF_TYPE = "zkc:proof:tax:v9"
TAX_V10_PROOF_TYPE = "zkc:proof:tax:v10"
SANCTIONS_V9_PROOF_TYPE = "zkc:proof:sanctions:v9"
SANCTIONS_V10_PROOF_TYPE = "zkc:proof:sanctions:v10"

_AUTHENTICATED_HISTORICAL_PROOF_TYPES = frozenset(
    {
        JURISDICTION_PROOF_TYPE,
        JURISDICTION_V2_PROOF_TYPE,
        ACCREDITATION_PROOF_TYPE, ACCREDITATION_V2_PROOF_TYPE,
        ACCREDITATION_V3_PROOF_TYPE, ACCREDITATION_V4_PROOF_TYPE,
        ACCREDITATION_V5_PROOF_TYPE, ACCREDITATION_V6_PROOF_TYPE,
        SOURCE_PROOF_TYPE, SOURCE_V2_PROOF_TYPE, SOURCE_V3_PROOF_TYPE,
        SOURCE_V4_PROOF_TYPE, SOURCE_V5_PROOF_TYPE, SOURCE_V6_PROOF_TYPE,
        TAX_PROOF_TYPE, TAX_V2_PROOF_TYPE, TAX_V3_PROOF_TYPE,
        TAX_V4_PROOF_TYPE, TAX_V5_PROOF_TYPE, TAX_V6_PROOF_TYPE,
        SANCTIONS_PROOF_TYPE, SANCTIONS_V2_PROOF_TYPE, SANCTIONS_V3_PROOF_TYPE,
        SANCTIONS_V4_PROOF_TYPE, SANCTIONS_V5_PROOF_TYPE, SANCTIONS_V6_PROOF_TYPE,
    }
)

_HEX32 = re.compile(r"^0x[0-9a-f]{64}$")
_SELECTIVE_DISCLOSURE_ENTRY_KEYS = frozenset(
    {"proofType", "proof", "publicInputs", "principalConsent"}
)
_SELECTIVE_DISCLOSURE_PUBLIC_INPUT_KEYS = frozenset(
    {
        "presentation_pseudonym",
        "scope_id",
        "claim_binding",
        "proof_context",
        "accumulator_root",
        "accumulator_epoch",
        "timestamp",
        "current_epoch",
        "issuer_public_key_x",
        "issuer_public_key_y",
        "credential_attribute_count",
        "disclosure_count",
        "disclosed_flags",
        "disclosed_attributes",
    }
)


def _validate_selective_disclosure_entry(proof_entry: dict) -> None:
    """Stdlib mirror of the versioned selective-disclosure proof-entry schemas."""
    if set(proof_entry) - {"bindingSelector"} != _SELECTIVE_DISCLOSURE_ENTRY_KEYS:
        raise EnvelopeError("selective-disclosure proof entry has unsupported or missing fields")
    if proof_entry["proofType"] not in SELECTIVE_DISCLOSURE_PROOF_TYPES:
        raise EnvelopeError("selective-disclosure proofType is not canonical")
    if not isinstance(proof_entry["proof"], str) or not proof_entry["proof"]:
        raise EnvelopeError("selective-disclosure proof must be a non-empty string")
    if proof_entry["principalConsent"] is not True:
        raise EnvelopeError("selective-disclosure proof requires principalConsent=true")

    public_inputs = proof_entry["publicInputs"]
    layout_bound = proof_entry["proofType"] in _LAYOUT_BOUND_DISCLOSURE_PROOF_TYPES
    expected_inputs = _SELECTIVE_DISCLOSURE_PUBLIC_INPUT_KEYS
    if layout_bound:
        expected_inputs = expected_inputs | {"layout_id"}
    if not isinstance(public_inputs, dict) or set(public_inputs) != expected_inputs:
        raise EnvelopeError(
            "selective-disclosure publicInputs have unsupported or missing fields"
        )
    if layout_bound:
        try:
            parse_attribute_layout_id(public_inputs["layout_id"])
        except ValueError as exc:
            raise EnvelopeError(f"selective-disclosure layout_id is invalid: {exc}") from exc

    field_names = (
        "presentation_pseudonym",
        "scope_id",
        "claim_binding",
        "proof_context",
        "accumulator_root",
    )
    for name in field_names:
        value = public_inputs[name]
        if not isinstance(value, str) or not _HEX32.fullmatch(value):
            raise EnvelopeError(f"selective-disclosure {name} must be canonical hex")
        try:
            hex_to_field(value)
        except ValueError as exc:
            raise EnvelopeError(
                f"selective-disclosure {name} must be a canonical field element"
            ) from exc
    if hex_to_field(public_inputs["proof_context"]) == 0:
        raise EnvelopeError("selective-disclosure proof_context must be non-zero")

    for name in ("issuer_public_key_x", "issuer_public_key_y"):
        value = public_inputs[name]
        if not isinstance(value, str) or not _HEX32.fullmatch(value):
            raise EnvelopeError(f"selective-disclosure {name} must be 32-byte hex")

    integer_ranges = {
        "accumulator_epoch": (0, (1 << 64) - 1),
        "timestamp": (1, (1 << 64) - 1),
        "current_epoch": (0, (1 << 64) - 1),
        "credential_attribute_count": (1, 8),
        "disclosure_count": (1, 8),
    }
    for name, (minimum, maximum) in integer_ranges.items():
        value = public_inputs[name]
        if type(value) is not int or not minimum <= value <= maximum:
            raise EnvelopeError(f"selective-disclosure {name} is outside its integer range")

    flags = public_inputs["disclosed_flags"]
    if not isinstance(flags, list) or len(flags) != 8 or not all(type(flag) is bool for flag in flags):
        raise EnvelopeError("selective-disclosure disclosed_flags must be eight booleans")
    attributes = public_inputs["disclosed_attributes"]
    if not isinstance(attributes, list) or len(attributes) != 8:
        raise EnvelopeError("selective-disclosure disclosed_attributes must contain eight fields")
    for value in attributes:
        if not isinstance(value, str) or not _HEX32.fullmatch(value):
            raise EnvelopeError("selective-disclosure disclosed attribute must be canonical hex")
        try:
            hex_to_field(value)
        except ValueError as exc:
            raise EnvelopeError(
                "selective-disclosure disclosed attribute must be a canonical field element"
            ) from exc


# ---------------------------------------------------------------------------
# Request-binding registry (spec §6.2 step 4e).
#
# A proof is evidence of what the verifier asked for only when its public
# inputs bind to the request. The request-binding contract covers every
# individual proof family, including jurisdiction, accreditation, source, tax,
# and sanctions. It prevents an inclusion proof from satisfying an exclusion
# request and prevents one of the four shared-verification-key predicate
# meanings from being relabelled as another.
#
# The registry is DEFAULT-DENY: a proof type with no entry is rejected with
# UNBOUND_PROOF_TYPE. That is the point. Adding a predicate without declaring
# how it binds to the request is the failure mode this table exists to kill, so
# forgetting an entry must cost a rejection, never a silent acceptance.
#
# Scope: every proof type an encoder in schemas/public-inputs declares EXCEPT
# the aggregation types (`zkc:proof:aggregation:v1`, `zkc:proof:aggregate:v2`,
# and the draft beta.25 transport identity `zkc:proof:aggregate:v3`).
# Aggregation is envelope-level. Only v1 blocks are checked as commitments.
# An aggregation identifier in an individual proof entry is rejected here.
# ---------------------------------------------------------------------------

# Handler selectors. The first three delegate to the specialised checks that
# already bound those families; only ``predicate`` is the generic binding.
_HANDLER_KYC = "kyc"
_HANDLER_SELECTIVE_DISCLOSURE = "selective_disclosure"
_HANDLER_REBIND = "rebind"
_HANDLER_REBIND_AUTH = "rebind_auth"
_HANDLER_PREDICATE = "predicate"
_HANDLER_CODE_SPACE = "code_space"

# Sentinel default meaning "the verifier MUST state this parameter". A slot
# with any other default mirrors the holder's own ``.get(key, default)``, which
# is what makes the recomputed claim binding bit-for-bit comparable.
_MANDATORY = object()

# Rebind statement routing is deliberately exact and additive. In particular,
# a request for either frozen proof type can never select a binding-v2 circuit
# merely because it shares the same ABI.
_LEGACY_REBIND_PROOF_TYPES = frozenset((REBIND_PROOF_TYPE, REBIND_V2_PROOF_TYPE))
_SUCCESSOR_REBIND_PROOF_TYPES = frozenset(
    (REBIND_BINDING_V2_PROOF_TYPE, REBIND_V2_BINDING_V2_PROOF_TYPE)
)
_LINKABLE_REBIND_PROOF_TYPES = frozenset(
    (REBIND_PROOF_TYPE, REBIND_BINDING_V2_PROOF_TYPE)
)
_SCOPED_REBIND_PROOF_TYPES = frozenset(
    (REBIND_V2_PROOF_TYPE, REBIND_V2_BINDING_V2_PROOF_TYPE)
)

# ---------------------------------------------------------------------------
# Credential-continuity containment (security remediation, 2026-09-06).
#
# Every one of the four historical credential-rebind statements constrains
# ONLY that the prover knows the two binding keys behind the old and new
# holder handles. The credential it claims to migrate -- holder commitment,
# credential_id, issuer_id_hash, schema_id_hash, both validity bounds -- is a
# set of unconstrained private witnesses the prover picks freely; no issuer
# signature and no accumulator membership are verified. A valid proof is
# therefore evidence of attacker-chosen key continuity, never of an
# issuer-created, non-revoked credential. Request-pinned issuerIdHash /
# schemaIdHash filters compare a prover-chosen value against a verifier
# expectation and are not authentication either.
#
# Both verifier entry points reject these identities BEFORE any backend
# verification, with or without a configured issuer trust policy, so that
# "the proof backend returned true" can never surface as a credential
# continuity result. The historical circuit sources, encoders, sidecars,
# artifacts and registry pins are byte-frozen and untouched by this gate.
# ---------------------------------------------------------------------------
_UNAUTHENTICATED_REBIND_PROOF_TYPES = frozenset(
    (
        REBIND_PROOF_TYPE,
        REBIND_V2_PROOF_TYPE,
        REBIND_BINDING_V2_PROOF_TYPE,
        REBIND_V2_BINDING_V2_PROOF_TYPE,
    )
)
# The authenticated rebind successors, by presentation profile.
_LINKABLE_REBIND_AUTH_PROOF_TYPES = frozenset(
    (REBIND_AUTH_PROOF_TYPE, "zkc:proof:credential_rebind:v4")
)
_SCOPED_REBIND_AUTH_PROOF_TYPES = frozenset(
    (REBIND_AUTH_V2_PROOF_TYPE, REBIND_AUTH_V3_PROOF_TYPE, "zkc:proof:rebind:v6")
)
_REBIND_AUTH_PROOF_TYPES = _LINKABLE_REBIND_AUTH_PROOF_TYPES | _SCOPED_REBIND_AUTH_PROOF_TYPES

# Proof types whose non-revocation state MUST come from AUTHENTICATED issuer
# metadata-v2 announcement-chain ingestion, never from a bare epoch view. A
# prover-controlled root or current epoch is not revocation authentication
# (spec sections 7.4.5 and 2.4).
_AUTHENTICATED_ACCUMULATOR_REQUIRED = (
    SELECTIVE_DISCLOSURE_PROOF_TYPES | _REBIND_AUTH_PROOF_TYPES
)

_UNAUTHENTICATED_REBIND_MESSAGE = (
    "proof type {proof_type} asserts credential continuity without authenticating "
    "issuance or revocation (its credential fields are unconstrained prover "
    "witnesses); rejected by the credential-rebind security containment"
)

# ---------------------------------------------------------------------------
# Envelope-generation binding (security remediation, review 2026-10-04).
#
# The verifier credits a presentation to a holder handle it reads BY NAME from
# ``publicInputs``: ``holder_commitment`` on the v1 (linkable) path,
# ``presentation_pseudonym`` / ``scope_id`` on the v2 path. A proof backend,
# however, only ever checks the inputs its circuit's encoder DECLARES
# (``PublicInputEncoder.field_elements`` walks the declared list and ignores
# every other key). Without the two rules below a presenter could wrap a
# presentation-family proof in a v1 envelope next to an injected, unconstrained
# ``holder_commitment`` -- or a linkable proof in a v2 envelope next to a
# victim's pseudonym -- and the verifier would credit the presentation to a
# handle no circuit ever constrained:
#
#   1. ``publicInputs`` MUST carry exactly the encoder-declared names of the
#      circuit that verifies the entry; anything else is MALFORMED_PROOF.
#   2. A circuit's family is derived from its encoder's holder-handle inputs,
#      and a proof is admissible only in the envelope generation of its
#      family; a mismatch is PROFILE_MISMATCH.
#
# The family is read from the encoder documents, never from a hand-kept list,
# so a new circuit cannot be added to the wrong side of the boundary. A circuit
# that declares no holder handle, or both kinds, belongs to no envelope.
# ---------------------------------------------------------------------------
_LINKABLE_CIRCUIT_FAMILY = "linkable"
_PRESENTATION_CIRCUIT_FAMILY = "presentation"
_LINKABLE_HANDLE_INPUTS = frozenset(("holder_commitment", "old_holder_commitment"))
_PRESENTATION_HANDLE_INPUTS = frozenset(
    ("presentation_pseudonym", "old_presentation_pseudonym")
)
_ENVELOPE_VERSION_BY_FAMILY = {
    _LINKABLE_CIRCUIT_FAMILY: "zkc:proof:v1",
    _PRESENTATION_CIRCUIT_FAMILY: "zkc:proof:v2",
}

# How linkable each presentation profile is. An authenticated envelope may
# answer at most as linkably as its APR asked (the holder only ever
# downgrades, spec section 5.9.2 rule 4).
_PRESENTATION_PROFILE_RANK = {
    ANONYMOUS_PROFILE: 0,
    SCOPED_PROFILE: 1,
    LINKABLE_PROFILE: 2,
}


def _circuit_family(declared_names) -> str | None:
    """Envelope family of a circuit, from its encoder's declared input names."""
    linkable = bool(_LINKABLE_HANDLE_INPUTS & declared_names)
    presentation = bool(_PRESENTATION_HANDLE_INPUTS & declared_names)
    if linkable and not presentation:
        return _LINKABLE_CIRCUIT_FAMILY
    if presentation and not linkable:
        return _PRESENTATION_CIRCUIT_FAMILY
    return None


@dataclass(frozen=True)
class _Param:
    """A request parameter, read as an exact canonical field integer.

    Every numeric predicate parameter enters a BN254 transcript.  Accepting
    Python/JSON aliases or reducing an out-of-range value would let ``x`` and
    ``x + FIELD_MODULUS`` name the same proof requirement, so the verifier
    requires an actual integer already in canonical field range."""

    key: str
    default: object = _MANDATORY
    upper_bound: int = FIELD_MODULUS


@dataclass(frozen=True)
class _BoolParam:
    """A request parameter that must remain an exact JSON boolean."""

    key: str
    default: object = _MANDATORY


@dataclass(frozen=True)
class _PredicateType:
    """The proof type's ``predicate_type`` selector.

    Resolved from the P4 binding sidecar (``schemas/public-input-bindings/
    <circuit>.json`` → ``predicateTypes``), whose values CI cross-checks against
    the circuit's own ``PREDICATE_*`` Noir constants. Never a literal here: the
    selector's authority is the circuit source, not this file."""


@dataclass(frozen=True)
class _PublicComparison:
    """A public input compared DIRECTLY against a request-derived value.

    ``decoder`` mirrors how the holder serialises the field into the envelope:
    ``field`` for canonical hex, ``int`` for an exact u8 JSON integer."""

    name: str
    decoder: str
    source: object


@dataclass(frozen=True)
class _FixedValue:
    """A binding source the CIRCUIT fixes to one literal value; NEVER settable
    by the request, because the circuit never constrains this public input on
    this predicate branch (e.g. accreditation's ``set_root`` — main.nr:194-197
    leaves it unconstrained). ``_Param(..., default=value)`` would still let a
    request that supplies a *different* value make the verifier EXPECT that
    other value — binding nothing, since the circuit never checked it either.
    A ``_FixedValue`` instead REJECTS a request that asks for anything other
    than the literal: expecting the request's own emptiness would be honoring
    a requirement the predicate structurally cannot express.

    ``request_key`` names the request parameter this fixed slot corresponds to
    (for a precise rejection message) — it is inspected ONLY to reject a
    disagreeing request, never to change what value is actually bound."""

    value: int
    request_key: str


@dataclass(frozen=True)
class _FixedBool:
    """A boolean transcript slot fixed by a predicate's semantics."""

    value: bool
    request_key: str


@dataclass(frozen=True)
class _CanonicalSetRoot:
    """Derive-and-compare source for a jurisdiction or sanctions set root.

    The load-bearing comparison is ``derived_root == proof.public_inputs[root]``.
    The signed request also carries ``root_key`` so the holder receives the
    verifier's root through the APR; both holder and verifier independently
    derive it from ``codes_key`` and reject a disagreement.

    Request-parameter shape (documented normatively; sanctions uses the generic
    blocked-set key and jurisdiction uses its own so claim-type scoping stays
    explicit):
      * ``codes_key`` — ``request.parameters[proofType][codes_key]``: a JSON
        array of integer codes (pre-dedup/pre-sort; ``CanonicalCodeSet``
        canonicalizes). ``zkc_crypto.CANONICAL_SET_PARAM`` (``"canonicalSet"``)
        is for sanctions; ``zkc_crypto.JURISDICTION_CANONICAL_SET_PARAM``
        (``"jurisdictionCanonicalSet"``) is for jurisdiction.
      * ``root_key`` — the legacy bare-root parameter (``"setRoot"`` /
        ``"jurisdictionSetRoot"``).
      * ``claim_type_source`` — for jurisdiction only, the ``_Param`` naming
        the claim-type parameter folded into every leaf
        (``jurisdiction_leaf_encoder``); ``None`` for sanctions, which uses
        ``raw_code_leaf``.
      * ``mode`` / ``mode_source`` — EXACTLY ONE is set, and the set's mode is
        never defaulted (``zkc_crypto.canonical_set``: only an EXCLUSION set is
        sentinel-bracketed, and bracketing an inclusion set makes codes 0 and
        65535 provable members of it, since the circuits' inclusion branches are
        bare Merkle membership checks). ``mode`` is a literal for the proof
        types whose direction is fixed by the predicate itself
        (sanctions-clearance = exclusion); ``mode_source`` is the ``_Param`` naming the request
        parameter that selects it — jurisdiction's MANDATORY ``membershipType``,
        the only predicate offering both directions. Because the two modes build
        different trees, a jurisdiction exclusion set and an inclusion set over
        the same codes derive DIFFERENT roots; that is correct and the verifier
        must publish the root for the direction it is actually asking about.

    Behaviour:
      * ``root_key`` is always mandatory because it is the APR-distributed root.
      * exclusion also requires ``codes_key``; there is no warning-only bare-root
        bypass for the construction obligation.
      * jurisdiction inclusion may retain its pre-P5 bare-root shape because
        sorted-neighbour soundness is not involved; when codes are supplied,
        the root is still derived and compared.
      * a canonical set supplied under the WRONG key for this predicate
        (``canonicalSet`` on jurisdiction, ``jurisdictionCanonicalSet`` on a
        raw-code predicate) -> REQUIREMENTS_NOT_MET. Ignoring it would silently
        downgrade the request to the unverified bare-root path — the operator
        asked for derive-and-compare and would get none, with no signal.
      * a malformed canonical set (not a JSON array, non-int/bool entries, a
        sentinel or out-of-domain code) -> REQUIREMENTS_NOT_MET, never
        a crash (fail closed at every exit, per this chokepoint's contract)."""

    codes_key: str
    root_key: str
    claim_type_source: object = None
    mode: str = None
    mode_source: object = None


@dataclass(frozen=True)
class _PredicateBinding:
    """The generic contract: versioned claim slots plus direct comparisons."""

    # Feed compute_claim_binding_3(slot0, slot1, slot2, context.value,
    # context.timestamp) — the preimage the holder and the circuit both use.
    claim_slots: tuple
    # Published formula generation. Existing entries use compute_claim_binding_3;
    # remaining-predicate v3/v4 use compute_claim_binding_4.
    claim_binding_version: int = 3
    # Public inputs the claim binding does NOT cover, or that deserve a precise
    # error of their own. Recomputing the claim binding alone would miss these.
    public_comparisons: tuple = ()
    # Request parameter names this predicate structurally CANNOT bind (e.g. a
    # private circuit witness outside the claim-binding preimage). Never
    # rejected — a verifier is allowed to ask for them — but flagged with a
    # warning so accepting the proof is never mistaken for having enforced
    # them. See ``_verify_predicate_requirements``.
    unbindable: tuple = ()
    # Exact-boolean request keys whose positive value legacy circuits cannot
    # attest. False/absent is safe; true and non-booleans fail closed.
    legacy_fail_closed_bools: tuple = ()


@dataclass(frozen=True)
class _RequestBinding:
    handler: str
    predicate: object = None


# jurisdiction: claim_binding IS the whole binding surface — set root,
# membership direction, and required claim type are all in its preimage — but
# set root and direction are ALSO directly readable, so they get their own
# comparison for a precise error. ``requiredClaimType`` is mandatory even
# though the holder defaults it to the credential's OWN claimType: the verifier
# cannot know that value, so accepting a default would let the holder pick
# which claim type it proved membership for.
#
# The set root itself is a ``_CanonicalSetRoot`` (D4): when the request
# supplies ``jurisdictionCanonicalSet``, the expected root is DERIVED (scoped
# by this same ``requiredClaimType``, since jurisdiction leaves fold the claim
# type in) rather than trusted as a bare literal. The SAME instance is used
# for both the claim-binding slot and the direct comparison below so it is
# resolved exactly once per proof — see
# the per-call cache in ``_verify_predicate_requirements``.
#
# Jurisdiction is the ONE predicate with both directions, so its set mode comes
# from the request's ``membershipType`` (mandatory since P1 — the verifier
# therefore always knows which tree to build): EXCLUSION brackets, INCLUSION
# does not, and the two derive different roots.
_JURISDICTION_SET_ROOT = _CanonicalSetRoot(
    codes_key=JURISDICTION_CANONICAL_SET_PARAM,
    root_key="jurisdictionSetRoot",
    claim_type_source=_Param("requiredClaimType"),
    mode_source=_Param("membershipType"),
)
_JURISDICTION_BINDING = _PredicateBinding(
    claim_slots=(
        _JURISDICTION_SET_ROOT,
        _Param("membershipType"),
        _Param("requiredClaimType"),
    ),
    public_comparisons=(
        _PublicComparison("jurisdiction_set_root", "field", _JURISDICTION_SET_ROOT),
        _PublicComparison("membership_type", "int", _Param("membershipType")),
    ),
)


def _remaining_predicate_binding(
    *,
    required_0,
    required_1,
    set_root,
    flag_required=None,
    unbindable=(),
    legacy_fail_closed_bools=(),
) -> _RequestBinding:
    """Contract for one of the four zkc_remaining_predicates meanings.

    The claim binding covers ``(predicate_type, required_0, required_1)`` only —
    ``set_root`` is a standalone public input OUTSIDE that preimage, so a
    binding recomputation alone never checks it and the prover would be free to
    choose its own membership set. It is compared directly. ``set_root`` is one
    of three source kinds:

      * ``_CanonicalSetRoot`` — sanctions-clearance (and its v2 sibling): the
        expected exclusion root is derived from the signed canonical code set
        and compared to the proof public input. Jurisdiction uses the same
        source type in its dedicated binding above.
      * ``_FixedValue`` — a branch where the circuit never constrains this input
        at all (accreditation), so the only sound "requirement" is the literal
        the spec fixes, and a request asking for anything else is rejected.
      * ``_Param`` — a plain live, request-supplied requirement. Source-of-funds
        and tax-residency retain this direct binding because their private codes
        span the full Field and are outside P5's u16 blocked-set surface.

    Slots the circuit branch ignores are still HASHED into the claim binding, so
    a dead slot must still mirror the holder's default exactly."""
    claim_slots = (_PredicateType(), required_0, required_1)
    claim_binding_version = 3
    if flag_required is not None:
        claim_slots += (flag_required,)
        claim_binding_version = 4
    return _RequestBinding(
        handler=_HANDLER_PREDICATE,
        predicate=_PredicateBinding(
            claim_slots=claim_slots,
            claim_binding_version=claim_binding_version,
            public_comparisons=(
                _PublicComparison("predicate_type", "int", _PredicateType()),
                _PublicComparison("set_root", "field", set_root),
            ),
            unbindable=unbindable,
            legacy_fail_closed_bools=legacy_fail_closed_bools,
        ),
    )


# Sanctions clearance is the raw-u16 blocked-set predicate covered by P5. The
# source/tax inclusion predicates take full-Field private codes and have a
# separate code-0/padding collision, so they deliberately retain their direct
# request-root binding instead of being misrepresented as covered by this u16
# builder.
_SANCTIONS_CANONICAL_SET_ROOT = _CanonicalSetRoot(
    codes_key=CANONICAL_SET_PARAM, root_key="setRoot", mode=CANONICAL_SET_EXCLUSION
)


_REQUEST_BINDINGS = {
    # Specialised checks that already bound their family; the registry records
    # WHICH check owns them so the chokepoint stays the single accept path.
    KYC_PROOF_TYPE: _RequestBinding(handler=_HANDLER_KYC),
    KYC_V2_PROOF_TYPE: _RequestBinding(handler=_HANDLER_KYC),
    COMMUNITY_KYC_V2_PROOF_TYPE: _RequestBinding(handler=_HANDLER_KYC),
    KYC_V3_PROOF_TYPE: _RequestBinding(handler=_HANDLER_KYC),
    SELECTIVE_DISCLOSURE_PROOF_TYPE: _RequestBinding(handler=_HANDLER_SELECTIVE_DISCLOSURE),
    SELECTIVE_DISCLOSURE_V2_PROOF_TYPE: _RequestBinding(
        handler=_HANDLER_SELECTIVE_DISCLOSURE
    ),
    SELECTIVE_DISCLOSURE_V3_PROOF_TYPE: _RequestBinding(handler=_HANDLER_SELECTIVE_DISCLOSURE),
    REBIND_PROOF_TYPE: _RequestBinding(handler=_HANDLER_REBIND),
    REBIND_V2_PROOF_TYPE: _RequestBinding(handler=_HANDLER_REBIND),
    REBIND_BINDING_V2_PROOF_TYPE: _RequestBinding(handler=_HANDLER_REBIND),
    REBIND_V2_BINDING_V2_PROOF_TYPE: _RequestBinding(handler=_HANDLER_REBIND),
    # Authenticated successors: their own handler, so they can never inherit
    # the deprecated statements' filter-only semantics.
    REBIND_AUTH_PROOF_TYPE: _RequestBinding(handler=_HANDLER_REBIND_AUTH),
    REBIND_AUTH_V2_PROOF_TYPE: _RequestBinding(handler=_HANDLER_REBIND_AUTH),
    REBIND_AUTH_V3_PROOF_TYPE: _RequestBinding(handler=_HANDLER_REBIND_AUTH),
    # v2 reuses the v1 parameter keys and the v1 claim-binding formula; only the
    # holder handle differs (presentation pseudonym instead of commitment), and
    # that is not part of any predicate claim binding.
    JURISDICTION_PROOF_TYPE: _RequestBinding(
        handler=_HANDLER_PREDICATE, predicate=_JURISDICTION_BINDING
    ),
    JURISDICTION_V2_PROOF_TYPE: _RequestBinding(
        handler=_HANDLER_PREDICATE, predicate=_JURISDICTION_BINDING
    ),
    # accreditation: required_0 is the minimum level the circuit compares
    # against (claim_0 >= required_0), so the verifier must state it. required_1
    # is circuit-dead here and hashed only. set_root is UNCONSTRAINED by the
    # circuit on this branch (main.nr:194-197) — normatively MUST be 0 for
    # accreditation (docs/zkc_public_input_classification.md:65-67,
    # schemas/public-input-bindings/zkc_remaining_predicates.json) — so it is a
    # ``_FixedValue``, not a request-settable ``_Param``: a request supplying a
    # non-zero setRoot is rejected outright rather than echoed back as an
    # "expectation" the predicate cannot actually enforce (see ``_FixedValue``).
    # ``flagRequired`` is a private circuit witness outside the legacy
    # claim-binding preimage. Positive/malformed legacy requests fail closed;
    # the v3/v4 entries below bind the exact boolean as their fourth slot.
    #
    # Canonical-set keys are rejected centrally for every unsupported proof
    # type before handler dispatch, so accreditation cannot silently ignore one.
    ACCREDITATION_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", upper_bound=1 << 8),
        required_1=_Param("required1", 0),
        set_root=_FixedValue(0, "setRoot"),
        legacy_fail_closed_bools=("flagRequired",),
    ),
    ACCREDITATION_V2_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", upper_bound=1 << 8),
        required_1=_Param("required1", 0),
        set_root=_FixedValue(0, "setRoot"),
        legacy_fail_closed_bools=("flagRequired",),
    ),
    ACCREDITATION_V3_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", upper_bound=1 << 8),
        required_1=_Param("required1", 0),
        flag_required=_BoolParam("flagRequired", False),
        set_root=_FixedValue(0, "setRoot"),
    ),
    ACCREDITATION_V4_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", upper_bound=1 << 8),
        required_1=_Param("required1", 0),
        flag_required=_BoolParam("flagRequired", False),
        set_root=_FixedValue(0, "setRoot"),
    ),
    ACCREDITATION_V5_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", upper_bound=1 << 8),
        required_1=_Param("required1", 0),
        flag_required=_BoolParam("flagRequired", False),
        set_root=_FixedValue(0, "setRoot"),
    ),
    ACCREDITATION_V6_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", upper_bound=1 << 8),
        required_1=_Param("required1", 0),
        flag_required=_BoolParam("flagRequired", False),
        set_root=_FixedValue(0, "setRoot"),
    ),
    # source of funds: the accepted-source set root is the entire requirement,
    # so it is mandatory; both required slots are circuit-dead but hashed.
    # P5's u16 blocked-set construction does not apply here: claim_0 is a full
    # Field and raw code 0 aliases padding. Keep P1's direct request-root bind.
    SOURCE_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        set_root=_Param("setRoot"),
    ),
    SOURCE_V2_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        set_root=_Param("setRoot"),
    ),
    SOURCE_V3_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_Param("setRoot"),
    ),
    SOURCE_V4_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_Param("setRoot"),
    ),
    SOURCE_V5_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_Param("setRoot"),
    ),
    SOURCE_V6_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_Param("setRoot"),
    ),
    # tax residency: accepted-jurisdiction set root AND the minimum tax year
    # (claim_1 >= required_1) are both live requirements.
    TAX_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", upper_bound=1 << 64),
        set_root=_Param("setRoot"),
    ),
    TAX_V2_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", upper_bound=1 << 64),
        set_root=_Param("setRoot"),
    ),
    TAX_V3_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", upper_bound=1 << 64),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_Param("setRoot"),
    ),
    TAX_V4_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", upper_bound=1 << 64),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_Param("setRoot"),
    ),
    TAX_V5_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", upper_bound=1 << 64),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_Param("setRoot"),
    ),
    TAX_V6_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", upper_bound=1 << 64),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_Param("setRoot"),
    ),
    # sanctions clearance: the blocked-list root is the entire requirement.
    SANCTIONS_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        set_root=_SANCTIONS_CANONICAL_SET_ROOT,
    ),
    SANCTIONS_V2_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        set_root=_SANCTIONS_CANONICAL_SET_ROOT,
    ),
    SANCTIONS_V3_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_SANCTIONS_CANONICAL_SET_ROOT,
    ),
    SANCTIONS_V4_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_SANCTIONS_CANONICAL_SET_ROOT,
    ),
    SANCTIONS_V5_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_SANCTIONS_CANONICAL_SET_ROOT,
    ),
    SANCTIONS_V6_PROOF_TYPE: _remaining_predicate_binding(
        required_0=_Param("required0", 0),
        required_1=_Param("required1", 0),
        flag_required=_FixedBool(False, "flagRequired"),
        set_root=_SANCTIONS_CANONICAL_SET_ROOT,
    ),
}

# Successors retain the corresponding published public-input ABI and request
# transcript.  The version boundary is enforced by the circuit/VK and issuer
# digest, not by changing request vocabulary.
_REQUEST_BINDINGS[JURISDICTION_V3_PROOF_TYPE] = _REQUEST_BINDINGS[JURISDICTION_PROOF_TYPE]
_REQUEST_BINDINGS[JURISDICTION_V4_PROOF_TYPE] = _REQUEST_BINDINGS[JURISDICTION_V2_PROOF_TYPE]
_REQUEST_BINDINGS[JURISDICTION_V5_PROOF_TYPE] = _REQUEST_BINDINGS[JURISDICTION_V4_PROOF_TYPE]
for _v7, _v5 in (
    (ACCREDITATION_V7_PROOF_TYPE, ACCREDITATION_V5_PROOF_TYPE),
    (ACCREDITATION_V8_PROOF_TYPE, ACCREDITATION_V6_PROOF_TYPE),
    (SOURCE_V7_PROOF_TYPE, SOURCE_V5_PROOF_TYPE),
    (SOURCE_V8_PROOF_TYPE, SOURCE_V6_PROOF_TYPE),
    (TAX_V7_PROOF_TYPE, TAX_V5_PROOF_TYPE),
    (TAX_V8_PROOF_TYPE, TAX_V6_PROOF_TYPE),
    (SANCTIONS_V7_PROOF_TYPE, SANCTIONS_V5_PROOF_TYPE),
    (SANCTIONS_V8_PROOF_TYPE, SANCTIONS_V6_PROOF_TYPE),
):
    _REQUEST_BINDINGS[_v7] = _REQUEST_BINDINGS[_v5]

for _v9, _v8 in (
    (ACCREDITATION_V9_PROOF_TYPE, ACCREDITATION_V8_PROOF_TYPE),
    (SOURCE_V9_PROOF_TYPE, SOURCE_V8_PROOF_TYPE),
    (TAX_V9_PROOF_TYPE, TAX_V8_PROOF_TYPE),
    (SANCTIONS_V9_PROOF_TYPE, SANCTIONS_V8_PROOF_TYPE),
):
    _REQUEST_BINDINGS[_v9] = _REQUEST_BINDINGS[_v8]

for _v10, _v9 in (
    (ACCREDITATION_V10_PROOF_TYPE, ACCREDITATION_V9_PROOF_TYPE),
    (SOURCE_V10_PROOF_TYPE, SOURCE_V9_PROOF_TYPE),
    (TAX_V10_PROOF_TYPE, TAX_V9_PROOF_TYPE),
    (SANCTIONS_V10_PROOF_TYPE, SANCTIONS_V9_PROOF_TYPE),
):
    _REQUEST_BINDINGS[_v10] = _REQUEST_BINDINGS[_v9]

_REQUEST_BINDINGS.update(
    (proof_type, _RequestBinding(handler=_HANDLER_CODE_SPACE)) for proof_type in CODE_SPACE_PROOF_TO_KIND
)
_REQUEST_BINDINGS.update({
    successor: _REQUEST_BINDINGS[predecessor]
    for successor, predecessor in NONZERO_CREDENTIAL_PROOF_PREDECESSORS.items()
})

# Canonical-set parameter names are reserved protocol keys. Supplying one on a
# proof type that does not support it, or supplying the other predicate's key,
# is a hard request error rather than an ignored hint that creates false
# assurance. Both envelope generations use the same semantic mapping.
_CANONICAL_SET_KEY_BY_PROOF_TYPE = {
    JURISDICTION_PROOF_TYPE: JURISDICTION_CANONICAL_SET_PARAM,
    JURISDICTION_V2_PROOF_TYPE: JURISDICTION_CANONICAL_SET_PARAM,
    JURISDICTION_V3_PROOF_TYPE: JURISDICTION_CANONICAL_SET_PARAM,
    JURISDICTION_V4_PROOF_TYPE: JURISDICTION_CANONICAL_SET_PARAM,
    JURISDICTION_V5_PROOF_TYPE: JURISDICTION_CANONICAL_SET_PARAM,
    SANCTIONS_PROOF_TYPE: CANONICAL_SET_PARAM,
    SANCTIONS_V2_PROOF_TYPE: CANONICAL_SET_PARAM,
    SANCTIONS_V3_PROOF_TYPE: CANONICAL_SET_PARAM,
    SANCTIONS_V4_PROOF_TYPE: CANONICAL_SET_PARAM,
    SANCTIONS_V5_PROOF_TYPE: CANONICAL_SET_PARAM,
    SANCTIONS_V6_PROOF_TYPE: CANONICAL_SET_PARAM,
    SANCTIONS_V7_PROOF_TYPE: CANONICAL_SET_PARAM,
    SANCTIONS_V8_PROOF_TYPE: CANONICAL_SET_PARAM,
    SANCTIONS_V9_PROOF_TYPE: CANONICAL_SET_PARAM,
    SANCTIONS_V10_PROOF_TYPE: CANONICAL_SET_PARAM,
    **{
        proof_type: JURISDICTION_CANONICAL_SET_PARAM if kind == "jurisdiction" else CANONICAL_SET_PARAM
        for proof_type, kind in CODE_SPACE_PROOF_TO_KIND.items()
    },
}

# Immutable accreditation v1/v2 cannot bind ``flagRequired`` and therefore use
# ``legacy_fail_closed_bools``. Successor v3/v4 include an exact boolean fourth
# slot; non-accreditation successors fix it false because it has no semantics
# on those branches.


class _BindingUnavailable(Exception):
    """Internal: a request-binding source could not be resolved.

    Carries the structured code the chokepoint reports; never escapes the
    verifier."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class VerificationRequest:
    """What the verifier required of the holder (mirrors the proof request)."""

    proof_types: list
    parameters: dict
    context: ProofContext
    max_proof_age: int = 3600
    # issuer_id -> IssuerAccumulatorState (the verifier's accumulator view).
    accumulator_states: dict = field(default_factory=dict)
    # Exact v2 selectors keyed by proof type. Both verify() and
    # verify_authenticated() require each pinned proof to carry exactly this
    # selector; verify_authenticated also requires byte-exact agreement with
    # the signed request extension.
    binding_selectors: dict = field(default_factory=dict)


def _snapshot_request(request: VerificationRequest) -> VerificationRequest:
    # Use the same request values for APR comparison and the later public-input
    # checks. Accumulator-state objects retain their authenticated provenance.
    return replace(
        request,
        proof_types=copy.deepcopy(request.proof_types),
        parameters=copy.deepcopy(request.parameters),
        binding_selectors=copy.deepcopy(request.binding_selectors),
    )


def _canonical_json(value) -> str:
    """Canonical JSON, byte-identical to what the APR digest commits to."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _is_json_array(value) -> bool:
    """Return whether ``value`` is the reference JSON-array representation.

    APR parameters originate as JSON, whose arrays decode to ``list``.  Tuple
    aliases are rejected even though Python's serializer would encode them as
    arrays, preserving the normative non-array refusal at every preflight."""
    return isinstance(value, list)


def _apr_presentation_proof_types(signed_request) -> dict:
    """v1 proof type -> the spelling(s) the APR's own presentation legitimately
    resolves to, mirroring :func:`zkc_holder.client.Holder._resolve_presentation`
    (client.py ~865-905) rather than guessing a fixed default.

    The holder computes ``effective = min(apr_profile, holder_profile)`` by
    ``_PRESENTATION_RANK`` (ANONYMOUS:0 < SCOPED:1 < LINKABLE:2, client.py
    104-108) and answers with the ``:v1`` family spelling only when
    ``effective`` is LINKABLE; ANONYMOUS or SCOPED both answer with the sibling
    ``:v2`` spelling (same ``_FAMILY_V2_PROOF_TYPE`` table entry — see
    ``resolve_presentation_proof_type``). ``apr_profile`` is:
      * the request's ``presentation.profile``, defaulting to ANONYMOUS when
        the block is present but silent on profile (client.py:878) — NOT
        LINKABLE;
      * when there is no presentation block at all, the holder's OWN ceiling
        (``holder_profile`` itself, client.py 884-887) — a value this verifier
        cannot observe.

    Whenever ``apr_profile`` is ANONYMOUS or SCOPED, ``min(apr_profile,
    holder_profile)`` can only land on ANONYMOUS or SCOPED (both rank below or
    at LINKABLE), which share one spelling — so the v2 sibling is the sole,
    DETERMINISTIC answer. Whenever ``apr_profile`` is LINKABLE (declared
    explicitly, or because the request never named a presentation and the
    holder's own default/override ceiling governs unseen), ``holder_profile``
    could still pull ``effective`` down to ANONYMOUS/SCOPED without this
    verifier ever finding out — so BOTH the v1 and the v2 spelling of the SAME
    family are accepted for that proof type. This does not loosen which
    PREDICATE was authorised (the family is still fixed by the signed
    request): it only accepts either legitimate presentation-profile spelling
    of it, exactly as far as the verifier can actually mirror the holder's
    real resolution.

    A proof type with no ``:v1`` family/profile surface is left untranslated
    (single-element tuple of itself) and must then match verbatim, as before."""
    if "presentation" in signed_request:
        presentation = signed_request["presentation"]
        if not isinstance(presentation, dict):
            raise ValueError("authenticated presentation must be an object")
        apr_profile = presentation.get("profile", ANONYMOUS_PROFILE)
        if apr_profile not in (
            ANONYMOUS_PROFILE,
            SCOPED_PROFILE,
            LINKABLE_PROFILE,
        ):
            raise ValueError(
                f"authenticated presentation has unknown profile: {apr_profile!r}"
            )
        explicit_profile = apr_profile if "profile" in presentation else None
    else:
        apr_profile = LINKABLE_PROFILE
        explicit_profile = None
    def resolve(proof_type, profile):
        try:
            return resolve_presentation_proof_type_for_request(proof_type, profile)
        except Exception:  # no surface for this profile
            return None

    renamed = {}
    for proof_type in signed_request.get("proofTypes", []):
        # Resolve per profile the holder can actually land on. The scoped
        # spelling is resolved on its own because rebind has no anonymous
        # statement: a scoped APR naming credential_rebind:v3 is answered with
        # rebind:v4, which must therefore be accepted rather than demanding the
        # linkable spelling verbatim (spec 7.4.7). Every family with both an
        # anonymous and a linkable surface resolves exactly as before, since
        # its scoped spelling equals its anonymous one.
        presentation_type = resolve(proof_type, ANONYMOUS_PROFILE)
        scoped_type = resolve(proof_type, SCOPED_PROFILE)
        linkable_type = resolve(proof_type, LINKABLE_PROFILE)
        if linkable_type is None:
            continue  # no family/profile surface: compare verbatim
        if presentation_type is None:
            # No anonymous statement (rebind): an anonymous APR keeps the
            # verbatim comparison, since no rebind is accepted anonymously.
            if scoped_type is None or apr_profile == ANONYMOUS_PROFILE:
                continue
            presentation_type = scoped_type
        legacy_type = legacy_presentation_proof_type_for_verification(
            proof_type, explicit_profile
        )
        if apr_profile in (ANONYMOUS_PROFILE, SCOPED_PROFILE):
            renamed[proof_type] = tuple(
                dict.fromkeys(item for item in (presentation_type, legacy_type) if item)
            )
        else:
            renamed[proof_type] = tuple(
                dict.fromkeys(
                    item for item in (linkable_type, presentation_type, legacy_type) if item
                )
            )
    return renamed


def _parse_rfc3339(value: str) -> int:
    timestamp = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int(timestamp.timestamp())


class ZKCVerifier:
    def __init__(
        self,
        repo_root,
        trust_policy: VerifierTrustPolicy,
        backend: VerifyBackend,
        vk_store: VerificationKeyStore = None,
    ):
        self._root = pathlib.Path(repo_root)
        self._trust_policy = trust_policy
        self._backend = backend
        self._seen_apr_nonces = set()
        self._vk_store = vk_store if vk_store is not None else VerificationKeyStore.from_repo(repo_root)
        self._circuit_by_proof_type = self._load_circuit_map()
        self._public_input_shape_by_circuit = self._load_public_input_shapes()
        self._predicate_type_by_proof_type = self._load_predicate_type_map()
        (
            self._conditional_pins_by_proof_type,
            self._conditional_pin_contract_errors,
        ) = self._load_conditional_pin_contracts()
        # Closed request-parameter key sets (spec 6.2.1): sidecar ``param:``
        # references plus the documented request-only keys. One immutable
        # snapshot per verifier, like the conditional-pin contracts above.
        (
            self._request_parameter_keys,
            self._request_parameter_contract_errors,
        ) = request_parameter_contracts(self._root, self._circuit_by_proof_type)
        # Predicate registry view, used only when the verifier's own policy
        # requires a review status (verifier-local; no global default).
        self._predicate_registry = PredicateRegistry.from_repo(repo_root)

    def _load_circuit_map(self) -> dict:
        mapping, self._encoder_resolution_errors = encoder_circuits(self._root)
        return mapping

    def _load_public_input_shapes(self) -> dict:
        """circuit -> (encoder-declared input names, envelope family).

        Read from the same encoder documents the production backend encodes
        with, so the names admitted here are exactly the names ``bb verify``
        binds. Keyed by circuit rather than proof type because a
        selector-bound entry resolves its circuit through the registry."""
        shapes = {}
        encoder_dir = self._root / "schemas" / "public-inputs"
        for path in sorted(encoder_dir.glob("*.json")):
            encoder = json.loads(path.read_text())
            names = frozenset(entry["name"] for entry in encoder["publicInputs"])
            shapes[encoder["circuit"]] = (names, _circuit_family(names))
        return shapes

    def _load_predicate_type_map(self) -> dict:
        """proofType -> ``predicate_type`` selector, read once at construction.

        The authority is the P4 binding sidecar, whose values CI cross-checks
        against the circuit's own ``PREDICATE_*`` Noir constants — so this map
        cannot drift from the circuit that enforces the selector. A circuit with
        no sidecar (or a sidecar publishing no map) simply contributes nothing:
        the chokepoint then fails closed with UNBOUND_PROOF_TYPE rather than
        falling back to a default."""
        mapping = {}
        for circuit in sorted(set(self._circuit_by_proof_type.values())):
            try:
                bindings = PublicInputBindings.for_circuit(self._root, circuit)
            except (OSError, ValueError, KeyError, TypeError):
                continue
            for proof_type in bindings.predicate_types:
                # Only honor a sidecar's claim over a proof type the encoders
                # actually route to that same circuit.
                if self._circuit_by_proof_type.get(proof_type) == circuit:
                    mapping[proof_type] = bindings.predicate_type_for(proof_type)
        return mapping

    def _load_conditional_pin_contracts(self) -> tuple[dict, dict]:
        """Snapshot every proof type's sidecar-declared optional request pins.

        Loading once at construction gives a verification session one immutable
        contract snapshot.  A missing or malformed sidecar is retained as an
        explicit error state rather than represented by an empty tuple: an
        empty tuple means the sidecar was successfully loaded and declares no
        conditional pins.
        """
        pins_by_proof_type = {}
        errors_by_proof_type = {}
        for proof_type in _SUCCESSOR_REBIND_PROOF_TYPES | _REBIND_AUTH_PROOF_TYPES:
            circuit = self._circuit_by_proof_type.get(proof_type)
            try:
                if circuit is None:
                    raise ValueError(f"proof type {proof_type} has no public-input circuit")
                bindings = PublicInputBindings.for_circuit(self._root, circuit)
                pins_by_proof_type[proof_type] = bindings.conditional_pins()
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                errors_by_proof_type[proof_type] = str(exc)
        return pins_by_proof_type, errors_by_proof_type

    def predicate_review_statuses(self, proof_type: str) -> tuple:
        """Registry review statuses of the entries serving a proof type.

        Exposed so verifier policy decisions can inspect registry status; the
        registry itself never decides trust (Safeguard 1)."""
        return self._predicate_registry.statuses(proof_type)

    # ------------------------------------------------------------------

    def verify(self, envelope, request: VerificationRequest) -> VerificationResult:
        """Verify a compliance-proof envelope, version-dispatched.

        A ``zkc:proof:v1`` envelope (``holderBinding``, implicitly the linkable
        profile) takes the v1 path; it is refused only by a policy that sets
        ``accepted_profiles`` explicitly without the linkable profile. A
        ``zkc:proof:v2`` envelope (``presentationBinding``) runs the profile
        gate + shape-consistency checks. Every evaluated proof entry must be
        of the circuit family its envelope generation carries and must carry
        exactly its encoder-declared public inputs. An envelope that is neither
        v1 nor v2 is rejected fail-closed.

        This entry point has no authenticated request, so it cannot know which
        scope the holder should have derived: it NEVER recomputes ``scope_id``
        and accepts a scoped envelope under whatever scope the holder chose
        (shape-consistent with its proofs). The result reports
        ``scope_recomputed=False``; a scoped pseudonym from here is no
        continuity handle. Under ``require_presentation_continuity`` a scoped
        answer is therefore SCOPE_MISMATCH here; use ``verify_authenticated``.
        """
        try:
            envelope = copy.deepcopy(envelope)
            request = _snapshot_request(request)
        except (AttributeError, TypeError, ValueError, RecursionError):
            result = VerificationResult()
            result.add(Code.MALFORMED_PROOF, "verification inputs could not be snapshotted")
            return result
        requested_code_space = isinstance(request.proof_types, (list, tuple)) and any(
            isinstance(proof_type, str) and proof_type in CODE_SPACE_PROOF_TO_KIND
            for proof_type in request.proof_types
        )
        if requested_code_space or self._raw_proof_types(envelope, CODE_SPACE_PROOF_TO_KIND):
            result = VerificationResult()
            result.add(Code.UNSIGNED_REQUEST, "code-space proofs require an authenticated APR")
            return result
        historical = self._raw_proof_types(envelope, _AUTHENTICATED_HISTORICAL_PROOF_TYPES)
        if historical:
            result = VerificationResult()
            for proof_type in historical:
                result.add(
                    Code.UNSIGNED_REQUEST,
                    f"deprecated proof type {proof_type} requires literal signed APR authorization",
                    proof_type=proof_type,
                )
            return result
        result = self._verify_dispatch(envelope, request)
        self._enforce_presentation_continuity(result)
        return result

    @staticmethod
    def _unrequested_parameter_blocks(request) -> tuple:
        """Sorted ``repr``s of parameter keys absent from ``request.proof_types``.

        A non-mapping parameter table is left to the per-proof chokepoint,
        which already rejects it with REQUIREMENTS_NOT_MET."""
        parameters = getattr(request, "parameters", None)
        if not isinstance(parameters, Mapping):
            return ()
        requested = getattr(request, "proof_types", None)
        requested = (
            {item for item in requested if isinstance(item, str)}
            if isinstance(requested, (list, tuple))
            else set()
        )
        return tuple(sorted(repr(key) for key in parameters if key not in requested))

    @staticmethod
    def _raw_proof_types(envelope, candidates) -> tuple:
        """Find APR-only identities without taking structural validation away."""
        if not isinstance(envelope, dict) or not isinstance(envelope.get("proofs"), list):
            return ()
        found = []
        for entry in envelope["proofs"]:
            if not isinstance(entry, dict):
                return ()
            proof_type = entry.get("proofType")
            if isinstance(proof_type, str) and proof_type in candidates and proof_type not in found:
                found.append(proof_type)
        return tuple(found)

    @staticmethod
    def _unauthenticated_rebind_proof_types(envelope, request) -> tuple:
        """Every contained credential-rebind identity the exchange names.

        Scans the envelope's proof entries AND the verifier request so that a
        contained identity is refused whether the holder presented it or the
        verifier asked for it. Structural validation is deliberately not
        pre-empted: a malformed envelope naming no contained identity still
        reaches the ordinary MALFORMED_PROOF path."""
        found = []
        proof_types = list(getattr(request, "proof_types", None) or [])
        if isinstance(envelope, dict) and isinstance(envelope.get("proofs"), list):
            for entry in envelope["proofs"]:
                if isinstance(entry, dict):
                    proof_types.append(entry.get("proofType"))
        for proof_type in proof_types:
            if proof_type in _UNAUTHENTICATED_REBIND_PROOF_TYPES and proof_type not in found:
                found.append(proof_type)
        return tuple(found)

    def _verify_dispatch(self, envelope, request: VerificationRequest) -> VerificationResult:
        """Version dispatch after the caller-specific authorization gate."""
        # Security containment: shared by verify() and verify_authenticated().
        # An APR authenticates the REQUESTER; it never authenticates a
        # credential, so the authenticated path gets no escape from this gate.
        contained = self._unauthenticated_rebind_proof_types(envelope, request)
        if contained:
            result = VerificationResult()
            for proof_type in contained:
                logger.warning(
                    "rejected unauthenticated credential-rebind proof type %s: "
                    "the statement proves key continuity only, not an issuer-created "
                    "non-revoked credential",
                    proof_type,
                )
                result.add(
                    Code.UNAUTHENTICATED_CREDENTIAL,
                    _UNAUTHENTICATED_REBIND_MESSAGE.format(proof_type=proof_type),
                    proof_type=proof_type,
                )
            return result
        # The caller's exact selector pins constrain both public entrypoints.
        # Keep the containment gate above this check so an unsafe historical
        # statement cannot be made admissible by changing its selector.
        pins = request.binding_selectors
        if not isinstance(pins, dict):
            result = VerificationResult()
            result.add(Code.MALFORMED_BINDING_SELECTOR, "binding selectors must be a mapping")
            return result
        result = VerificationResult()
        proofs = envelope.get("proofs") if isinstance(envelope, dict) else None
        # The versioned envelope validators report shape errors below.
        for proof_entry in proofs if isinstance(proofs, list) else []:
            if not isinstance(proof_entry, dict):
                continue
            proof_type = proof_entry.get("proofType")
            if not isinstance(proof_type, str) or proof_type not in pins:
                continue
            try:
                selector_key(pins[proof_type])
            except ValueError as exc:
                result.add(Code.MALFORMED_BINDING_SELECTOR, str(exc), proof_type=proof_type)
                continue
            if proof_entry.get("bindingSelector") != pins[proof_type]:
                result.add(
                    Code.MALFORMED_BINDING_SELECTOR,
                    "proof is missing or rewrites the exact requested binding selector",
                    proof_type=proof_type,
                )
        if result.errors:
            return result
        version = envelope.get("version") if isinstance(envelope, dict) else None
        if version == "zkc:proof:v2":
            result = self._verify_v2(envelope, request)
        else:
            # Everything else routes to the frozen v1 path: a genuine v1
            # envelope verifies as before, and any unsupported/malformed
            # version is caught by the v1 structural validator's
            # MALFORMED_PROOF (byte-identical to the pre-dispatch behavior).
            result = self._verify_v1(envelope, request)
        # Closed parameter table (spec 6.2.1, mirroring the APR signing rule
        # in zkc_crypto.apr): a parameter block for a proof type the request
        # does not list is never read by any per-proof check, so a
        # requirement stated there (a misspelled proof-type key, a predicate
        # the operator forgot to list) would be dropped silently. It always
        # fails the request; the per-proof diagnostics are kept beside it.
        # Both sides use the request's own spelling: verify_authenticated has
        # already required this request to agree with its re-keyed APR.
        unrequested = self._unrequested_parameter_blocks(request)
        if unrequested:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                "verifier request supplies parameters for proof type(s) it does not "
                f"request: {', '.join(unrequested)}",
            )
        return result

    def _verify_v1(self, envelope, request: VerificationRequest) -> VerificationResult:
        """v1 verification (linkable profile).

        Honest v1 envelopes verify exactly as before. Two later hardenings
        apply: a policy that explicitly omits the linkable profile refuses the
        envelope, and each proof entry must be a linkable-family circuit with
        exactly its declared public inputs (see the envelope-generation
        binding above)."""
        result = VerificationResult()

        # 0. Parse / structural validation. A malformed envelope is rejected
        #    immediately: no other field can be trusted.
        try:
            validate_compliance_proof_v1(envelope)
        except EnvelopeError as exc:
            result.add(Code.MALFORMED_PROOF, str(exc))
            return result

        try:
            context = ProofContext.from_metadata(envelope["metadata"]["context"])
            generated_at = _parse_rfc3339(envelope["metadata"]["generatedAt"])
            expires_at = _parse_rfc3339(envelope["metadata"]["expiresAt"])
            holder_commitment = hex_to_field(envelope["holderBinding"]["commitment"])
        except (ValueError, KeyError) as exc:
            result.add(Code.MALFORMED_PROOF, f"unparseable envelope metadata: {exc}")
            return result

        # Effective presentation: a v1 envelope is the linkable profile. Its
        # handle (the global holder commitment) is reported after step 4, and
        # only when a requested proof was checked against it.
        result.presentation_profile = LINKABLE_PROFILE

        # 1. Freshness.
        now = request.context.timestamp
        if generated_at < now - request.max_proof_age:
            result.add(Code.STALE_PROOF, "proof generatedAt exceeds maxProofAge")
        if expires_at < now:
            result.add(Code.EXPIRED_PROOF, "proof has expired")

        # 2. Context binding.
        if context.value != request.context.value or context.profile != request.context.profile:
            result.add(Code.CONTEXT_MISMATCH, "proof bound to a different context")
        elif not context.reconstructs():
            result.add(
                Code.CONTEXT_MISMATCH,
                "context structured fields do not reconstruct the context value",
            )
        if (
            self._trust_policy.required_context_profile
            and context.profile != self._trust_policy.required_context_profile
        ):
            result.add(Code.CONTEXT_MISMATCH, "context profile not accepted by trust policy")

        # 2a. Linkable-profile gate. A policy that sets accepted_profiles
        #     explicitly accepts a v1 envelope only when it lists the linkable
        #     profile; an unset policy keeps accepting v1 for compatibility.
        if not self._trust_policy.accepts_linkable_envelopes:
            result.add(
                Code.PROFILE_NOT_ACCEPTED,
                f"linkable zkc:proof:v1 envelopes are not accepted: the verifier's "
                f"accepted profiles are {sorted(self._trust_policy.accepted_profiles)}",
            )

        # 3. Holder binding.
        if holder_commitment == 0:
            result.add(Code.INVALID_BINDING, "holder commitment must be non-zero")

        # 4. Individual proofs.
        handle_bound = False
        for proof_entry in envelope["proofs"]:
            proof_type = proof_entry["proofType"]
            if proof_type not in request.proof_types:
                # Extra proof: ignored for validity per spec §6.2 step 4a,
                # but flagged — a verifier must not silently accept more
                # disclosure than it asked for.
                result.add_warning(
                    WarningCode.OVER_DISCLOSURE,
                    f"envelope discloses {proof_type}, which this request did not ask for",
                    proof_type=proof_type,
                )
                continue
            # Every evaluated entry compares its own holder handle with the
            # envelope binding (an inconsistency is an error), so one
            # evaluated entry on a valid result proves the handle.
            handle_bound = True
            self._verify_individual(proof_entry, request, holder_commitment, result)
        if handle_bound:
            result.presentation_handle = field_to_hex(holder_commitment)

        # 5. All required proof types present.
        present = {entry["proofType"] for entry in envelope["proofs"]}
        for required in request.proof_types:
            if required not in present:
                result.add(
                    Code.MISSING_PROOF,
                    f"required proof type missing: {required}",
                    proof_type=required,
                )

        # 6. Aggregation (when present).
        if "aggregation" in envelope:
            self._verify_aggregation(envelope, request, holder_commitment, result)

        logger.info(
            "verified envelope valid=%s codes=%s backend=%s production_backend=%s",
            result.valid,
            ",".join(result.codes()) or "-",
            self._backend.name,
            self._backend.is_production,
        )
        return result

    def _verify_v2(self, envelope, request: VerificationRequest) -> VerificationResult:
        """v2 (presentation-profile) verification: the profile gate + per-proof
        shape-consistency anti-replay check (design §6 rules 1-2), over the same
        freshness/context/individual-proof machinery as v1. Rule 4 governs
        scoped rebind and rejects aggregation blocks. The shape-consistency
        check replaces the v1 comparison against holder_commitment.

        Scope recomputation (rule 3) is NOT done here: this path is shared by
        ``verify()``, which has no authenticated verifier identity, and so
        accepts any non-zero, shape-consistent ``scopeId`` the holder chose.
        Only ``verify_authenticated`` recomputes scope (``_recompute_scope``)
        and reports ``scope_recomputed=True``.
        """
        result = VerificationResult()

        # 0. Parse / structural validation (v2 schema: presentationBinding, no
        #    holderBinding). Fail closed on a malformed envelope.
        try:
            validate_compliance_proof_v2(envelope)
        except EnvelopeError as exc:
            result.add(Code.MALFORMED_PROOF, str(exc))
            return result

        try:
            context = ProofContext.from_metadata(envelope["metadata"]["context"])
            generated_at = _parse_rfc3339(envelope["metadata"]["generatedAt"])
            expires_at = _parse_rfc3339(envelope["metadata"]["expiresAt"])
            binding = envelope["presentationBinding"]
            presentation_profile = binding["profile"]
            if presentation_profile == SCOPED_PROFILE:
                binding_pseudonym = hex_to_field(binding["pseudonym"])
                binding_scope_id = hex_to_field(binding["scopeId"])
            else:
                binding_pseudonym = 0
                binding_scope_id = 0
        except (ValueError, KeyError) as exc:
            result.add(Code.MALFORMED_PROOF, f"unparseable envelope metadata: {exc}")
            return result

        # Effective presentation, as the holder answered (it may be a
        # downgrade from what the verifier asked for, spec 5.9.2 rule 4).
        # A scoped handle is reported after step 4, and only when a
        # requested proof was shape-checked against it.
        result.presentation_profile = presentation_profile

        # 1. Freshness (identical to v1).
        now = request.context.timestamp
        if generated_at < now - request.max_proof_age:
            result.add(Code.STALE_PROOF, "proof generatedAt exceeds maxProofAge")
        if expires_at < now:
            result.add(Code.EXPIRED_PROOF, "proof has expired")

        # 2. Context binding (identical to v1).
        if context.value != request.context.value or context.profile != request.context.profile:
            result.add(Code.CONTEXT_MISMATCH, "proof bound to a different context")
        elif not context.reconstructs():
            result.add(
                Code.CONTEXT_MISMATCH,
                "context structured fields do not reconstruct the context value",
            )
        if (
            self._trust_policy.required_context_profile
            and context.profile != self._trust_policy.required_context_profile
        ):
            result.add(Code.CONTEXT_MISMATCH, "context profile not accepted by trust policy")

        # 3. Profile gate (design §6 rule 1). v1 envelopes meet the linkable
        #    gate in _verify_v1 instead. Accept only profiles the policy allows.
        accepted_profiles = self._trust_policy.accepted_profiles
        if presentation_profile not in accepted_profiles:
            result.add(
                Code.PROFILE_NOT_ACCEPTED,
                f"presentation profile {presentation_profile} not in the verifier's "
                f"accepted profiles {sorted(accepted_profiles)}",
            )

        # 4. Individual proofs + per-proof shape consistency (design §6 rule 2).
        handle_bound = False
        for proof_entry in envelope["proofs"]:
            proof_type = proof_entry["proofType"]
            if proof_type not in request.proof_types:
                result.add_warning(
                    WarningCode.OVER_DISCLOSURE,
                    f"envelope discloses {proof_type}, which this request did not ask for",
                    proof_type=proof_type,
                )
                continue
            # Every evaluated entry is shape-checked against the binding.
            handle_bound = True
            self._verify_individual_v2(
                proof_entry,
                request,
                presentation_profile,
                binding_pseudonym,
                binding_scope_id,
                result,
            )

        if handle_bound and presentation_profile == SCOPED_PROFILE:
            result.presentation_handle = field_to_hex(binding_pseudonym)
            result.scope_id = field_to_hex(binding_scope_id)

        # 5. All required proof types present (identical to v1).
        present = {entry["proofType"] for entry in envelope["proofs"]}
        for required in request.proof_types:
            if required not in present:
                result.add(
                    Code.MISSING_PROOF,
                    f"required proof type missing: {required}",
                    proof_type=required,
                )

        # 5'. Same-holder binding of a composite answer. Linkable envelopes
        #     bind every proof to one holderCommitment and scoped envelopes to
        #     one in-circuit pseudonym; an anonymous envelope binds nothing, so
        #     two of its answers may come from two holders (pooling).
        answering = sorted({
            entry["proofType"]
            for entry in envelope["proofs"]
            if entry["proofType"] in request.proof_types
        })
        if (
            presentation_profile == ANONYMOUS_PROFILE
            and len(answering) >= 2
            and self._trust_policy.accept_independent_anonymous_proofs is not True
        ):
            result.add(
                Code.UNBOUND_COMPOSITE,
                f"anonymous presentation answers {len(answering)} requested proofs "
                f"({', '.join(answering)}) but binds them to no single holder; request "
                "the scoped profile (scopePolicy 'session' scopes the pseudonym to one "
                "request context) "
                "or declare the proofs independent in the verifier policy",
            )

        # 6. Aggregation is unsupported in v2 envelopes (§7.3).
        if "aggregation" in envelope:
            result.add(
                Code.INVALID_AGGREGATION,
                "aggregation is unsupported in zkc:proof:v2 envelopes",
            )

        logger.info(
            "verified v2 envelope valid=%s profile=%s codes=%s backend=%s production_backend=%s",
            result.valid,
            presentation_profile,
            ",".join(result.codes()) or "-",
            self._backend.name,
            self._backend.is_production,
        )
        return result

    # ------------------------------------------------------------------

    def verify_authenticated(
        self, apr, envelope, request: VerificationRequest, *, now=None, seen_nonces=None
    ) -> VerificationResult:
        """Verify the verifier's own APR and atomically consume it on success.

        The default nonce store lasts for this verifier instance. Callers that
        recreate instances must provide a shared mutable set; multi-process
        services need an atomic shared store at their integration boundary.
        Failed verification releases its reservation. Authentication failures
        return before artifact resolution or proof-backend work.
        Omitted ``now`` uses wall-clock Unix seconds, independently of the APR
        and proof context; an explicit trusted time supports historical checks.
        """
        result = VerificationResult()
        when = now
        seen = self._seen_apr_nonces if seen_nonces is None else seen_nonces
        try:
            apr = copy.deepcopy(apr)
            envelope = copy.deepcopy(envelope)
            request = _snapshot_request(request)
            policy = self._trust_policy
            if not verify_apr_signature(apr or {}):
                raise ValueError("invalid APR signature")
            if (
                not policy.verifier_id
                or apr["verifierId"] != policy.verifier_id
                or apr_signer_pubkey(apr) not in policy.verifier_signing_keys
            ):
                raise ValueError("APR signer or verifierId is not configured for this verifier")
            nonce = field_to_hex(hex_to_field(apr["nonce"]))
            if apr["nonce"] != nonce:
                raise ValueError("APR nonce must use canonical field encoding")
            if not isinstance(seen, MutableSet):
                raise ValueError("APR nonce store must be a mutable set")
        except (AttributeError, KeyError, TypeError, ValueError, RecursionError) as exc:
            result.add(Code.UNSIGNED_REQUEST, f"request not authenticated: {exc}")
            return result
        if not self._request_matches_apr(apr, request, result):
            return result
        with _APR_NONCE_LOCK:
            fresh, reason = apr_freshness(apr, when, seen)
            if not fresh:
                result.add(Code.UNSIGNED_REQUEST, f"request not authenticated: {reason}")
                return result
            try:
                seen.add(nonce)
                if nonce not in seen:
                    raise ValueError("nonce store did not retain the reservation")
            except Exception:
                result.add(Code.UNSIGNED_REQUEST, "APR nonce store could not record the request")
                return result
        accepted = False
        try:
            result = self._verify_authenticated_reserved(apr, envelope, request)
            accepted = result.valid
            return result
        finally:
            if not accepted:
                with _APR_NONCE_LOCK:
                    seen.discard(nonce)

    def _verify_authenticated_reserved(self, apr, envelope, request) -> VerificationResult:
        result = VerificationResult()

        # Step 0b: purpose binding. A proof bound under a different purpose has a
        # different context value and is rejected with PURPOSE_MISMATCH.
        purpose_bound_request = False
        try:
            purpose_bound_request = (
                apr["request"]["context"]["profile"] == PURPOSE_BOUND_PROFILE
            )
        except (KeyError, TypeError):
            purpose_bound_request = False
        if purpose_bound_request:
            try:
                envelope_value = hex_to_field(envelope["metadata"]["context"]["value"])
                if envelope_value != recompute_purpose_bound_context(apr):
                    result.add(
                        Code.PURPOSE_MISMATCH, "bound purpose does not match request"
                    )
            except (KeyError, TypeError, ValueError):
                result.add(
                    Code.PURPOSE_MISMATCH,
                    "purpose-bound context could not be reconstructed",
                )

        # Step 0c: scope recomputation (design §6 rule 3). For a SCOPED v2
        # envelope on the authenticated path, the verifier recomputes scope_id
        # from its OWN authenticated identity (the APR signer key) + the APR
        # scopePolicy + rotation epoch and compares to presentationBinding.scopeId
        # — a scoped proof for a scope not derived from this verifier's identity
        # (e.g. one bound to a different verifier) is SCOPE_MISMATCH.
        scope_recomputed = self._recompute_scope(apr, envelope, request, result)

        # Step 0e: profile agreement. The holder answers with
        # min(APR profile, its own ceiling), so an envelope MORE linkable than
        # the signed APR asked for is never an honest answer to it -- e.g. a v1
        # envelope (which _recompute_scope never inspects) under a scoped APR.
        self._check_apr_presentation_profile(apr, envelope, result)

        # Exact APR agreement authorizes the compatibility-only dispatch.
        inner = self._verify_dispatch(envelope, request)
        result.errors.extend(inner.errors)
        result.warnings.extend(inner.warnings)
        result.bindings.extend(inner.bindings)
        result.presentation_profile = inner.presentation_profile
        result.presentation_handle = inner.presentation_handle
        result.scope_id = inner.scope_id
        # Both read the same presentationBinding.scopeId: True only for a
        # scoped envelope whose scope equals this verifier's recomputation
        # AND whose handle a requested proof bound (scope_id is reported
        # only then).
        result.scope_recomputed = (
            scope_recomputed
            and inner.presentation_profile == SCOPED_PROFILE
            and inner.scope_id is not None
        )
        self._enforce_presentation_continuity(result)
        return result

    def _enforce_presentation_continuity(self, result) -> None:
        """Continuity-required policy (spec section 5.9.4).

        With ``require_presentation_continuity`` an accepted answer must carry
        a continuity handle the holder could not choose per presentation: a
        scoped pseudonym under a scope this verifier recomputed from its own
        identity, or the linkable holder commitment. An anonymous answer (the
        downgrade a holder may make, section 5.9.2 rule 4) is PROFILE_MISMATCH;
        a scoped answer whose scope was not recomputed is SCOPE_MISMATCH. A
        scoped or linkable answer in which no requested proof bound the handle
        (e.g. a request listing no proof types) is PROFILE_MISMATCH too: its
        binding handle is an unproven, presenter-chosen value. A result whose
        envelope did not parse already carries its own error."""
        if not self._trust_policy.require_presentation_continuity:
            return
        profile = result.presentation_profile
        if profile == ANONYMOUS_PROFILE or (profile is None and result.valid):
            result.add(
                Code.PROFILE_MISMATCH,
                "the verifier requires presentation continuity, but the anonymous "
                "presentation carries no holder handle",
            )
        elif profile is not None and result.presentation_handle is None:
            result.add(
                Code.PROFILE_MISMATCH,
                "the verifier requires presentation continuity, but no requested "
                "proof binds the presentation handle",
            )
        elif profile == SCOPED_PROFILE and not result.scope_recomputed:
            if Code.SCOPE_MISMATCH not in result.codes():
                result.add(
                    Code.SCOPE_MISMATCH,
                    "the verifier requires presentation continuity, but it did not "
                    "recompute this scope from its own authenticated identity "
                    "(use verify_authenticated)",
                )

    def _request_matches_apr(self, apr, request: VerificationRequest, result) -> bool:
        """Does the caller's request agree with the AUTHENTICATED APR?

        Compared by the SAME canonical JSON the signed commitment uses
        (``sort_keys``, no whitespace, no NaN), which makes the comparison
        deliberately type-strict: JSON ``true`` is not ``1`` and not ``1.0``.
        The holder side already depends on that strictness, so loosening it here
        would let a request that the holder treated as different pass as the
        same one. ``parameters`` defaults to ``{}`` exactly as the digest does,
        so an APR that omits the key behaves identically to one carrying ``{}``.
        The only translation applied is the protocol's own presentation-profile
        proof-type resolution (see :func:`_apr_presentation_proof_types`): each
        signed proof type may accept one or two legitimate spellings (never
        more than the family it names), and the supplied request's actual
        spelling at that position — when it is one of them — is the one used
        to key the corresponding parameters, so this never has to guess which
        spelling the holder chose; it only accepts a spelling the APR actually
        authorised."""
        signed = apr.get("request", {}) if isinstance(apr, dict) else {}
        if not isinstance(signed, dict):
            result.add(
                Code.UNSIGNED_REQUEST,
                "Request differs from signed APR: authenticated request is malformed",
            )
            return False
        try:
            authenticated_context = canonical_request_context(signed["context"])
            supplied_context = canonical_request_context(request.context.to_metadata())
            if authenticated_context.get("verifierId", self._trust_policy.verifier_id) != self._trust_policy.verifier_id:
                raise ValueError("context verifierId disagrees with configured verifier")
            extensions = signed.get("extensions", {})
            if not isinstance(extensions, dict):
                raise ValueError("request extensions must be an object")
            constraints = extensions.get(VERIFICATION_CONTEXT_EXTENSION)
            if VERIFICATION_CONTEXT_EXTENSION in extensions:
                if not isinstance(constraints, dict) or set(constraints) != {"context", "maxProofAge"}:
                    raise ValueError("malformed signed verification-context extension")
                bound_context = canonical_request_context(constraints["context"])
                if _canonical_json(bound_context) != _canonical_json(authenticated_context):
                    raise ValueError("signed context extension disagrees with APR context")
                authenticated_age = constraints["maxProofAge"]
            else:
                if authenticated_context["profile"] not in ("zkc:context:verifier-session:v1", PURPOSE_BOUND_PROFILE):
                    raise ValueError("opaque context requires a signed verification-context extension")
                authenticated_age = LEGACY_MAX_PROOF_AGE
            if type(authenticated_age) is not int or authenticated_age < 0:
                raise ValueError("signed maxProofAge must be a non-negative integer")
            wire_age = signed.get("maxProofAge", authenticated_age)
            if type(wire_age) is not int or wire_age != authenticated_age:
                raise ValueError("maxProofAge differs from signed verification constraints")
            if type(request.max_proof_age) is not int or request.max_proof_age < 0:
                raise ValueError("verification maxProofAge must be a non-negative integer")
            renamed = _apr_presentation_proof_types(signed)
            raw_signed_proof_types = signed.get("proofTypes")
            if (
                not isinstance(raw_signed_proof_types, list)
                or any(
                    not isinstance(proof_type, str) or not proof_type
                    for proof_type in raw_signed_proof_types
                )
            ):
                raise TypeError(
                    "authenticated proofTypes must be an array of non-empty strings"
                )
            signed_proof_types = list(raw_signed_proof_types)
            if len(set(signed_proof_types)) != len(signed_proof_types):
                raise ValueError("authenticated proofTypes must not contain duplicates")
            supplied_proof_types = list(request.proof_types)
            resolved_key_for_signed_type = {}
            resolved_destinations = set()
            authenticated_types = []
            seen_signed_types = set()
            seen_families = set()
            for index, signed_type in enumerate(signed_proof_types):
                if signed_type in seen_signed_types:
                    raise ValueError(
                        f"authenticated request repeats proof type {signed_type!r}"
                    )
                seen_signed_types.add(signed_type)
                try:
                    family = family_for_v1_proof_type(signed_type)
                except Exception:
                    family = None
                if family is not None:
                    if family in seen_families:
                        raise ValueError(
                            f"authenticated request repeats predicate family {family!r} "
                            "through multiple proof-type aliases"
                        )
                    seen_families.add(family)
                choices = renamed.get(signed_type, (signed_type,))
                supplied_type = (
                    supplied_proof_types[index] if index < len(supplied_proof_types) else None
                )
                resolved = supplied_type if supplied_type in choices else choices[0]
                if resolved in resolved_destinations:
                    raise ValueError(
                        "authenticated proofTypes collide after presentation resolution"
                    )
                resolved_destinations.add(resolved)
                authenticated_types.append(resolved)
                resolved_key_for_signed_type[signed_type] = resolved
            signed_parameters = signed.get("parameters", {})
            if not isinstance(signed_parameters, dict):
                raise TypeError("authenticated parameters must be an object")
            expected_parameter_keys = set(signed_proof_types)
            actual_parameter_keys = set(signed_parameters)
            if actual_parameter_keys != expected_parameter_keys:
                raise ValueError(
                    "authenticated parameter keys must exactly match proofTypes"
                )
            authenticated_parameters = {
                resolved_key_for_signed_type[proof_type]: signed_parameters[proof_type]
                for proof_type in signed_proof_types
            }
            signed_selectors = parse_request_selectors(
                signed.get("extensions"), signed_proof_types
            )
            authenticated_selectors = {
                resolved_key_for_signed_type[proof_type]: selector
                for proof_type, selector in signed_selectors.items()
            }
            pairs = (
                ("context", authenticated_context, supplied_context),
                ("maxProofAge", authenticated_age, request.max_proof_age),
                ("parameters", authenticated_parameters, request.parameters),
                ("proofTypes", authenticated_types, list(request.proof_types)),
                ("bindingSelectors", authenticated_selectors, request.binding_selectors),
            )
            mismatched = [
                name
                for name, authenticated, supplied in pairs
                if _canonical_json(authenticated) != _canonical_json(supplied)
            ]
        except (KeyError, TypeError, ValueError) as exc:
            result.add(
                Code.UNSIGNED_REQUEST,
                f"Request differs from signed APR: request could not be "
                f"canonicalized for comparison: {exc}",
            )
            return False
        if mismatched:
            result.add(
                Code.UNSIGNED_REQUEST,
                f"Request differs from signed APR: verification request "
                f"disagrees with the authenticated request: {', '.join(mismatched)}",
            )
            return False
        return True

    @staticmethod
    def _check_apr_presentation_profile(apr, envelope, result) -> None:
        """Reject an envelope more linkable than its APR's presentation profile.

        An APR without a ``presentation`` block leaves the profile to the
        holder's own ceiling, so it constrains nothing here. A malformed block
        or envelope is reported by the request-agreement and structural checks
        instead, so this check only ever adds the one comparison it owns."""
        signed = apr.get("request") if isinstance(apr, dict) else None
        presentation = signed.get("presentation") if isinstance(signed, dict) else None
        if not isinstance(presentation, dict):
            return
        apr_profile = presentation.get("profile", ANONYMOUS_PROFILE)
        if apr_profile not in _PRESENTATION_PROFILE_RANK:
            return
        if not isinstance(envelope, dict):
            return
        version = envelope.get("version")
        if version == "zkc:proof:v1":
            envelope_profile = LINKABLE_PROFILE
        elif version == "zkc:proof:v2" and isinstance(envelope.get("presentationBinding"), dict):
            envelope_profile = envelope["presentationBinding"].get("profile")
        else:
            return
        if envelope_profile not in _PRESENTATION_PROFILE_RANK:
            return
        if _PRESENTATION_PROFILE_RANK[envelope_profile] > _PRESENTATION_PROFILE_RANK[apr_profile]:
            result.add(
                Code.PROFILE_MISMATCH,
                f"envelope presentation profile {envelope_profile} is more linkable "
                f"than the authenticated request's {apr_profile}",
            )

    def _recompute_scope(self, apr, envelope, request, result) -> bool:
        """Scope recomputation for a scoped v2 envelope (design §6 rule 3).

        Only a ``zkc:proof:v2`` envelope declaring the scoped profile is subject
        to this check; anonymous/linkable envelopes carry no scope to recompute.
        The verifier recomputes ``scope_id`` exactly as the holder did
        (:mod:`zkc_holder.client`): ``verifier_identity`` from the APR signer's
        SEC1 key, the APR-declared ``scopePolicy``, and
        ``rotation_epoch = timestamp // rotationEpochSeconds`` (0 when no
        rotation). A ``protocol:<name>`` scope remains local to the pinned
        signer identity and is honored ONLY when the policy explicitly
        declares it. Any mismatch (or an unrecomputable
        scope) is ``SCOPE_MISMATCH``; fail closed.

        Returns True only when the envelope is scoped and its ``scopeId``
        equals this verifier's own recomputation.
        """
        if not isinstance(envelope, dict) or envelope.get("version") != "zkc:proof:v2":
            return False
        binding = envelope.get("presentationBinding")
        if not isinstance(binding, dict) or binding.get("profile") != SCOPED_PROFILE:
            return False

        try:
            binding_scope_id = hex_to_field(binding["scopeId"])
        except (KeyError, ValueError, TypeError):
            result.add(Code.SCOPE_MISMATCH, "scoped envelope carries no recoverable scopeId")
            return False

        try:
            block = apr["request"]["presentation"]
            scope_policy = block["scopePolicy"]
            if not isinstance(scope_policy, str) or not scope_policy:
                raise ValueError("empty scopePolicy")
        except (KeyError, TypeError, ValueError):
            # The verifier cannot establish its own scope for this envelope, so
            # it cannot attest the scoped proof is bound to its identity.
            result.add(
                Code.SCOPE_MISMATCH,
                "scoped envelope could not be checked against the verifier's own scope",
            )
            return False

        # Named protocol scopes still include the pinned signing identity;
        # their additional consent/declaration gate remains mandatory.
        if scope_policy.startswith("protocol:") and (
            scope_policy not in self._trust_policy.declared_protocol_scopes
        ):
            result.add(
                Code.SCOPE_MISMATCH,
                f"scoped presentation uses protocol scope {scope_policy!r} that the "
                f"verifier policy does not declare",
            )
            return False

        try:
            # Shared holder/verifier derivation (zkc_crypto.apr) — the two
            # sides call the SAME function so they can never drift.
            expected_scope_id = scope_from_apr_presentation(
                apr, block, request.context.timestamp
            )
        except (TypeError, ValueError):
            result.add(
                Code.SCOPE_MISMATCH,
                "verifier could not recompute a scope for the presentation",
            )
            return False

        if binding_scope_id != expected_scope_id:
            result.add(
                Code.SCOPE_MISMATCH,
                "presentation scope was not derived from the verifier's own "
                "authenticated identity",
            )
            return False
        return True

    # ------------------------------------------------------------------

    def _verify_accumulator_state(
        self,
        *,
        issuer_id,
        proof_type,
        accumulator_epoch,
        current_epoch,
        accumulator_root,
        request,
        result,
    ) -> None:
        """Apply verifier-local freshness and authenticated-root policy."""
        state = request.accumulator_states.get(issuer_id)
        if state is None:
            result.add(
                Code.STALE_ACCUMULATOR,
                f"no accumulator state available for issuer {issuer_id}",
                proof_type=proof_type,
            )
            return
        if (
            proof_type in _AUTHENTICATED_ACCUMULATOR_REQUIRED
            and not _is_authenticated_accumulator_state(state)
        ):
            result.add(
                Code.UNAUTHENTICATED_ACCUMULATOR,
                f"{proof_type} roots require authenticated metadata-v2 ingestion",
                proof_type=proof_type,
            )
            return

        lag = min(
            self._trust_policy.max_epoch_lag,
            getattr(state, "max_epoch_lag", self._trust_policy.max_epoch_lag),
        )
        if current_epoch != state.current_epoch:
            result.add(
                Code.STALE_ACCUMULATOR,
                f"proof current_epoch {current_epoch} differs from verifier view "
                f"{state.current_epoch} for {proof_type}",
                proof_type=proof_type,
            )
        elif accumulator_epoch + lag < state.current_epoch:
            result.add(
                Code.STALE_ACCUMULATOR,
                f"accumulator epoch too old for {proof_type}",
                proof_type=proof_type,
            )
        elif accumulator_epoch > state.current_epoch:
            result.add(
                Code.STALE_ACCUMULATOR,
                f"accumulator epoch {accumulator_epoch} is ahead of verifier view "
                f"{state.current_epoch} for {proof_type}",
                proof_type=proof_type,
            )
        elif (
            proof_type in _AUTHENTICATED_ACCUMULATOR_REQUIRED
            and state.roots.get(accumulator_epoch) != accumulator_root
        ):
            result.add(
                Code.STALE_ACCUMULATOR,
                f"authenticated accumulator root unavailable or mismatched for epoch "
                f"{accumulator_epoch} ({proof_type})",
                proof_type=proof_type,
            )
        elif accumulator_epoch not in state.roots:
            # The circuit proves membership only in the root the prover chose,
            # so an unrecorded epoch would accept a revoked holder's self-made
            # tree. Fail closed unless the policy explicitly opts out.
            if self._trust_policy.allow_unrecorded_accumulator_roots:
                logger.warning(
                    "accepted %s from issuer %s WITHOUT a revocation check: no "
                    "accumulator root is recorded for epoch %s and the trust policy "
                    "sets allow_unrecorded_accumulator_roots",
                    proof_type,
                    issuer_id,
                    accumulator_epoch,
                )
                result.add_warning(
                    WarningCode.UNCHECKED_ACCUMULATOR_ROOT,
                    f"no issuer accumulator root is recorded for epoch {accumulator_epoch}; "
                    f"revocation was not checked for {proof_type} "
                    "(allow_unrecorded_accumulator_roots)",
                    proof_type=proof_type,
                )
            else:
                result.add(
                    Code.STALE_ACCUMULATOR,
                    f"no issuer accumulator root is recorded for epoch {accumulator_epoch}, "
                    f"so the proof's root cannot be checked for revocation ({proof_type})",
                    proof_type=proof_type,
                )
        elif state.roots[accumulator_epoch] != accumulator_root:
            result.add(
                Code.STALE_ACCUMULATOR,
                f"accumulator root not recognized for epoch {accumulator_epoch} "
                f"({proof_type})",
                proof_type=proof_type,
            )

    def _has_declared_public_inputs(self, circuit, proof_entry, result) -> bool:
        """``publicInputs`` carries exactly the circuit's encoder-declared names.

        The backend binds only declared inputs, so an undeclared key is a value
        no proof constrains; reading one (a holder handle above all) would let
        the presenter choose it. A missing key cannot be encoded at all."""
        proof_type = proof_entry["proofType"]
        shape = self._public_input_shape_by_circuit.get(circuit)
        if shape is None:
            result.add(
                Code.UNKNOWN_PROOF_TYPE,
                f"circuit {circuit} for {proof_type} has no public-input encoder",
                proof_type=proof_type,
            )
            return False
        declared = shape[0]
        supplied = set(proof_entry["publicInputs"])
        if supplied == declared:
            return True
        undeclared = sorted(supplied - declared)
        missing = sorted(declared - supplied)
        details = []
        if undeclared:
            details.append(f"undeclared {undeclared}")
        if missing:
            details.append(f"missing {missing}")
        result.add(
            Code.MALFORMED_PROOF,
            f"publicInputs for {proof_type} must carry exactly the inputs declared by "
            f"the {circuit} encoder ({'; '.join(details)})",
            proof_type=proof_type,
        )
        return False

    def _matches_envelope_family(self, circuit, proof_type, envelope_family, result) -> bool:
        """Is ``circuit`` of the family this envelope generation carries?"""
        family = self._public_input_shape_by_circuit[circuit][1]
        if family == envelope_family:
            return True
        expected = _ENVELOPE_VERSION_BY_FAMILY[envelope_family]
        if family is None:
            message = (
                f"circuit {circuit} for {proof_type} declares no single holder handle "
                f"and cannot appear in a {expected} envelope"
            )
        else:
            message = (
                f"proof type {proof_type} is a {family}-family circuit ({circuit}) and "
                f"belongs in a {_ENVELOPE_VERSION_BY_FAMILY[family]} envelope, not a "
                f"{expected} envelope"
            )
        result.add(Code.PROFILE_MISMATCH, message, proof_type=proof_type)
        return False

    def _matches_contained_circuit(self, circuit, proof_type, result) -> bool:
        if proof_type in (
            _AUTHENTICATED_HISTORICAL_PROOF_TYPES | _UNAUTHENTICATED_REBIND_PROOF_TYPES
        ) and not matches_containment_identity(self._root, circuit, proof_type):
            result.add(
                Code.UNKNOWN_PROOF_TYPE,
                f"circuit {circuit} is not the frozen contained identity for {proof_type}",
                proof_type=proof_type,
            )
            return False
        return True

    def _check_artifact_review(self, proof_type, vk_hash, result, vk_bytes=None) -> bool:
        """Apply local assurance requirements to every alias of the selected VK.

        A presenter cannot obtain a stronger claim by changing proof type or
        binding selector. Source and build review remain independent gates;
        no source-review requirement is introduced when local policy is empty.
        """
        vk_sha256 = "sha256:" + hashlib.sha256(vk_bytes).hexdigest() if vk_bytes is not None else ""
        if vk_hash is None and not vk_sha256:
            if self._trust_policy.accepted_review_statuses:
                result.add(
                    Code.UNKNOWN_VERIFICATION_KEY,
                    "review policy requires a manifest-pinned verification key identity",
                    proof_type=proof_type,
                )
                return False
            return True
        sources, bindings = self._predicate_registry.artifact_review_statuses(
            vk_hash, vk_sha256=vk_sha256
        )
        source_policy = self._trust_policy.accepted_review_statuses
        binding_policy = self._trust_policy.accepted_binding_review_statuses
        if "deprecated" in sources and "deprecated" not in source_policy:
            result.add(
                Code.DEPRECATED_PROOF_TYPE,
                "the selected verification key is also published by a deprecated identity",
                proof_type=proof_type,
            )
            return False
        if "deprecated" in bindings:
            result.add(
                Code.DEPRECATED_BINDING,
                "the selected verification key is also published by a deprecated binding",
                proof_type=proof_type,
            )
            return False
        if source_policy and (not sources or not set(sources).issubset(source_policy)):
            result.add(
                Code.UNREVIEWED_PREDICATE,
                f"source review statuses {list(sources) or ['<none>']} of identities "
                "publishing the selected verification key do not satisfy verifier policy",
                proof_type=proof_type,
            )
            return False
        if binding_policy and not set(bindings).issubset(binding_policy):
            result.add(
                Code.UNREVIEWED_PREDICATE,
                f"binding review statuses {list(bindings)} of identities publishing "
                "the selected verification key do not satisfy verifier policy",
                proof_type=proof_type,
            )
            return False
        return True

    def _legacy_review_allows(self, proof_type, circuit, result) -> bool:
        """Keep v1 source-review and unsafe-identity gates on inferred aliases."""
        statuses = {
            entry.review_status
            for entry in self._predicate_registry.resolve_all(proof_type)
            if entry.circuit == circuit
        }
        if (
            statuses == {"deprecated"}
            and "deprecated" not in self._trust_policy.accepted_review_statuses
        ):
            result.add(
                Code.DEPRECATED_PROOF_TYPE,
                f"proof type {proof_type} is served only by deprecated registry "
                "entries; accepting it requires a verifier policy that lists "
                "'deprecated' in accepted_review_statuses",
                proof_type=proof_type,
            )
            return False
        if self._trust_policy.accepted_review_statuses:
            if not statuses or not statuses.issubset(self._trust_policy.accepted_review_statuses):
                result.add(
                    Code.UNREVIEWED_PREDICATE,
                    f"registry review status {sorted(statuses) or ['<none>']} for "
                    f"{proof_type} does not satisfy verifier policy",
                    proof_type=proof_type,
                )
                return False
        return True

    def _legacy_alias_evidence(self, proof_type, circuit, result) -> tuple:
        """Apply entry-v2 binding gates when a legacy artifact is a binding artifact.

        Returns ``(allowed, evidence)``; ``evidence`` is None when the legacy
        artifact is no binding's artifact. The caller records it only after
        every later gate passes.

        A legacy VK can be the *same artifact* as a v2 binding. Every VK-store
        manifest, loaded-registry, and declared binding is inspected, across
        proof types, before the frozen legacy path is allowed. One exact,
        unambiguous alias inherits every v2 gate, including the local
        allowlist; a cross-wired or partial alias cannot acquire authority
        through the legacy circuit name. A legacy artifact with no alias is not
        a binding, so binding gates do not govern it. The presented proof
        keeps its own circuit and VK either way.
        """
        try:
            vk_sha256, vk_hash, acir_hash = self._vk_store.legacy_vk_identity(circuit)
        except ValueError as exc:
            result.add(Code.UNKNOWN_VERIFICATION_KEY, str(exc), proof_type=proof_type)
            return False, None
        identified = vk_sha256 is not None or vk_hash is not None
        manifest_candidates = self._vk_store.binding_vk_candidates(vk_sha256, vk_hash)
        registry_candidates = self._predicate_registry.binding_vk_candidates(vk_sha256, vk_hash)
        declared_candidates = self._predicate_registry.declared_binding_vk_candidates(
            vk_sha256, vk_hash
        )
        # Without any VK pin the absence of an alias cannot be shown, so a
        # proof type or circuit name that a binding uses fails closed.
        unprovable = not identified and (
            self._predicate_registry.has_v2_source(proof_type)
            or self._vk_store.has_binding_for_circuit(circuit)
        )
        if not (
            unprovable or manifest_candidates or registry_candidates or declared_candidates
        ):
            return True, None
        # A minimal VK-store manifest may omit binding rows; the registry
        # binding was cross-checked against the committed manifest at load.
        if (
            not identified
            or len(manifest_candidates) > 1
            or len(registry_candidates) != 1
            or len(declared_candidates) != 1
        ):
            result.add(
                Code.UNKNOWN_BINDING,
                "selector-less proof has no unique exact VK binding alias",
                proof_type=proof_type,
            )
            return False, None
        binding = registry_candidates[0]
        governed = {
            "predicateId": binding.predicate_id,
            "entryVersion": binding.entry_version,
            "sourceId": binding.source_id,
            "bindingId": binding.binding_id,
            "circuit": binding.circuit,
            "acirHash": binding.acir_hash,
            "vkHash": binding.vk_hash,
            "vkSha256": binding.vk_sha256,
        }
        legacy_pins = {"vkSha256": vk_sha256, "vkHash": vk_hash, "acirHash": acir_hash}
        if (
            any(declared_candidates[0].get(key) != value for key, value in governed.items())
            or any(
                row.get(key) != value
                for row in manifest_candidates
                for key, value in governed.items()
            )
            or any(
                value is not None and governed[key] != value
                for key, value in legacy_pins.items()
            )
        ):
            result.add(
                Code.UNKNOWN_BINDING,
                "selector-less proof has an inconsistent or cross-wired VK binding alias",
                proof_type=proof_type,
            )
            return False, None
        # The same artifact may also have a separate v1 circuit name and
        # proof type. Apply the exact binding's own source gates, while
        # keeping the presented proof's v1 identity and checks.
        published_types = self._predicate_registry.binding_proof_types(binding.selector)
        if len(published_types) != 1:
            result.add(
                Code.UNKNOWN_BINDING,
                "VK binding alias has no unique published proof type",
                proof_type=proof_type,
            )
            return False, None
        owning_type = published_types[0]
        owning_source = self._predicate_registry.binding_source(owning_type, binding.selector)
        legacy_entries = [
            entry for entry in self._predicate_registry.resolve_all(proof_type)
            if entry.circuit == circuit
        ]
        if (
            owning_source is None
            or (circuit == binding.circuit and owning_type != proof_type)
            or not legacy_entries
            or any(
                entry.source_sha256 != owning_source.source_sha256
                or entry.public_inputs != owning_source.public_inputs
                for entry in legacy_entries
            )
        ):
            result.add(
                Code.UNKNOWN_BINDING,
                "VK alias does not preserve the presented source and public-input contract",
                proof_type=proof_type,
            )
            return False, None
        if self._resolve_binding_gates(owning_type, binding.selector, result, proof_type) is None:
            return False, None
        evidence = self._vk_store.binding_evidence(binding.selector) or {
            **governed,
            "toolchain": dict(binding.toolchain),
            "buildProfile": binding.build_profile,
            "artifactManifestKey": binding.manifest_key,
        }
        return True, {
            **evidence,
            "resolution": "legacyVkAlias",
            "presentedProofType": proof_type,
            "presentedCircuit": circuit,
        }

    def _resolve_binding_gates(self, proof_type, selector, result, reported_type):
        """One exact registry binding resolution under this verifier's policy."""
        try:
            return self._predicate_registry.resolve_binding(
                proof_type,
                selector,
                accepted_source_statuses=self._trust_policy.accepted_review_statuses,
                accepted_binding_statuses=self._trust_policy.accepted_binding_review_statuses,
                allowed_binding_ids=self._trust_policy.accepted_binding_ids,
                allow_inactive=self._trust_policy.allow_inactive_bindings,
            )
        except BindingResolutionError as exc:
            codes = {
                "malformed": Code.MALFORMED_BINDING_SELECTOR,
                "unknown": Code.UNKNOWN_BINDING,
                "cross_wired": Code.UNKNOWN_BINDING,
                "inactive": Code.INACTIVE_BINDING,
                "deprecated": Code.DEPRECATED_BINDING,
                "disallowed": Code.DISALLOWED_BINDING,
                "source_review": Code.UNREVIEWED_PREDICATE,
                "binding_review": Code.UNREVIEWED_PREDICATE,
            }
            result.add(
                codes.get(exc.reason, Code.UNKNOWN_BINDING), str(exc), proof_type=reported_type
            )
            return None

    def _resolve_proof_artifact(self, proof_entry, result, *, load_vk=True, audit_binding=True):
        """Resolve exactly one legacy circuit or one selector-bound v2 artifact."""
        proof_type = proof_entry["proofType"]
        # These frozen statements are known to be forgeable. Advisory,
        # non-exclusive registry labels cannot reactivate them, including
        # when the registry is absent or another lineage lists the same type.
        if (
            proof_type in _AUTHENTICATED_HISTORICAL_PROOF_TYPES
            and "deprecated" not in self._trust_policy.accepted_review_statuses
        ):
            result.add(
                Code.DEPRECATED_PROOF_TYPE,
                f"known unsafe historical proof type {proof_type} requires a verifier "
                "policy that explicitly lists 'deprecated' in accepted_review_statuses",
                proof_type=proof_type,
            )
            return None
        selector = proof_entry.get("bindingSelector")
        if selector is None:
            circuit = self._circuit_by_proof_type.get(proof_type)
            if circuit is None:
                result.add(
                    Code.UNKNOWN_PROOF_TYPE,
                    f"proof type {proof_type} does not resolve to a known registry circuit",
                    proof_type=proof_type,
                )
                return None
            if not self._matches_contained_circuit(circuit, proof_type, result):
                return None
            if not self._legacy_review_allows(proof_type, circuit, result):
                return None

            allowed, alias_evidence = self._legacy_alias_evidence(proof_type, circuit, result)
            if not allowed:
                return None
            vk_bytes = None
            if load_vk and self._backend.is_production:
                try:
                    vk_bytes = self._vk_store.lookup(circuit)
                except ValueError as exc:
                    result.add(Code.UNKNOWN_VERIFICATION_KEY, str(exc), proof_type=proof_type)
                    return None
                if vk_bytes is None:
                    result.add(
                        Code.UNKNOWN_VERIFICATION_KEY,
                        f"no manifest-pinned verification key for circuit {circuit}",
                        proof_type=proof_type,
                    )
                    return None
            vk_hash = self._vk_store.vk_hash(circuit)
            if not self._check_artifact_review(
                proof_type, "0x" + vk_hash.hex() if vk_hash is not None else None, result, vk_bytes
            ):
                return None
            if audit_binding and alias_evidence and alias_evidence not in result.bindings:
                result.bindings.append(alias_evidence)
            return circuit, vk_bytes, None

        resolved = self._resolve_binding_gates(proof_type, selector, result, proof_type)
        if resolved is None:
            return None
        if not self._matches_contained_circuit(resolved.binding.circuit, proof_type, result):
            return None
        evidence = self._vk_store.binding_evidence(selector)
        if (
            evidence is None
            or evidence["sourceId"] != resolved.source.source_id
            or evidence["vkHash"] != resolved.binding.vk_hash
            or evidence["vkSha256"] != resolved.binding.vk_sha256
        ):
            result.add(
                Code.UNKNOWN_VERIFICATION_KEY,
                "selected binding does not agree with the committed artifact manifest",
                proof_type=proof_type,
            )
            return None
        vk_bytes = None
        if load_vk and self._backend.is_production:
            try:
                vk_bytes = self._vk_store.lookup_binding(selector)
            except ValueError as exc:
                result.add(Code.UNKNOWN_VERIFICATION_KEY, str(exc), proof_type=proof_type)
                return None
            if vk_bytes is None:
                result.add(
                    Code.UNKNOWN_VERIFICATION_KEY,
                    "selected binding has no manifest-pinned verification key",
                    proof_type=proof_type,
                )
                return None
        if not self._check_artifact_review(proof_type, evidence["vkHash"], result, vk_bytes):
            return None
        if audit_binding and evidence not in result.bindings:
            result.bindings.append(evidence)
        return resolved.binding.circuit, vk_bytes, selector

    def _verify_individual(self, proof_entry, request, holder_commitment, result) -> None:
        proof_type = proof_entry["proofType"]
        public_inputs = proof_entry["publicInputs"]

        if proof_type in SELECTIVE_DISCLOSURE_PROOF_TYPES:
            try:
                _validate_selective_disclosure_entry(proof_entry)
            except EnvelopeError as exc:
                result.add(Code.MALFORMED_PROOF, str(exc), proof_type=proof_type)
                return

        resolved_artifact = self._resolve_proof_artifact(proof_entry, result)
        if resolved_artifact is None:
            return
        circuit, vk_bytes, _selector = resolved_artifact

        # Default-deny request binding. A proof type that resolves to a circuit
        # but declares no binding contract would verify cryptographically and
        # then bind to nothing, so it is rejected before any further work.
        if proof_type not in _REQUEST_BINDINGS:
            result.add(
                Code.UNBOUND_PROOF_TYPE,
                f"proof type {proof_type} has no registered request-binding contract",
                proof_type=proof_type,
            )
            return

        # 4a'. Envelope-generation binding: exactly the declared public inputs,
        #      and only a linkable-family circuit in a v1 envelope.
        if not self._has_declared_public_inputs(circuit, proof_entry, result):
            return
        if not self._matches_envelope_family(
            circuit, proof_type, _LINKABLE_CIRCUIT_FAMILY, result
        ) and proof_type not in _REBIND_AUTH_PROOF_TYPES:
            return

        # 4b. Exact legacy or selector-bound verification-key lookup + proof.
        if not self._backend.verify(circuit, proof_entry["proof"], public_inputs, vk_bytes):
            result.add(Code.INVALID_PROOF, f"invalid proof for {proof_type}", proof_type=proof_type)
            return

        # Credential-rebind carries a distinct public-input shape (no issuer
        # public key or accumulator witness), so it gets a dedicated branch
        # rather than the issuer/accumulator-centric default path below.
        if proof_type in _LINKABLE_REBIND_PROOF_TYPES:
            self._verify_rebind(proof_type, public_inputs, request, holder_commitment, result)
            return

        # Every authenticated rebind successor gets its own branch on BOTH
        # envelope paths, so a successor wrapped in the other envelope
        # generation still meets issuer-identity agreement and the
        # profile/handle checks rather than the generic predicate path.
        if proof_type in _REBIND_AUTH_PROOF_TYPES:
            self._verify_rebind_auth(
                proof_type,
                public_inputs,
                request,
                holder_commitment,
                result,
                presentation_profile=LINKABLE_PROFILE,
                binding_scope_id=None,
            )
            return

        # Parse the public inputs we reason about below; fail closed.
        try:
            proof_context = hex_to_field(public_inputs["proof_context"])
            proof_holder = hex_to_field(public_inputs["holder_commitment"])
            claim_binding = hex_to_field(public_inputs["claim_binding"])
            accumulator_epoch = int(public_inputs["accumulator_epoch"])
            current_epoch = int(public_inputs["current_epoch"])
            accumulator_root = hex_to_field(public_inputs["accumulator_root"])
            timestamp = int(public_inputs["timestamp"])
            issuer_key_x = bytes.fromhex(public_inputs["issuer_public_key_x"].removeprefix("0x"))
            issuer_key_y = bytes.fromhex(public_inputs["issuer_public_key_y"].removeprefix("0x"))
        except (KeyError, ValueError) as exc:
            result.add(
                Code.MALFORMED_PROOF,
                f"unparseable public inputs for {proof_type}: {exc}",
                proof_type=proof_type,
            )
            return

        # 4b'. Context binding of the proof itself.
        if proof_context != request.context.value:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof context mismatch for {proof_type}",
                proof_type=proof_type,
            )
        if timestamp != request.context.timestamp:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof timestamp does not match context timestamp for {proof_type}",
                proof_type=proof_type,
            )

        # Holder binding consistency across the envelope.
        if proof_holder != holder_commitment:
            result.add(
                Code.INVALID_BINDING,
                f"proof holder commitment differs from envelope holder binding for {proof_type}",
                proof_type=proof_type,
            )

        # 4d. Issuer trust (no canonical issuers; key-exact allowlist match).
        issuer = self._trust_policy.issuer_by_key(issuer_key_x, issuer_key_y)
        if issuer is None:
            result.add(
                Code.UNTRUSTED_ISSUER,
                f"issuer public key not in trust policy for {proof_type}",
                proof_type=proof_type,
            )
            return
        if not self._trust_policy.trusts(issuer, proof_type):
            result.add(
                Code.UNTRUSTED_ISSUER,
                f"issuer {issuer.issuer_id} not trusted for {proof_type}",
                proof_type=proof_type,
            )
            return

        # 4c. Accumulator freshness and authenticated root acceptance.
        self._verify_accumulator_state(
            issuer_id=issuer.issuer_id,
            proof_type=proof_type,
            accumulator_epoch=accumulator_epoch,
            current_epoch=current_epoch,
            accumulator_root=accumulator_root,
            request=request,
            result=result,
        )

        # 4e. Per-predicate request binding — the single chokepoint.
        self._verify_type_specific_requirements(
            proof_type, public_inputs, request, claim_binding, proof_context, timestamp, result
        )

    # ------------------------------------------------------------------

    def _verify_individual_v2(
        self,
        proof_entry,
        request,
        presentation_profile,
        binding_pseudonym,
        binding_scope_id,
        result,
    ) -> None:
        """Individual v2 (presentation-profile) proof verification.

        Mirrors :meth:`_verify_individual` (circuit resolution, review-status
        gate, VK/backend verification, proof-context binding, issuer trust,
        accumulator freshness, type-specific requirement check) but REPLACES the
        v1 holder_commitment envelope-vs-proof consistency check with the design
        §6 rule 2 shape-consistency check over ``presentation_pseudonym`` /
        ``scope_id``: an anonymous binding pins both to the anonymous sentinel;
        a scoped binding pins them to the envelope pseudonym/scope. Any mismatch
        is ``PROFILE_MISMATCH`` (anti-replay). Scope recomputation (rule 3) and
        the rebind/aggregation v2 branches (rule 4) land in later tasks.
        """
        proof_type = proof_entry["proofType"]
        public_inputs = proof_entry["publicInputs"]

        if proof_type in SELECTIVE_DISCLOSURE_PROOF_TYPES:
            try:
                _validate_selective_disclosure_entry(proof_entry)
            except EnvelopeError as exc:
                result.add(Code.MALFORMED_PROOF, str(exc), proof_type=proof_type)
                return

        resolved_artifact = self._resolve_proof_artifact(proof_entry, result)
        if resolved_artifact is None:
            return
        circuit, vk_bytes, _selector = resolved_artifact

        # Default-deny request binding (same gate as the v1 path).
        if proof_type not in _REQUEST_BINDINGS:
            result.add(
                Code.UNBOUND_PROOF_TYPE,
                f"proof type {proof_type} has no registered request-binding contract",
                proof_type=proof_type,
            )
            return

        # Envelope-generation binding (same rules as the v1 path, mirrored):
        # exactly the declared public inputs, presentation-family circuits only.
        if not self._has_declared_public_inputs(circuit, proof_entry, result):
            return
        if not self._matches_envelope_family(
            circuit, proof_type, _PRESENTATION_CIRCUIT_FAMILY, result
        ) and proof_type not in _REBIND_AUTH_PROOF_TYPES:
            return

        if not self._backend.verify(circuit, proof_entry["proof"], public_inputs, vk_bytes):
            result.add(Code.INVALID_PROOF, f"invalid proof for {proof_type}", proof_type=proof_type)
            return

        # Rebind v2 carries a distinct public-input shape: old/new presentation
        # pseudonyms + one shared scope_id, and no single ``presentation_pseudonym``
        # / issuer key / accumulator witness. It is dispatched to its own branch
        # BEFORE the generic per-proof shape check (which parses
        # ``presentation_pseudonym``, absent here). Rebind is scoped-only
        # (design §4.2), so the envelope binding is always scoped; the branch
        # checks scope/pseudonym consistency with the envelope binding itself.
        # The linkable successor is routed here too, so wrapping it in a v2
        # envelope still meets every rebind control rather than the generic
        # predicate path.
        if proof_type in _REBIND_AUTH_PROOF_TYPES:
            self._verify_rebind_auth(
                proof_type,
                public_inputs,
                request,
                binding_pseudonym,
                result,
                presentation_profile=presentation_profile,
                binding_scope_id=binding_scope_id,
            )
            return

        if proof_type in _SCOPED_REBIND_PROOF_TYPES:
            self._verify_rebind_v2(
                proof_type,
                public_inputs,
                request,
                presentation_profile,
                binding_pseudonym,
                binding_scope_id,
                result,
            )
            return

        # Shape consistency (design §6 rule 2). Parse the presentation handles;
        # fail closed if they are absent/unparseable.
        try:
            proof_pseudonym = hex_to_field(public_inputs["presentation_pseudonym"])
            proof_scope_id = hex_to_field(public_inputs["scope_id"])
        except (KeyError, ValueError) as exc:
            result.add(
                Code.MALFORMED_PROOF,
                f"unparseable presentation handles for {proof_type}: {exc}",
                proof_type=proof_type,
            )
            return

        if presentation_profile == ANONYMOUS_PROFILE:
            if proof_pseudonym != 0 or proof_scope_id != 0:
                result.add(
                    Code.PROFILE_MISMATCH,
                    f"anonymous presentation requires a zero pseudonym and scope for "
                    f"{proof_type}",
                    proof_type=proof_type,
                )
        else:  # SCOPED_PROFILE
            if proof_scope_id == 0:
                result.add(
                    Code.PROFILE_MISMATCH,
                    f"scoped presentation requires a non-zero scope for {proof_type}",
                    proof_type=proof_type,
                )
            if proof_pseudonym != binding_pseudonym:
                result.add(
                    Code.PROFILE_MISMATCH,
                    f"proof pseudonym differs from the envelope presentation binding for "
                    f"{proof_type}",
                    proof_type=proof_type,
                )
            if proof_scope_id != binding_scope_id:
                result.add(
                    Code.PROFILE_MISMATCH,
                    f"proof scope differs from the envelope presentation binding for "
                    f"{proof_type}",
                    proof_type=proof_type,
                )

        # Parse the predicate public inputs (v2 replaces holder_commitment with
        # the presentation handles already parsed above; the rest is unchanged).
        try:
            proof_context = hex_to_field(public_inputs["proof_context"])
            claim_binding = hex_to_field(public_inputs["claim_binding"])
            accumulator_epoch = int(public_inputs["accumulator_epoch"])
            current_epoch = int(public_inputs["current_epoch"])
            accumulator_root = hex_to_field(public_inputs["accumulator_root"])
            timestamp = int(public_inputs["timestamp"])
            issuer_key_x = bytes.fromhex(public_inputs["issuer_public_key_x"].removeprefix("0x"))
            issuer_key_y = bytes.fromhex(public_inputs["issuer_public_key_y"].removeprefix("0x"))
        except (KeyError, ValueError) as exc:
            result.add(
                Code.MALFORMED_PROOF,
                f"unparseable public inputs for {proof_type}: {exc}",
                proof_type=proof_type,
            )
            return

        # Context binding of the proof itself.
        if proof_context != request.context.value:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof context mismatch for {proof_type}",
                proof_type=proof_type,
            )
        if timestamp != request.context.timestamp:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof timestamp does not match context timestamp for {proof_type}",
                proof_type=proof_type,
            )

        # Issuer trust (no canonical issuers; key-exact allowlist match).
        issuer = self._trust_policy.issuer_by_key(issuer_key_x, issuer_key_y)
        if issuer is None:
            result.add(
                Code.UNTRUSTED_ISSUER,
                f"issuer public key not in trust policy for {proof_type}",
                proof_type=proof_type,
            )
            return
        if not self._trust_policy.trusts(issuer, proof_type):
            result.add(
                Code.UNTRUSTED_ISSUER,
                f"issuer {issuer.issuer_id} not trusted for {proof_type}",
                proof_type=proof_type,
            )
            return

        # Accumulator freshness and authenticated root acceptance.
        self._verify_accumulator_state(
            issuer_id=issuer.issuer_id,
            proof_type=proof_type,
            accumulator_epoch=accumulator_epoch,
            current_epoch=current_epoch,
            accumulator_root=accumulator_root,
            request=request,
            result=result,
        )

        # Per-predicate request binding — the same chokepoint the v1 path uses.
        # The v2 claim bindings are computed identically to v1 (the v2 witnesses
        # reuse the v1 claim-binding preimages), so one registry serves both.
        self._verify_type_specific_requirements(
            proof_type, public_inputs, request, claim_binding, proof_context, timestamp, result
        )

    # ------------------------------------------------------------------

    def _verify_type_specific_requirements(
        self, proof_type, public_inputs, request, claim_binding, proof_context, timestamp, result
    ) -> None:
        """Reference ``verifyTypeSpecificRequirements`` implementation (§6.2 step 4e).

        Bind a verified proof to the request that asked for it. The method name
        deliberately mirrors the normative specification so the documented
        function and the executable shared chokepoint cannot drift into two
        independently interpreted checks.

        This lives in ``_verify_individual`` / ``_verify_individual_v2`` and NOT
        in :meth:`verify_authenticated` on purpose. Nothing outside the profile
        tests calls ``verify_authenticated``: every consumer (the predicate
        tests, the conformance adapters, ``zkc_agent.verify_counterparty``,
        ``zkc_holder.audit_export.reverify_bundle_proofs``) enters through bare
        ``verify``. Binding on the authenticated path only would have left all of
        them verifying against nothing — which is precisely the hole being
        closed. ``verify_authenticated`` ADDS its APR-agreement check on top of
        this, it does not replace it.

        Fail closed at every exit: a proof type with no registered contract is
        UNBOUND_PROOF_TYPE, an unparseable public input is MALFORMED_PROOF, and
        a missing or unusable request parameter is REQUIREMENTS_NOT_MET. No
        check is ever skipped because a value happens to be absent."""
        contract = _REQUEST_BINDINGS.get(proof_type)
        if contract is None:
            result.add(
                Code.UNBOUND_PROOF_TYPE,
                f"proof type {proof_type} has no registered request-binding contract",
                proof_type=proof_type,
            )
            return

        all_parameters = request.parameters
        if (
            not isinstance(all_parameters, dict)
            or proof_type not in all_parameters
            or not isinstance(all_parameters[proof_type], dict)
        ):
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request lacks usable parameters for {proof_type}",
                proof_type=proof_type,
            )
            return

        parameters = all_parameters[proof_type]
        predecessor = NONZERO_CREDENTIAL_PROOF_PREDECESSORS.get(proof_type, proof_type)
        expected_key = _CANONICAL_SET_KEY_BY_PROOF_TYPE.get(predecessor)
        unsupported = [
            key
            for key in CANONICAL_SET_PARAM_KEYS
            if key in parameters and key != expected_key
        ]
        if unsupported:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request supplies unsupported canonical-set parameter(s) "
                f"{', '.join(repr(key) for key in unsupported)} for {proof_type}",
                proof_type=proof_type,
            )
            return

        # Closed parameter vocabulary (security review R2.4). Every handler
        # below reads exact key names and defaults absent ones, so a key
        # outside the contract would otherwise be ignored silently: a
        # misspelled ``flagRequired`` dropped the requirement it stated while
        # the request still verified. Reject before any handler can default.
        accepted = self._request_parameter_keys.get(proof_type)
        if accepted is None:
            reason = self._request_parameter_contract_errors.get(
                proof_type, "no public-input binding sidecar resolves this proof type"
            )
            result.add(
                Code.UNBOUND_PROOF_TYPE,
                f"request-parameter contract is unavailable for {proof_type}: {reason}",
                proof_type=proof_type,
            )
            return
        unknown = unknown_request_parameters(accepted, parameters)
        if unknown:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request supplies unknown parameter(s) "
                f"{', '.join(repr(key) for key in unknown)} for {proof_type}; its "
                f"request-binding contract accepts only "
                f"{', '.join(repr(key) for key in sorted(accepted)) or 'no parameters'}",
                proof_type=proof_type,
            )
            return

        if contract.handler == _HANDLER_KYC:
            self._verify_kyc_requirements(proof_type, request, claim_binding, result)
            return
        if contract.handler == _HANDLER_CODE_SPACE:
            self._verify_code_space_requirements(proof_type, public_inputs, parameters, request, claim_binding, result)
            return
        if contract.handler == _HANDLER_SELECTIVE_DISCLOSURE:
            self._verify_selective_disclosure_requirements(
                proof_type,
                public_inputs,
                request,
                claim_binding,
                proof_context,
                timestamp,
                result,
            )
            return
        if contract.handler == _HANDLER_REBIND_AUTH:
            # The authenticated successors' envelope, issuer-trust and
            # revocation checks run in _verify_rebind_auth before this
            # dispatcher; only the optional sidecar pins remain.
            self._verify_conditional_request_pins(proof_type, public_inputs, parameters, result)
            # credentialId is admitted as the holder's selector of the
            # credential to migrate, but no step-4e rule compares it with the
            # free credential_id public input. Accepting the proof is
            # therefore not evidence the requested credential was migrated.
            if "credentialId" in parameters:
                result.add_warning(
                    WarningCode.UNBINDABLE_PARAMETER,
                    f"request parameter 'credentialId' for {proof_type} selects the "
                    "holder's credential but is not compared with the proof's "
                    "credential_id; acceptance is not evidence that this credential "
                    "was migrated, so a consumer that needs it MUST compare it itself",
                    proof_type=proof_type,
                )
            return
        if contract.handler == _HANDLER_REBIND:
            # Rebind has a distinct public-input shape, so its envelope/context
            # and claim-binding integrity checks run in _verify_rebind* before
            # reaching this dispatcher. Frozen proof types retain their
            # established hard-coded optional filters; only additive binding-v2
            # statements consume the structured sidecar pin contract.
            if proof_type in _SUCCESSOR_REBIND_PROOF_TYPES:
                self._verify_conditional_request_pins(
                    proof_type, public_inputs, parameters, result
                )
            elif proof_type in _LEGACY_REBIND_PROOF_TYPES:
                self._verify_rebind_requirements(proof_type, public_inputs, parameters, result)
            else:
                result.add(
                    Code.UNBOUND_PROOF_TYPE,
                    f"proof type {proof_type} has no rebind request-binding route",
                    proof_type=proof_type,
                )
            return
        self._verify_predicate_requirements(
            proof_type, contract.predicate, public_inputs, request, claim_binding, result
        )

    @staticmethod
    def _verify_code_space_requirements(proof_type, public_inputs, parameters, request, claim_binding, result):
        try:
            bound_set = resolve_code_space_request(proof_type, parameters)
        except (TypeError, ValueError) as exc:
            result.add(Code.REQUIREMENTS_NOT_MET, f"invalid code-space request: {exc}", proof_type=proof_type)
            return

        kind = bound_set.space.kind
        expected_public = {"code_space_id": bound_set.space.id}
        context = request.context
        if kind == "jurisdiction":
            membership_type = parameters["membershipType"]
            expected_public.update(
                jurisdiction_set_root=field_to_hex(bound_set.root),
                membership_type=membership_type,
                required_verification_method=bound_set.required_verification_method,
            )
            predecessor = compute_claim_binding_3(
                bound_set.root, membership_type, parameters["requiredClaimType"], context.value, context.timestamp,
            )
        else:
            predicate_type = PROFILE_PROOF_TYPES[proof_type]
            expected_public.update(set_root=field_to_hex(bound_set.root), predicate_type=predicate_type)
            predecessor = compute_claim_binding_4(
                predicate_type, 0, bound_set.minimum_tax_year, False, context.value, context.timestamp,
            )
        expected_binding = bind_code_space_statement(
            kind, bound_set.space.field_id, predecessor, bound_set.required_verification_method,
        )
        if claim_binding != expected_binding:
            result.add(Code.REQUIREMENTS_NOT_MET, "claim binding differs from the code-space request", proof_type=proof_type)
        for name, expected in expected_public.items():
            actual = public_inputs.get(name)
            if type(actual) is not type(expected) or actual != expected:
                result.add(Code.REQUIREMENTS_NOT_MET, f"{name} differs from the code-space request", proof_type=proof_type)

    def _verify_kyc_requirements(self, proof_type, request, claim_binding, result) -> None:
        """KYC level + exact five-boolean attribute binding for v1 and v2."""
        parameters = request.parameters.get(proof_type, {})
        try:
            required_level = parameters["requiredLevel"]
            required_attributes = parameters["requiredAttributes"]
        except (KeyError, TypeError):
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request lacks usable parameters for {proof_type}",
                proof_type=proof_type,
            )
            return
        if (
            type(required_level) is not int
            or not 0 <= required_level <= 0xFF
            or not isinstance(required_attributes, list)
            or len(required_attributes) != 5
            or any(type(flag) is not bool for flag in required_attributes)
        ):
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request lacks usable parameters for {proof_type}",
                proof_type=proof_type,
            )
            return
        expected_binding = compute_claim_binding_2(
            required_level,
            compute_attribute_flags_hash(required_attributes),
            request.context.value,
            request.context.timestamp,
        )
        if claim_binding != expected_binding:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"claim binding does not attest the requested parameters for {proof_type}",
                proof_type=proof_type,
            )

    def _verify_conditional_request_pins(
        self, proof_type, public_inputs, parameters, result
    ) -> bool:
        """Apply every optional Field equality filter declared by the sidecar.

        Absence of a parameter deliberately means "no filter".  Presence means
        an exact canonical BN254 integer is required; in particular, ``null``
        is not another spelling of omission.  The sidecar is the authoritative
        mapping from a proof's snake-case public input to its camel-case
        request parameter, so this check remains correct when circuits reorder
        their public inputs or add future conditional pins.
        """
        if proof_type in self._conditional_pin_contract_errors:
            result.add(
                Code.UNBOUND_PROOF_TYPE,
                f"conditional request-pin contract is unavailable or malformed for "
                f"{proof_type}: {self._conditional_pin_contract_errors[proof_type]}",
                proof_type=proof_type,
            )
            return False
        if proof_type not in self._conditional_pins_by_proof_type:
            result.add(
                Code.UNBOUND_PROOF_TYPE,
                f"proof type {proof_type} has no conditional request-pin contract",
                proof_type=proof_type,
            )
            return False
        pins = self._conditional_pins_by_proof_type[proof_type]

        valid = True
        for public_name, parameter in pins:
            if parameter not in parameters:
                continue
            expected = parameters[parameter]
            if type(expected) is not int or not 0 <= expected < FIELD_MODULUS:
                result.add(
                    Code.REQUIREMENTS_NOT_MET,
                    f"conditional request pin '{parameter}' is not a canonical field "
                    f"integer for {proof_type}",
                    proof_type=proof_type,
                )
                valid = False
                continue
            try:
                actual = hex_to_field(public_inputs[public_name])
            except (KeyError, TypeError, ValueError) as exc:
                result.add(
                    Code.MALFORMED_PROOF,
                    f"unparseable public input '{public_name}' for conditional request "
                    f"pin in {proof_type}: {exc}",
                    proof_type=proof_type,
                )
                valid = False
                continue
            if actual != expected:
                result.add(
                    Code.REQUIREMENTS_NOT_MET,
                    f"public input '{public_name}' does not match conditional request "
                    f"pin '{parameter}' for {proof_type}",
                    proof_type=proof_type,
                )
                valid = False
        return valid

    def _verify_rebind_requirements(self, proof_type, public_inputs, parameters, result) -> None:
        """Frozen issuer/schema filters for the two legacy rebind statements.

        This intentionally retains the original request vocabulary and
        hard-coded public names. Binding-v2 successor statements use the
        structured sidecar contract above instead, so their policy cannot be
        mistaken for a retroactive semantic change to a published proof type.
        """
        try:
            actual = {
                "issuerIdHash": hex_to_field(public_inputs["issuer_id_hash"]),
                "schemaIdHash": hex_to_field(public_inputs["schema_id_hash"]),
            }
        except (KeyError, TypeError, ValueError) as exc:
            result.add(
                Code.MALFORMED_PROOF,
                f"unparseable rebind filter public inputs for {proof_type}: {exc}",
                proof_type=proof_type,
            )
            return

        labels = {"issuerIdHash": "issuer", "schemaIdHash": "schema"}
        for key, label in labels.items():
            # Preserve the frozen proof types' published request semantics:
            # explicit null is equivalent to omission.
            # Binding-v2 successors use _verify_conditional_request_pins,
            # where presence is strict and null is rejected.
            expected = parameters.get(key)
            if expected is None:
                continue
            if type(expected) is not int or not 0 <= expected < FIELD_MODULUS:
                result.add(
                    Code.REQUIREMENTS_NOT_MET,
                    f"rebind {label} id hash filter is not a canonical field integer "
                    f"for {proof_type}",
                    proof_type=proof_type,
                )
                continue
            if actual[key] != expected:
                result.add(
                    Code.REQUIREMENTS_NOT_MET,
                    f"rebind {label} id hash does not match the requested {label} "
                    f"for {proof_type}",
                    proof_type=proof_type,
                )

    def _resolve_binding_source(self, proof_type, source, parameters, result, cache) -> int:
        """Resolve one registry source to the integer the verifier expects.

        ``result`` and ``cache`` are used by ``_CanonicalSetRoot`` sources.
        Resolution is memoized per call (keyed by ``id(source)``) so a source
        reused across both a claim slot and a public comparison (jurisdiction's
        set root) is derived only once per proof."""
        if isinstance(source, _CanonicalSetRoot):
            cache_key = id(source)
            if cache_key not in cache:
                cache[cache_key] = self._resolve_canonical_set_root(
                    proof_type, source, parameters, result
                )
            return cache[cache_key]
        if isinstance(source, _PredicateType):
            predicate_type = self._predicate_type_by_proof_type.get(proof_type)
            if predicate_type is None:
                # One verification key covers four predicate meanings, so with
                # no selector there is nothing separating them. Never default.
                raise _BindingUnavailable(
                    Code.UNBOUND_PROOF_TYPE,
                    f"no published predicate_type selector for {proof_type}",
                )
            return predicate_type
        if isinstance(source, _BoolParam):
            value = parameters.get(source.key, source.default)
            if value is _MANDATORY:
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request lacks required parameter '{source.key}' for {proof_type}",
                )
            if type(value) is not bool:
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request parameter '{source.key}' must be an exact JSON "
                    f"boolean for {proof_type}",
                )
            return value
        if isinstance(source, _FixedBool):
            supplied = parameters.get(source.request_key, source.value)
            if type(supplied) is not bool:
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request parameter '{source.request_key}' must be an exact "
                    f"JSON boolean for {proof_type}",
                )
            if supplied is not source.value:
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request parameter '{source.request_key}' must be "
                    f"{str(source.value).lower()} for {proof_type}: the parameter is only "
                    "meaningful for institutional accreditation",
                )
            return source.value
        if isinstance(source, _FixedValue):
            # The circuit never constrains this input on this branch, so the
            # request is never allowed to move it: a request asking for
            # anything but the fixed literal is asking for something the
            # predicate cannot express, and is rejected rather than silently
            # "expected" at whatever value the request happens to supply.
            supplied = parameters.get(source.request_key, source.value)
            if type(supplied) is not int or not 0 <= supplied < FIELD_MODULUS:
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request parameter '{source.request_key}' is not an "
                    f"integer in the BN254 field range for {proof_type}",
                )
            if supplied != source.value:
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request parameter '{source.request_key}' must be "
                    f"{source.value} for {proof_type}: the predicate never constrains "
                    "this public input, so it cannot enforce any other value",
                )
            return source.value
        value = parameters.get(source.key, source.default)
        if value is _MANDATORY:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request lacks required parameter '{source.key}' for {proof_type}",
            )
        if type(value) is not int or not 0 <= value < source.upper_bound:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request parameter '{source.key}' must be an exact integer "
                f"in [0, {source.upper_bound}) for {proof_type}",
            )
        return value

    def _canonical_set_mode(self, proof_type, source, parameters, result) -> str:
        """The mode (inclusion/exclusion) this predicate's set must be built in.

        NEVER defaulted. Only an exclusion set is sentinel-bracketed, and
        bracketing an inclusion set makes codes 0 and 65535 provable members of
        it (the circuits' inclusion branches are bare Merkle membership checks
        with no domain constraint on the subject code). Fixed by the predicate
        for the raw-code proof types; read from the request's MANDATORY
        ``membershipType`` for jurisdiction, the one predicate offering both."""
        if source.mode is not None:
            return source.mode
        if source.mode_source is None:  # pragma: no cover - registry invariant
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"no canonical-set mode declared for {proof_type}; refusing to "
                "default it",
            )
        membership_type = parameters.get(source.mode_source.key, _MANDATORY)
        if membership_type is _MANDATORY:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request lacks required parameter "
                f"'{source.mode_source.key}' for {proof_type}",
            )
        if type(membership_type) is not int:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request parameter '{source.mode_source.key}' must be an "
                f"integer for {proof_type}",
            )
        if membership_type == MEMBERSHIP_TYPE_EXCLUSION:
            return CANONICAL_SET_EXCLUSION
        if membership_type == MEMBERSHIP_TYPE_INCLUSION:
            return CANONICAL_SET_INCLUSION
        raise _BindingUnavailable(
            Code.REQUIREMENTS_NOT_MET,
            f"verifier request parameter '{source.mode_source.key}' for {proof_type} "
            f"is {membership_type}, which names neither inclusion "
            f"({MEMBERSHIP_TYPE_INCLUSION}) nor exclusion "
            f"({MEMBERSHIP_TYPE_EXCLUSION}); the canonical set's mode cannot be "
            "resolved and is never defaulted",
        )

    def _resolve_canonical_set_root(self, proof_type, source, parameters, result) -> int:
        """Derive and compare a canonical jurisdiction/sanctions root.

        The signed request root is mandatory for holder distribution. Exclusion
        additionally requires the code set that makes the root independently
        derivable; jurisdiction inclusion may retain its legacy bare-root shape.
        Malformed input always becomes REQUIREMENTS_NOT_MET, never a crash.
        """
        # A canonical set supplied under a key this predicate does not read is
        # REJECTED, never ignored. Ignoring it silently downgrades the request
        # to the unverified bare-root path (or to "no root at all"): the
        # operator asked for derive-and-compare, would get none, and the
        # holder's matching fail-fast would be a complete no-op — the exact
        # false assurance this chokepoint exists to prevent.
        mis_keyed = [
            key
            for key in CANONICAL_SET_PARAM_KEYS
            if key != source.codes_key and key in parameters
        ]
        if mis_keyed:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request supplies canonical set parameter(s) "
                f"{', '.join(repr(key) for key in mis_keyed)} for {proof_type}, which "
                f"reads its canonical set from '{source.codes_key}'; a mis-keyed set "
                "would be silently ignored, so it is rejected instead",
            )

        mode = self._canonical_set_mode(proof_type, source, parameters, result)
        has_codes = source.codes_key in parameters
        has_root = source.root_key in parameters
        codes_value = parameters.get(source.codes_key)
        root_value = parameters.get(source.root_key)

        if not has_root or root_value is None:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request lacks APR-distributed root parameter "
                f"'{source.root_key}' for {proof_type}",
            )

        if type(root_value) is not int or not 0 <= root_value < FIELD_MODULUS:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request parameter '{source.root_key}' for {proof_type} "
                "must be an integer in the BN254 field range",
            )

        if not has_codes:
            if mode == CANONICAL_SET_EXCLUSION:
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request lacks required canonical blocked-set parameter "
                    f"'{source.codes_key}' for exclusion proof {proof_type}; a bare root "
                    "cannot attest sortedness, uniqueness, consecutive indices, or "
                    "sentinel bracketing",
                )
            # Jurisdiction inclusion has no sorted-neighbour construction
            # obligation, so its established direct request-root binding remains
            # valid when no canonical codes are supplied.
            return root_value

        # A canonical set was supplied: DERIVE the root (D1/D4) rather than
        # trust any literal. Malformed input is REQUIREMENTS_NOT_MET, never a
        # crash — every conversion below is guarded.
        if not _is_json_array(codes_value):
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request parameter '{source.codes_key}' for {proof_type} must "
                "be a JSON array of integer codes",
            )
        if len(codes_value) > CANONICAL_SET_MAX_REQUEST_CODES:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request parameter '{source.codes_key}' for {proof_type} "
                f"has more than {CANONICAL_SET_MAX_REQUEST_CODES} entries before "
                "deduplication",
            )
        codes = []
        for code in codes_value:
            if isinstance(code, bool) or not isinstance(code, int):
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request parameter '{source.codes_key}' for {proof_type} "
                    "must contain only integer codes",
                )
            codes.append(code)

        claim_type = None
        if source.claim_type_source is not None:
            claim_type = parameters.get(source.claim_type_source.key, _MANDATORY)
            if claim_type is _MANDATORY:
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request lacks required parameter "
                    f"'{source.claim_type_source.key}' for {proof_type}",
                )
            if type(claim_type) is not int or not 0 <= claim_type <= 0xFF:
                raise _BindingUnavailable(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request parameter '{source.claim_type_source.key}' "
                    f"must be a u8 integer for {proof_type}",
                )
        try:
            if claim_type is not None:
                derived_set = CanonicalCodeSet.for_jurisdiction(codes, claim_type, mode)
            else:
                if mode != CANONICAL_SET_EXCLUSION:  # pragma: no cover - registry invariant
                    raise CanonicalSetError(
                        "sanctions canonical set must use exclusion mode"
                    )
                derived_set = CanonicalCodeSet.for_sanctions(codes)
            derived_root = derived_set.root()
        except CanonicalSetError as exc:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request parameter '{source.codes_key}' for {proof_type} does "
                f"not form a valid canonical set: {exc}",
            ) from exc

        supplied_root = root_value
        if supplied_root != derived_root:
            raise _BindingUnavailable(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request supplies '{source.codes_key}' and "
                f"'{source.root_key}' for {proof_type}, and they disagree: the "
                f"canonical set derives root {derived_root:#x} but "
                f"'{source.root_key}' states {supplied_root:#x}",
            )

        return derived_root

    def _verify_predicate_requirements(
        self, proof_type, binding, public_inputs, request, claim_binding, result
    ) -> None:
        """Generic predicate binding: claim-binding recompute + direct compares.

        Both halves are needed. The recompute is the half the circuit itself
        already guarantees (it asserts the same preimage), so it catches any
        swapped slot; the direct comparisons catch what the preimage does NOT
        cover — ``set_root`` above all — and give a precise error for the
        ``predicate_type`` selector that separates four meanings sharing one
        verification key."""
        parameters = request.parameters.get(proof_type, {})
        if not isinstance(parameters, dict):
            # Fail closed rather than crash: a non-mapping value (None, a
            # list, ...) here would otherwise reach ``.get`` inside
            # ``_resolve_binding_source`` and raise AttributeError past this
            # method's own docstring ("fail closed at every exit"). Mirrors
            # the KYC path's (KeyError, TypeError, ValueError) catch below.
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request lacks usable parameters for {proof_type}",
                proof_type=proof_type,
            )
            return

        # Interim fail-closed policy for immutable legacy circuits. They do
        # not bind these booleans, so only absent/false is safe. A positive
        # requirement must use the successor statement that commits to it.
        for key in binding.legacy_fail_closed_bools:
            if key not in parameters:
                continue
            value = parameters[key]
            if type(value) is not bool:
                result.add(
                    Code.REQUIREMENTS_NOT_MET,
                    f"verifier request parameter '{key}' for {proof_type} must be an "
                    "exact JSON boolean",
                    proof_type=proof_type,
                )
                return
            if value:
                result.add(
                    Code.REQUIREMENTS_NOT_MET,
                    f"legacy proof type {proof_type} cannot attest {key}=true; require "
                    "the current v7/v8 successor proof type",
                    proof_type=proof_type,
                )
                return

        # A request parameter a future contract declares structurally
        # unbindable is never rejected — a
        # verifier may legitimately want it enforced — but silently accepting
        # it would be false assurance because no proof can attest that it was
        # checked. Warn, don't error: warnings never affect ``.valid``
        # (errors.py), so the warning informs the caller without rejecting the
        # request. Reserved canonical-set keys are different: the central
        # dispatch above rejects them on unsupported predicates rather than
        # treating them as unbindable hints.
        for key in binding.unbindable:
            if key in parameters:
                result.add_warning(
                    WarningCode.UNBINDABLE_PARAMETER,
                    f"request parameter '{key}' for {proof_type} cannot be enforced by "
                    "any verifier on this predicate: it is a private circuit witness "
                    "outside the public claim binding, so nothing in the proof attests "
                    "to it and acceptance is not evidence the requirement was met",
                    proof_type=proof_type,
                )

        # Per-call memoization for ``_CanonicalSetRoot`` sources: a source
        # shared between a claim slot and a public comparison is derived once.
        cache = {}
        try:
            slots = [
                self._resolve_binding_source(proof_type, source, parameters, result, cache)
                for source in binding.claim_slots
            ]
            expected_public = [
                (
                    comparison,
                    self._resolve_binding_source(
                        proof_type, comparison.source, parameters, result, cache
                    ),
                )
                for comparison in binding.public_comparisons
            ]
        except _BindingUnavailable as exc:
            result.add(exc.code, exc.message, proof_type=proof_type)
            return

        # The context value/timestamp come from the REQUEST, not the proof: the
        # binding must attest what this verifier asked for. A proof carrying a
        # different context has already been flagged CONTEXT_MISMATCH above.
        if binding.claim_binding_version == 3:
            expected_binding = compute_claim_binding_3(
                slots[0],
                slots[1],
                slots[2],
                request.context.value,
                request.context.timestamp,
            )
        elif binding.claim_binding_version == 4:
            expected_binding = compute_claim_binding_4(
                slots[0],
                slots[1],
                slots[2],
                slots[3],
                request.context.value,
                request.context.timestamp,
            )
        else:  # pragma: no cover - static registry invariant
            result.add(
                Code.UNBOUND_PROOF_TYPE,
                f"unsupported claim-binding generation for {proof_type}",
                proof_type=proof_type,
            )
            return
        if claim_binding != expected_binding:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"claim binding does not attest the requested parameters for {proof_type}",
                proof_type=proof_type,
            )

        for comparison, expected in expected_public:
            try:
                raw = public_inputs[comparison.name]
                if comparison.decoder == "field":
                    actual = hex_to_field(raw)
                else:
                    if type(raw) is not int or not 0 <= raw <= 0xFF:
                        raise ValueError("expected an exact u8 integer")
                    actual = raw
            except (KeyError, TypeError, ValueError) as exc:
                result.add(
                    Code.MALFORMED_PROOF,
                    f"unparseable public input {comparison.name} for {proof_type}: {exc}",
                    proof_type=proof_type,
                )
                continue
            if actual != expected:
                result.add(
                    Code.REQUIREMENTS_NOT_MET,
                    f"public input {comparison.name} does not match the requested value "
                    f"for {proof_type}",
                    proof_type=proof_type,
                )

    def _verify_selective_disclosure_requirements(
        self,
        proof_type,
        public_inputs,
        request,
        claim_binding,
        proof_context,
        timestamp,
        result,
    ) -> None:
        """Check only the public disclosure policy/transcript contract.

        Issuer signature, credential contents, holder binding, and
        non-revocation stay inside the ZKC circuit plus the generic issuer
        policy path above. ZKA/AFP consumers therefore need no issuer logic.
        """
        try:
            credential_count = public_inputs["credential_attribute_count"]
            disclosure_count = public_inputs["disclosure_count"]
            if type(credential_count) is not int or type(disclosure_count) is not int:
                raise ValueError("disclosure counts must be integers")
            flags = public_inputs["disclosed_flags"]
            encoded_values = public_inputs["disclosed_attributes"]
            if not isinstance(flags, list) or len(flags) != 8:
                raise ValueError("disclosed_flags must contain exactly 8 booleans")
            if not all(type(flag) is bool for flag in flags):
                raise ValueError("disclosed_flags must contain only booleans")
            if not isinstance(encoded_values, list) or len(encoded_values) != 8:
                raise ValueError("disclosed_attributes must contain exactly 8 fields")
            values = [hex_to_field(value) for value in encoded_values]
            if not 1 <= credential_count <= 8:
                raise ValueError("credential_attribute_count must be between 1 and 8")
            if disclosure_count != sum(flags) or disclosure_count < 1:
                raise ValueError("disclosure_count must equal the non-empty public mask")
            if any(flags[credential_count:]):
                raise ValueError("disclosure mask selects a credential padding position")
            if any(value != 0 for flag, value in zip(flags, values) if not flag):
                raise ValueError("hidden disclosed-attribute slots must be zero")
        except (KeyError, TypeError, ValueError) as exc:
            result.add(
                Code.MALFORMED_PROOF,
                f"unparseable selective-disclosure public inputs: {exc}",
                proof_type=proof_type,
            )
            return

        parameters = request.parameters.get(proof_type, {})
        if not isinstance(parameters, dict):
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request lacks usable parameters for {proof_type}",
                proof_type=proof_type,
            )
            return
        positions = parameters.get("disclosedPositions")
        try:
            requested_layout = parse_attribute_layout_id(parameters.get("layoutId"))
        except ValueError as exc:
            result.add(Code.REQUIREMENTS_NOT_MET, str(exc), proof_type=proof_type)
            return

        if proof_type in _LAYOUT_BOUND_DISCLOSURE_PROOF_TYPES:
            layout_id = parse_attribute_layout_id(public_inputs["layout_id"])
            if layout_id != requested_layout:
                result.add(Code.REQUIREMENTS_NOT_MET, "proof layoutId differs from the request", proof_type=proof_type)
            expected_binding = compute_selective_disclosure_binding_v3(
                layout_id, credential_count, flags, values, proof_context, timestamp,
            )
        else:
            issuer_key_x = bytes.fromhex(public_inputs["issuer_public_key_x"][2:])
            issuer_key_y = bytes.fromhex(public_inputs["issuer_public_key_y"][2:])
            layout_id = self._trust_policy.legacy_attribute_layout_id(issuer_key_x, issuer_key_y)
            if layout_id != parameters["layoutId"]:
                result.add(
                    Code.REQUIREMENTS_NOT_MET,
                    "requested layoutId does not match a single trusted pin for the issuer key",
                    proof_type=proof_type,
                )
            expected_binding = compute_selective_disclosure_binding(
                credential_count, flags, values, proof_context, timestamp,
            )
        if (
            not isinstance(positions, list)
            or any(type(position) is not int for position in positions)
            or len(set(positions)) != len(positions)
            or any(position < 0 or position >= credential_count for position in positions)
        ):
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"verifier request lacks usable disclosedPositions for {proof_type}",
                proof_type=proof_type,
            )
            return
        expected_flags = [position in set(positions) for position in range(8)]
        if flags != expected_flags:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"disclosure mask does not match requested positions for {proof_type}",
                proof_type=proof_type,
            )
        if claim_binding != expected_binding:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"typed disclosure transcript mismatch for {proof_type}",
                proof_type=proof_type,
            )

    # ------------------------------------------------------------------

    def _verify_rebind_auth(
        self,
        proof_type,
        public_inputs,
        request,
        binding_handle,
        result,
        *,
        presentation_profile,
        binding_scope_id,
    ) -> None:
        """Verify an ISSUER-AUTHENTICATED credential-rebind proof (spec 7.4.5).

        Serves both successors from both envelope paths: ``binding_handle`` is
        the envelope's holder commitment on the v1 path and its presentation
        pseudonym on the v2 path, and ``presentation_profile`` is the
        envelope's profile (linkable for a v1 envelope). The linkable
        statement is admissible only in a v1 envelope and the scoped ones only
        in a scoped v2 envelope; anything else is PROFILE_MISMATCH, and the
        issuer controls below still run so the result reports them too.

        Unlike the deprecated rebind branches, this applies the FULL
        issuer-authenticated path -- exact key trust, issuer-identity
        agreement, and an authenticated accumulator root/epoch for the same
        issuer -- because the statement actually authenticates a credential.
        There is no escape from those controls: a request pin is applied only
        afterwards and can only narrow acceptance. Fail closed at every exit.
        """
        scoped = proof_type in _SCOPED_REBIND_AUTH_PROOF_TYPES
        try:
            if scoped:
                old_handle = hex_to_field(public_inputs["old_presentation_pseudonym"])
                new_handle = hex_to_field(public_inputs["new_presentation_pseudonym"])
                scope_id = hex_to_field(public_inputs["scope_id"])
            else:
                old_handle = hex_to_field(public_inputs["old_holder_commitment"])
                new_handle = hex_to_field(public_inputs["new_holder_commitment"])
                scope_id = None
            credential_id = hex_to_field(public_inputs["credential_id"])
            issuer_id_hash = hex_to_field(public_inputs["issuer_id_hash"])
            proof_context = hex_to_field(public_inputs["proof_context"])
            timestamp = int(public_inputs["timestamp"])
            claim_binding = hex_to_field(public_inputs["claim_binding"])
            accumulator_root = hex_to_field(public_inputs["accumulator_root"])
            accumulator_epoch = int(public_inputs["accumulator_epoch"])
            current_epoch = int(public_inputs["current_epoch"])
            issuer_key_x = bytes.fromhex(public_inputs["issuer_public_key_x"].removeprefix("0x"))
            issuer_key_y = bytes.fromhex(public_inputs["issuer_public_key_y"].removeprefix("0x"))
        except (KeyError, ValueError, TypeError) as exc:
            result.add(
                Code.MALFORMED_PROOF,
                f"unparseable public inputs for {proof_type}: {exc}",
                proof_type=proof_type,
            )
            return

        # Presentation shape (scoped successor only): rebind is verifier-facing
        # continuity, so the envelope MUST be scoped and its handles MUST match.
        if scoped:
            if presentation_profile != SCOPED_PROFILE:
                result.add(
                    Code.PROFILE_MISMATCH,
                    f"rebind requires the scoped presentation profile for {proof_type}",
                    proof_type=proof_type,
                )
            if scope_id == 0:
                result.add(
                    Code.PROFILE_MISMATCH,
                    f"rebind requires a non-zero scope for {proof_type}",
                    proof_type=proof_type,
                )
            if scope_id != binding_scope_id:
                result.add(
                    Code.PROFILE_MISMATCH,
                    f"rebind scope differs from the envelope presentation binding "
                    f"for {proof_type}",
                    proof_type=proof_type,
                )
            if old_handle != binding_handle:
                result.add(
                    Code.PROFILE_MISMATCH,
                    f"rebind old pseudonym differs from the envelope presentation binding "
                    f"for {proof_type}",
                    proof_type=proof_type,
                )
        else:
            if presentation_profile != LINKABLE_PROFILE:
                result.add(
                    Code.PROFILE_MISMATCH,
                    f"linkable rebind {proof_type} requires a zkc:proof:v1 envelope",
                    proof_type=proof_type,
                )
            if old_handle != binding_handle:
                # A rebind is presented under the holder's CURRENT (old) identity.
                result.add(
                    Code.INVALID_BINDING,
                    f"rebind old holder commitment differs from envelope holder binding "
                    f"for {proof_type}",
                    proof_type=proof_type,
                )

        # The circuit already enforces old != new; reject defensively.
        if old_handle == new_handle:
            result.add(
                Code.INVALID_BINDING,
                f"rebind does not change the holder handle for {proof_type}",
                proof_type=proof_type,
            )

        # Context binding of the proof itself.
        if proof_context != request.context.value:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof context mismatch for {proof_type}",
                proof_type=proof_type,
            )
        if timestamp != request.context.timestamp:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof timestamp does not match context timestamp for {proof_type}",
                proof_type=proof_type,
            )

        # Issuer trust: exact key-allowlist membership, trusted for THIS proof
        # type. Everything below depends on it, so it returns on failure.
        issuer = self._trust_policy.issuer_by_key(issuer_key_x, issuer_key_y)
        if issuer is None:
            result.add(
                Code.UNTRUSTED_ISSUER,
                f"issuer public key not in trust policy for {proof_type}",
                proof_type=proof_type,
            )
            return
        if not self._trust_policy.trusts(issuer, proof_type):
            result.add(
                Code.UNTRUSTED_ISSUER,
                f"issuer {issuer.issuer_id} not trusted for {proof_type}",
                proof_type=proof_type,
            )
            return

        # Issuer identity agreement: the credential the issuer signed names the
        # SAME issuer whose key the verifier just matched. Without this a
        # trusted key could carry an attestation labelled with another issuer.
        if issuer_id_hash != string_to_field(issuer.issuer_id):
            result.add(
                Code.UNTRUSTED_ISSUER,
                f"proof issuer identity does not match the trusted issuer "
                f"{issuer.issuer_id} for {proof_type}",
                proof_type=proof_type,
            )
            return

        # Authenticated non-revocation state for that issuer (spec 7.4.5): the
        # root/epoch MUST come from signed announcement-chain ingestion.
        self._verify_accumulator_state(
            issuer_id=issuer.issuer_id,
            proof_type=proof_type,
            accumulator_epoch=accumulator_epoch,
            current_epoch=current_epoch,
            accumulator_root=accumulator_root,
            request=request,
            result=result,
        )

        # Claim-binding integrity over the profile's handles and the
        # authenticated credential id.
        expected_binding = compute_claim_binding_3(
            old_handle, new_handle, credential_id, proof_context, timestamp
        )
        if claim_binding != expected_binding:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"claim binding does not attest the rebind public inputs for {proof_type}",
                proof_type=proof_type,
            )

        # Optional request pins LAST: after authentication, narrowing only.
        self._verify_type_specific_requirements(
            proof_type,
            public_inputs,
            request,
            claim_binding,
            proof_context,
            timestamp,
            result,
        )

    # ------------------------------------------------------------------

    def _verify_rebind(self, proof_type, public_inputs, request, holder_commitment, result) -> None:
        """Envelope-level verification of a ``zkc_credential_rebind`` proof.

        The rebind circuit migrates a credential from an old holder commitment
        to a new one and, unlike the predicate circuits, carries no issuer
        signature or accumulator witness — its public inputs have neither an
        issuer public key nor an accumulator epoch/root to check. This branch
        verifies what the rebind proof *does* bind: context, the holder binding
        (a rebind is presented under the holder's current/old identity), the
        claim-binding integrity over the public values, and any issuer/schema
        the verifier pinned in its request. Fail closed, like the default path.

        SECURITY: these checks are structural only. None of them authenticates
        the credential (see ``_UNAUTHENTICATED_REBIND_PROOF_TYPES``); the
        dispatch-level containment rejects every historical rebind identity
        before this branch can run, and the branch re-checks that here so a
        direct call can never accept one either.
        """
        if proof_type in _UNAUTHENTICATED_REBIND_PROOF_TYPES:
            result.add(
                Code.UNAUTHENTICATED_CREDENTIAL,
                _UNAUTHENTICATED_REBIND_MESSAGE.format(proof_type=proof_type),
                proof_type=proof_type,
            )
            return
        try:
            old_holder = hex_to_field(public_inputs["old_holder_commitment"])
            new_holder = hex_to_field(public_inputs["new_holder_commitment"])
            credential_id = hex_to_field(public_inputs["credential_id"])
            proof_context = hex_to_field(public_inputs["proof_context"])
            timestamp = int(public_inputs["timestamp"])
            claim_binding = hex_to_field(public_inputs["claim_binding"])
        except (KeyError, ValueError) as exc:
            result.add(
                Code.MALFORMED_PROOF,
                f"unparseable public inputs for {proof_type}: {exc}",
                proof_type=proof_type,
            )
            return

        # Context binding of the proof itself.
        if proof_context != request.context.value:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof context mismatch for {proof_type}",
                proof_type=proof_type,
            )
        if timestamp != request.context.timestamp:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof timestamp does not match context timestamp for {proof_type}",
                proof_type=proof_type,
            )

        # Holder binding: a rebind is presented under the holder's CURRENT (old)
        # identity, proving migration to new_holder_commitment, so the envelope
        # holder binding must equal the OLD holder commitment.
        if old_holder != holder_commitment:
            result.add(
                Code.INVALID_BINDING,
                f"rebind old holder commitment differs from envelope holder binding "
                f"for {proof_type}",
                proof_type=proof_type,
            )
        # The circuit already enforces old != new; reject defensively so a no-op
        # rebind can never bind the envelope to a holder it never moved from.
        if new_holder == old_holder:
            result.add(
                Code.INVALID_BINDING,
                f"rebind does not change the holder commitment for {proof_type}",
                proof_type=proof_type,
            )

        # Claim-binding integrity: claim_binding must commit to exactly these
        # public values, so a verifier cannot be shown a proof whose public
        # holders/credential/context were swapped under a stale binding.
        expected_binding = compute_claim_binding_3(
            old_holder, new_holder, credential_id, proof_context, timestamp
        )
        if claim_binding != expected_binding:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"claim binding does not attest the rebind public inputs for {proof_type}",
                proof_type=proof_type,
            )
        self._verify_type_specific_requirements(
            proof_type,
            public_inputs,
            request,
            claim_binding,
            proof_context,
            timestamp,
            result,
        )

    # ------------------------------------------------------------------

    def _verify_rebind_v2(
        self,
        proof_type,
        public_inputs,
        request,
        presentation_profile,
        binding_pseudonym,
        binding_scope_id,
        result,
    ) -> None:
        """Envelope-level verification of a v2 ``zkc_credential_rebind`` proof
        (design §4.2, §6 rule 4).

        The v2 rebind public inputs are pseudonym-keyed: index 0/1 carry the old
        and new presentation pseudonyms sharing one ``scope_id`` (index 2); the
        global holder commitments are private witnesses. Rebind is verifier-facing
        continuity, so it is **scoped-only** — ``scope_id`` must be non-zero, and
        the envelope binding must be the scoped profile. This branch enforces:
        scope non-zero, ``old != new`` (defensively — the circuit also enforces
        it), scope/old-pseudonym consistency with the envelope binding (rule 2
        anti-replay, replacing the v1 ``old_holder == holder_commitment`` check),
        context binding, claim-binding integrity over the pseudonym-keyed values,
        and the pinned issuer/schema requirement checks. Fail closed.

        SECURITY: structural checks only -- see ``_verify_rebind``. The
        historical scoped identities are rejected at dispatch and again here.
        """
        if proof_type in _UNAUTHENTICATED_REBIND_PROOF_TYPES:
            result.add(
                Code.UNAUTHENTICATED_CREDENTIAL,
                _UNAUTHENTICATED_REBIND_MESSAGE.format(proof_type=proof_type),
                proof_type=proof_type,
            )
            return
        try:
            old_pseudonym = hex_to_field(public_inputs["old_presentation_pseudonym"])
            new_pseudonym = hex_to_field(public_inputs["new_presentation_pseudonym"])
            scope_id = hex_to_field(public_inputs["scope_id"])
            credential_id = hex_to_field(public_inputs["credential_id"])
            proof_context = hex_to_field(public_inputs["proof_context"])
            timestamp = int(public_inputs["timestamp"])
            claim_binding = hex_to_field(public_inputs["claim_binding"])
        except (KeyError, ValueError) as exc:
            result.add(
                Code.MALFORMED_PROOF,
                f"unparseable public inputs for {proof_type}: {exc}",
                proof_type=proof_type,
            )
            return

        # Rebind is scoped-only: no anonymous rebind exists.
        if presentation_profile != SCOPED_PROFILE:
            result.add(
                Code.PROFILE_MISMATCH,
                f"rebind requires the scoped presentation profile for {proof_type}",
                proof_type=proof_type,
            )
        if scope_id == 0:
            result.add(
                Code.PROFILE_MISMATCH,
                f"rebind requires a non-zero scope for {proof_type}",
                proof_type=proof_type,
            )

        # Shape consistency with the envelope binding (design §6 rule 2). The
        # rebind is presented under the holder's CURRENT (old) identity, so the
        # envelope binding pseudonym must equal the OLD presentation pseudonym,
        # and the binding scope must equal the proof's scope.
        if scope_id != binding_scope_id:
            result.add(
                Code.PROFILE_MISMATCH,
                f"rebind scope differs from the envelope presentation binding for {proof_type}",
                proof_type=proof_type,
            )
        if old_pseudonym != binding_pseudonym:
            result.add(
                Code.PROFILE_MISMATCH,
                f"rebind old pseudonym differs from the envelope presentation binding "
                f"for {proof_type}",
                proof_type=proof_type,
            )

        # The circuit already enforces old != new; reject defensively so a no-op
        # rebind can never bind the envelope to a pseudonym it never moved from.
        if old_pseudonym == new_pseudonym:
            result.add(
                Code.INVALID_BINDING,
                f"rebind does not change the presentation pseudonym for {proof_type}",
                proof_type=proof_type,
            )

        # Context binding of the proof itself.
        if proof_context != request.context.value:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof context mismatch for {proof_type}",
                proof_type=proof_type,
            )
        if timestamp != request.context.timestamp:
            result.add(
                Code.CONTEXT_MISMATCH,
                f"proof timestamp does not match context timestamp for {proof_type}",
                proof_type=proof_type,
            )

        # Claim-binding integrity: v2 claim_binding commits to the PSEUDONYMS
        # (design §4.2), so a verifier cannot be shown a proof whose public
        # pseudonyms/credential/context were swapped under a stale binding.
        expected_binding = compute_claim_binding_3(
            old_pseudonym, new_pseudonym, credential_id, proof_context, timestamp
        )
        if claim_binding != expected_binding:
            result.add(
                Code.REQUIREMENTS_NOT_MET,
                f"claim binding does not attest the rebind public inputs for {proof_type}",
                proof_type=proof_type,
            )
        self._verify_type_specific_requirements(
            proof_type,
            public_inputs,
            request,
            claim_binding,
            proof_context,
            timestamp,
            result,
        )

    # ------------------------------------------------------------------

    def _verify_aggregation(self, envelope, request, holder_commitment, result) -> None:
        """Check the legacy envelope commitment over individually checked proofs."""
        aggregation = envelope["aggregation"]
        if any(entry["proofType"] not in request.proof_types for entry in envelope["proofs"]):
            result.add(Code.INVALID_AGGREGATION, "aggregation includes an unrequested proof")
            return

        try:
            commitments = []
            type_fields = []
            consent_flags = []
            for proof_entry in envelope["proofs"]:
                # Use the same binding-policy decision as individual verification.
                # Keep artifact errors from duplicating the individual diagnostics.
                artifact_result = VerificationResult()
                resolved = self._resolve_proof_artifact(
                    proof_entry, artifact_result, load_vk=False, audit_binding=False
                )
                if resolved is None:
                    reasons = "; ".join(
                        f"{error.code}: {error.message}" for error in artifact_result.errors
                    )
                    result.add(
                        Code.INVALID_AGGREGATION,
                        f"aggregation proof artifact is not admitted ({reasons})",
                    )
                    return
                circuit, _vk_bytes, selector = resolved
                vk_hash = (
                    self._vk_store.binding_vk_hash(selector)
                    if selector is not None
                    else self._vk_store.vk_hash(circuit)
                )
                if vk_hash is None:
                    result.add(
                        Code.INVALID_AGGREGATION,
                        f"no manifest-pinned verification key hash for circuit {circuit}",
                    )
                    return
                commitments.append(commitment_for_envelope_proof(proof_entry, vk_hash))
                type_fields.append(string_to_field(proof_entry["proofType"]))
                consent_flags.append(bool(proof_entry["principalConsent"]))

            expected_inputs = [field_to_hex(value) for value in commitments]
            if aggregation["inputProofCommitments"] != expected_inputs:
                result.add(Code.INVALID_AGGREGATION, "input proof commitments do not match proofs")
                return
            expected_commitment = aggregate_commitments(
                request.context.value,
                holder_commitment,
                commitments,
                type_fields,
                consent_flags,
            )
            if hex_to_field(aggregation["aggregationCommitment"]) != expected_commitment:
                result.add(Code.INVALID_AGGREGATION, "aggregation commitment mismatch")
                return
            expected_claim = aggregated_claim_binding(expected_commitment, request.context.value)
            if hex_to_field(aggregation["aggregatedClaimBinding"]) != expected_claim:
                result.add(Code.INVALID_AGGREGATION, "aggregated claim binding mismatch")
        except Exception as exc:  # fail closed on anything unexpected
            result.add(Code.INVALID_AGGREGATION, f"aggregation verification failed: {type(exc).__name__}")
