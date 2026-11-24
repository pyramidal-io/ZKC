"""ZKC holder client (spec §5).

Non-custodial by construction: the master seed and credential binding key
never leave this process, are never serialized by the SDK, and are never
logged. Remote parties (issuers, verifiers, provers) only ever receive public
inputs, commitments, and proofs.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import hmac
import json
import logging
from collections.abc import Mapping

from zkc_crypto import (
    CANONICAL_SET_EXCLUSION,
    CANONICAL_SET_INCLUSION,
    CANONICAL_SET_MAX_REQUEST_CODES,
    CANONICAL_SET_PARAM,
    CANONICAL_SET_PARAM_KEYS,
    JURISDICTION_CANONICAL_SET_PARAM,
    FIELD_MODULUS,
    LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES,
    CanonicalCodeSet,
    CanonicalSetError,
    EnvelopeError,
    ProofContext,
    PURPOSE_BOUND_PROFILE,
    VERIFIER_SESSION_PROFILE,
    apr_freshness,
    apr_signer_pubkey,
    scope_from_apr_presentation,
    derive_credential_binding_key,
    derive_holder_commitment,
    field_to_hex,
    master_seed_to_bytes,
    parse_attribute_layout_id,
    receipt_digest_from_dict,
    sign_receipt,
    string_to_field,
    validate_compliance_proof_v1,
    validate_envelope,
    verify_apr_signature,
)
from zkc_crypto.apr import (
    LEGACY_MAX_PROOF_AGE,
    VERIFICATION_CONTEXT_EXTENSION,
    canonical_request_context,
)
from zkc_crypto.code_space_requests import (
    CODE_SPACE_ID_PARAM,
    REQUIRED_VERIFICATION_METHOD_PARAM,
    resolve_code_space_request,
)
from zkc_crypto.code_spaces import CODE_SPACE_CREDENTIAL_TO_KIND, CODE_SPACE_PROOF_TO_KIND, get_code_space
from zkc_crypto.code_space_transcripts import bind_code_space_statement
from zkc_crypto.credential_id_successors import (
    NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS,
    NONZERO_CREDENTIAL_PROOF_PREDECESSORS,
)
from zkc_crypto.ecdsa_secp256k1 import public_key_bytes, verify
from zkc_crypto.holder_keys import (
    derive_fresh_receipt_key,
    derive_linkable_receipt_key,
    derive_scoped_receipt_key,
    holder_public_key,
)
from zkc_crypto.presentation import (
    ANONYMOUS_PROFILE,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
    derive_verifier_identity,
)
from zkc_registry.predicate_v2 import parse_request_selectors

from . import aggregation as agg
from .ceilings import EXACT_MEMBER, set_disclosure
from .accumulator import MAX_EPOCH_LAG, AccumulatorProvider
from .backend import (
    COMMUNITY_KYC_V2_CIRCUIT,
    COMMUNITY_KYC_V2_PROOF_TYPE,
    KYC_CIRCUIT,
    KYC_PROOF_TYPE,
    KYC_V2_CIRCUIT,
    KYC_V2_PROOF_TYPE,
    KYC_V3_CIRCUIT,
    KYC_V3_PROOF_TYPE,
    ProofBackend,
    build_kyc_witness,
    build_kyc_witness_v2,
    stub_proof_payload,
)
from .credential import Credential, ProofRequest
from .disclosure import (
    DISCLOSURE_CIRCUIT,
    DISCLOSURE_V2_CIRCUIT,
    DISCLOSURE_V3_CIRCUIT,
    DISCLOSURE_V3_PROOF_TYPE,
    build_selective_disclosure_witness,
)
from .predicates import (
    JURISDICTION_V1_CIRCUIT,
    JURISDICTION_V1_PROOF_TYPE,
    JURISDICTION_V2_CIRCUIT,
    JURISDICTION_V2_PROOF_TYPE,
    JURISDICTION_V3_CIRCUIT,
    JURISDICTION_V3_PROOF_TYPE,
    JURISDICTION_V4_CIRCUIT,
    JURISDICTION_V4_PROOF_TYPE,
    JURISDICTION_V5_CIRCUIT,
    JURISDICTION_V5_PROOF_TYPE,
    JURISDICTION_V6_CIRCUIT,
    JURISDICTION_V6_PROOF_TYPE,
    MEMBERSHIP_TYPE_EXCLUSION,
    MEMBERSHIP_TYPE_INCLUSION,
    PREDICATE_ACCREDITATION,
    PREDICATE_SANCTIONS_CLEARANCE,
    PREDICATE_SOURCE_OF_FUNDS,
    PREDICATE_TAX_RESIDENCY,
    PROFILE_PROOF_TYPES,
    validate_profile_request_domains,
    REBIND_CIRCUIT,
    REBIND_PROOF_TYPE,
    REBIND_BINDING_V2_CIRCUIT,
    REBIND_BINDING_V2_PROOF_TYPE,
    REBIND_BINDING_V2_STATEMENT_DOMAIN,
    REBIND_V2_CIRCUIT,
    REBIND_V2_BINDING_V2_CIRCUIT,
    REBIND_V2_BINDING_V2_PROOF_TYPE,
    REBIND_V2_BINDING_V2_STATEMENT_DOMAIN,
    REBIND_AUTH_CIRCUIT,
    REBIND_AUTH_V2_CIRCUIT,
    REBIND_AUTH_V3_CIRCUIT,
    REBIND_AUTH_V3_PROOF_TYPE,
    REMAINING_CIRCUIT,
    REMAINING_V2_CIRCUIT,
    REMAINING_V3_CIRCUIT,
    REMAINING_V4_CIRCUIT,
    REMAINING_V5_CIRCUIT,
    REMAINING_V6_CIRCUIT,
    REMAINING_V7_CIRCUIT,
    REMAINING_V8_CIRCUIT,
    REMAINING_V9_CIRCUIT,
    REMAINING_V10_CIRCUIT,
    REMAINING_V11_CIRCUIT,
    build_jurisdiction_witness,
    build_jurisdiction_witness_v2,
    build_profile_witness,
    build_profile_witness_v2,
    build_profile_witness_v3,
    build_profile_witness_v4,
    build_profile_witness_v5,
    build_profile_witness_v6,
    build_profile_witness_v7,
    build_profile_witness_v8,
    build_rebind_witness,
    build_rebind_witness_v2,
    build_rebind_auth_witness,
    build_rebind_auth_witness_v2,
    refuse_unauthenticated_rebind,
    credential_proof_type_for_request,
    request_contract_proof_types,
    resolve_presentation_proof_type_for_request,
)
from .errors import (
    AmbiguousCredentialError,
    AnonymousCompositeRefusedError,
    BackendUnavailableError,
    CanonicalSetMismatchError,
    ConsentRequiredError,
    ConstraintViolationError,
    ContextError,
    ExactMemberConsentRequiredError,
    HolderError,
    NoMatchingCredentialError,
    OpaquePredicateError,
    StaleCredentialError,
    StaleWitnessError,
    UnauthenticatedRequestError,
    UnknownIssuerError,
)
from .rebind_secret import RebindSecret, refuse_secret_parameters
from .registry import BindingResolutionError, DEFAULT_ACCEPTED_STATUSES, PredicateRegistry
from .store import CredentialStore, InMemoryCredentialStore


def _canonical_json(value) -> str:
    """Canonical JSON used to compare signed and effective APR members."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _apr_context_matches_request(
    signed_request: dict, context: ProofContext, max_proof_age: int
) -> bool:
    """Compare authenticated context and age before any holder disclosure."""
    if not isinstance(context, ProofContext):
        raise ValueError("request context must be a ProofContext")
    # These fields would otherwise disappear during metadata serialization.
    if not context.verifier_id and context.session_id != 0:
        raise ValueError("context sessionId requires a verifierId")
    if context.profile != PURPOSE_BOUND_PROFILE and (context.purpose or context.purpose_tag):
        raise ValueError("context purpose fields require the purpose-bound profile")
    authenticated = canonical_request_context(signed_request["context"])
    supplied = canonical_request_context(context.to_metadata())
    extensions = signed_request.get("extensions", {})
    if not isinstance(extensions, dict):
        raise ValueError("request extensions must be an object")
    age = LEGACY_MAX_PROOF_AGE
    if VERIFICATION_CONTEXT_EXTENSION in extensions:
        constraints = extensions[VERIFICATION_CONTEXT_EXTENSION]
        if not isinstance(constraints, dict) or set(constraints) != {"context", "maxProofAge"}:
            raise ValueError("malformed signed verification-context extension")
        age = constraints["maxProofAge"]
        if type(age) is not int or age < 0:
            raise ValueError("signed maxProofAge must be a non-negative integer")
        bound = canonical_request_context(constraints["context"])
        if _canonical_json(bound) != _canonical_json(authenticated):
            raise ValueError("signed context extension disagrees with APR context")
    elif authenticated["profile"] not in (VERIFIER_SESSION_PROFILE, PURPOSE_BOUND_PROFILE):
        raise ValueError("opaque context requires a signed verification-context extension")
    wire_age = signed_request.get("maxProofAge", age)
    if type(wire_age) is not int or wire_age != age:
        raise ValueError("maxProofAge differs from signed verification constraints")
    if type(max_proof_age) is not int or max_proof_age < 0:
        raise ValueError("holder maxProofAge must be a non-negative integer")
    return _canonical_json(authenticated) == _canonical_json(supplied) and max_proof_age == age


def _is_json_array(value) -> bool:
    """Return whether ``value`` is the reference JSON-array representation.

    APR parameters originate as JSON, whose arrays decode to ``list``.  A
    tuple may serialize like an array but is not itself a JSON input and the
    canonical-set procedure requires non-array inputs to be rejected."""
    return isinstance(value, list)


def _canonical_set_mode(membership_type: int) -> str:
    """Protocol ``membership_type`` -> canonical-set mode.

    The mode decides sentinel bracketing, so it is resolved explicitly rather
    than defaulted: an EXCLUSION set is bracketed (every edge subject gets two
    real neighbours), an INCLUSION set is NOT (a sentinel leaf there would be a
    provable member of a set the verifier never declared it in)."""
    if int(membership_type) == MEMBERSHIP_TYPE_EXCLUSION:
        return CANONICAL_SET_EXCLUSION
    if int(membership_type) == MEMBERSHIP_TYPE_INCLUSION:
        return CANONICAL_SET_INCLUSION
    raise CanonicalSetMismatchError(
        f"membershipType {membership_type} names neither inclusion "
        f"({MEMBERSHIP_TYPE_INCLUSION}) nor exclusion ({MEMBERSHIP_TYPE_EXCLUSION}); "
        "the canonical set's mode cannot be resolved and is never defaulted"
    )


def _requires_exact_member_consent(proof_type: str, parameters: dict) -> bool:
    """A root and a fixed inclusion path constrain the credential to one code."""
    if not isinstance(parameters, dict):
        return False
    if proof_type in CODE_SPACE_PROOF_TO_KIND:
        _, outcome = set_disclosure(proof_type, parameters)
        return outcome == EXACT_MEMBER
    predecessor = NONZERO_CREDENTIAL_PROOF_PREDECESSORS.get(proof_type, proof_type)
    if predecessor in _JURISDICTION_PROOF_TYPES:
        return (
            parameters.get("membershipType") == MEMBERSHIP_TYPE_INCLUSION
            and JURISDICTION_CANONICAL_SET_PARAM not in parameters
        )
    return PROFILE_PROOF_TYPES.get(proof_type) in (
        PREDICATE_SOURCE_OF_FUNDS, PREDICATE_TAX_RESIDENCY,
    )


def _snapshot_proof_request(request: ProofRequest) -> ProofRequest:
    """Keep the reviewed proof types and parameter blocks stable while proving."""
    snapshot = copy.copy(request)
    snapshot.proof_types = copy.copy(request.proof_types)
    snapshot.binding_selectors = copy.deepcopy(request.binding_selectors)
    if isinstance(request.parameters, Mapping):
        snapshot.parameters = {
            proof_type: copy.deepcopy(dict(block)) if isinstance(block, Mapping) else block
            for proof_type, block in request.parameters.items()
        }
    return snapshot


def _validate_profile_request_domains(request: ProofRequest) -> None:
    """Validate original request values before profile resolution or int()."""
    for proof_type in request.proof_types:
        predicate_type = PROFILE_PROOF_TYPES.get(proof_type)
        if predicate_type is None:
            continue
        parameters = request.parameters.get(proof_type, {})
        if not isinstance(parameters, dict):
            raise CanonicalSetMismatchError(
                f"request parameters for {proof_type} must be a JSON object"
            )
        validate_profile_request_domains(
            predicate_type, parameters.get("required0", 0), parameters.get("required1", 0)
        )


def _profile_flag_required(
    parameters: dict,
    proof_type: str,
    predicate_type: int,
) -> bool:
    """Read flagRequired without Python truthiness or semantic aliases."""
    value = parameters.get("flagRequired", False)
    if type(value) is not bool:
        raise HolderError(
            f"request parameter 'flagRequired' for {proof_type} must be an exact JSON boolean"
        )
    if value and predicate_type != PREDICATE_ACCREDITATION:
        raise HolderError(
            f"request parameter 'flagRequired' is only meaningful for accreditation, not "
            f"{proof_type}"
        )
    if value and proof_type in (
        "zkc:proof:accreditation:v1",
        "zkc:proof:accreditation:v2",
    ):
        raise HolderError(
            f"legacy proof type {proof_type} cannot attest flagRequired=true; "
            "require the current v7/v8 successor proof type"
        )
    return value


__all__ = ["HolderClient"]

logger = logging.getLogger("zkc.holder")

_JURISDICTION_PROOF_TYPES = frozenset(
    {
        JURISDICTION_V1_PROOF_TYPE,
        JURISDICTION_V2_PROOF_TYPE,
        JURISDICTION_V3_PROOF_TYPE,
        JURISDICTION_V4_PROOF_TYPE,
        JURISDICTION_V5_PROOF_TYPE,
        JURISDICTION_V6_PROOF_TYPE,
    }
)

# Presentation-profile privacy ranks (design §1): a HIGHER rank carries MORE
# holder-linking information, so the holder may only ever move DOWN this ladder
# (downgrade-only, design §5.2 rule 4). anonymous < scoped < linkable.
_PRESENTATION_RANK = {
    ANONYMOUS_PROFILE: 0,
    SCOPED_PROFILE: 1,
    LINKABLE_PROFILE: 2,
}


# Rebind statements take no issuer credential through the ordinary
# selection path (they prove key continuity from their own witness).
_REBIND_CIRCUITS = frozenset(
    {
        REBIND_AUTH_CIRCUIT,
        REBIND_CIRCUIT,
        REBIND_BINDING_V2_CIRCUIT,
        REBIND_AUTH_V2_CIRCUIT,
        REBIND_AUTH_V3_CIRCUIT,
        REBIND_V2_CIRCUIT,
        REBIND_V2_BINDING_V2_CIRCUIT,
    }
)


def _malformed_parameters(proof_type: str, exc: Exception) -> ConstraintViolationError:
    """A coded refusal for a request parameter of the wrong shape or type.

    Names the proof type and the exception type (and a missing key's name),
    never a parameter value."""
    detail = f"missing key {exc}" if isinstance(exc, KeyError) else type(exc).__name__
    return ConstraintViolationError(
        f"request parameters for {proof_type} are malformed ({detail}); "
        "refusing before proving"
    )


class _Presentation:
    """Resolved presentation for one authenticated exchange.

    ``profile`` is the effective presentation profile (anonymous/scoped/linkable)
    and ``scope_id`` is the holder-derived scope (0 for anonymous/linkable).
    Presentation-profile naming — distinct from the remaining-predicates
    "profile" predicate.
    """

    __slots__ = ("profile", "scope_id")

    def __init__(self, profile: str, scope_id: int = 0):
        self.profile = profile
        self.scope_id = int(scope_id)

    @property
    def is_v2(self) -> bool:
        return self.profile in (ANONYMOUS_PROFILE, SCOPED_PROFILE)


def _utc_rfc3339(timestamp: int) -> str:
    return (
        datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


class HolderClient:
    """Reference ZKC holder SDK client."""

    def __init__(
        self,
        master_seed: int | bytes | str,
        registry: PredicateRegistry,
        backend: ProofBackend,
        store: CredentialStore = None,
        accumulator_provider: AccumulatorProvider = None,
        accepted_review_statuses: tuple = None,
        accepted_binding_review_statuses: tuple = None,
        allowed_binding_ids: tuple = (),
        delegation_use_store=None,
    ):
        # Safeguard 4 gate: registry review statuses this holder will use
        # without an explicit opt-in. Defaults to DEFAULT_ACCEPTED_STATUSES
        # ('reviewed' + 'self_attested' — both must publish review evidence).
        # A holder that requires INDEPENDENT review passes ("reviewed",);
        # anything outside the set still needs allow_opaque=True and is logged.
        self._accepted_review_statuses = tuple(
            DEFAULT_ACCEPTED_STATUSES
            if accepted_review_statuses is None
            else accepted_review_statuses
        )
        self._accepted_binding_review_statuses = tuple(
            DEFAULT_ACCEPTED_STATUSES
            if accepted_binding_review_statuses is None
            else accepted_binding_review_statuses
        )
        self._allowed_binding_ids = tuple(allowed_binding_ids)
        # Secrets stay in-process; never logged, never serialized.
        self._master_seed = master_seed_to_bytes(master_seed)
        self._credential_binding_key = derive_credential_binding_key(self._master_seed)
        self._holder_commitment = derive_holder_commitment(self._credential_binding_key)
        self._registry = registry
        self._backend = backend
        self._store = store if store is not None else InMemoryCredentialStore()
        self._accumulator_provider = accumulator_provider
        self._delegation_use_store = delegation_use_store
        # Structured record of every explicit opaque/unreviewed-predicate
        # override (Safeguard 4: overrides are explicit AND recorded).
        self.override_log = []

    @classmethod
    def from_seed(
        cls,
        master_seed: int | bytes | str,
        registry: PredicateRegistry,
        backend: ProofBackend,
        **kwargs,
    ) -> "HolderClient":
        return cls(master_seed, registry, backend, **kwargs)

    # --- binding -------------------------------------------------------------

    def get_binding_commitment(self) -> int:
        """KDC §A.6 holder commitment (safe to share with issuers)."""
        return self._holder_commitment

    def binding_challenge_response(
        self, issuer_id: str, schema_id: str, nonce: str, expires_at: int
    ) -> str:
        """Answer an issuer holder-binding challenge (adapter protocol beta).

        Only the response field element leaves the client; the master seed and
        binding key never do.
        """
        # Local import: zkc_issuer.provider imports zkc_holder, so a module-level
        # import here would create a package cycle.
        from zkc_issuer.binding import compute_binding_response

        from zkc_crypto import hex_to_field

        response = compute_binding_response(
            self._holder_commitment,
            issuer_id,
            schema_id,
            hex_to_field(nonce),
            int(expires_at),
        )
        return field_to_hex(response)

    # --- non-custodial delegation (spec §5.3–§5.4) ----------------------------

    def delegate_viewing(
        self, principal_key_x, principal_key_y, scope, *, issued_at, nonce,
        requests=None, consents=None,
    ):
        """Mint a holder-signed ``DelegationToken`` authorizing ``principal`` to
        exercise ``scope`` (spec §5.4 ``delegateViewing``).

        The master seed and credential binding key never leave the client — only
        the capability token (public material + a signature under a
        domain-separated delegation key) does. The delegation key and serialized
        holder commitment are both derived from this client's same canonical
        seed bytes; token-carried key coordinates are compatibility metadata.
        Pass ``requests`` only after local review: every request field is
        committed into the capability. Omitting it mints a historical token
        for inspection only; such tokens cannot authorize holder material.
        """
        from zkc_crypto.delegation import mint_delegation_token
        from .delegation import _scoped_requests, delegation_request_digest

        # Historical tokens can still be inspected, but cannot release holder
        # material. A usable capability signs the exact locally reviewed batch.
        request_digest = b"" if requests is None else delegation_request_digest(
            _scoped_requests(requests, scope), consents=consents,
        )

        return mint_delegation_token(
            master_seed=self._master_seed,
            holder_commitment=self._holder_commitment,
            principal_key_x=principal_key_x,
            principal_key_y=principal_key_y,
            scope=scope,
            issued_at=issued_at,
            nonce=nonce,
            request_digest=request_digest,
        )

    def authorize_delegated_material(
        self, token, requests, *, now=None, principal_signature=None,
        authorization_nonce=None, consents=None, allow_unauthenticated=False,
        allow_opaque=False, allow_linkable=False, exact_member_consents: dict = None,
    ):
        """Pre-authorize the in-scope proof material a delegate may present.

        The holder (which custodies the seed) generates the proof envelopes for
        the scoped requests in its own environment — spec §5.3 property 2, the
        "holder-controlled execution environment" option — and returns
        ``{proof_type: envelope}``: viewing-limited material with no seed,
        binding key, or witness plaintext. Fails closed if the token was not
        issued by this holder or a request falls outside the delegated scope.
        Token-supplied holder-key coordinates are metadata; authorization is
        anchored to the delegation key derived from this holder's authenticated
        local seed, and every key mismatch or invalid signature is rejected
        before proof generation.
        ``now`` must be a trusted local clock, and ``principal_signature``
        signs ``delegation_authorization_digest(token.digest(),
        delegation_request_digest(requests, consents=consents),
        authorization_nonce)`` with a fresh 32-byte nonce. A shared durable use store
        reserves one use per request before any proving; failures do not refund.

        Delegated requests carry no Authenticated Proof Request, so this path
        is subject to the same Safeguard 6 default as :meth:`generate_proof`:
        it refuses unless the holder passes ``allow_unauthenticated=True``,
        and each generated request records an ``UNAUTHENTICATED`` override.
        Each envelope follows the reviewed request's holder-local
        ``presentation_profile`` (spec §5.9): anonymous (the default) yields
        ``zkc:proof:v2`` with the presentation-resolved sibling proof type;
        scoped is refused (no APR, no scope); linkable yields ``zkc:proof:v1``
        only with the holder's ``allow_linkable=True``. A predicate outside
        the holder's accepted review statuses (for example a draft v2
        sibling) needs the explicit, logged ``allow_opaque=True``. Every opt-in
        must be exactly ``True``. These checks run for every request before
        any use is reserved, so their refusals consume no budget and record no
        override: the opt-ins, profile and linkable consent, secret and
        unknown parameter keys, selectors, context, composite and
        anonymous-composite rules, rebind containment, the Safeguard 4 gate,
        and pure credential selection (trust, expiry, KYC level/attributes,
        canonical-set reconciliation). Witness refresh, revocation/accumulator,
        backend and proving failures happen after the reservation and still
        consume the reserved uses; earlier proofs in the batch are discarded.
        Fixed inclusion paths require holder-local ``exact_member_consents``
        for the requested proof types, as in :meth:`generate_proof`.
        """
        from zkc_crypto.delegation import (
            DELEGATION_TOKEN_DIGEST_VERSION,
            DelegationError,
            DelegationToken,
            ViewingScope,
            derive_delegation_signing_key,
            delegation_authorization_digest,
            validate_scope_identifiers,
        )
        from .delegation import _scoped_requests, _snapshot_consents, delegation_request_digest

        if type(token) is not DelegationToken or type(token.scope) is not ViewingScope:
            raise DelegationError("delegation token representation is invalid")
        # Only the length-prefixed v2 digest is accepted; unknown versions,
        # including the retired NUL-terminated v1 transcript, fail closed.
        if (type(token.digest_version) is not int
                or token.digest_version != DELEGATION_TOKEN_DIGEST_VERSION):
            raise DelegationError("unsupported delegation token digest version")

        principal_key_coordinates = (token.principal_key_x, token.principal_key_y)
        if any(
            type(coordinate) is not bytes or len(coordinate) != 32
            for coordinate in principal_key_coordinates
        ):
            raise DelegationError(
                "delegation token principal key coordinates are invalid"
            )

        scope = token.scope
        if (
            type(scope.proof_types) is not tuple
            or not scope.proof_types
            or any(type(proof_type) is not str for proof_type in scope.proof_types)
            or type(scope.verifier_id) is not str
        ):
            raise DelegationError("delegation token scope representation is invalid")
        # Proof types and verifier id must be nonempty and free of control,
        # format (invisible), separator and unassigned characters.
        validate_scope_identifiers(scope)

        unsigned_token_fields = (
            (scope.context_value, FIELD_MODULUS),
            (scope.expires_at, 1 << 64),
            (scope.max_uses, 1 << 32),
            (token.holder_commitment, FIELD_MODULUS),
            (token.issued_at, 1 << 64),
            (token.nonce, FIELD_MODULUS),
        )
        if any(
            type(value) is not int or not 0 <= value < upper_bound
            for value, upper_bound in unsigned_token_fields
        ) or scope.max_uses < 1:
            raise DelegationError("delegation token integer fields are invalid")

        if type(token.signature) is not bytes or len(token.signature) != 64:
            raise DelegationError("delegation token signature is invalid")

        # Validate the untrusted representation before constant-time comparison.
        # Both comparisons run even when X differs, then the locally derived key
        # (not the token's claimed key) verifies the signature.
        holder_key_coordinates = (token.holder_key_x, token.holder_key_y)
        if any(
            type(coordinate) is not bytes or len(coordinate) != 32
            for coordinate in holder_key_coordinates
        ):
            raise DelegationError("delegation token holder key coordinates are invalid")

        expected_holder_key_x, expected_holder_key_y = public_key_bytes(
            derive_delegation_signing_key(self._master_seed)
        )
        holder_key_x_matches = hmac.compare_digest(
            expected_holder_key_x, token.holder_key_x
        )
        holder_key_y_matches = hmac.compare_digest(
            expected_holder_key_y, token.holder_key_y
        )
        if not (holder_key_x_matches and holder_key_y_matches):
            raise DelegationError("delegation token was not issued by this holder")

        try:
            token_digest = token.digest()
        except (AttributeError, TypeError, ValueError, OverflowError) as exc:
            raise DelegationError("delegation token representation is invalid") from exc

        if not verify(
            expected_holder_key_x,
            expected_holder_key_y,
            token.signature,
            token_digest,
        ):
            raise DelegationError("delegation token signature is invalid")
        if token.holder_commitment != self._holder_commitment:
            raise DelegationError("delegation token was not issued by this holder")
        if type(token.request_digest) is not bytes or len(token.request_digest) != 32:
            raise DelegationError("legacy delegation lacks a reviewed request commitment")
        if type(now) is not int or not 0 <= now < (1 << 64):
            raise DelegationError("delegation authorization requires an explicit trusted clock")
        if now < token.issued_at or now > scope.expires_at:
            raise DelegationError("delegation token is not currently valid")
        snapshots = _scoped_requests(requests, scope)
        reviewed_consents = _snapshot_consents(consents, snapshots)
        request_digest = delegation_request_digest(snapshots, consents=reviewed_consents)
        if not hmac.compare_digest(request_digest, token.request_digest):
            raise DelegationError("request differs from the holder-reviewed delegation")
        if type(authorization_nonce) is not bytes or len(authorization_nonce) != 32:
            raise DelegationError("fresh delegation authorization nonce is required")
        if (
            type(principal_signature) is not bytes or len(principal_signature) != 64
            or not verify(
                token.principal_key_x, token.principal_key_y, principal_signature,
                delegation_authorization_digest(token_digest, request_digest, authorization_nonce),
            )
        ):
            raise DelegationError("delegation principal signature is invalid")
        if self._delegation_use_store is None:
            raise DelegationError("durable delegation usage storage is required")
        # Safeguard 6: no delegated request is verifier-authenticated. Refuse
        # by default, and run every request's admission and preflight checks
        # (profile and linkable consent, Safeguard 2 and 4 gates, composite
        # rules, parameters, context) before any use is reserved.
        if allow_unauthenticated is not True:
            raise UnauthenticatedRequestError(
                "refusing to generate delegated material for requests without an "
                "Authenticated Proof Request (Safeguard 6); pass "
                "allow_unauthenticated=True to override explicitly"
            )
        exact_member_consents = dict(exact_member_consents or {})
        plans = []
        for request in snapshots:
            presentation = self._admit_unauthenticated(request, allow_linkable)
            plan = self._preflight(
                request, presentation, consents=reviewed_consents,
                allow_opaque=allow_opaque, refuse_unprovable=True,
                exact_member_consents=exact_member_consents,
            )
            plans.append(plan)
        # Check the entire batch's consent before consulting credential holdings.
        for request, plan in zip(snapshots, plans):
            for proof_type, emitted_proof_type, _, entry in plan:
                circuit = NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS.get(entry.circuit, entry.circuit)
                if circuit in _REBIND_CIRCUITS:
                    continue
                try:
                    credential = self.select_credential(
                        request, emitted_proof_type, requested_proof_type=proof_type,
                    )
                    self._reconcile_canonical_set(
                        emitted_proof_type, credential, request.parameters.get(proof_type, {})
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise _malformed_parameters(proof_type, exc) from exc
        token_id = hashlib.sha256(
            b"zkc/holder-delegation-use:v1\0"
            + expected_holder_key_x + expected_holder_key_y + token.nonce.to_bytes(32, "big")
        ).digest()
        # Reserve the complete batch before generating any material. Never
        # refund: a failure can occur after a proof or a response was produced.
        self._delegation_use_store.reserve(
            token_id, token_digest, len(snapshots), scope.max_uses, authorization_nonce,
        )
        material = {}
        for request in snapshots:
            envelope = self.generate_proof(
                request, consents=reviewed_consents, allow_unauthenticated=True,
                allow_opaque=allow_opaque, allow_linkable=allow_linkable,
                exact_member_consents=exact_member_consents,
            )
            for proof_type in request.proof_types:
                material[proof_type] = envelope
        return material

    # --- credential management ------------------------------------------------

    def store_credential(self, credential: Credential) -> None:
        if credential.holder_commitment != self._holder_commitment:
            raise HolderError("credential is bound to a different holder commitment")
        self._store.put(credential)
        logger.info(
            "stored credential type=%s issuer=%s id=%s",
            credential.credential_type,
            credential.issuer_id,
            field_to_hex(credential.credential_id),
        )

    def remove_credential(self, credential_id: int, issuer_id: str = None) -> None:
        """Drop a credential from the store (e.g. superseded by renewal).

        Credential identifiers are issuer-chosen. Without ``issuer_id`` this
        raises ``AmbiguousCredentialError`` when credentials from more than
        one issuer carry ``credential_id``; it never guesses which to drop.
        """
        self._store.delete(credential_id, issuer_id=issuer_id)
        logger.info("removed credential id=%s", field_to_hex(credential_id))

    def list_credentials(self, proof_type: str = None, issuer_ids=None) -> list:
        credentials = self._store.list()
        if proof_type is not None:
            credentials = [c for c in credentials if c.proof_type == proof_type]
        if issuer_ids is not None:
            allowed = set(issuer_ids)
            credentials = [c for c in credentials if c.issuer_id in allowed]
        return credentials

    def update_witness(self, credential_id: int, issuer_id: str = None):
        """Refresh the non-revocation witness from the issuer accumulator.

        Credential identifiers are issuer-chosen. Without ``issuer_id`` this
        raises ``AmbiguousCredentialError`` when credentials from more than
        one issuer carry ``credential_id``.
        """
        if self._accumulator_provider is None:
            raise StaleWitnessError("no accumulator provider configured for witness refresh")
        credential = self._store.get(credential_id, issuer_id=issuer_id)
        if credential is None:
            raise NoMatchingCredentialError("credential not found in store")
        witness = self._accumulator_provider.witness(
            credential.issuer_id, credential.credential_id
        )
        credential.witness = witness
        self._store.put(credential)
        return witness

    # --- selection -------------------------------------------------------------

    def select_credential(
        self, request: ProofRequest, proof_type: str, *, requested_proof_type: str | None = None,
    ) -> Credential:
        """Pick a credential satisfying the request for one proof type.

        Fail closed with a structured error explaining why nothing matched.
        """
        # Security containment: no live credential is ever selected for an
        # unauthenticated credential-rebind statement.
        refuse_unauthenticated_rebind(proof_type)
        predecessor = NONZERO_CREDENTIAL_PROOF_PREDECESSORS.get(proof_type, proof_type)
        stored_proof_type = credential_proof_type_for_request(predecessor)
        # The binding-v2 rebind successors retain the frozen credential
        # schema. They are deliberately kept separate from the generic profile
        # successor map because rebind has its own credential shape.
        if proof_type in (
            REBIND_BINDING_V2_PROOF_TYPE,
            REBIND_V2_BINDING_V2_PROOF_TYPE,
        ):
            stored_proof_type = REBIND_PROOF_TYPE
            candidates = self.list_credentials(proof_type=stored_proof_type)
        else:
            # Prefer an exact current credential.  A v8 presentation shares
            # the validFrom-bound v7 credential. Jurisdiction v4 first shares
            # the already-safe v3 credential, then historical generations
            # fall back only through their explicit compatibility map.
            candidates = self.list_credentials(proof_type=proof_type)
            if not candidates and predecessor != proof_type:
                candidates = self.list_credentials(proof_type=predecessor)
            if not candidates and proof_type in (
                JURISDICTION_V4_PROOF_TYPE,
                JURISDICTION_V5_PROOF_TYPE,
            ):
                candidates = self.list_credentials(proof_type=JURISDICTION_V3_PROOF_TYPE)
            if not candidates and proof_type == "zkc:proof:accreditation:v8":
                candidates = self.list_credentials(proof_type="zkc:proof:accreditation:v7")
            if not candidates and proof_type == "zkc:proof:source:v8":
                candidates = self.list_credentials(proof_type="zkc:proof:source:v7")
            if not candidates and proof_type == "zkc:proof:tax:v8":
                candidates = self.list_credentials(proof_type="zkc:proof:tax:v7")
            if not candidates and proof_type == "zkc:proof:sanctions:v8":
                candidates = self.list_credentials(proof_type="zkc:proof:sanctions:v7")
            if stored_proof_type != proof_type and (
                not candidates or proof_type in LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES
            ):
                candidates.extend(self.list_credentials(proof_type=stored_proof_type))
        if not candidates:
            raise NoMatchingCredentialError(
                f"no stored credential compatible with request proof type {proof_type}"
            )

        trusted = [c for c in candidates if request.trust_policy.trusts(c.issuer_id, proof_type)]
        if not trusted:
            raise UnknownIssuerError(
                f"no credential for {proof_type} comes from an issuer in the verifier trust policy"
            )

        timestamp = request.context.timestamp
        fresh = [c for c in trusted if c.expires_at == 0 or c.expires_at > timestamp]
        if not fresh:
            raise StaleCredentialError(f"all matching credentials for {proof_type} are expired")

        if predecessor in LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES or predecessor == DISCLOSURE_V3_PROOF_TYPE:
            parameters = request.parameters.get(requested_proof_type or proof_type, {})
            layout_id = parameters.get("layoutId")
            try:
                parse_attribute_layout_id(layout_id)
            except ValueError as exc:
                raise _malformed_parameters(proof_type, exc) from exc
            if predecessor == DISCLOSURE_V3_PROOF_TYPE:
                matching = [
                    c for c in fresh if c.credential_type == "zkc:cred:attribute-set:v2"
                    and c.claims.get("layoutId") == layout_id
                ]
            else:
                matching = [
                    c for c in fresh if c.credential_type == "zkc:cred:attribute-set:v1"
                    and c.attribute_layout_id == layout_id
                ]
            if not matching:
                raise NoMatchingCredentialError(
                    f"no trusted credential matches the requested layoutId for {proof_type}"
                )
            return matching[0]

        if proof_type in CODE_SPACE_PROOF_TO_KIND:
            kind = CODE_SPACE_PROOF_TO_KIND[proof_type]
            parameters = request.parameters.get(requested_proof_type or proof_type, {})
            try:
                space = get_code_space(parameters.get(CODE_SPACE_ID_PARAM), kind)
            except (AttributeError, ValueError) as exc:
                raise _malformed_parameters(proof_type, exc) from exc
            matching = [
                c for c in fresh if CODE_SPACE_CREDENTIAL_TO_KIND.get(c.credential_type) == kind
                and c.claims.get("codeSpaceId") == space.id
            ]
            if not matching:
                raise NoMatchingCredentialError(
                    f"no trusted credential matches the requested codeSpaceId for {proof_type}"
                )
            return matching[0]

        # Minimal disclosure: prefer the lowest-privilege credential that
        # satisfies the request (Safeguard 2). For KYC: lowest level wins.
        if predecessor in (
            KYC_PROOF_TYPE,
            KYC_V2_PROOF_TYPE,
            COMMUNITY_KYC_V2_PROOF_TYPE,
            KYC_V3_PROOF_TYPE,
        ):
            parameters = request.parameters.get(
                proof_type, request.parameters.get(KYC_PROOF_TYPE, {})
            )
            required_level = int(parameters.get("requiredLevel", 1))
            required_attributes = [bool(f) for f in parameters.get("requiredAttributes", [False] * 5)]
            satisfying = [
                c
                for c in fresh
                if int(c.claims["level"]) >= required_level
                and all(
                    (not req) or verified
                    for req, verified in zip(required_attributes, c.claims["verifiedAttributes"])
                )
            ]
            if not satisfying:
                raise NoMatchingCredentialError(
                    f"no credential satisfies the requested KYC parameters for {proof_type}"
                )
            return min(satisfying, key=lambda c: int(c.claims["level"]))
        return fresh[0]

    # --- proof generation --------------------------------------------------------

    def _resolve_binding(self, request, requested_proof_type, emitted_proof_type):
        selector = request.binding_selectors.get(
            emitted_proof_type, request.binding_selectors.get(requested_proof_type)
        )
        if selector is None:
            return None
        try:
            return self._registry.resolve_binding(
                emitted_proof_type,
                selector,
                accepted_source_statuses=self._accepted_review_statuses,
                accepted_binding_statuses=self._accepted_binding_review_statuses,
                allowed_binding_ids=self._allowed_binding_ids,
            )
        except BindingResolutionError as exc:
            raise OpaquePredicateError(
                f"binding selector for {emitted_proof_type} failed closed "
                f"({exc.reason}): {exc}"
            ) from exc

    def _gated_entry(
        self, proof_type, emitted_proof_type, resolved_binding, allow_opaque, *, record=True
    ):
        """Resolve the registry entry for one emitted proof type and apply the
        Safeguard 4 gate. Both the v1 and the v2 (presentation-profile) paths
        use this gate: a v2 sibling is a separate registry entry with its own
        review status, so it never inherits its v1 family's status.

        ``allow_opaque`` overrides only when it is exactly ``True``. With
        ``record=False`` (``_preflight``) the gate refuses exactly as it would,
        but records and logs nothing, and returns ``None`` for an opaque proof
        type whose override the generation path will record."""
        if resolved_binding is not None:
            # resolve_binding already failed closed on the source and binding
            # review statuses; there is no override for an exact selector.
            entry = resolved_binding.source
        else:
            # An accepted entry wins. Without one, allow_unaccepted returns an
            # entry only so the gate below can tell an unreviewed entry from
            # an opaque proof type; the gate still refuses it.
            entry = self._registry.resolve(
                emitted_proof_type,
                accepted_statuses=self._accepted_review_statuses,
                allow_unaccepted=True,
            )
        if entry is None:
            # Safeguard 4: refuse opaque predicates by default.
            if allow_opaque is not True:
                raise OpaquePredicateError(
                    f"predicate {proof_type} (proof type {emitted_proof_type}) does not "
                    "resolve to a reviewed registry entry; refusing by default "
                    "(pass allow_opaque=True to override explicitly)"
                )
            if not record:
                return None
            # Explicit, logged opt-in (Safeguard 4). The reference SDK
            # still cannot build a witness for an unreviewed predicate, so
            # generation proceeds to a capability failure — but the
            # override itself is honored and recorded.
            self._record_override(
                proof_type, "OPAQUE", "predicate does not resolve to any registry entry"
            )
            raise BackendUnavailableError(
                f"opaque predicate {proof_type} acknowledged via explicit opt-in, but the "
                "reference SDK has no witness builder for unreviewed predicates"
            )
        status = entry.review_status
        if status not in self._accepted_review_statuses:
            # Safeguard 4: entries whose status is outside this holder's
            # accepted set (by default draft / in_review / deprecated) are
            # refused — the same logged override extends to them.
            if allow_opaque is not True:
                raise OpaquePredicateError(
                    f"predicate {proof_type} resolves to registry entry "
                    f"{entry.predicate_id or entry.circuit} ({emitted_proof_type}) with "
                    f"review status '{status}', which is not in this holder's accepted set "
                    f"{list(self._accepted_review_statuses)}; refusing by default "
                    "(pass allow_opaque=True to override explicitly)"
                )
            if not record:
                return entry
            self._record_override(
                proof_type,
                "UNREVIEWED",
                f"registry entry {entry.predicate_id or entry.circuit} "
                f"({emitted_proof_type}) has review status '{status}'",
                predicate_id=entry.predicate_id,
            )
        elif entry.self_attested and record:
            # Accepted by default, but never silently: the audit trail
            # records that this predicate carries no independent review.
            logger.info(
                "using SELF-ATTESTED predicate %s (registry entry %s): the author "
                "published evidence of their own verification; no independent review "
                "exists. Pass accepted_review_statuses=('reviewed',) to refuse these.",
                proof_type,
                entry.predicate_id or entry.circuit,
            )
        return entry

    def generate_proof(
        self,
        request: ProofRequest,
        *,
        allow_unauthenticated: bool = False,
        allow_linkable: bool = False,
        consents: dict = None,
        exact_member_consents: dict = None,
        allow_opaque: bool = False,
        aggregate: bool = False,
    ) -> dict:
        """Answer a proof request that carries NO Authenticated Proof Request.

        Safeguard 6 (spec §1.4): a request without a valid APR is
        unauthenticated, so this method refuses it by default with
        ``UnauthenticatedRequestError``. Answer verifier requests through
        :meth:`generate_authenticated_proof` instead; it also returns the
        holder-custodied Disclosure Receipt. Passing
        ``allow_unauthenticated=True`` is the explicit opt-in: the override is
        recorded in ``override_log`` (kind ``UNAUTHENTICATED``) and logged.

        The envelope honors ``request.presentation_profile`` (spec §5.9), the
        holder-local profile choice, as the authenticated path does when the
        APR is silent on presentation:

        - anonymous (the ``ProofRequest`` default) yields a ``zkc:proof:v2``
          ``presentationBinding`` envelope and never a ``holderBinding``;
        - scoped is refused, because a scope derives from an authenticated
          verifier key that an unauthenticated request does not have;
        - linkable yields the frozen ``zkc:proof:v1`` ``holderBinding``
          envelope only with the holder's explicit ``allow_linkable=True``;
          without it the request is refused with ``ConsentRequiredError``.

        Every opt-in must be exactly ``True``. Every check that can refuse
        the request before proving runs before the override is recorded.
        For a fixed inclusion path, ``exact_member_consents={proof_type: True}``
        explicitly authorizes exact-code disclosure for that requested proof
        type. Supply this consent locally for the reviewed request.
        """
        if allow_unauthenticated is not True:
            raise UnauthenticatedRequestError(
                "refusing to answer a proof request without an Authenticated Proof "
                "Request (Safeguard 6); answer it with generate_authenticated_proof(apr, "
                "request), or pass allow_unauthenticated=True to override explicitly"
            )
        request = _snapshot_proof_request(request)
        exact_member_consents = dict(exact_member_consents or {})
        presentation = self._admit_unauthenticated(request, allow_linkable)
        self._preflight(
            request, presentation, consents=consents, allow_opaque=allow_opaque,
            aggregate=aggregate,
            exact_member_consents=exact_member_consents,
        )
        self._record_override(
            request.proof_types[0],
            "UNAUTHENTICATED",
            "opted in to answer a proof request that carries no Authenticated Proof "
            f"Request (presentation profile {presentation.profile})",
        )
        return self._generate_envelope(
            request,
            presentation,
            consents=consents,
            allow_opaque=allow_opaque,
            aggregate=aggregate,
            exact_member_consents=exact_member_consents,
        )

    def _admit_unauthenticated(self, request: ProofRequest, allow_linkable) -> _Presentation:
        """Admission for an opted-in request without an APR; side-effect free.

        Returns the presentation the holder-local profile selects. Binding
        selectors need an authenticated APR extension; scoped and unknown
        profiles fail in ``_resolve_presentation``; a linkable profile needs
        the holder's explicit ``allow_linkable=True`` (spec §5.9: linkable is
        the explicitly consented profile)."""
        # Secrets never travel in a request (spec 7.4.4).
        refuse_secret_parameters(request.parameters, "proof request")
        if any(isinstance(proof_type, str) and proof_type in CODE_SPACE_PROOF_TO_KIND
               for proof_type in request.proof_types):
            raise UnauthenticatedRequestError("code-space proofs require an authenticated APR")
        if request.binding_selectors:
            raise UnauthenticatedRequestError(
                "predicate-entry v2 binding selectors require an authenticated APR extension"
            )
        presentation = self._resolve_presentation(None, request, authenticated=False)
        if presentation.profile == LINKABLE_PROFILE and allow_linkable is not True:
            raise ConsentRequiredError(
                "the request selects the linkable presentation profile, which discloses "
                "the global holder commitment; the holder must consent explicitly "
                "(allow_linkable=True)"
            )
        return presentation

    def _emitted_proof_type(self, proof_type: str, presentation: _Presentation) -> str:
        """The identity the holder emits for ``proof_type`` under ``presentation``."""
        # Security containment: no profile may select or resolve into a
        # historical credential-rebind identity; refuse with a stable error
        # before any registry resolution, credential selection, or proving.
        refuse_unauthenticated_rebind(proof_type)
        if presentation.is_v2:
            emitted_proof_type = resolve_presentation_proof_type_for_request(
                proof_type, presentation.profile
            )
        else:
            try:
                emitted_proof_type = resolve_presentation_proof_type_for_request(
                    proof_type, LINKABLE_PROFILE
                )
            except ConstraintViolationError:
                if proof_type in NONZERO_CREDENTIAL_PROOF_PREDECESSORS:
                    raise
                if proof_type in CODE_SPACE_PROOF_TO_KIND or proof_type in (
                    KYC_V3_PROOF_TYPE,
                    JURISDICTION_V5_PROOF_TYPE,
                    "zkc:proof:accreditation:v9",
                    "zkc:proof:accreditation:v10",
                    "zkc:proof:source:v9",
                    "zkc:proof:source:v10",
                    "zkc:proof:tax:v9",
                    "zkc:proof:tax:v10",
                    "zkc:proof:sanctions:v9",
                    "zkc:proof:sanctions:v10",
                    REBIND_AUTH_V3_PROOF_TYPE,
                    "zkc:proof:selective_disclosure:v2",
                    DISCLOSURE_V3_PROOF_TYPE,
                ):
                    raise
                emitted_proof_type = proof_type
        refuse_unauthenticated_rebind(emitted_proof_type)
        return emitted_proof_type

    def _preflight(
        self,
        request: ProofRequest,
        presentation: _Presentation,
        *,
        consents: dict = None,
        exact_member_consents: dict = None,
        allow_opaque: bool = False,
        aggregate: bool = False,
        _binding_selectors_authenticated: bool = False,
        refuse_unprovable: bool = False,
    ) -> list:
        """Every request-level refusal, run before any side effect.

        Side-effect free: it records no override, logs nothing, reserves
        nothing, selects no credential, and proves nothing. Callers run it
        before they record a Safeguard 6 override or reserve a delegation
        use, and proof generation runs it again first. Returns
        ``[(proof_type, emitted_proof_type, resolved_binding, entry), ...]``.

        An opaque proof type under ``allow_opaque=True`` passes, because the
        generation path records that override before its capability failure;
        ``refuse_unprovable=True`` refuses it here instead (delegation, where
        a doomed attempt would consume a use).
        """
        if type(presentation) is not _Presentation:
            raise HolderError("proof generation requires a resolved presentation profile")
        # Secrets never travel in a request (spec 7.4.4): refuse before any
        # registry resolution, credential selection, or proving.
        refuse_secret_parameters(request.parameters, "proof request")
        # Closed parameter vocabulary (spec 6.2.1), AFTER the secret check so
        # a secret-bearing request keeps its SECRET_IN_REQUEST refusal: a key
        # this holder would ignore must not leave a requirement silently
        # unmet in a request (and APR) it answers. Checked against the
        # identity the holder will emit.
        self._registry.refuse_unknown_request_parameters(
            request.proof_types,
            request.parameters,
            resolve=lambda proof_type: request_contract_proof_types(
                proof_type, (presentation.profile,)
            ),
        )
        _validate_profile_request_domains(request)
        if request.binding_selectors and not _binding_selectors_authenticated:
            raise UnauthenticatedRequestError(
                "predicate-entry v2 binding selectors require an authenticated APR extension"
            )
        if aggregate and presentation.is_v2:
            # The aggregation commitment binds the global holder commitment,
            # which a v2 presentation must never carry: fail instead of
            # silently dropping or leaking it.
            raise HolderError(
                "aggregation binds the global holder commitment and is only available "
                f"under the linkable profile, not {presentation.profile}"
            )
        if not isinstance(request.context, ProofContext):
            raise ContextError("proof request carries no proof context")
        if request.context.value == 0 or request.context.timestamp <= 0:
            raise ContextError("proof context must have a non-zero value and timestamp")
        if not request.context.reconstructs():
            raise ContextError("proof context structured fields do not reproduce context value")
        if not request.proof_types:
            raise HolderError("proof request lists no proof types")

        # Spec 5.9.2 rule 5: anonymous proofs bind to no single holder, so a
        # conforming verifier rejects an anonymous answer to two or more proof
        # types (UNBOUND_COMPOSITE, 5.9.4). Refuse before consent or proving:
        # the doomed answer would only disclose which predicates we satisfy.
        if (
            presentation.profile == ANONYMOUS_PROFILE
            and len(set(request.proof_types)) >= 2
            and request.allow_unlinked_composite is not True
        ):
            raise AnonymousCompositeRefusedError(
                f"refusing to answer {len(request.proof_types)} proof types "
                f"({', '.join(request.proof_types)}) under the anonymous presentation "
                "profile: anonymous proofs bind to no single holder, so a conforming "
                "verifier rejects the composite (UNBOUND_COMPOSITE) and answering would "
                "only disclose which predicates this holder satisfies; answer under the "
                "scoped profile with scopePolicy 'session' (the APR requests "
                f"{SCOPED_PROFILE} and presentation_profile permits it), or set "
                "allow_unlinked_composite=True only if the verifier declares the "
                "proofs independent"
            )

        # Safeguard 2: composite disclosure needs explicit per-predicate consent.
        consents = dict(consents or {})
        if len(request.proof_types) > 1:
            missing = [pt for pt in request.proof_types if not consents.get(pt)]
            if missing:
                raise ConsentRequiredError(
                    "composite disclosure requires explicit consent per predicate; "
                    f"missing consent for: {', '.join(missing)}"
                )

        plan = []
        exact_member_consents = exact_member_consents or {}
        for proof_type in request.proof_types:
            emitted_proof_type = self._emitted_proof_type(proof_type, presentation)
            resolved_binding = self._resolve_binding(request, proof_type, emitted_proof_type)
            entry = self._gated_entry(
                proof_type, emitted_proof_type, resolved_binding, allow_opaque, record=False
            )
            if entry is None and refuse_unprovable:
                raise BackendUnavailableError(
                    f"opaque predicate {proof_type} has no registry entry, so the reference "
                    "SDK has no witness builder for it"
                )
            parameters = request.parameters.get(proof_type, {})
            if emitted_proof_type in CODE_SPACE_PROOF_TO_KIND:
                try:
                    get_code_space(parameters.get(CODE_SPACE_ID_PARAM), CODE_SPACE_PROOF_TO_KIND[emitted_proof_type])
                except (AttributeError, ValueError) as exc:
                    raise _malformed_parameters(proof_type, exc) from exc
            circuit = entry.circuit if entry else None
            if NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS.get(circuit, circuit) in (
                DISCLOSURE_CIRCUIT, DISCLOSURE_V2_CIRCUIT, DISCLOSURE_V3_CIRCUIT,
            ):
                try:
                    parse_attribute_layout_id(parameters.get("layoutId"))
                except ValueError as exc:
                    raise _malformed_parameters(proof_type, exc) from exc
            if (
                _requires_exact_member_consent(emitted_proof_type, parameters)
                and exact_member_consents.get(proof_type) is not True
            ):
                raise ExactMemberConsentRequiredError(
                    f"{proof_type} requires consent to exact-code disclosure for a "
                    "fixed path or singleton code set (pass exact_member_consents locally)"
                )
            plan.append((proof_type, emitted_proof_type, resolved_binding, entry))
        return plan

    def _generate_envelope(
        self,
        request: ProofRequest,
        presentation: _Presentation,
        *,
        consents: dict = None,
        exact_member_consents: dict = None,
        allow_opaque: bool = False,
        aggregate: bool = False,
        _binding_selectors_authenticated: bool = False,
    ) -> dict:
        """Generate a zkc:proof envelope for an already admitted request.

        Callers resolve admission (Safeguard 6) and the presentation first.
        ``presentation`` selects the envelope version (design §3, the
        profile→version rule): the linkable profile produces the legacy
        ``zkc:proof:v1`` ``holderBinding`` envelope; an anonymous or scoped
        presentation produces a ``zkc:proof:v2`` ``presentationBinding``
        envelope built from the v2 circuits. Every request-level refusal
        (``_preflight``) runs before any override is recorded or any proof
        is produced.
        """
        plan = self._preflight(
            request,
            presentation,
            consents=consents,
            exact_member_consents=exact_member_consents,
            allow_opaque=allow_opaque,
            aggregate=aggregate,
            _binding_selectors_authenticated=_binding_selectors_authenticated,
        )
        for proof_type, emitted_proof_type, _, _ in plan:
            if _requires_exact_member_consent(
                emitted_proof_type, request.parameters.get(proof_type, {})
            ):
                reason = "holder consented to exact-code disclosure using a fixed inclusion path"
                if emitted_proof_type in CODE_SPACE_PROOF_TO_KIND:
                    reason = "holder consented to exact-code disclosure for the code-space request"
                self._record_override(
                    proof_type, "EXACT_MEMBER", reason,
                )
        consents = dict(consents or {})
        if presentation.is_v2:
            return self._generate_proof_v2(
                request, presentation, plan, consents=consents, allow_opaque=allow_opaque
            )

        proofs = []
        for proof_type, emitted_proof_type, resolved_binding, _ in plan:
            entry = self._gated_entry(
                proof_type, emitted_proof_type, resolved_binding, allow_opaque
            )
            proofs.append(
                self._generate_individual_proof(
                    request,
                    proof_type,
                    entry,
                    consents,
                    emitted_proof_type=emitted_proof_type,
                    binding_selector=(
                        resolved_binding.binding.selector if resolved_binding is not None else None
                    ),
                )
            )

        generated_at = request.context.timestamp
        envelope = {
            "version": "zkc:proof:v1",
            "metadata": {
                "generatedAt": _utc_rfc3339(generated_at),
                "expiresAt": _utc_rfc3339(generated_at + max(int(request.max_proof_age), 1)),
                "context": request.context.to_metadata(),
            },
            "proofs": proofs,
            "holderBinding": {"commitment": field_to_hex(self._holder_commitment)},
        }

        if aggregate:
            envelope["aggregation"] = self._build_aggregation(envelope, request, consents)

        try:
            validate_compliance_proof_v1(envelope)
        except EnvelopeError as exc:
            raise HolderError(f"generated envelope failed self-validation: {exc}") from exc
        logger.info(
            "generated zkc:proof:v1 envelope proof_types=%s backend=%s production_backend=%s",
            ",".join(request.proof_types),
            self._backend.name,
            self._backend.is_production,
        )
        return envelope

    # --- v2 (presentation-profile) proof generation ---------------------------

    def _generate_proof_v2(
        self,
        request: ProofRequest,
        presentation: _Presentation,
        plan: list,
        *,
        consents: dict,
        allow_opaque: bool = False,
    ) -> dict:
        """Assemble a ``zkc:proof:v2`` ``presentationBinding`` envelope (design §3).

        The holder resolves each requested v1 predicate family to its sibling
        ``:v2`` proof type/circuit, builds a v2 witness with the negotiated
        scope, and emits a ``presentationBinding`` block (never ``holderBinding``).
        Each v2 sibling is its own registry entry with its own review status,
        so this path applies the same Safeguard-4 gate as the v1 path: opaque
        proof types and entries outside the holder's accepted review statuses
        are refused unless the caller passes the explicit, logged
        ``allow_opaque=True`` override. ``plan`` comes from ``_preflight``,
        which already ran every request-level refusal.
        """
        if presentation.profile == ANONYMOUS_PROFILE and len(set(request.proof_types)) >= 2:
            logger.info(
                "answering %d proof types anonymously (allow_unlinked_composite=True): "
                "the proofs are not bound to one holder",
                len(request.proof_types),
            )

        proofs = []
        for proof_type, v2_proof_type, resolved_binding, _ in plan:
            entry = self._gated_entry(proof_type, v2_proof_type, resolved_binding, allow_opaque)
            proofs.append(
                self._generate_individual_proof_v2(
                    request,
                    proof_type,
                    v2_proof_type,
                    entry,
                    presentation,
                    consents,
                    binding_selector=(
                        resolved_binding.binding.selector if resolved_binding is not None else None
                    ),
                )
            )

        generated_at = request.context.timestamp
        binding = {"profile": presentation.profile}
        if presentation.profile == SCOPED_PROFILE:
            pseudonym = self._presentation_pseudonym(presentation.scope_id)
            binding["pseudonym"] = field_to_hex(pseudonym)
            binding["scopeId"] = field_to_hex(presentation.scope_id)

        envelope = {
            "version": "zkc:proof:v2",
            "metadata": {
                "generatedAt": _utc_rfc3339(generated_at),
                "expiresAt": _utc_rfc3339(generated_at + max(int(request.max_proof_age), 1)),
                "context": request.context.to_metadata(),
            },
            "proofs": proofs,
            "presentationBinding": binding,
        }

        try:
            validate_envelope(envelope)
        except EnvelopeError as exc:
            raise HolderError(f"generated envelope failed self-validation: {exc}") from exc
        logger.info(
            "generated zkc:proof:v2 envelope profile=%s proof_types=%s backend=%s "
            "production_backend=%s",
            presentation.profile,
            ",".join(request.proof_types),
            self._backend.name,
            self._backend.is_production,
        )
        return envelope

    def _presentation_pseudonym(self, scope_id: int) -> int:
        """The holder's scoped pseudonym in ``scope_id`` (0 for anonymous)."""
        from zkc_crypto.presentation import derive_presentation_pseudonym

        if int(scope_id) == 0:
            return 0
        return derive_presentation_pseudonym(self._credential_binding_key, int(scope_id))

    def _generate_individual_proof_v2(
        self, request, proof_type, v2_proof_type, entry, presentation, consents,
        binding_selector=None,
    ) -> dict:
        """Assemble + prove one v2 predicate for the negotiated presentation."""
        circuit = NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS.get(entry.circuit, entry.circuit)
        try:
            if circuit in (REBIND_AUTH_V2_CIRCUIT, REBIND_AUTH_V3_CIRCUIT):
                full_witness = self._build_rebind_auth_witness(
                    request, proof_type, scope_id=presentation.scope_id
                )
            elif entry.circuit in (REBIND_V2_CIRCUIT, REBIND_V2_BINDING_V2_CIRCUIT):
                full_witness = self._build_rebind_witness_v2(request, proof_type, presentation)
                if entry.circuit == REBIND_V2_BINDING_V2_CIRCUIT:
                    full_witness["statement_domain"] = REBIND_V2_BINDING_V2_STATEMENT_DOMAIN
            else:
                credential = self.select_credential(
                    request, v2_proof_type, requested_proof_type=proof_type,
                )
                issuer = request.trust_policy.issuer(credential.issuer_id)
                witness, current_epoch = self._refresh_nonrevocation(request, credential)
                parameters = request.parameters.get(proof_type, {})
                parameters = self._reconcile_canonical_set(v2_proof_type, credential, parameters)
                full_witness = self._build_predicate_witness_v2(
                    circuit,
                    v2_proof_type,
                    request,
                    credential,
                    issuer,
                    witness,
                    current_epoch,
                    parameters,
                    presentation,
                )
        except (KeyError, TypeError, ValueError) as exc:
            # A parameter value of the wrong shape or type is a coded
            # refusal, never a raw Python exception.
            raise _malformed_parameters(proof_type, exc) from exc
        proof = self._backend.prove(entry.circuit, full_witness)
        result = {
            "proofType": v2_proof_type,
            "proof": proof,
            "publicInputs": self._backend.public_inputs(entry.circuit, full_witness),
            "principalConsent": bool(consents.get(proof_type, len(request.proof_types) == 1)),
        }
        if binding_selector is not None:
            result["bindingSelector"] = binding_selector
        return result

    def _build_predicate_witness_v2(
        self,
        circuit,
        proof_type,
        request,
        credential,
        issuer,
        witness,
        current_epoch,
        parameters,
        presentation,
    ) -> dict:
        scope_id = presentation.scope_id
        if circuit in (DISCLOSURE_CIRCUIT, DISCLOSURE_V2_CIRCUIT, DISCLOSURE_V3_CIRCUIT):
            if "disclosedPositions" not in parameters:
                raise HolderError(
                    "selective disclosure requires explicit disclosedPositions"
                )
            return build_selective_disclosure_witness(
                master_seed=self._master_seed,
                credential=credential,
                issuer=issuer,
                witness=witness,
                disclosed_positions=parameters["disclosedPositions"],
                proof_context=request.context.value,
                timestamp=request.context.timestamp,
                current_epoch=current_epoch,
                scope_id=scope_id,
                layout_id=parameters["layoutId"] if circuit == DISCLOSURE_V3_CIRCUIT else None,
            )
        if circuit in (KYC_V2_CIRCUIT, KYC_V3_CIRCUIT):
            return build_kyc_witness_v2(
                credential_binding_key=self._credential_binding_key,
                credential=credential,
                issuer=issuer,
                witness=witness,
                required_level=int(parameters.get("requiredLevel", 1)),
                required_attributes=parameters.get("requiredAttributes", [False] * 5),
                proof_context=request.context.value,
                timestamp=request.context.timestamp,
                current_epoch=current_epoch,
                scope_id=scope_id,
            )
        if circuit in (
            JURISDICTION_V2_CIRCUIT,
            JURISDICTION_V4_CIRCUIT,
            JURISDICTION_V5_CIRCUIT,
            JURISDICTION_V6_CIRCUIT,
        ):
            full_witness = build_jurisdiction_witness_v2(
                credential_binding_key=self._credential_binding_key,
                credential=credential,
                issuer=issuer,
                witness=witness,
                membership_type=int(parameters.get("membershipType", 0)),
                required_claim_type=int(
                    parameters.get("requiredClaimType", credential.claims["claimType"])
                ),
                jurisdiction_set_root=int(parameters["jurisdictionSetRoot"]),
                membership_path_index=int(parameters.get("membershipPathIndex", 0)),
                membership_siblings=parameters.get("membershipSiblings", [0] * 32),
                predecessor_code=int(parameters.get("predecessorCode", 0)),
                predecessor_path_index=int(parameters.get("predecessorPathIndex", 0)),
                predecessor_siblings=parameters.get("predecessorSiblings", [0] * 32),
                successor_code=int(parameters.get("successorCode", 0)),
                successor_path_index=int(parameters.get("successorPathIndex", 0)),
                successor_siblings=parameters.get("successorSiblings", [0] * 32),
                proof_context=request.context.value,
                timestamp=request.context.timestamp,
                current_epoch=current_epoch,
                scope_id=scope_id,
            )
            if circuit == JURISDICTION_V6_CIRCUIT:
                space = get_code_space(credential.claims.get("codeSpaceId"), "jurisdiction")
                method = parameters.get(REQUIRED_VERIFICATION_METHOD_PARAM, 0)
                full_witness["code_space_id"] = space.field_id
                full_witness["required_verification_method"] = method
                full_witness["claim_binding"] = bind_code_space_statement(
                    "jurisdiction", space.field_id, full_witness["claim_binding"], method,
                )
            return full_witness
        if circuit in (
            REMAINING_V2_CIRCUIT,
            REMAINING_V4_CIRCUIT,
            REMAINING_V6_CIRCUIT,
            REMAINING_V8_CIRCUIT,
            REMAINING_V9_CIRCUIT,
            REMAINING_V10_CIRCUIT,
            REMAINING_V11_CIRCUIT,
        ):
            predicate_type = PROFILE_PROOF_TYPES.get(proof_type)
            if predicate_type is None:
                raise OpaquePredicateError(
                    f"profile circuit has no predicate type for {proof_type}"
                )
            flag_required = _profile_flag_required(
                parameters,
                proof_type,
                predicate_type,
            )
            builder = {
                REMAINING_V2_CIRCUIT: build_profile_witness_v2,
                REMAINING_V4_CIRCUIT: build_profile_witness_v4,
                REMAINING_V6_CIRCUIT: build_profile_witness_v6,
                REMAINING_V8_CIRCUIT: build_profile_witness_v8,
                REMAINING_V9_CIRCUIT: build_profile_witness_v8,
                REMAINING_V10_CIRCUIT: build_profile_witness_v8,
                REMAINING_V11_CIRCUIT: build_profile_witness_v8,
            }[circuit]
            full_witness = builder(
                predicate_type=predicate_type,
                credential_binding_key=self._credential_binding_key,
                credential=credential,
                issuer=issuer,
                witness=witness,
                required_0=parameters.get("required0", 0),
                required_1=parameters.get("required1", 0),
                flag_required=flag_required,
                set_root=int(parameters.get("setRoot", 0)),
                path_index=int(parameters.get("pathIndex", 0)),
                siblings=parameters.get("siblings", [0] * 32),
                predecessor_code=int(parameters.get("predecessorCode", 0)),
                predecessor_path_index=int(parameters.get("predecessorPathIndex", 0)),
                predecessor_siblings=parameters.get("predecessorSiblings", [0] * 32),
                successor_code=int(parameters.get("successorCode", 0)),
                successor_path_index=int(parameters.get("successorPathIndex", 0)),
                successor_siblings=parameters.get("successorSiblings", [0] * 32),
                proof_context=request.context.value,
                timestamp=request.context.timestamp,
                current_epoch=current_epoch,
                scope_id=scope_id,
            )
            if circuit == REMAINING_V11_CIRCUIT:
                kind = CODE_SPACE_PROOF_TO_KIND[proof_type]
                space = get_code_space(credential.claims.get("codeSpaceId"), kind)
                full_witness["code_space_id"] = space.field_id
                full_witness["claim_binding"] = bind_code_space_statement(
                    kind, space.field_id, full_witness["claim_binding"],
                )
            return full_witness
        raise OpaquePredicateError(
            f"reference SDK has no v2 witness builder for circuit {circuit} ({proof_type})"
        )

    def _build_rebind_witness_v2(
        self, request: ProofRequest, proof_type: str, presentation: _Presentation
    ) -> dict:
        """Build the v2 credential-rebind witness (scoped-only, design §4.2)."""
        parameters = request.parameters.get(proof_type, {})
        credential = self.select_credential(request, proof_type)
        new_binding_key = self._rebind_secret_key(request)
        return build_rebind_witness_v2(
            old_credential_binding_key=self._credential_binding_key,
            new_credential_binding_key=new_binding_key,
            credential=credential,
            issuer_id_hash=int(parameters["issuerIdHash"]),
            schema_id_hash=int(parameters["schemaIdHash"]),
            proof_context=request.context.value,
            timestamp=request.context.timestamp,
            scope_id=presentation.scope_id,
        )

    # ------------------------------------------------------------------
    # Verifier accountability (Safeguard 6, spec §5.5–§5.6).
    # ------------------------------------------------------------------

    def generate_authenticated_proof(
        self,
        apr: dict,
        request: ProofRequest,
        *,
        allow_unauthenticated: bool = False,
        allow_linkable: bool = False,
        now: int = None,
        seen_nonces=None,
        consents: dict = None,
        exact_member_consents: dict = None,
        allow_opaque: bool = False,
        aggregate: bool = False,
    ) -> dict:
        """Answer an Authenticated Proof Request and retain a Disclosure Receipt.

        Fail-closed (Safeguard 6): refuses by default unless `apr` is a valid,
        fresh, signed APR whose proof types, parameters, and bound context
        exactly match `request`. Overriding the default requires an explicit,
        logged `allow_unauthenticated=True`. Disagreement with a valid signed
        context or proof-age policy cannot be overridden.
        Omitted ``now`` uses wall-clock Unix seconds. Historical simulations
        must pass their own trusted integer time explicitly.
        Returns {"envelope": ..., "receipt": ...}; the receipt is
        holder-custodied and returned to the caller, never persisted by the
        SDK.

        Nonces must use canonical lowercase, 32-byte padded field encoding.
        `seen_nonces` is checked but not populated: the caller records observed
        canonical nonces and passes the persistent container to later calls.
        The default empty set supplies no cross-call replay tracking; durable
        cross-request tracking remains the caller's responsibility.

        Linkable consent: under a request that authenticates, the holder's
        ``presentation_profile=LINKABLE_PROFILE`` ceiling together with an APR
        that asks for linkable (or is silent on presentation) is the consent
        to the linkable profile. On the ``allow_unauthenticated=True`` override
        path no verifier is authenticated, so a linkable answer additionally
        needs the holder's exact ``allow_linkable=True``, as in
        :meth:`generate_proof`; otherwise ``ConsentRequiredError`` is raised
        before anything is recorded. Every opt-in counts only when it is
        exactly ``True``. A signed request also needs holder-local
        ``exact_member_consents`` for any fixed inclusion path, as in
        :meth:`generate_proof`."""
        # Keep the signed demand and immutable ProofContext reference stable
        # while the backend runs, even if the caller edits its request objects.
        apr = copy.deepcopy(apr)
        request = _snapshot_proof_request(request)
        seen = set() if seen_nonces is None else seen_nonces
        when = now
        # The APR is verifier-signed and verifier-retained: a secret named in
        # it is refused before authentication, receipts, or proving.
        refuse_secret_parameters(apr, "authenticated proof request")
        refuse_secret_parameters(request.parameters, "proof request")
        authenticated = self._authenticate_request(
            apr, request, allow_unauthenticated, when, seen
        )
        presentation = self._resolve_presentation(apr, request, authenticated)
        if (
            not authenticated
            and presentation.profile == LINKABLE_PROFILE
            and allow_linkable is not True
        ):
            raise ConsentRequiredError(
                "an unauthenticated request answered under the linkable presentation "
                "profile discloses the global holder commitment; the holder must "
                "consent explicitly (allow_linkable=True)"
            )
        options = {
            "consents": consents,
            "exact_member_consents": dict(exact_member_consents or {}),
            "allow_opaque": allow_opaque,
            "aggregate": aggregate,
        }
        # Every request-level refusal runs before the override is recorded.
        self._preflight(
            request, presentation, _binding_selectors_authenticated=authenticated, **options
        )
        if not authenticated:
            # Explicit, logged opt-in (Safeguard 6 mirrors the Safeguard 4 posture).
            self._record_override(
                request.proof_types[0],
                "UNAUTHENTICATED",
                "opted in to answer a request that is not a valid Authenticated Proof Request",
            )
        envelope = self._generate_envelope(
            request,
            presentation,
            _binding_selectors_authenticated=authenticated,
            **options,
        )
        receipt = self._answer_receipt(apr, envelope, request, presentation, authenticated)
        return {"envelope": envelope, "receipt": receipt}

    def answer_as_hosted_service(self, apr: dict, request: ProofRequest, **kwargs) -> dict:
        """A hosted SDK/prover answering on the holder's behalf MUST hand the
        receipt back and retain nothing (Safeguard 6 non-custody, §5.6).

        Takes exactly the keyword arguments of
        :meth:`generate_authenticated_proof`; any other keyword is a
        ``TypeError`` before any check runs."""
        result = self.generate_authenticated_proof(apr, request, **kwargs)
        return {
            "envelope": result["envelope"],
            "receipt": result["receipt"],
            "retained": False,
            "custody": "holder",
        }

    def refusal_receipt(self, apr: dict, request: ProofRequest) -> dict:
        """A holder-signed Disclosure Receipt for an explicitly refused APR
        (outcome="refused"), so a decline is portable evidence too (§5.6)."""
        refuse_secret_parameters(apr, "refused authenticated proof request")
        receipt = {
            "apr": apr,
            "outcome": "refused",
            "recordedAt": request.context.timestamp,
        }
        # A refusal presents no handle, so it is signed under a fresh key
        # (spec §5.6.1) and cannot link to any other receipt.
        return sign_receipt(receipt, self._fresh_receipt_key(receipt))

    def receipt_public_key(self, *, verifier_identity: int = None, scope_id: int = None) -> dict:
        """Public half of a stable receipt key, for the holder to give a
        relying party out of band as its ``expected_holder_key`` (spec §5.6.1).

        Pass exactly one of ``verifier_identity`` (linkable receipts under an
        authenticated APR from that verifier) or ``scope_id`` (scoped
        receipts in that scope). Anonymous, refusal and unauthenticated
        receipts use fresh keys that nobody can derive again, the holder
        included; a third party cannot anchor them (spec §5.6.1)."""
        if (verifier_identity is None) == (scope_id is None):
            raise HolderError("pass exactly one of verifier_identity or scope_id")
        try:
            if scope_id is not None:
                key = derive_scoped_receipt_key(self._master_seed, scope_id)
            else:
                key = derive_linkable_receipt_key(self._master_seed, verifier_identity)
        except ValueError as exc:
            raise HolderError(str(exc)) from exc
        return holder_public_key(key)

    def _authenticate_request(
        self, apr: dict, request: ProofRequest, allow_unauthenticated: bool, now: int, seen_nonces
    ) -> bool:
        """Validate the APR; return whether it authenticated cleanly.

        True iff the APR carried a valid, fresh, context-bound verifier
        signature. False means the caller explicitly opted in to answering an
        unauthenticated request (`allow_unauthenticated=True`) — a scoped
        presentation can never be established in that case (design §5.2 rule 1).
        A context that contradicts a valid signed APR is always refused.
        """
        signature_valid = verify_apr_signature(apr)
        if signature_valid:
            fresh, reason = apr_freshness(apr, now, seen_nonces)
        else:
            fresh, reason = False, "invalid or missing verifier signature"
        context_bound = False
        request_bound = False
        if signature_valid:
            try:
                signed_request = apr["request"]
                context_bound = _apr_context_matches_request(
                    signed_request, request.context, request.max_proof_age
                )
                request_bound = _canonical_json(
                    {
                        "proofTypes": signed_request["proofTypes"],
                        "parameters": signed_request.get("parameters", {}),
                        "bindingSelectors": parse_request_selectors(
                            signed_request.get("extensions"), signed_request["proofTypes"]
                        ),
                    }
                ) == _canonical_json(
                    {
                        "proofTypes": list(request.proof_types),
                        "parameters": request.parameters,
                        "bindingSelectors": request.binding_selectors,
                    }
                )
            except (KeyError, TypeError, ValueError):
                request_bound = False

        if signature_valid and fresh and context_bound and request_bound:
            return True

        signed_context_disagreement = signature_valid and not context_bound
        if allow_unauthenticated is not True or signed_context_disagreement:
            problems = []
            if not signature_valid:
                problems.append("invalid or missing verifier signature")
            elif not fresh:
                problems.append(reason)
            if signature_valid and not context_bound:
                problems.append("request context or proof age disagrees with the signed APR or context extension")
            if signature_valid and not request_bound:
                problems.append(
                    "proof types or parameters, or binding selectors, differ from the signed APR"
                )
            raise UnauthenticatedRequestError(
                "refusing to answer an unauthenticated proof request: "
                + "; ".join(problems)
                + (
                    " (signed context disagreement cannot be overridden)"
                    if signed_context_disagreement
                    else " (pass allow_unauthenticated=True to override explicitly)"
                )
            )
        # The caller records the explicit opt-in once every refusal has run.
        return False

    def _resolve_presentation(
        self, apr: dict, request: ProofRequest, authenticated: bool
    ) -> _Presentation:
        """Negotiate the effective presentation profile + scope (design §5.2).

        The APR's optional ``request.presentation`` block declares what the
        verifier asks for; ``request.presentation_profile`` is the holder's own
        ceiling. The effective profile is the MORE private (lower-rank) of the
        two — the holder may downgrade but never silently upgrade. A scoped
        result requires an authenticated APR and a scopePolicy; the holder
        derives ``scope_id`` ITSELF from the authenticated signer key and never
        accepts a verifier-supplied literal scope.
        """
        holder_profile = request.presentation_profile
        if holder_profile not in _PRESENTATION_RANK:
            raise HolderError(f"unknown holder presentation profile: {holder_profile!r}")

        missing = object()
        block = missing
        # ``apr is None``: no APR at all (``generate_proof``), so no verifier
        # presentation block exists and the holder's own profile governs.
        if apr is not None:
            try:
                signed_request = apr["request"]
                if isinstance(signed_request, dict):
                    block = signed_request.get("presentation", missing)
            except (KeyError, TypeError):
                pass

        if block is not missing:
            if not isinstance(block, dict):
                raise HolderError("APR presentation block must be an object")
            # A verifier NEVER supplies a pre-derived scope: the holder derives
            # scope itself from the authenticated signer key (design §5.2 rule 2).
            if "scopeId" in block or "scope_id" in block:
                raise HolderError(
                    "APR presentation block carries a verifier-supplied scopeId; "
                    "the holder derives scope itself and never accepts one on the wire"
                )
            apr_profile = block.get("profile", ANONYMOUS_PROFILE)
            if apr_profile not in _PRESENTATION_RANK:
                raise HolderError(
                    f"APR requests unknown presentation profile: {apr_profile!r}"
                )
        else:
            # Verifier is silent on presentation: the holder's own ceiling
            # governs (a silent APR can never establish a scoped pseudonym).
            apr_profile = holder_profile

        # Downgrade-only: pick the MORE private (lower-rank) of the two.
        effective = min(
            (apr_profile, holder_profile), key=lambda p: _PRESENTATION_RANK[p]
        )

        if effective == SCOPED_PROFILE:
            # Scoped continuity requires an authenticated verifier identity and
            # an explicit scopePolicy (design §5.2 rule 1).
            if not authenticated:
                raise UnauthenticatedRequestError(
                    "a scoped presentation requires an authenticated APR; "
                    "an unauthenticated request can only be answered anonymously"
                )
            if block is missing or "scopePolicy" not in block:
                raise HolderError(
                    "a scoped presentation requires an APR presentation block "
                    "with a scopePolicy"
                )
            scope_policy = block["scopePolicy"]
            if not isinstance(scope_policy, str) or not scope_policy:
                raise HolderError("APR scopePolicy must be a non-empty string")
            # A named "protocol:" scope needs separate consent even though
            # its derivation still includes the signing identity.
            # (design §5.2 rule 3).
            if scope_policy.startswith("protocol:") and not request.allow_protocol_scope:
                raise HolderError(
                    f"APR requests a named protocol scope ({scope_policy}); the holder "
                    "must consent explicitly (allow_protocol_scope=True)"
                )
            try:
                # Shared holder/verifier derivation (zkc_crypto.apr) — the two
                # sides call the SAME function so they can never drift.
                scope_id = scope_from_apr_presentation(
                    apr, block, request.context.timestamp
                )
            except ValueError as exc:
                raise HolderError(str(exc)) from exc
            return _Presentation(SCOPED_PROFILE, scope_id)

        # anonymous or linkable: no scope.
        return _Presentation(effective, 0)

    def _answer_receipt(
        self, apr: dict, envelope: dict, request: ProofRequest, presentation, authenticated: bool
    ) -> dict:
        # The receipt response binds ONLY the active profile's handle (design
        # §5.3): anonymous binds no holder-derived value; scoped binds the
        # presentation pseudonym + scope; the global holderCommitment survives
        # only in the v1/linkable path.
        response = {
            "contextValue": envelope["metadata"]["context"]["value"],
            "answeredProofTypes": [entry["proofType"] for entry in envelope["proofs"]],
        }
        presentation_profile = presentation.profile
        if presentation_profile == ANONYMOUS_PROFILE:
            # Anonymous: no holder handle at all.
            pass
        elif presentation_profile == SCOPED_PROFILE:
            binding = envelope["presentationBinding"]
            response["presentationPseudonym"] = binding["pseudonym"]
            response["scopeId"] = binding["scopeId"]
        else:
            # v1/linkable path: the global commitment is the active handle.
            response["holderCommitment"] = field_to_hex(self._holder_commitment)
        receipt = {
            "apr": apr,
            "outcome": "answered",
            "response": response,
            "recordedAt": request.context.timestamp,
        }
        return sign_receipt(
            receipt, self._answer_receipt_key(apr, presentation, authenticated, receipt)
        )

    def _fresh_receipt_key(self, receipt: dict) -> int:
        """One-receipt key over a discarded random nonce and this receipt's
        own digest (spec §5.6.1); it can never be derived again."""
        return derive_fresh_receipt_key(self._master_seed, receipt_digest_from_dict(receipt))

    def _answer_receipt_key(
        self, apr: dict, presentation, authenticated: bool, receipt: dict
    ) -> int:
        """Profile-scoped receipt key (spec §5.6.1): the key links no more
        than the active profile's handle. Derived in-process from the exact
        seed bytes; never serialized, never logged, never stored."""
        if not authenticated:
            # No authenticated verifier identity: nothing stable to scope to.
            return self._fresh_receipt_key(receipt)
        if presentation.profile == SCOPED_PROFILE:
            return derive_scoped_receipt_key(self._master_seed, presentation.scope_id)
        if presentation.profile == LINKABLE_PROFILE:
            return derive_linkable_receipt_key(
                self._master_seed, derive_verifier_identity(apr_signer_pubkey(apr))
            )
        return self._fresh_receipt_key(receipt)

    def _record_override(
        self, proof_type: str, kind: str, reason: str, predicate_id: str = ""
    ) -> None:
        """Record an explicit fail-closed override: structured + logged.

        `kind` is OPAQUE / UNREVIEWED (Safeguard 4, opaque predicate),
        UNAUTHENTICATED (Safeguard 6, unsigned proof request), or EXACT_MEMBER
        (disclosure through a fixed inclusion path). The warning is
        kind-aware so the audit trail attributes the override to the correct
        safeguard and opt-in flag."""
        record = {
            "proofType": proof_type,
            "kind": kind,
            "reason": reason,
            "predicateId": predicate_id,
        }
        self.override_log.append(record)
        if kind == "UNAUTHENTICATED":
            logger.warning(
                "UNAUTHENTICATED REQUEST OPT-IN: holder explicitly overrode the Safeguard 6 "
                "default refusal to answer an unauthenticated proof request for %s "
                "(allow_unauthenticated=True): %s",
                proof_type,
                reason,
            )
        elif kind == "EXACT_MEMBER":
            logger.warning("EXACT MEMBER DISCLOSURE OPT-IN for %s: %s", proof_type, reason)
        else:
            logger.warning(
                "OPAQUE PREDICATE OPT-IN: holder explicitly overrode the Safeguard 4 default "
                "refusal for unreviewed predicate %s (allow_opaque=True): %s",
                proof_type,
                reason,
            )

    def _generate_individual_proof(
        self,
        request: ProofRequest,
        proof_type: str,
        entry,
        consents: dict,
        *,
        emitted_proof_type: str = None,
        binding_selector=None,
    ) -> dict:
        """Assemble + prove one predicate, dispatching by the resolved circuit.

        The credential-rebind circuit takes no issuer signature or accumulator
        witness (it proves holder-commitment re-derivation only), so it is
        handled on its own path. Every other predicate selects a credential,
        refreshes its non-revocation witness, and builds a circuit-specific
        witness from the proof request parameters.
        """
        emitted_proof_type = emitted_proof_type or proof_type
        circuit = NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS.get(entry.circuit, entry.circuit)
        try:
            if circuit == REBIND_AUTH_CIRCUIT:
                full_witness = self._build_rebind_auth_witness(request, proof_type)
            elif entry.circuit in (REBIND_CIRCUIT, REBIND_BINDING_V2_CIRCUIT):
                full_witness = self._build_rebind_witness(request, proof_type)
                if entry.circuit == REBIND_BINDING_V2_CIRCUIT:
                    full_witness["statement_domain"] = REBIND_BINDING_V2_STATEMENT_DOMAIN
            else:
                credential = self.select_credential(request, emitted_proof_type)
                issuer = request.trust_policy.issuer(credential.issuer_id)
                witness, current_epoch = self._refresh_nonrevocation(request, credential)
                parameters = request.parameters.get(proof_type, {})
                parameters = self._reconcile_canonical_set(emitted_proof_type, credential, parameters)
                full_witness = self._build_predicate_witness(
                    circuit,
                    emitted_proof_type,
                    request,
                    credential,
                    issuer,
                    witness,
                    current_epoch,
                    parameters,
                )
        except (KeyError, TypeError, ValueError) as exc:
            # A parameter value of the wrong shape or type is a coded
            # refusal, never a raw Python exception.
            raise _malformed_parameters(proof_type, exc) from exc
        proof = self._backend.prove(entry.circuit, full_witness)
        result = {
            "proofType": emitted_proof_type,
            "proof": proof,
            "publicInputs": self._backend.public_inputs(entry.circuit, full_witness),
            "principalConsent": bool(consents.get(proof_type, len(request.proof_types) == 1)),
        }
        if binding_selector is not None:
            result["bindingSelector"] = binding_selector
        return result

    def _refresh_nonrevocation(self, request: ProofRequest, credential: Credential):
        """Shared non-revocation witness refresh + epoch-lag check."""
        witness = credential.witness
        if self._accumulator_provider is not None:
            witness = self.update_witness(
                credential.credential_id, issuer_id=credential.issuer_id
            )
        if witness is None:
            raise StaleWitnessError(
                "credential has no accumulator witness and no provider is configured"
            )
        current_epoch = request.current_epochs.get(
            credential.issuer_id,
            self._accumulator_provider.current_epoch(credential.issuer_id)
            if self._accumulator_provider is not None
            else witness.accumulator_epoch,
        )
        if current_epoch - witness.accumulator_epoch > MAX_EPOCH_LAG:
            raise StaleWitnessError(
                "accumulator witness epoch exceeds MAX_EPOCH_LAG and could not be refreshed"
            )
        return witness, current_epoch

    def _reconcile_canonical_set(self, proof_type: str, credential, parameters: dict) -> dict:
        """D6 fail-fast: reconcile a canonical code set BEFORE proving.

        Mirrors the verifier's derive-and-compare chokepoint
        (``zkc_verifier.verifier._resolve_canonical_set_root``, D4) on the
        holder side. Without this reconciliation, the ordinary witness builders
        echo a request root without learning how its tree was built, so a root
        the holder cannot build a witness for fails only at nargo/circuit
        proving time as an opaque constraint violation.

        P5 applies to jurisdiction and sanctions-clearance. Source-of-funds and
        tax-residency use full-Field private codes and have a separate raw-zero
        padding flaw, so treating this u16 builder as their canonical policy
        would be incorrect. A reserved canonical-set key on any unsupported
        proof type is rejected rather than silently ignored.

        The set is built in the mode the PREDICATE implies, never a default:
        sanctions-clearance is always exclusion (sentinel-bracketed), and
        jurisdiction takes its direction from the request's ``membershipType``.
        Since the two modes are different trees, this must
        agree with the verifier's own choice or the derived roots will not
        match — which is precisely what this method exists to catch early.

        When codes ARE supplied: build the same
        :class:`zkc_crypto.CanonicalCodeSet` the verifier would build, derive
        its root, and:
          * reject (``CanonicalSetMismatchError``) if a canonical set arrived
            under a key this proof type does not read (``canonicalSet`` on
            jurisdiction, ``jurisdictionCanonicalSet`` on sanctions) —
            ignoring it would silently downgrade the request to
            the bare-root path and make this whole fail-fast a no-op;
          * require the APR-distributed bare root and reject if it disagrees
            with the derived one — the two are contradicting each other, so
            fail closed rather than silently pick one;
          * reject if the credential's own code cannot be proven against that
            set (not a member when membership is required, or IS a member
            when exclusion is required) — this is the "cannot build a
            witness" case, now a clean HolderError instead of a downstream
            nargo failure;
          * otherwise return a NEW parameters dict with the witness fields
            (membership path_index/siblings, or predecessor/successor
            witness fields) filled in from the canonical set, and the bare
            root parameter set to the derived root, so the existing witness
        builders need no further changes.
        """
        if not isinstance(parameters, dict):
            raise CanonicalSetMismatchError(
                f"request parameters for {proof_type} must be a JSON object"
            )

        if proof_type in CODE_SPACE_PROOF_TO_KIND:
            return self._reconcile_code_space_set(proof_type, credential, parameters)

        proof_type = NONZERO_CREDENTIAL_PROOF_PREDECESSORS.get(proof_type, proof_type)
        if proof_type in _JURISDICTION_PROOF_TYPES:
            codes_key = JURISDICTION_CANONICAL_SET_PARAM
            root_key = "jurisdictionSetRoot"
        elif (
            proof_type in PROFILE_PROOF_TYPES
            and PROFILE_PROOF_TYPES[proof_type] == PREDICATE_SANCTIONS_CLEARANCE
        ):
            # Sanctions-clearance is the raw-u16 blocked-set predicate.
            codes_key = CANONICAL_SET_PARAM
            root_key = "setRoot"
        else:
            unsupported = [key for key in CANONICAL_SET_PARAM_KEYS if key in parameters]
            if unsupported:
                raise CanonicalSetMismatchError(
                    f"request supplies unsupported canonical-set parameter(s) "
                    f"{', '.join(repr(key) for key in unsupported)} for {proof_type}"
                )
            return parameters

        # A canonical set under a key this proof type does not read is
        # REJECTED, not ignored (mirrors the verifier's chokepoint). Ignoring
        # it would silently bypass the derive-and-compare path and make this
        # fail-fast a no-op, with no signal to anyone.
        mis_keyed = [
            key
            for key in CANONICAL_SET_PARAM_KEYS
            if key != codes_key and key in parameters
        ]
        if mis_keyed:
            raise CanonicalSetMismatchError(
                f"request supplies canonical set parameter(s) "
                f"{', '.join(repr(key) for key in mis_keyed)} for {proof_type}, which "
                f"reads its canonical set from '{codes_key}'; a mis-keyed set would be "
                "silently ignored, so it is rejected instead"
            )

        try:
            if proof_type in _JURISDICTION_PROOF_TYPES:
                membership_type = parameters["membershipType"]
                claim_type = parameters["requiredClaimType"]
                if type(membership_type) is not int:
                    raise TypeError("membershipType must be an integer")
                if type(claim_type) is not int:
                    raise TypeError("requiredClaimType must be an integer")
            else:
                membership_type = MEMBERSHIP_TYPE_EXCLUSION
                claim_type = None
            mode = _canonical_set_mode(membership_type)
        except (KeyError, TypeError, ValueError) as exc:
            raise CanonicalSetMismatchError(
                f"request lacks a usable membership mode for {proof_type}: {exc}"
            ) from exc

        if root_key not in parameters or parameters.get(root_key) is None:
            raise CanonicalSetMismatchError(
                f"request lacks APR-distributed root parameter '{root_key}' for {proof_type}"
            )

        supplied_root_int = parameters[root_key]
        if (
            type(supplied_root_int) is not int
            or not 0 <= supplied_root_int < FIELD_MODULUS
        ):
            raise CanonicalSetMismatchError(
                f"request parameter '{root_key}' for {proof_type} must be an "
                "integer in the BN254 field range"
            )

        if codes_key not in parameters:
            if mode == CANONICAL_SET_EXCLUSION:
                raise CanonicalSetMismatchError(
                    f"request lacks required canonical blocked-set parameter "
                    f"'{codes_key}' for exclusion proof {proof_type}"
                )
            return parameters

        codes_value = parameters.get(codes_key)

        # The canonical-set procedure accepts only the reference JSON-array
        # representation (``list``); tuple and other iterable aliases fail
        # closed even if a JSON serializer would encode them as an array.
        if not _is_json_array(codes_value):
            raise CanonicalSetMismatchError(
                f"request parameter '{codes_key}' for {proof_type} must be a "
                "JSON array of integer codes"
            )
        if len(codes_value) > CANONICAL_SET_MAX_REQUEST_CODES:
            raise CanonicalSetMismatchError(
                f"request parameter '{codes_key}' for {proof_type} has more than "
                f"{CANONICAL_SET_MAX_REQUEST_CODES} entries before deduplication"
            )
        codes = []
        for code in codes_value:
            if isinstance(code, bool) or not isinstance(code, int):
                raise CanonicalSetMismatchError(
                    f"request parameter '{codes_key}' for {proof_type} must contain "
                    "only integer codes"
                )
            codes.append(code)

        # The membership direction is settled BEFORE the set is built, because
        # it decides the set's shape: only an EXCLUSION set is sentinel-
        # bracketed. Bracketing an inclusion set would put codes 0 and 65535
        # in it as provable members (the circuits' inclusion branches are bare
        # Merkle membership checks with no domain constraint), so the mode is
        # never defaulted at the builder — see zkc_crypto.canonical_set.
        # Consequence: a jurisdiction exclusion set and an inclusion set over
        # the same codes have DIFFERENT roots, so the holder must build the one
        # the request's membershipType names, exactly as the verifier does.
        canonical_set_error = None
        try:
            if proof_type in _JURISDICTION_PROOF_TYPES:
                # Jurisdiction is the one predicate with both directions.
                canonical_set = CanonicalCodeSet.for_jurisdiction(
                    codes, claim_type, mode
                )
            else:
                canonical_set = CanonicalCodeSet.for_sanctions(codes)
        except (TypeError, ValueError, CanonicalSetError) as exc:
            canonical_set_error = str(exc)
        if canonical_set_error is not None:
            raise CanonicalSetMismatchError(
                f"could not build the canonical code set for {proof_type}: "
                f"{canonical_set_error}"
            )

        subject_unusable = False
        try:
            claim_key = (
                "jurisdictionCode"
                if proof_type in _JURISDICTION_PROOF_TYPES
                else "claim0"
            )
            subject_code = int(credential.claims[claim_key])
        except (KeyError, TypeError, ValueError):
            subject_unusable = True
        if subject_unusable:
            raise CanonicalSetMismatchError(
                f"credential does not contain a usable canonical-set subject for "
                f"{proof_type}"
            )

        derived_root = canonical_set.root()
        if supplied_root_int != derived_root:
            raise CanonicalSetMismatchError(
                f"request supplies both '{codes_key}' and '{root_key}' for "
                f"{proof_type}, and they disagree: the canonical set derives root "
                f"{derived_root:#x} but '{root_key}' states {supplied_root_int:#x}"
            )

        reconciled = dict(parameters)
        reconciled[root_key] = derived_root

        witness = None
        try:
            if membership_type == MEMBERSHIP_TYPE_INCLUSION:
                witness = canonical_set.membership_witness(subject_code)
                reconciled["membershipPathIndex"] = witness.path_index
                reconciled["membershipSiblings"] = list(witness.siblings)
            else:
                witness = canonical_set.non_membership_witness(subject_code)
                reconciled["predecessorCode"] = witness.predecessor_code
                reconciled["predecessorPathIndex"] = witness.predecessor_path_index
                reconciled["predecessorSiblings"] = list(witness.predecessor_siblings)
                reconciled["successorCode"] = witness.successor_code
                reconciled["successorPathIndex"] = witness.successor_path_index
                reconciled["successorSiblings"] = list(witness.successor_siblings)
        except CanonicalSetError:
            pass
        if witness is None:
            raise CanonicalSetMismatchError(
                f"credential cannot satisfy the requested canonical-set {mode} "
                f"statement for {proof_type}"
            )

        return reconciled

    @staticmethod
    def _reconcile_code_space_set(proof_type, credential, parameters):
        try:
            bound_set = resolve_code_space_request(proof_type, parameters)
            kind = bound_set.space.kind
            claims = credential.claims
            if claims.get("codeSpaceId") != bound_set.space.id:
                raise ValueError("credential and APR code spaces differ")
            jurisdiction = kind == "jurisdiction"
            subject = bound_set.space.validate_code(claims["jurisdictionCode" if jurisdiction else "claim0"])
            if jurisdiction:
                if claims["claimType"] != parameters["requiredClaimType"]:
                    raise ValueError("jurisdiction claim type differs from the APR")
                method = bound_set.required_verification_method
                if method and claims["verificationMethod"] != method:
                    raise ValueError("jurisdiction verification method differs from the APR")
            elif kind == "tax" and claims["claim1"] < bound_set.minimum_tax_year:
                raise ValueError("tax year is below the APR minimum")

            if bound_set.code_set.mode == CANONICAL_SET_INCLUSION:
                proof = bound_set.code_set.membership_witness(subject)
                if jurisdiction:
                    return {**parameters, "membershipPathIndex": proof.path_index,
                            "membershipSiblings": list(proof.siblings)}
                return {**parameters, "pathIndex": proof.path_index, "siblings": list(proof.siblings)}

            proof = bound_set.code_set.non_membership_witness(subject)
            return {
                **parameters,
                "predecessorCode": proof.predecessor_code,
                "predecessorPathIndex": proof.predecessor_path_index,
                "predecessorSiblings": list(proof.predecessor_siblings),
                "successorCode": proof.successor_code,
                "successorPathIndex": proof.successor_path_index,
                "successorSiblings": list(proof.successor_siblings),
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise CanonicalSetMismatchError(f"code-space proof request cannot be satisfied for {proof_type}") from exc

    def _build_predicate_witness(
        self,
        circuit,
        proof_type,
        request,
        credential,
        issuer,
        witness,
        current_epoch,
        parameters,
    ) -> dict:
        if circuit in (KYC_CIRCUIT, COMMUNITY_KYC_V2_CIRCUIT):
            return build_kyc_witness(
                credential_binding_key=self._credential_binding_key,
                credential=credential,
                issuer=issuer,
                witness=witness,
                required_level=int(parameters.get("requiredLevel", 1)),
                required_attributes=parameters.get("requiredAttributes", [False] * 5),
                proof_context=request.context.value,
                timestamp=request.context.timestamp,
                current_epoch=current_epoch,
            )
        if circuit in (JURISDICTION_V1_CIRCUIT, JURISDICTION_V3_CIRCUIT):
            return build_jurisdiction_witness(
                credential_binding_key=self._credential_binding_key,
                credential=credential,
                issuer=issuer,
                witness=witness,
                membership_type=int(parameters.get("membershipType", 0)),
                required_claim_type=int(
                    parameters.get("requiredClaimType", credential.claims["claimType"])
                ),
                jurisdiction_set_root=int(parameters["jurisdictionSetRoot"]),
                membership_path_index=int(parameters.get("membershipPathIndex", 0)),
                membership_siblings=parameters.get("membershipSiblings", [0] * 32),
                predecessor_code=int(parameters.get("predecessorCode", 0)),
                predecessor_path_index=int(parameters.get("predecessorPathIndex", 0)),
                predecessor_siblings=parameters.get("predecessorSiblings", [0] * 32),
                successor_code=int(parameters.get("successorCode", 0)),
                successor_path_index=int(parameters.get("successorPathIndex", 0)),
                successor_siblings=parameters.get("successorSiblings", [0] * 32),
                proof_context=request.context.value,
                timestamp=request.context.timestamp,
                current_epoch=current_epoch,
            )
        if circuit in (
            REMAINING_CIRCUIT,
            REMAINING_V3_CIRCUIT,
            REMAINING_V5_CIRCUIT,
            REMAINING_V7_CIRCUIT,
        ):
            predicate_type = PROFILE_PROOF_TYPES.get(proof_type)
            if predicate_type is None:
                raise OpaquePredicateError(
                    f"profile circuit has no predicate type for {proof_type}"
                )
            flag_required = _profile_flag_required(
                parameters,
                proof_type,
                predicate_type,
            )
            builder = {
                REMAINING_CIRCUIT: build_profile_witness,
                REMAINING_V3_CIRCUIT: build_profile_witness_v3,
                REMAINING_V5_CIRCUIT: build_profile_witness_v5,
                REMAINING_V7_CIRCUIT: build_profile_witness_v7,
            }[circuit]
            return builder(
                predicate_type=predicate_type,
                credential_binding_key=self._credential_binding_key,
                credential=credential,
                issuer=issuer,
                witness=witness,
                required_0=parameters.get("required0", 0),
                required_1=parameters.get("required1", 0),
                flag_required=flag_required,
                set_root=int(parameters.get("setRoot", 0)),
                path_index=int(parameters.get("pathIndex", 0)),
                siblings=parameters.get("siblings", [0] * 32),
                predecessor_code=int(parameters.get("predecessorCode", 0)),
                predecessor_path_index=int(parameters.get("predecessorPathIndex", 0)),
                predecessor_siblings=parameters.get("predecessorSiblings", [0] * 32),
                successor_code=int(parameters.get("successorCode", 0)),
                successor_path_index=int(parameters.get("successorPathIndex", 0)),
                successor_siblings=parameters.get("successorSiblings", [0] * 32),
                proof_context=request.context.value,
                timestamp=request.context.timestamp,
                current_epoch=current_epoch,
            )
        raise OpaquePredicateError(
            f"reference SDK has no witness builder for circuit {circuit} ({proof_type})"
        )

    @staticmethod
    def _rebind_secret_key(request: ProofRequest) -> int:
        """The rebind's NEW binding key, from the holder-local channel only.

        Never read from ``request.parameters``: those are verifier-chosen and,
        on the authenticated path, verifier-signed (spec 7.4.4)."""
        secret = request.rebind_secret
        if not isinstance(secret, RebindSecret):
            raise HolderError(
                "credential rebind requires a holder-local RebindSecret "
                "(ProofRequest.rebind_secret) naming the new binding key"
            )
        return secret.credential_binding_key

    def _build_rebind_auth_witness(
        self, request: ProofRequest, proof_type: str, *, scope_id: int = None
    ) -> dict:
        """Build an ISSUER-AUTHENTICATED rebind witness (spec section 7.4).

        Unlike the deprecated rebind builders, nothing here is copied from an
        unauthenticated credential object: the credential's issuer, schema,
        holder commitment, identifier and validity all enter the witness
        through the issuer-signed attestation, whose signature this client
        verifies locally against the trust policy's key BEFORE proving, and the
        non-revocation witness is refreshed and epoch-checked first. The
        credential to migrate is named explicitly by the request, never
        guessed.
        """
        parameters = request.parameters.get(proof_type, {}) or {}
        if "credentialId" not in parameters:
            raise HolderError(
                "authenticated credential rebind requires a credentialId parameter naming "
                "the credential to migrate"
            )
        credential_id = parameters["credentialId"]
        if isinstance(credential_id, bool) or not isinstance(credential_id, int):
            raise HolderError("credentialId must be a canonical field integer")
        # credentialId is issuer-chosen: credentials from several issuers may
        # carry it. Only a credential whose issuer this request trusts for the
        # proof type can be migrated, so narrow to those; two trusted matches
        # are refused, never guessed between.
        matches = [c for c in self._store.list() if c.credential_id == credential_id]
        if not matches:
            raise NoMatchingCredentialError(
                "no stored credential matches the requested credentialId"
            )
        if len(matches) > 1:
            matches = [
                c for c in matches if request.trust_policy.trusts(c.issuer_id, proof_type)
            ]
            if not matches:
                raise UnknownIssuerError(
                    f"credential issuer is not trusted for {proof_type} by this request"
                )
            if len(matches) > 1:
                raise AmbiguousCredentialError(
                    "stored credentials from several issuers trusted by this request "
                    "carry the requested credentialId"
                )
        credential = matches[0]
        if credential.rebind_attestation is None:
            raise NoMatchingCredentialError(
                "the stored credential carries no issuer rebind attestation; ask the issuer "
                "to emit zkc:attestation:credential-rebind:v1 material for it"
            )
        issuer = request.trust_policy.issuer(credential.issuer_id)
        if issuer is None or not request.trust_policy.trusts(credential.issuer_id, proof_type):
            raise UnknownIssuerError(
                f"credential issuer is not trusted for {proof_type} by this request"
            )
        new_binding_key = self._rebind_secret_key(request)
        witness, current_epoch = self._refresh_nonrevocation(request, credential)
        common = {
            "old_credential_binding_key": self._credential_binding_key,
            "new_credential_binding_key": new_binding_key,
            "credential": credential,
            "issuer_public_key_x": issuer.public_key_x,
            "issuer_public_key_y": issuer.public_key_y,
            "accumulator_witness": witness,
            "current_epoch": current_epoch,
            "proof_context": request.context.value,
            "timestamp": request.context.timestamp,
        }
        if scope_id is None:
            return build_rebind_auth_witness(**common)
        return build_rebind_auth_witness_v2(scope_id=int(scope_id), **common)

    def _build_rebind_witness(self, request: ProofRequest, proof_type: str) -> dict:
        """Build the credential-rebind witness.

        Rebind migrates a credential from this client's holder commitment to a
        new one derived from a fresh binding key. Both binding keys stay
        in-process. The new binding key comes from the holder-local
        RebindSecret; request parameters supply only the issuer/schema id
        hashes the credential must match.
        """
        parameters = request.parameters.get(proof_type, {})
        credential = self.select_credential(request, proof_type)
        new_binding_key = self._rebind_secret_key(request)
        return build_rebind_witness(
            old_credential_binding_key=self._credential_binding_key,
            new_credential_binding_key=new_binding_key,
            credential=credential,
            issuer_id_hash=int(parameters["issuerIdHash"]),
            schema_id_hash=int(parameters["schemaIdHash"]),
            proof_context=request.context.value,
            timestamp=request.context.timestamp,
        )

    # --- aggregation entry point ----------------------------------------------------

    def _build_aggregation(self, envelope: dict, request: ProofRequest, consents: dict) -> dict:
        proofs = envelope["proofs"]
        commitments = []
        type_fields = []
        consent_flags = []
        for proof_entry in proofs:
            # Simulated-recursion vk binding: the manifest-pinned UltraHonk vk
            # hash (registry circuit.vkHash, CI-cross-checked against
            # artifacts/manifest.json) — the commitment binds the verification
            # key actually verified against, never a source-derived stand-in.
            selector = proof_entry.get("bindingSelector")
            if selector is not None:
                try:
                    resolved = self._registry.resolve_binding(
                        proof_entry["proofType"],
                        selector,
                        accepted_source_statuses=self._accepted_review_statuses,
                        accepted_binding_statuses=self._accepted_binding_review_statuses,
                        allowed_binding_ids=self._allowed_binding_ids,
                    )
                except BindingResolutionError as exc:
                    raise HolderError(f"aggregation binding resolution failed: {exc}") from exc
                vk_hash = resolved.binding.vk_hash
                circuit = resolved.binding.circuit
            else:
                # Every proof here already passed the Safeguard-4 gate (or its
                # logged override) in _gated_entry; resolve the same entry.
                entry = self._registry.resolve(
                    proof_entry["proofType"],
                    accepted_statuses=self._accepted_review_statuses,
                    allow_unaccepted=True,
                )
                vk_hash = entry.vk_hash if entry is not None else ""
                circuit = entry.circuit if entry is not None else proof_entry["proofType"]
            if not vk_hash:
                raise HolderError(
                    f"no manifest-pinned verification key hash for circuit {circuit}; "
                    "aggregation requires an exact registry/manifest vkHash"
                )
            vk_bytes = bytes.fromhex(vk_hash.removeprefix("0x"))
            commitments.append(agg.commitment_for_envelope_proof(proof_entry, vk_bytes))
            type_fields.append(string_to_field(proof_entry["proofType"]))
            consent_flags.append(bool(proof_entry["principalConsent"]))

        commitment = agg.aggregate_commitments(
            request.context.value,
            self._holder_commitment,
            commitments,
            type_fields,
            consent_flags,
        )
        claim_binding = agg.aggregated_claim_binding(commitment, request.context.value)
        return {
            "proof": stub_proof_payload(
                "zkc_aggregation",
                {
                    "aggregation_commitment": field_to_hex(commitment),
                    "aggregated_claim_binding": field_to_hex(claim_binding),
                    "holder_commitment": field_to_hex(self._holder_commitment),
                    "context": field_to_hex(request.context.value),
                    "num_proofs": len(proofs),
                },
            ),
            "inputProofCommitments": [field_to_hex(c) for c in commitments],
            "aggregationCommitment": field_to_hex(commitment),
            "aggregatedClaimBinding": field_to_hex(claim_binding),
        }
