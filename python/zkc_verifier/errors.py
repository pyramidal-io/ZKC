"""Structured verification errors (spec §6.2).

Every rejection carries a stable machine-readable code. The set is closed and
enumerated here; tests exercise each code deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from zkc_crypto.presentation import ANONYMOUS_PROFILE, SCOPED_PROFILE

__all__ = [
    "VerificationErrorCode",
    "VerificationError",
    "VerificationResult",
    "VerificationWarningCode",
    "VerificationWarning",
]


# Presentation profiles a zkc:proof:v2 envelope can declare (section 6.1).
_V2_WIRE_PROFILES = (ANONYMOUS_PROFILE, SCOPED_PROFILE)


class VerificationErrorCode:
    """Closed enumeration of verification error codes."""

    MALFORMED_PROOF = "MALFORMED_PROOF"
    STALE_PROOF = "STALE_PROOF"
    EXPIRED_PROOF = "EXPIRED_PROOF"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    INVALID_BINDING = "INVALID_BINDING"
    INVALID_PROOF = "INVALID_PROOF"
    UNKNOWN_PROOF_TYPE = "UNKNOWN_PROOF_TYPE"
    UNREVIEWED_PREDICATE = "UNREVIEWED_PREDICATE"
    UNKNOWN_VERIFICATION_KEY = "UNKNOWN_VERIFICATION_KEY"
    STALE_ACCUMULATOR = "STALE_ACCUMULATOR"
    UNAUTHENTICATED_ACCUMULATOR = "UNAUTHENTICATED_ACCUMULATOR"
    UNTRUSTED_ISSUER = "UNTRUSTED_ISSUER"
    REQUIREMENTS_NOT_MET = "REQUIREMENTS_NOT_MET"
    MISSING_PROOF = "MISSING_PROOF"
    INVALID_AGGREGATION = "INVALID_AGGREGATION"
    # Verifier accountability (Safeguard 6, spec §5.5/§6.2). Adjacent to the
    # existing STALE_PROOF / CONTEXT_MISMATCH family; existing semantics are
    # unchanged.
    UNSIGNED_REQUEST = "UNSIGNED_REQUEST"
    PURPOSE_MISMATCH = "PURPOSE_MISMATCH"
    # Presentation profiles (design §6). PROFILE_NOT_ACCEPTED: the envelope's
    # profile is not in the verifier's accepted_profiles (a v1 envelope is
    # the linkable profile, gated only by an explicitly configured policy).
    # PROFILE_MISMATCH: a proof entry's presentation_pseudonym/scope_id are
    # inconsistent with the envelope presentationBinding (anti-replay shape
    # check, replacing the v1 holder_commitment envelope-vs-proof check); a
    # proof entry's circuit family does not match its envelope generation; or
    # an authenticated envelope is more linkable than its APR asked for; or
    # the verifier policy requires continuity
    # (require_presentation_continuity) and the envelope is anonymous.
    # SCOPE_MISMATCH: a scoped proof was not derived from THIS verifier's
    # authenticated identity (D2), including a scoped answer under a
    # continuity-required policy whose scope this verifier could not
    # recompute (plain verify() never can).
    PROFILE_NOT_ACCEPTED = "PROFILE_NOT_ACCEPTED"
    PROFILE_MISMATCH = "PROFILE_MISMATCH"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    # Request binding (spec §6.2 step 4e). UNBOUND_PROOF_TYPE is the
    # default-deny verdict of the verifier's request-binding registry: a proof
    # type with no declared contract binding it to the request is REJECTED, so
    # a predicate added without a binding contract fails closed instead of
    # verifying against nothing. The authenticated path's request-vs-APR
    # disagreement guard (the caller-supplied VerificationRequest disagreeing
    # with the signed APR whose digest already commits to proofTypes +
    # parameters) is the exact condition spec §5.5 step 0 names, and it reuses
    # that step's own code, UNSIGNED_REQUEST, rather than minting a new one
    # (see docs/adr/0003-request-binding-chokepoint.md).
    UNBOUND_PROOF_TYPE = "UNBOUND_PROOF_TYPE"
    # Credential-continuity containment (security remediation, 2026-09-06).
    # The four historical credential-rebind identities prove only that the
    # prover controls two binding keys; every credential field they carry is
    # an unconstrained private witness, so a cryptographically valid proof
    # authenticates neither issuance nor live revocation state. The verifier
    # rejects them at BOTH entry points before any backend verification, with
    # or without a configured issuer trust policy. Backend proof validity never
    # implies authenticated credential continuity.
    UNAUTHENTICATED_CREDENTIAL = "UNAUTHENTICATED_CREDENTIAL"
    # Authenticated use of a known unsafe historical identity requires the
    # explicit "deprecated" policy, independent of advisory registry labels.
    # Also emitted when every listing of another identity is deprecated.
    DEPRECATED_PROOF_TYPE = "DEPRECATED_PROOF_TYPE"
    # An anonymous presentation answers two or more requested proofs but
    # nothing binds them to ONE holder (anonymous proofs publish no holder
    # handle), so proofs from different holders could be pooled to satisfy a
    # conjunctive request. Same-holder composites use the scoped profile
    # (scopePolicy "session" keeps sessions unlinkable).
    UNBOUND_COMPOSITE = "UNBOUND_COMPOSITE"
    MALFORMED_BINDING_SELECTOR = "MALFORMED_BINDING_SELECTOR"
    UNKNOWN_BINDING = "UNKNOWN_BINDING"
    INACTIVE_BINDING = "INACTIVE_BINDING"
    DEPRECATED_BINDING = "DEPRECATED_BINDING"
    DISALLOWED_BINDING = "DISALLOWED_BINDING"

    ALL = (
        MALFORMED_PROOF,
        STALE_PROOF,
        EXPIRED_PROOF,
        CONTEXT_MISMATCH,
        INVALID_BINDING,
        INVALID_PROOF,
        UNKNOWN_PROOF_TYPE,
        UNREVIEWED_PREDICATE,
        UNKNOWN_VERIFICATION_KEY,
        STALE_ACCUMULATOR,
        UNAUTHENTICATED_ACCUMULATOR,
        UNTRUSTED_ISSUER,
        REQUIREMENTS_NOT_MET,
        MISSING_PROOF,
        INVALID_AGGREGATION,
        UNSIGNED_REQUEST,
        PURPOSE_MISMATCH,
        PROFILE_NOT_ACCEPTED,
        PROFILE_MISMATCH,
        SCOPE_MISMATCH,
        UNBOUND_PROOF_TYPE,
        UNAUTHENTICATED_CREDENTIAL,
        DEPRECATED_PROOF_TYPE,
        UNBOUND_COMPOSITE,
        MALFORMED_BINDING_SELECTOR,
        UNKNOWN_BINDING,
        INACTIVE_BINDING,
        DEPRECATED_BINDING,
        DISALLOWED_BINDING,
    )


@dataclass(frozen=True)
class VerificationError:
    code: str
    message: str
    proof_type: str = ""

    def __post_init__(self):
        if self.code not in VerificationErrorCode.ALL:
            raise ValueError(f"unknown verification error code: {self.code}")

    def to_dict(self) -> dict:
        output = {"code": self.code, "message": self.message}
        if self.proof_type:
            output["proofType"] = self.proof_type
        return output


class VerificationWarningCode:
    """Closed enumeration of NON-FATAL verification warnings.

    Warnings never affect validity: they flag disclosure-hygiene issues a
    verifier should not silently ignore (e.g. an envelope disclosing more
    than was asked for), without rejecting an otherwise valid proof.
    """

    OVER_DISCLOSURE = "OVER_DISCLOSURE"
    OVERBROAD_REQUEST = "OVERBROAD_REQUEST"
    # A request parameter the predicate structurally cannot bind. Retained for
    # wire compatibility; legacy flagRequired now fails closed instead.
    UNBINDABLE_PARAMETER = "UNBINDABLE_PARAMETER"
    # The verifier accepted a proof whose accumulator_root it could not check
    # because it records no issuer root for that epoch. Emitted ONLY under the
    # explicit VerifierTrustPolicy.allow_unrecorded_accumulator_roots opt-out:
    # revocation was NOT enforced for that proof.
    UNCHECKED_ACCUMULATOR_ROOT = "UNCHECKED_ACCUMULATOR_ROOT"

    ALL = (
        OVER_DISCLOSURE,
        OVERBROAD_REQUEST,
        UNBINDABLE_PARAMETER,
        UNCHECKED_ACCUMULATOR_ROOT,
    )


@dataclass(frozen=True)
class VerificationWarning:
    code: str
    message: str
    proof_type: str = ""

    def __post_init__(self):
        if self.code not in VerificationWarningCode.ALL:
            raise ValueError(f"unknown verification warning code: {self.code}")

    def to_dict(self) -> dict:
        output = {"code": self.code, "message": self.message}
        if self.proof_type:
            output["proofType"] = self.proof_type
        return output


@dataclass
class VerificationResult:
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    # Exact binding/VK evidence for successful v2 artifact resolution.
    bindings: list = field(default_factory=list)
    # Effective presentation of the envelope as parsed (spec section 5.9.4,
    # "Reporting the effective presentation"). A caller relies on these only
    # when ``valid`` is true. ``presentation_profile`` is the profile the
    # holder actually answered with (a v1 envelope is the linkable profile),
    # which may be LESS linkable than the profile the verifier asked for: a
    # holder may downgrade scoped -> anonymous (section 5.9.2 rule 4).
    # ``presentation_handle`` is the canonical hex of the profile's public
    # holder handle: the scoped presentationPseudonym, the linkable
    # holderCommitment, or None for anonymous (no handle exists). It and
    # ``scope_id`` (the scoped envelope's scopeId) are reported only when at
    # least one requested proof was checked against the envelope binding; an
    # envelope answering no requested proof leaves both None, because its
    # binding handle is then an unproven, presenter-chosen value.
    # ``scope_recomputed`` is True ONLY when verify_authenticated recomputed
    # scope_id from this verifier's own pinned signing identity and it
    # matched; plain verify() never recomputes it, so a scoped pseudonym it
    # reports is under a HOLDER-CHOSEN scope and is no continuity handle.
    presentation_profile: Optional[str] = None
    presentation_handle: Optional[str] = None
    scope_id: Optional[str] = None
    scope_recomputed: bool = False

    @property
    def valid(self) -> bool:
        # Validity depends on errors ONLY; warnings are advisory.
        return not self.errors

    def codes(self) -> list:
        return [error.code for error in self.errors]

    def warning_codes(self) -> list:
        return [warning.code for warning in self.warnings]

    def add(self, code: str, message: str, proof_type: str = "") -> None:
        self.errors.append(VerificationError(code=code, message=message, proof_type=proof_type))

    def add_warning(self, code: str, message: str, proof_type: str = "") -> None:
        self.warnings.append(
            VerificationWarning(code=code, message=message, proof_type=proof_type)
        )

    def to_dict(self) -> dict:
        output = {
            "valid": self.valid,
            "errors": [error.to_dict() for error in self.errors],
            "warnings": [warning.to_dict() for warning in self.warnings],
        }
        # Preserve the exact legacy wire result when no v2 binding was used.
        if self.bindings:
            output["bindings"] = list(self.bindings)
        # The effective presentation joins the wire result for zkc:proof:v2
        # envelopes only (anonymous or scoped). A v1 (linkable) result keeps
        # the exact legacy wire shape; its attributes are still populated.
        if self.presentation_profile in _V2_WIRE_PROFILES:
            presentation = {
                "profile": self.presentation_profile,
                "scopeRecomputed": self.scope_recomputed,
            }
            if self.presentation_handle is not None:
                presentation["pseudonym"] = self.presentation_handle
            if self.scope_id is not None:
                presentation["scopeId"] = self.scope_id
            output["presentation"] = presentation
        return output
