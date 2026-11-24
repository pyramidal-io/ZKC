"""Structured, fail-closed errors for the ZKC holder SDK.

Every error carries a stable machine-readable code. Messages never contain
secret material (seeds, binding keys, witness values, stored claims).
"""

from __future__ import annotations

__all__ = [
    "HolderError",
    "NoMatchingCredentialError",
    "AmbiguousCredentialError",
    "StaleCredentialError",
    "StaleWitnessError",
    "UnknownIssuerError",
    "OpaquePredicateError",
    "OverbroadRequestError",
    "ContextError",
    "ConsentRequiredError",
    "ExactMemberConsentRequiredError",
    "ConstraintViolationError",
    "BackendUnavailableError",
    "StorageError",
    "ForbiddenMaterialError",
    "UnauthenticatedRequestError",
    "ReceiptRetentionError",
    "CanonicalSetMismatchError",
    "UnauthenticatedProofTypeError",
    "AnonymousCompositeRefusedError",
    "SecretInRequestError",
]


class HolderError(Exception):
    """Base class; subclasses define a stable `code`."""

    code = "HOLDER_ERROR"

    def __init__(self, message: str):
        super().__init__(f"[{self.code}] {message}")
        self.message = message


class NoMatchingCredentialError(HolderError):
    code = "NO_MATCHING_CREDENTIAL"


class AmbiguousCredentialError(HolderError):
    """A lookup named only a ``credentialId`` and stored credentials from more
    than one issuer carry it. Issuers choose credential identifiers, so an
    identifier is unique only within its issuer; the holder never guesses
    which credential was meant. Name the issuer as well."""

    code = "AMBIGUOUS_CREDENTIAL"


class StaleCredentialError(HolderError):
    code = "STALE_CREDENTIAL"


class StaleWitnessError(HolderError):
    code = "STALE_WITNESS"


class UnknownIssuerError(HolderError):
    code = "UNKNOWN_ISSUER"


class OpaquePredicateError(HolderError):
    code = "OPAQUE_PREDICATE_REFUSED"


class OverbroadRequestError(HolderError):
    """A verifier request asks beyond its published policy or beyond the
    holder's consent scope. `elements` is a structured list of the overbroad
    elements ({proofType, element, requested, permitted, kind})."""

    code = "OVERBROAD_REQUEST"

    def __init__(self, message: str, elements=()):
        super().__init__(message)
        self.elements = tuple(dict(element) for element in elements)


class ContextError(HolderError):
    code = "INVALID_CONTEXT"


class ConsentRequiredError(HolderError):
    code = "CONSENT_REQUIRED"


class ExactMemberConsentRequiredError(ConsentRequiredError):
    """A fixed inclusion path requires consent to disclose an exact code."""

    code = "EXACT_MEMBER_CONSENT_REQUIRED"


class ConstraintViolationError(HolderError):
    code = "CONSTRAINT_VIOLATION"


class BackendUnavailableError(HolderError):
    code = "BACKEND_UNAVAILABLE"


class StorageError(HolderError):
    code = "STORAGE_ERROR"


class ForbiddenMaterialError(HolderError):
    code = "FORBIDDEN_MATERIAL"


class UnauthenticatedRequestError(HolderError):
    """Safeguard 6: a conforming SDK refuses by default to answer a request
    that is not a valid Authenticated Proof Request (spec §5.5)."""

    code = "UNSIGNED_REQUEST"


class ReceiptRetentionError(HolderError):
    """Safeguard 6: receipts are holder-custodied; a hosted SDK/service is
    asked to retain one and refuses (spec §5.6)."""

    code = "RECEIPT_RETENTION_REFUSED"


class CanonicalSetMismatchError(HolderError):
    """Spec §7.2c: canonical-set request data could not be reconciled before
    proving. This covers malformed or unsupported canonical parameters, a
    missing/mismatched APR-distributed root, and a credential code for which
    the required membership or exclusion witness cannot exist. Raised instead
    of letting an unprovable or contradictory request reach the ZK backend as
    an opaque witness-constraint failure."""

    code = "CANONICAL_SET_MISMATCH"


class AnonymousCompositeRefusedError(HolderError):
    """The request asks for two or more proofs and the effective presentation
    profile is anonymous. Anonymous proofs bind to no single holder, so a
    conforming verifier rejects the answer (UNBOUND_COMPOSITE, spec 5.9.4) and
    generating it would only disclose which predicates the holder satisfies.
    Refused before any proving unless ``ProofRequest.allow_unlinked_composite``
    is set (spec 5.9.2)."""

    code = "ANONYMOUS_COMPOSITE_REFUSED"


class SecretInRequestError(HolderError):
    """A request, APR, negotiation request or verifier policy names holder
    secret material (e.g. a rebind's ``newMasterSeed``). Refused before any
    proving: secrets travel only through holder-local channels (spec 7.4.4)."""

    code = "SECRET_IN_REQUEST"


class UnauthenticatedProofTypeError(HolderError):
    """Security containment: the requested proof type asserts credential
    continuity (a credential rebind) but its circuit authenticates neither
    issuance nor live revocation state -- every credential field it carries is
    an unconstrained prover witness. The holder SDK never selects, generates,
    or migrates a live credential through such a statement; an explicit
    request fails with this stable code instead of silently downgrading."""

    code = "UNAUTHENTICATED_PROOF_TYPE"
