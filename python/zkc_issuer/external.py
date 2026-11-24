"""Production issuer adapter skeleton: plugging in a real credential provider.

``ExternalProviderAdapter`` shows where a real KYC / sanctions / accreditation
/ jurisdiction vendor integrates with ZKC. Everything except subject
verification — binding challenge, digest signing, accumulator registration,
metadata, revocation, privacy boundary — is the shared adapter machinery
(``BaseIssuerAdapter``); the ONLY provider-specific surface is the
``ProviderClient`` boundary below.

THIS MODULE PERFORMS NO NETWORK CALLS. The bundled ``StaticProviderClient``
is fixture-driven. For the reference KYC capability, a production deployment
replaces it with a client that calls the vendor's API inside
``ProviderClient.verify_subject`` and maps the vendor's decision into the
provider-neutral ``ProviderDecision`` shape. ``ExternalProviderAdapter`` is
KYC-only by default. A production adapter for any other schema must subclass it
and declare a validated, nonempty exact ``supported_schema_ids`` frozenset plus
an exact ``MappingProxyType`` ``schema_required_privacy_profiles`` mapping with
a nonempty exact ``frozenset`` entry for every supported schema. Replacing only
the client does not add capabilities.

Provider boundary rules (enforced by the conformance kit):

* the provider client receives only the subject-verification payload, which
  has already passed the privacy-boundary scan — wallet material never
  reaches a vendor;
* the decision returns issuer-attestable claims for the requested schema,
  never raw identity documents;
* provider failures surface as ``PROVIDER_VERIFICATION_FAILED`` (or
  ``RATE_LIMITED``) — never ad-hoc exceptions leaking vendor detail.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from zkc_crypto import hex_to_field

from .adapter import BaseIssuerAdapter, _reference_session_identity
from .errors import AdapterError
from .schemas import ATTRIBUTE_SET_V1_SCHEMA_ID, RUNTIME_ATTESTATION_SCHEMA_ID, CredentialSchema

__all__ = [
    "ProviderDecision",
    "ProviderClient",
    "StaticProviderClient",
    "ExternalProviderAdapter",
    "reference_external_adapter",
]

_PROVIDER_ERROR = "provider verification failed"
_MAX_PROVIDER_REF_UTF8_BYTES = 256
_MAX_PROVIDER_CONTAINER_DEPTH = 32
_MAX_PROVIDER_VALUE_NODES = 4096
_MAX_PROVIDER_KEY_UTF8_BYTES = 4096
_MAX_U64 = (1 << 64) - 1


def _copy_provider_claims(value) -> dict:
    """Return an owned, bounded plain-container copy of provider claims."""

    seen_containers: set[int] = set()
    node_count = [0]

    def copy_node(current, container_depth: int):
        node_count[0] += 1
        if node_count[0] > _MAX_PROVIDER_VALUE_NODES:
            raise ValueError(_PROVIDER_ERROR)

        current_type = type(current)
        if current_type is dict:
            if container_depth >= _MAX_PROVIDER_CONTAINER_DEPTH:
                raise ValueError(_PROVIDER_ERROR)
            if id(current) in seen_containers:
                raise ValueError(_PROVIDER_ERROR)
            seen_containers.add(id(current))
            copied = {}
            for key, child in current.items():
                if type(key) is not str:
                    raise ValueError(_PROVIDER_ERROR)
                try:
                    key_size = len(key.encode("utf-8"))
                except UnicodeError:
                    raise ValueError(_PROVIDER_ERROR) from None
                if key_size > _MAX_PROVIDER_KEY_UTF8_BYTES:
                    raise ValueError(_PROVIDER_ERROR)
                copied[key] = copy_node(child, container_depth + 1)
            return copied
        if current_type is list:
            if container_depth >= _MAX_PROVIDER_CONTAINER_DEPTH:
                raise ValueError(_PROVIDER_ERROR)
            if id(current) in seen_containers:
                raise ValueError(_PROVIDER_ERROR)
            seen_containers.add(id(current))
            return [copy_node(child, container_depth + 1) for child in current]
        if current_type is tuple:
            if container_depth >= _MAX_PROVIDER_CONTAINER_DEPTH:
                raise ValueError(_PROVIDER_ERROR)
            if id(current) in seen_containers:
                raise ValueError(_PROVIDER_ERROR)
            seen_containers.add(id(current))
            return tuple(copy_node(child, container_depth + 1) for child in current)
        if current is None or current_type in (str, int, bool):
            return current
        raise ValueError(_PROVIDER_ERROR)

    copied_claims = copy_node(value, 0)
    if type(copied_claims) is not dict:
        raise ValueError(_PROVIDER_ERROR)
    return copied_claims


def _raise_provider_verification_failed() -> None:
    raise AdapterError("PROVIDER_VERIFICATION_FAILED", _PROVIDER_ERROR) from None


@dataclass(frozen=True)
class ProviderDecision:
    """A provider-neutral subject-verification outcome.

    ``provider_ref`` is a stable provider-owned subject identity, allocated
    inside its private store and independent of caller-supplied locators. It
    stays private and keys the subject/schema issuance lineage. Providers must
    authenticate the caller and authorize that subject for the supplied trusted
    ``authenticated_session``. ``holder_commitment`` is mandatory for runtime
    attestation: the commitment verified in authenticated evidence, never an
    echo of caller input. ``claims``/``expires_at`` are issuer-attestable data.
    For legacy attribute sets, ``attribute_layout_id`` is the provider's
    verified layout for the returned slots. For v2 the provider declares the
    layout in ``claims["layoutId"]``.
    """

    verified: bool
    provider_ref: str = ""
    claims: dict = field(default_factory=dict)
    expires_at: int = 0
    failure_reason: str = "provider verification failed"
    holder_commitment: str = None
    attribute_layout_id: str | None = None


class ProviderClient:
    """The vendor API boundary.

    ======================================================================
    ``verify_subject`` is the ONLY place a vendor API call belongs.
    Production: implement it against your provider; map the provider's
    decision into ``ProviderDecision``. Do not call vendors anywhere else.
    ======================================================================
    """

    def verify_subject(self, schema_id: str, payload: dict, *, authenticated_session: str) -> ProviderDecision:
        """Verify evidence AND authorize this subject for the trusted session.

        A public applicant/evidence locator alone never authenticates a caller.
        """
        raise NotImplementedError


class StaticProviderClient(ProviderClient):
    """Fixture-driven provider client (reference/testing; no network).

    ``decisions``: subjectId -> schema_id -> {"claims": …, "expiresAt": …}.
    ``subjectId`` is a public fixture selector, not authentication. This
    test-only client preallocates independent random private subject identities.
    Production providers must verify applicant authorization for the trusted
    authenticated session before returning a decision.
    """

    def __init__(self, decisions: dict):
        self._decisions = dict(decisions)
        self._subject_refs = {key: secrets.token_hex(32) for key in self._decisions}

    def verify_subject(self, schema_id: str, payload: dict, *, authenticated_session: str) -> ProviderDecision:
        subject = self._decisions.get(payload.get("subjectId"))
        if subject is None or schema_id not in subject:
            return ProviderDecision(verified=False)
        entry = subject[schema_id]
        return ProviderDecision(
            verified=True,
            provider_ref=self._subject_refs[payload.get("subjectId")],
            claims=entry["claims"],
            expires_at=int(entry["expiresAt"]),
            attribute_layout_id=entry.get("attributeLayoutId"),
        )


class ExternalProviderAdapter(BaseIssuerAdapter):
    """KYC-only reference adapter with pluggable subject verification.

    Non-KYC production adapters must subclass this type and declare validated
    ``supported_schema_ids`` and ``schema_required_privacy_profiles``.
    """

    conformance_subject_payload = {"subjectId": "applicant-1"}
    conformance_schema_id = "zkc:cred:kyc:v1"

    def __init__(self, provider_client: ProviderClient, **kwargs):
        kwargs.setdefault("issuer_id", "zkc:issuer:external-reference")
        kwargs.setdefault("display_name", "ZKC External Provider Reference Issuer")
        kwargs.setdefault("base_url", "https://issuer.external-reference.zkc.dev")
        super().__init__(**kwargs)
        self._provider_client = provider_client

    def _resolve_subject(self, schema: CredentialSchema, payload: dict) -> dict:
        # ---- vendor API call boundary (fixture-driven in the reference) ----
        decision = None
        provider_failed = False
        try:
            decision = self._provider_client.verify_subject(
                schema.schema_id, payload, authenticated_session=self._authenticated_session()
            )
        except Exception:
            provider_failed = True
        # ---------------------------------------------------------------------
        if provider_failed:
            decision = None
            _raise_provider_verification_failed()

        provider_ref = None
        expires_at = None
        copied_claims = None
        normalized_claims = None
        evidence_holder = None
        legacy_layout = {}
        provider_failed = False
        try:
            if type(decision) is not ProviderDecision or decision.verified is not True:
                raise ValueError(_PROVIDER_ERROR)
            provider_ref = decision.provider_ref
            expires_at = decision.expires_at
            if type(provider_ref) is not str or not provider_ref:
                raise ValueError(_PROVIDER_ERROR)
            if len(provider_ref.encode("utf-8")) > _MAX_PROVIDER_REF_UTF8_BYTES:
                raise ValueError(_PROVIDER_ERROR)
            if type(expires_at) is not int or not 0 <= expires_at <= _MAX_U64:
                raise ValueError(_PROVIDER_ERROR)
            if schema.schema_id == RUNTIME_ATTESTATION_SCHEMA_ID:
                evidence_holder = decision.holder_commitment
                if (
                    type(evidence_holder) is not str
                    or hex_to_field(evidence_holder) == 0
                    or evidence_holder != payload.get("holderCommitment")
                ):
                    raise ValueError(_PROVIDER_ERROR)
            copied_claims = _copy_provider_claims(decision.claims)
            normalized_claims = schema.normalize_claims(copied_claims)
            if type(normalized_claims) is not dict:
                raise ValueError(_PROVIDER_ERROR)
            if (
                schema.schema_id == RUNTIME_ATTESTATION_SCHEMA_ID
                and normalized_claims.get("validUntil") != expires_at
            ):
                raise ValueError(_PROVIDER_ERROR)
            if schema.schema_id == ATTRIBUTE_SET_V1_SCHEMA_ID:
                layout_id = decision.attribute_layout_id
                if layout_id is not None and type(layout_id) is not str:
                    raise ValueError(_PROVIDER_ERROR)
                legacy_layout["attributeLayoutId"] = layout_id
        except Exception:
            provider_failed = True

        decision = None
        copied_claims = None
        if provider_failed:
            provider_ref = None
            expires_at = None
            normalized_claims = None
            _raise_provider_verification_failed()

        resolved = {
            "providerRef": provider_ref,
            "holderCommitment": evidence_holder if schema.schema_id == RUNTIME_ATTESTATION_SCHEMA_ID else None,
            "credential": {
                "claims": normalized_claims,
                "expiresAt": expires_at,
                **legacy_layout,
            },
        }
        normalized_claims = None
        return resolved


# Reference fixture decisions for the bundled external adapter: one applicant
# who passes KYC. Used by the conformance kit and the DoD integration test.
REFERENCE_DECISIONS = {
    "applicant-1": {
        "zkc:cred:kyc:v1": {
            "claims": {"level": 2, "verifiedAttributes": [True, True, True, False, True]},
            "expiresAt": 2_000_000_000,
        },
    }
}


def reference_external_adapter(**kwargs) -> ExternalProviderAdapter:
    """A fresh fixture-driven external adapter (kit factory / tests)."""
    # Deterministic clock inside the test signing-key validity window.
    kwargs.setdefault("clock", lambda: 1_770_000_000)
    kwargs.setdefault("session_identity", _reference_session_identity)
    return ExternalProviderAdapter(StaticProviderClient(REFERENCE_DECISIONS), **kwargs)
