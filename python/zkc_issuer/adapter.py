"""Reference issuer adapters — the shared 4-stage implementation.

``BaseIssuerAdapter`` implements docs/zkc_issuer_adapter_protocol_v1.md end
to end: ``verify_subject`` → ``bind_holder_commitment`` (challenge/response)
→ ``issue_credential`` (real ECDSA signature over the circuit digest, plus a
fresh accumulator witness) → ``publish_revocation_handle``. The ONLY
provider-specific surface is ``_resolve_subject`` (how a subject passes
verification and which claims the issuer attests); everything else — binding,
signing, accumulator state, metadata, the privacy boundary — is shared.

``SandboxIssuerAdapter`` resolves subjects against bundled fixtures.
``zkc_issuer.external.ExternalProviderAdapter`` resolves them through a
pluggable provider client (the production-integration skeleton).

Provider-shaped but provider-neutral: no provider integration, no canonical
issuer. The privacy boundary is enforced at every stage: payloads carrying
wallet material (master seed, binding keys, ZKA address, note plaintext,
payment history, …) are rejected recursively, and nothing the adapter stores
or returns contains holder secrets.
"""

from __future__ import annotations

import abc
import collections
import secrets
import threading
import time
import weakref
from functools import wraps
from types import MappingProxyType
from typing import Mapping

from zkc_crypto import (
    FIELD_MODULUS,
    compute_rebind_attestation_digest,
    field_to_hex,
    hex_to_field,
    parse_attribute_layout_id,
    string_to_field,
)
from zkc_crypto.code_spaces import (
    CODE_SPACE_CREDENTIAL_TO_KIND,
    JURISDICTION_CODE_SPACE_ID,
    SCREENING_CODE_SPACE_ID,
    SOURCE_CODE_SPACE_ID,
    TAX_CODE_SPACE_ID,
    get_code_space,
)

from .accumulator import IssuerAccumulator
from .binding import BindingChallenge, DEFAULT_CHALLENGE_TTL_SECONDS, compute_binding_response
from .contract import IssuerAdapter
from .errors import (
    HUMAN_PRIVACY_PROFILE,
    KNOWN_PRIVACY_PROFILES,
    MACHINE_PRIVACY_PROFILE,
    AdapterError,
    reject_forbidden,
)
from .fixtures import SANDBOX_ATTRIBUTE_LAYOUT_ID, SANDBOX_FIXTURES
from .keys import IssuerSigningKey
from .ledger import ISSUANCE_LEDGER_VERSION, IssuanceLedgerError, IssuanceLedgerStore
from .metadata import DEFAULT_SERVICE_LEVELS, build_issuer_metadata, write_well_known
from .schemas import (
    ATTRIBUTE_SET_V1_SCHEMA_ID,
    ATTRIBUTE_SET_V2_SCHEMA_ID,
    RUNTIME_ATTESTATION_SCHEMA_ID,
    SUPPORTED_SCHEMAS,
    CredentialSchema,
)

__all__ = [
    "CREDENTIAL_ENVELOPE_VERSION",
    "MANDATORY_SCHEMA_PRIVACY_PROFILES",
    "validate_adapter_capabilities",
    "BaseIssuerAdapter",
    "SandboxIssuerAdapter",
]

CREDENTIAL_ENVELOPE_VERSION = "zkc:credential-envelope:v1"
# A reference accumulator has one issuer-ledger owner in this process. Weak
# keys do not retain dead accumulators; an existing epoch prevents takeover
# after restart when the private in-memory ledger is unavailable.
_ACCUMULATOR_OWNERS = weakref.WeakKeyDictionary()
_ACCUMULATOR_OWNERS_LOCK = threading.Lock()
_EXTERNAL_REFERENCE_SCHEMA_IDS = frozenset({"zkc:cred:kyc:v1"})
_SANDBOX_SCHEMA_IDS = frozenset(
    {
        "zkc:cred:accreditation:v2",
        ATTRIBUTE_SET_V1_SCHEMA_ID,
        ATTRIBUTE_SET_V2_SCHEMA_ID,
        "zkc:cred:jurisdiction:v1",
        "zkc:cred:kyc:v1",
        "zkc:cred:sanctions:v2",
        "zkc:cred:source:v2",
        "zkc:cred:tax:v2",
        *CODE_SPACE_CREDENTIAL_TO_KIND,
    }
)
_SANDBOX_CODE_SPACE_IDS = MappingProxyType({
    "zkc:cred:jurisdiction:v2": frozenset({JURISDICTION_CODE_SPACE_ID}),
    "zkc:cred:source:v3": frozenset({SOURCE_CODE_SPACE_ID}),
    "zkc:cred:tax:v3": frozenset({TAX_CODE_SPACE_ID}),
    "zkc:cred:sanctions:v3": frozenset({SCREENING_CODE_SPACE_ID}),
})
_SANDBOX_PRIVACY_PROFILES: Mapping[str, frozenset[str]] = MappingProxyType(
    {schema_id: frozenset({HUMAN_PRIVACY_PROFILE}) for schema_id in _SANDBOX_SCHEMA_IDS}
)
MANDATORY_SCHEMA_PRIVACY_PROFILES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        RUNTIME_ATTESTATION_SCHEMA_ID: frozenset(
            {HUMAN_PRIVACY_PROFILE, MACHINE_PRIVACY_PROFILE}
        )
    }
)


def validate_adapter_capabilities(
    supported_schema_ids,
    schema_required_privacy_profiles,
) -> tuple[frozenset[str], Mapping[str, frozenset[str]]]:
    """Validate and own an adapter's authoritative immutable capabilities."""
    if type(supported_schema_ids) is not frozenset:
        raise ValueError("supported_schema_ids must be an exact frozenset")
    if not supported_schema_ids:
        raise ValueError("supported_schema_ids must not be empty")
    if type(schema_required_privacy_profiles) is not MappingProxyType:
        raise ValueError("schema_required_privacy_profiles must be a MappingProxyType")
    if set(schema_required_privacy_profiles) != set(supported_schema_ids):
        raise ValueError("schema privacy profiles must cover exactly the supported schemas")
    owned_profiles = {}
    for schema_id in supported_schema_ids:
        if type(schema_id) is not str or schema_id not in SUPPORTED_SCHEMAS:
            raise ValueError("supported schema must exist in the global registry")
        if not SUPPORTED_SCHEMAS[schema_id].issuable:
            raise ValueError("supported schema must be current and issuable")
        profiles = schema_required_privacy_profiles[schema_id]
        if type(profiles) is not frozenset or not profiles:
            raise ValueError("schema privacy profiles must be nonempty exact frozensets")
        if not profiles.issubset(KNOWN_PRIVACY_PROFILES) or HUMAN_PRIVACY_PROFILE not in profiles:
            raise ValueError("schema privacy profiles must be known and include human")
        mandatory_profiles = MANDATORY_SCHEMA_PRIVACY_PROFILES.get(
            schema_id, frozenset({HUMAN_PRIVACY_PROFILE})
        )
        if not mandatory_profiles.issubset(profiles):
            raise ValueError("schema privacy profiles omit a mandatory profile")
        owned_profiles[schema_id] = frozenset(profiles)
    return frozenset(supported_schema_ids), MappingProxyType(owned_profiles)


def _serialized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._session_lock:
            return method(self, *args, **kwargs)
    return call


def _reference_session_identity():
    """TEST ONLY: the sandbox's single local caller; never a gateway identity."""
    return "zkc-reference-test-session"


class BaseIssuerAdapter(IssuerAdapter):
    """Shared 4-stage adapter machinery; subject resolution is abstract."""

    # How the conformance kit identifies a verifiable subject for this
    # adapter (merged into verify_subject payloads). Implementations with
    # provider-specific subject identification override this.
    conformance_subject_payload: dict = {}
    # Unexpired, unused binding challenges one subject session may hold.
    max_outstanding_challenges_per_subject: int = 8
    # Stage 4 is a public status/witness oracle: it answers for any
    # credential id, which every published accumulator leaf already reveals.
    # It stays rate-limited per window even when max_requests_per_stage is
    # None (threat model section 1.10).
    default_publication_reads_per_window: int = 600
    supported_schema_ids: frozenset[str] = _EXTERNAL_REFERENCE_SCHEMA_IDS
    schema_required_privacy_profiles: Mapping[str, frozenset[str]] = MappingProxyType(
        {schema_id: frozenset({HUMAN_PRIVACY_PROFILE}) for schema_id in _EXTERNAL_REFERENCE_SCHEMA_IDS}
    )
    schema_code_space_ids: Mapping[str, frozenset[str]] = MappingProxyType({})

    def __init__(
        self,
        issuer_id: str,
        display_name: str,
        signing_key: IssuerSigningKey = None,
        base_url: str = "https://issuer.sandbox.zkc.dev",
        accumulator: IssuerAccumulator = None,
        clock=time.time,
        max_requests_per_stage: int = None,
        service_levels: dict = None,
        session_identity=None,
        subject_session_ttl_seconds: int = 600,
        rate_limit_window_seconds: int = 60,
        issuance_ledger: IssuanceLedgerStore = None,
    ):
        (
            self.supported_schema_ids,
            self.schema_required_privacy_profiles,
        ) = validate_adapter_capabilities(
            self.supported_schema_ids,
            self.schema_required_privacy_profiles,
        )
        declarations = self.schema_code_space_ids
        required = self.supported_schema_ids.intersection(CODE_SPACE_CREDENTIAL_TO_KIND)
        if type(declarations) is not MappingProxyType or set(declarations) != required:
            raise ValueError("schema_code_space_ids must be an immutable declaration for exactly the code-space schemas")
        owned_spaces = {}
        for schema_id, ids in declarations.items():
            if type(ids) is not frozenset or not ids:
                raise ValueError("schema code-space declarations must be nonempty exact frozensets")
            for code_space_id in ids:
                get_code_space(code_space_id, CODE_SPACE_CREDENTIAL_TO_KIND[schema_id])
            owned_spaces[schema_id] = frozenset(ids)
        self.schema_code_space_ids = MappingProxyType(owned_spaces)
        self.issuer_id = issuer_id
        self.display_name = display_name
        self._signing_key = signing_key or IssuerSigningKey.test_issuer()
        self._base_url = base_url
        if accumulator is None:
            # Lazy import avoids a module cycle: zkc_revocation builds on the
            # issuer accumulator and key primitives. Launch adapters publish
            # signed v3 metadata by default; callers can still pass an explicit
            # IssuerAccumulator for legacy unsigned v1 compatibility.
            from zkc_revocation.service import RevocationAccumulatorService

            accumulator = RevocationAccumulatorService(
                accumulator_id=f"{issuer_id.rsplit(':', 1)[-1]}-active-credentials",
                update_endpoint=f"{base_url.rstrip('/')}/v1/revocation/updates",
                signing_key=self._signing_key,
                clock=clock,
            )
        self._accumulator = accumulator
        self._clock = clock
        if max_requests_per_stage is not None and (
            type(max_requests_per_stage) is not int or max_requests_per_stage < 1
        ):
            raise ValueError("max_requests_per_stage must be None or a positive integer")
        if (
            type(self.default_publication_reads_per_window) is not int
            or self.default_publication_reads_per_window < 1
        ):
            raise ValueError("default_publication_reads_per_window must be a positive integer")
        if type(rate_limit_window_seconds) is not int or not 1 <= rate_limit_window_seconds <= 86400:
            raise ValueError("rate limit window must be between 1 and 86400 seconds")
        self._max_requests_per_stage = max_requests_per_stage
        self._rate_limit_window_seconds = rate_limit_window_seconds
        self._service_levels = service_levels
        if type(subject_session_ttl_seconds) is not int or not 1 <= subject_session_ttl_seconds <= 3600:
            raise ValueError("subject session TTL must be between 1 and 3600 seconds")
        if session_identity is not None and not callable(session_identity):
            raise ValueError("session_identity must be a trusted callable")
        if issuance_ledger is not None and not isinstance(issuance_ledger, IssuanceLedgerStore):
            raise ValueError("issuance_ledger must be an IssuanceLedgerStore")
        self._session_identity = session_identity
        self._subject_session_ttl_seconds = subject_session_ttl_seconds
        self._issuance_ledger = issuance_ledger
        self._session_lock = threading.RLock()
        # Private provider identity + schema -> latest credential in one lineage.
        self._subject_credentials: dict = {}
        # (stage, authenticated client) -> timestamps inside the sliding window.
        self._rate_windows: dict = {}
        # Expiring subject_ref -> private verified session record.
        self._verified: dict = {}
        # subject_ref -> holder_commitment hex
        self._bindings: dict = {}
        # nonce hex -> BindingChallenge (single-use)
        self._challenges: dict = {}
        # credential_id -> private issuance/renewal record (never published).
        self._issued: dict = {}
        with _ACCUMULATOR_OWNERS_LOCK:
            if accumulator in _ACCUMULATOR_OWNERS:
                self._owns_issuance_ledger = False
            elif issuance_ledger is None:
                # Without a durable ledger only a genesis accumulator is safe:
                # a later epoch means lineage records exist that we lack.
                self._owns_issuance_ledger = accumulator.epoch == 0
            else:
                # Raises IssuanceLedgerError when the stores diverge.
                self._restore_issuance_ledger()
                self._owns_issuance_ledger = True
            if self._owns_issuance_ledger:
                _ACCUMULATOR_OWNERS[accumulator] = True

    # --- shared stage plumbing --------------------------------------------------

    @property
    def accumulator(self) -> IssuerAccumulator:
        return self._accumulator

    def _now(self) -> int:
        return int(self._clock())

    def _require_announcement_signer(self, now: int) -> None:
        """Refuse before the ledger write-ahead when no epoch can be signed.

        A signed accumulator (``RevocationAccumulatorService``) re-checks its
        announcement key when it signs; an unsigned v1 ``IssuerAccumulator``
        signs nothing and has no announcement key to check.
        """
        ensure_can_sign = getattr(self._accumulator, "ensure_can_sign", None)
        if ensure_can_sign is not None:
            ensure_can_sign(now)

    def _authenticated_session(self) -> str:
        # This callback reads trusted gateway context, never the JSON payload.
        identity = None
        try:
            identity = self._session_identity() if self._session_identity else None
        except Exception:
            pass
        if type(identity) is not str or not identity or len(identity) > 256:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "authenticated session required")
        return identity

    def _optional_session_identity(self):
        try:
            return self._authenticated_session()
        except AdapterError:
            return None

    def _rate_limit(self, stage: str, client, limit: int = None) -> None:
        """Per-client sliding-window limit, charged after request validation.

        ``client`` is the trusted authenticated session identity (``None`` is
        the shared bucket for unauthenticated publication reads). Callers
        charge a request only once it passed the payload checks, the privacy
        scan and authentication, and before any provider call or state
        lookup; a refused request is not recorded. ``limit`` overrides
        ``max_requests_per_stage`` for this call.
        """
        if limit is None:
            limit = self._max_requests_per_stage
        if limit is None:
            return
        with self._session_lock:
            now = self._now()
            horizon = now - self._rate_limit_window_seconds
            for key in [key for key, stamps in self._rate_windows.items() if stamps[-1] <= horizon]:
                del self._rate_windows[key]
            stamps = self._rate_windows.get((stage, client))
            if stamps is None:
                stamps = self._rate_windows[(stage, client)] = collections.deque()
            while stamps and stamps[0] <= horizon:
                stamps.popleft()
            if len(stamps) >= limit:
                raise AdapterError("RATE_LIMITED", f"{stage} request limit exceeded")
            stamps.append(now)

    def _prune_sessions(self) -> None:
        now = self._now()
        # Remove expired continuations and their challenge material.
        expired = {ref for ref, value in self._verified.items() if now >= value["sessionExpiresAt"]}
        for ref in expired:
            self._verified.pop(ref, None)
            self._bindings.pop(ref, None)
        self._challenges = {
            nonce: ch for nonce, ch in self._challenges.items()
            if ch.subject_ref not in expired and now < ch.expires_at
        }

    def _session(self, subject_ref) -> dict:
        identity = self._authenticated_session()
        self._prune_sessions()
        verified = self._verified.get(subject_ref) if type(subject_ref) is str else None
        if verified is None or verified["sessionIdentity"] != identity:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "subject session unavailable")
        return verified

    def _get_supported_schema(self, schema_id: str) -> CredentialSchema:
        if schema_id not in self.supported_schema_ids:
            raise AdapterError("UNSUPPORTED_SCHEMA", f"unsupported schema: {schema_id}")
        schema = SUPPORTED_SCHEMAS[schema_id]
        if not schema.issuable:
            raise AdapterError("UNSUPPORTED_SCHEMA", f"unsupported schema: {schema_id}")
        return schema

    def _legacy_attribute_layout(self, schema: CredentialSchema, credential_source: dict) -> dict:
        """Only a verified provider declaration can authorize this legacy layout."""
        if schema.schema_id != ATTRIBUTE_SET_V1_SCHEMA_ID:
            return {}
        layout_id = credential_source.get("attributeLayoutId")
        try:
            parse_attribute_layout_id(layout_id)
        except ValueError:
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED", "legacy credential has no canonical provider layout"
            ) from None
        key_layout_id = getattr(self._signing_key, "attribute_layout_id", None)
        if type(key_layout_id) is not str or layout_id != key_layout_id:
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED", "provider layout does not match the issuer signing key"
            )
        return {"attributeLayoutId": layout_id}

    def _admit_code_space(
        self, schema: CredentialSchema, credential_source: dict, *, from_ledger: bool = False
    ) -> dict:
        """Own authoritative verified claims and enforce the issuer's closed list."""
        if schema.schema_id not in CODE_SPACE_CREDENTIAL_TO_KIND:
            return credential_source
        try:
            claims = schema.normalize_claims(
                credential_source["claims"], allow_legacy_zero_expiry=from_ledger
            )
            if claims["codeSpaceId"] not in self.schema_code_space_ids[schema.schema_id]:
                raise ValueError("provider code space is not declared by this issuer")
            if credential_source["expiresAt"] != claims["validUntil"]:
                raise ValueError("expiresAt must equal validUntil")
        except (AdapterError, KeyError, TypeError, ValueError):
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED", "provider code-space claims are not admitted"
            ) from None
        return {"claims": claims, "expiresAt": credential_source["expiresAt"]}

    def _active_privacy_profiles(self) -> frozenset[str]:
        active = set()
        for profiles in self.schema_required_privacy_profiles.values():
            active.update(profiles)
        return frozenset(active)

    def _reject_unsafe_resolved_subject(self, resolved: dict, profiles: frozenset[str]) -> None:
        if type(resolved) is not dict:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "provider returned malformed subject")
        provider_ref = resolved.get("providerRef")
        credential = resolved.get("credential")
        if type(provider_ref) is not str or type(credential) is not dict:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "provider returned malformed subject")
        if type(credential.get("claims")) is not dict or "expiresAt" not in credential:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "provider returned malformed subject")
        reject_forbidden(resolved, profiles=profiles)

    def _enter_stage(self, stage: str, payload) -> None:
        """Validate the payload shape and privacy boundary (no rate charge)."""
        if not isinstance(payload, dict):
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", f"{stage} payload must be an object")
        reject_forbidden(payload, profiles=self._active_privacy_profiles())

    def _enter_authenticated_stage(self, stage: str) -> str:
        """Authenticate the caller, then charge its per-client rate window."""
        identity = self._authenticated_session()
        self._rate_limit(stage, identity)
        return identity

    # --- durable issuance ledger --------------------------------------------------

    @staticmethod
    def _ledger_failure(reason: str):
        raise IssuanceLedgerError(f"issuance ledger restore refused: {reason}")

    def _encode_ledger_record(self, credential_id: int, record: dict, state: str) -> dict:
        return {
            "credentialId": field_to_hex(credential_id),
            "state": state,
            "schemaId": record["schemaId"],
            "issuedAt": record["issuedAt"],
            "renewedFrom": record.get("renewedFrom"),
            "sessionIdentity": record["sessionIdentity"],
            "providerRef": record["providerRef"],
            "providerExpiresAt": record["providerExpiresAt"],
            "credential": record["credential"],
            "holderCommitment": record["holderCommitment"],
            "rebindWindow": list(record["rebindWindow"]),
        }

    def _decode_ledger_record(self, raw) -> tuple[int, str, dict]:
        def canonical(value) -> int:
            field = hex_to_field(value)
            if field == 0:
                raise ValueError("zero field element")
            return field

        def u64(value) -> int:
            if type(value) is not int or not 0 <= value < 2**64:
                raise ValueError("not a u64 integer")
            return value

        try:
            if type(raw) is not dict or set(raw) != {
                "credentialId", "state", "schemaId", "issuedAt", "renewedFrom",
                "sessionIdentity", "providerRef", "providerExpiresAt", "credential",
                "holderCommitment", "rebindWindow",
            }:
                raise ValueError("unexpected record fields")
            credential_id = canonical(raw["credentialId"])
            state = raw["state"]
            if state not in ("pending", "committed"):
                raise ValueError("unknown record state")
            for name in ("schemaId", "sessionIdentity", "providerRef"):
                if type(raw[name]) is not str or not raw[name]:
                    raise ValueError(f"{name} must be a non-empty string")
            source = raw["credential"]
            source_fields = {"claims", "expiresAt"}
            if type(source) is not dict:
                raise ValueError("malformed credential source")
            if raw["schemaId"] == ATTRIBUTE_SET_V1_SCHEMA_ID and "attributeLayoutId" in source:
                parse_attribute_layout_id(source["attributeLayoutId"])
                source_fields.add("attributeLayoutId")
            if set(source) != source_fields:
                raise ValueError("malformed credential source")
            if type(source["claims"]) is not dict:
                raise ValueError("malformed claims")
            if raw["schemaId"] in CODE_SPACE_CREDENTIAL_TO_KIND:
                schema = self._get_supported_schema(raw["schemaId"])
                # Records written before the expiry check must remain readable.
                admitted = self._admit_code_space(schema, source, from_ledger=True)
                if admitted != source:
                    raise ValueError("noncanonical code-space ledger claims")
            window = raw["rebindWindow"]
            if type(window) is not list or len(window) != 2:
                raise ValueError("malformed rebind window")
            record = {
                "schemaId": raw["schemaId"],
                "issuedAt": u64(raw["issuedAt"]),
                "sessionIdentity": raw["sessionIdentity"],
                "providerRef": raw["providerRef"],
                "providerExpiresAt": u64(raw["providerExpiresAt"]),
                "credential": {**source, "expiresAt": u64(source["expiresAt"])},
                "holderCommitment": field_to_hex(canonical(raw["holderCommitment"])),
                "rebindWindow": (u64(window[0]), u64(window[1])),
            }
            if raw["holderCommitment"] != record["holderCommitment"]:
                raise ValueError("holder commitment is not canonical hex")
            if raw["renewedFrom"] is not None:
                record["renewedFrom"] = field_to_hex(canonical(raw["renewedFrom"]))
            return credential_id, state, record
        except (AdapterError, TypeError, ValueError):
            self._ledger_failure("malformed ledger record")

    def _ledger_document(self, pending: tuple = None) -> dict:
        records = [
            self._encode_ledger_record(credential_id, record, "committed")
            for credential_id, record in self._issued.items()
        ]
        if pending is not None:
            records.append(self._encode_ledger_record(*pending, "pending"))
        return {
            "version": ISSUANCE_LEDGER_VERSION,
            "issuerId": self.issuer_id,
            "accumulatorId": self._accumulator.accumulator_id,
            "records": records,
        }

    def _save_ledger(self, pending: tuple = None) -> None:
        """Write the whole ledger; ``pending`` is a record about to take effect."""
        if self._issuance_ledger is not None:
            self._issuance_ledger.save_state(self._ledger_document(pending))

    def _restore_issuance_ledger(self) -> None:
        """Load and reconcile the durable ledger with the accumulator.

        Writes ahead of each accumulator mutation make every crash point
        recoverable: a pending record the accumulator knows is promoted, one
        it does not know is dropped. Any other disagreement fails closed.
        """
        state = self._issuance_ledger.load_state()
        known = self._accumulator.credential_ids()
        if state is None:
            if known or self._accumulator.epoch != 0:
                self._ledger_failure("the ledger is empty but the accumulator has issued state")
            self._save_ledger()
            return
        if type(state) is not dict or set(state) != {"version", "issuerId", "accumulatorId", "records"}:
            self._ledger_failure("malformed ledger document")
        if state["version"] != ISSUANCE_LEDGER_VERSION:
            self._ledger_failure("unsupported ledger version")
        if state["issuerId"] != self.issuer_id:
            self._ledger_failure("the ledger belongs to another issuer")
        if state["accumulatorId"] != self._accumulator.accumulator_id:
            self._ledger_failure("the ledger belongs to another accumulator")
        if type(state["records"]) is not list:
            self._ledger_failure("malformed ledger document")
        issued: dict = {}
        heads: dict = {}
        changed = False
        for raw in state["records"]:
            credential_id, record_state, record = self._decode_ledger_record(raw)
            if credential_id in issued:
                self._ledger_failure("duplicate credential record")
            if credential_id not in known:
                if record_state == "committed":
                    self._ledger_failure("a committed credential is missing from the accumulator")
                changed = True  # the mutation never happened
                continue
            changed = changed or record_state == "pending"
            lineage = (record["providerRef"], record["schemaId"])
            renewed_from = record.get("renewedFrom")
            if renewed_from is None:
                if lineage in heads:
                    self._ledger_failure("a subject has two issuance lineages")
            elif heads.get(lineage) != hex_to_field(renewed_from):
                self._ledger_failure("a renewal does not extend its lineage head")
            heads[lineage] = credential_id
            issued[credential_id] = record
        if not known.issubset(issued):
            self._ledger_failure("the accumulator holds credentials missing from the ledger")
        self._issued = issued
        self._subject_credentials = heads
        if changed:
            self._save_ledger()

    def _new_credential_id(self) -> int:
        """A fresh CSPRNG credential id: canonical, non-zero, never reused.

        Ids never derive from in-memory counters, so a restarted issuer cannot
        re-derive one that the durable accumulator already holds.
        """
        while True:
            credential_id = secrets.randbelow(FIELD_MODULUS - 1) + 1
            if credential_id not in self._issued and not self._accumulator.is_known(credential_id):
                return credential_id

    # --- stage 1: verify_subject ---------------------------------------------------

    @abc.abstractmethod
    def _resolve_subject(self, schema, payload: dict) -> dict:
        """Provider-specific subject resolution — THE provider boundary.

        Returns ``{"providerRef": str, "credential": {"claims": dict,
        "expiresAt": int}}`` for a subject that passes provider verification
        for ``schema``; raises AdapterError(PROVIDER_VERIFICATION_FAILED /
        RATE_LIMITED) otherwise. ``providerRef`` stays issuer-side only.
        Legacy attribute sets also require a provider-verified
        ``attributeLayoutId`` in ``credential``. For v2, ``claims.layoutId``
        identifies the provider's layout and is included in the signed digest.
        """

    @_serialized
    def verify_subject(self, payload: dict) -> dict:
        """Stage 1: provider-specific subject verification."""
        self._enter_stage("verify_subject", payload)
        schema = self._get_supported_schema(payload.get("schemaId"))
        # Charged before the provider call: failed verifications count.
        identity = self._enter_authenticated_stage("verify_subject")
        self._prune_sessions()
        resolved = self._resolve_subject(schema, payload)
        self._reject_unsafe_resolved_subject(
            resolved,
            self.schema_required_privacy_profiles[schema.schema_id],
        )
        credential_source = resolved["credential"]
        credential_source = self._admit_code_space(schema, credential_source)
        if schema.schema_id in (ATTRIBUTE_SET_V1_SCHEMA_ID, ATTRIBUTE_SET_V2_SCHEMA_ID):
            # Own the verified slot values through issuance even when a
            # fixture or provider reuses its response containers.
            credential_source = {
                **credential_source,
                "claims": schema.normalize_claims(credential_source["claims"]),
            }
        # Provider identity is private and stable; the wire handle is independent.
        subject_ref = secrets.token_hex(32)
        self._verified[subject_ref] = {
            "schemaId": schema.schema_id,
            "providerRef": resolved["providerRef"],
            "credential": credential_source,
            "sessionIdentity": identity,
            "sessionExpiresAt": self._now() + self._subject_session_ttl_seconds,
            "evidenceHolderCommitment": resolved.get("holderCommitment"),
        }
        return {
            "status": "verified",
            "subjectRef": subject_ref,
            "schemaId": schema.schema_id,
            "expiresAt": self._verified[subject_ref]["sessionExpiresAt"],
        }

    # --- stage 2: bind_holder_commitment ----------------------------------------------

    @_serialized
    def request_binding_challenge(self, payload: dict) -> dict:
        """First half of the bind stage: mint a single-use, expiring challenge."""
        self._enter_stage("bind_holder_commitment", payload)
        self._enter_authenticated_stage("bind_holder_commitment")
        subject_ref = payload.get("subjectRef")
        verified = self._session(subject_ref)
        if subject_ref in self._bindings:
            raise AdapterError("INVALID_HOLDER_CHALLENGE", "subject session is already bound")
        # _session purged expired challenges; cap what one session may hold.
        outstanding = sum(1 for ch in self._challenges.values() if ch.subject_ref == subject_ref)
        if outstanding >= self.max_outstanding_challenges_per_subject:
            raise AdapterError("RATE_LIMITED", "too many outstanding binding challenges")
        holder_commitment_hex = payload.get("holderCommitment")
        evidence_holder = verified.get("evidenceHolderCommitment")
        if evidence_holder is not None and holder_commitment_hex != evidence_holder:
            raise AdapterError("INVALID_HOLDER_CHALLENGE", "holder does not match verified evidence")
        try:
            commitment = hex_to_field(holder_commitment_hex)
        except ValueError:
            raise AdapterError(
                "INVALID_HOLDER_CHALLENGE", "holderCommitment is not a canonical field element"
            ) from None
        if commitment == 0:
            raise AdapterError("INVALID_HOLDER_CHALLENGE", "holderCommitment must be non-zero")
        if payload.get("schemaId") != verified["schemaId"]:
            raise AdapterError(
                "INVALID_HOLDER_CHALLENGE", "schemaId does not match the verified subject"
            )
        challenge = BindingChallenge.issue(
            subject_ref=subject_ref,
            holder_commitment_hex=holder_commitment_hex,
            schema_id=verified["schemaId"],
            now=self._now(),
            ttl_seconds=min(DEFAULT_CHALLENGE_TTL_SECONDS,
                            verified["sessionExpiresAt"] - self._now()),
        )
        self._challenges[field_to_hex(challenge.nonce)] = challenge
        response = challenge.to_dict()
        response["issuerId"] = self.issuer_id
        return response

    @_serialized
    def bind_holder_commitment(self, payload: dict) -> dict:
        """Second half of the bind stage: verify the challenge response."""
        self._enter_stage("bind_holder_commitment", payload)
        self._enter_authenticated_stage("bind_holder_commitment")
        verified = self._session(payload.get("subjectRef"))
        if payload.get("subjectRef") in self._bindings:
            raise AdapterError("INVALID_HOLDER_CHALLENGE", "subject session is already bound")
        nonce_hex = payload.get("nonce")
        if type(nonce_hex) is not str:
            raise AdapterError("INVALID_HOLDER_CHALLENGE", "invalid challenge nonce")
        challenge = self._challenges.pop(nonce_hex, None)  # single-use
        if challenge is None:
            # Expired challenges are purged, so they are indistinguishable here.
            raise AdapterError(
                "INVALID_HOLDER_CHALLENGE", "unknown, already-used or expired challenge nonce"
            )
        now = self._now()
        if now >= challenge.expires_at:
            raise AdapterError("INVALID_HOLDER_CHALLENGE", "challenge has expired")
        if (
            payload.get("subjectRef") != challenge.subject_ref
            or payload.get("holderCommitment") != challenge.holder_commitment_hex
            or payload.get("schemaId") != challenge.schema_id
        ):
            raise AdapterError(
                "INVALID_HOLDER_CHALLENGE", "challenge tuple does not match the issued challenge"
            )
        expected = compute_binding_response(
            hex_to_field(challenge.holder_commitment_hex),
            self.issuer_id,
            challenge.schema_id,
            challenge.nonce,
            challenge.expires_at,
        )
        response_hex = payload.get("challengeResponse")
        try:
            response_value = hex_to_field(response_hex)
        except ValueError:
            raise AdapterError(
                "INVALID_HOLDER_CHALLENGE", "challengeResponse is not a canonical field element"
            ) from None
        if response_value != expected:
            raise AdapterError("INVALID_HOLDER_CHALLENGE", "holder challenge response mismatch")
        evidence_holder = verified.get("evidenceHolderCommitment")
        if evidence_holder is not None and challenge.holder_commitment_hex != evidence_holder:
            raise AdapterError("INVALID_HOLDER_CHALLENGE", "holder does not match verified evidence")
        self._bindings[challenge.subject_ref] = challenge.holder_commitment_hex
        self._challenges = {
            nonce: ch for nonce, ch in self._challenges.items()
            if ch.subject_ref != challenge.subject_ref
        }
        return {
            "status": "bound",
            "subjectRef": challenge.subject_ref,
            "holderCommitment": challenge.holder_commitment_hex,
        }

    # --- rebind attestation (spec section 7.4.1) --------------------------------

    REBIND_ATTESTATION_VERSION = "zkc:attestation:credential-rebind:v1"

    @staticmethod
    def _rebind_window(claims: dict, expires_at: int) -> tuple[int, int]:
        """The credential's own validity window; an attestation never exceeds it.

        A window end is inclusive and ``expiresAt`` is exclusive, so an
        expiry bound becomes ``expiresAt - 1``.
        """
        valid_from = int(claims.get("validFrom", 0))
        ends = []
        if int(claims.get("validUntil", 0)) != 0:
            ends.append(int(claims["validUntil"]))
        if int(expires_at) != 0:
            ends.append(int(expires_at) - 1)
        valid_until = min(ends) if ends else 0
        if ends and valid_until <= valid_from:
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED", "credential has an empty rebind window"
            )
        return valid_from, valid_until

    def _sign_rebind_tuple(
        self, *, schema_id: str, holder_commitment: int, credential_id: int,
        valid_from: int, valid_until: int,
    ) -> dict:
        """PRIVATE: sign an exact tuple the caller has already authorized.

        Only issuance, renewal and the state-derived public method reach this.
        The digest is recomputed in-circuit by the authenticated rebind
        statements, so this signature is what makes a rebind proof evidence of
        an issuer-created credential. It names only the CURRENT holder
        commitment: no migration target is authorized here, and no old-to-new
        mapping is created (the audit-mapping rules of spec section 4.5 are
        unaffected).
        """
        digest = compute_rebind_attestation_digest(
            string_to_field(self.issuer_id),
            string_to_field(schema_id),
            holder_commitment,
            credential_id,
            valid_from,
            valid_until,
        )
        return {
            "version": self.REBIND_ATTESTATION_VERSION,
            "schemaId": schema_id,
            "validFrom": int(valid_from),
            "validUntil": int(valid_until),
            "signature": "0x" + self._signing_key.sign_digest(digest).hex(),
        }

    def _rebind_attestation_for(self, schema, holder_commitment_hex: str,
                                credential_id: int, window: tuple[int, int]) -> dict:
        """The attestation emitted alongside a freshly issued credential."""
        return self._sign_rebind_tuple(
            schema_id=schema.schema_id,
            holder_commitment=hex_to_field(holder_commitment_hex),
            credential_id=credential_id,
            valid_from=window[0],
            valid_until=window[1],
        )

    @_serialized
    def sign_rebind_attestation(self, payload: dict) -> dict:
        """Re-emit the rebind attestation for an issued, active credential.

        ``payload`` is exactly ``{"credentialId": "0x…"}``. Schema, holder
        commitment and validity window come from this issuer's private
        issuance record, never from the request, and only the authenticated
        session that owns the credential's lineage is served (spec 7.4.1).
        """
        self._enter_stage("sign_rebind_attestation", payload)
        if set(payload) != {"credentialId"}:
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED",
                "rebind attestation requests name only credentialId",
            )
        try:
            credential_id = hex_to_field(payload["credentialId"])
        except ValueError:
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE", "credentialId is not a canonical field element"
            ) from None
        identity = self._enter_authenticated_stage("sign_rebind_attestation")
        if not self._owns_issuance_ledger:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "issuer lineage ledger unavailable")
        issued = self._issued.get(credential_id)
        if issued is None or issued["sessionIdentity"] != identity:
            # Unknown and foreign credentials are indistinguishable to the caller.
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "credential session unavailable")
        if (
            self._subject_credentials.get((issued["providerRef"], issued["schemaId"])) != credential_id
            or not self._accumulator.is_active(credential_id)
        ):
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE", "credential is not active"
            )
        schema = self._get_supported_schema(issued["schemaId"])
        valid_from, valid_until = issued["rebindWindow"]
        now = self._now()
        if valid_until != 0 and now > valid_until:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "credential has expired")
        if not self._signing_key.is_valid_at(now):
            raise AdapterError(
                "EXPIRED_ISSUER_KEY", "issuer signing key is outside its validity window"
            )
        return self._sign_rebind_tuple(
            schema_id=schema.schema_id,
            holder_commitment=hex_to_field(issued["holderCommitment"]),
            credential_id=credential_id,
            valid_from=valid_from,
            valid_until=valid_until,
        )

    # --- stage 3: issue_credential -----------------------------------------------------

    @_serialized
    def issue_credential(self, payload: dict) -> dict:
        """Sign the credential digest and return the credential envelope."""
        self._enter_stage("issue_credential", payload)
        self._enter_authenticated_stage("issue_credential")
        subject_ref = payload.get("subjectRef")
        verified = self._session(subject_ref)
        if not self._owns_issuance_ledger:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "issuer lineage ledger unavailable")
        holder_commitment_hex = self._bindings.get(subject_ref)
        if holder_commitment_hex is None:
            raise AdapterError("INVALID_HOLDER_CHALLENGE", "subject is not holder-bound")
        schema = self._get_supported_schema(payload.get("schemaId"))
        if schema.schema_id != verified["schemaId"]:
            raise AdapterError(
                "UNSUPPORTED_SCHEMA", "schemaId does not match the verified subject"
            )
        now = self._now()
        if not self._signing_key.is_valid_at(now):
            raise AdapterError(
                "EXPIRED_ISSUER_KEY", "issuer signing key is outside its validity window"
            )
        self._require_announcement_signer(now)

        subject_key = (verified["providerRef"], schema.schema_id)
        if subject_key in self._subject_credentials:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "subject already has an issuance lineage; use renewal")
        credential_source = verified["credential"]
        credential_source = self._admit_code_space(schema, credential_source)
        legacy_layout = self._legacy_attribute_layout(schema, credential_source)
        claims = schema.normalize_claims(credential_source["claims"])
        expires_at = credential_source["expiresAt"]
        if type(expires_at) is not int or not 0 <= expires_at < 2**64:
            raise AdapterError("UNSUPPORTED_SCHEMA", "expiresAt out of range for u64")
        # The envelope uses zero for no expiry. Claim validity is checked by
        # the schema above.
        if expires_at != 0 and expires_at <= now:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "credential has already expired")
        holder_commitment = hex_to_field(holder_commitment_hex)
        credential_id = self._new_credential_id()

        retained_source = {
            "claims": schema.normalize_claims(claims), "expiresAt": expires_at, **legacy_layout
        }
        digest = schema.compute_digest(holder_commitment, credential_id, claims, expires_at)
        signature = self._signing_key.sign_digest(digest)
        rebind_window = self._rebind_window(claims, expires_at)
        rebind_attestation = self._rebind_attestation_for(
            schema, holder_commitment_hex, credential_id, rebind_window
        )
        record = {
            "schemaId": schema.schema_id,
            "issuedAt": now,
            "sessionIdentity": verified["sessionIdentity"],
            "providerRef": verified["providerRef"],
            "providerExpiresAt": expires_at,
            "credential": retained_source,
            "holderCommitment": holder_commitment_hex,
            "rebindWindow": rebind_window,
        }
        # Write ahead: a durable ledger reconciles a crash at any later point.
        self._save_ledger(pending=(credential_id, record))
        self._accumulator.register(credential_id)
        # Retain the committed issuance before any fallible publication read.
        self._issued[credential_id] = record
        self._subject_credentials[subject_key] = credential_id
        self._verified.pop(subject_ref)
        self._bindings.pop(subject_ref)
        self._challenges = {
            nonce: ch for nonce, ch in self._challenges.items()
            if ch.subject_ref != subject_ref
        }
        self._save_ledger()
        witness = self._accumulator.witness(credential_id)

        credential = {
            "credentialType": schema.credential_type,
            "proofType": schema.proof_type,
            "issuerId": self.issuer_id,
            "holderCommitment": holder_commitment_hex,
            "credentialId": field_to_hex(credential_id),
            "claims": claims,
            "expiresAt": expires_at,
            "signature": "0x" + signature.hex(),
            "witness": witness,
            "rebindAttestation": rebind_attestation,
            **legacy_layout,
        }
        revocation = self._accumulator.metadata()
        revocation["credentialId"] = field_to_hex(credential_id)
        return {
            "version": CREDENTIAL_ENVELOPE_VERSION,
            "issuer": {
                "issuerId": self.issuer_id,
                "keyId": self._signing_key.key_id,
                "scheme": self._signing_key.scheme,
            },
            "credential": credential,
            "revocation": revocation,
        }

    # --- stage 4: publish_revocation_handle -----------------------------------------------

    def publish_revocation_handle(self, payload: dict) -> dict:
        """Publish accumulator state (and per-credential status when asked)."""
        self._enter_stage("publish_revocation_handle", payload)
        credential_id_hex = payload.get("credentialId")
        credential_id = None
        if credential_id_hex is not None:
            try:
                credential_id = hex_to_field(credential_id_hex)
            except ValueError:
                raise AdapterError(
                    "REVOCATION_METADATA_UNAVAILABLE",
                    "credentialId is not a canonical field element",
                ) from None
        # Public reads need no session; an authenticated caller is charged
        # its own window, every unauthenticated caller one shared window.
        # Credential ids are public leaves, so a caller naming one is not
        # authorized by it: the status and witness below are public data.
        limit = self._max_requests_per_stage
        if limit is None:
            limit = self.default_publication_reads_per_window
        self._rate_limit("publish_revocation_handle", self._optional_session_identity(), limit)
        published = self._accumulator.metadata()
        if credential_id_hex is not None:
            published["credentialId"] = credential_id_hex
            if self._accumulator.is_active(credential_id):
                published["status"] = "active"
                published["witness"] = self._accumulator.witness(credential_id)
            elif self._accumulator.is_known(credential_id):
                published["status"] = "revoked"
            else:
                published["status"] = "unknown"
        return published

    # --- issuer-side administration (not adapter stages) ----------------------------------

    @_serialized
    def revoke_credential(self, credential_id: int) -> dict:
        """Issuer-side revocation; affects only future proof acceptance.

        An operator mutation: the caller is trusted issuer code. Over HTTP it
        is served only by ``zkc_transport.IssuerAdminServer``, which requires
        a signed operator request; a credential id never authorizes it.
        """
        self._accumulator.revoke(credential_id)
        return self._accumulator.metadata()

    @_serialized
    def renew_credential(self, payload: dict) -> dict:
        """Renew an active credential: re-issuance preserving the holder
        commitment with fresh validity and a fresh accumulator slot, with the
        old credential revoked ATOMICALLY (both-or-neither — the accumulator
        swap is a single validated epoch transition; any earlier failure
        leaves the old credential active and the accumulator untouched).

        ``payload``: {"credentialId": "0x…", "expiresAt": <int, optional —
        defaults to the current credential's expiry>}. A nonzero original
        provider expiry caps every replacement in the lineage, including
        after a caller has shortened a credential's validity.
        """
        self._enter_stage("renew_credential", payload)
        if "credentialId" not in payload or set(payload) - {"credentialId", "expiresAt"}:
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED",
                "renewal requests name only credentialId and optional expiresAt",
            )
        try:
            old_credential_id = hex_to_field(payload["credentialId"])
        except (KeyError, ValueError):
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE",
                "renewal payload lacks a canonical credentialId",
            ) from None
        identity = self._enter_authenticated_stage("renew_credential")
        if not self._owns_issuance_ledger:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "issuer lineage ledger unavailable")
        issued = self._issued.get(old_credential_id)
        if issued is None or issued["sessionIdentity"] != identity:
            # Do not disclose existence or status outside the owning session.
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "credential session unavailable")
        if (
            self._subject_credentials.get((issued["providerRef"], issued["schemaId"])) != old_credential_id
            or not self._accumulator.is_active(old_credential_id)
        ):
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE", "credential is not active"
            )
        holder_commitment_hex = issued["holderCommitment"]
        schema = self._get_supported_schema(issued["schemaId"])
        now = self._now()
        if not self._signing_key.is_valid_at(now):
            raise AdapterError(
                "EXPIRED_ISSUER_KEY", "issuer signing key is outside its validity window"
            )
        self._require_announcement_signer(now)

        credential_source = issued["credential"]
        legacy_layout = self._legacy_attribute_layout(schema, credential_source)
        old_expires_at = credential_source["expiresAt"]
        if old_expires_at != 0 and now >= old_expires_at:
            # An expired credential is not active; it needs fresh verification.
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED", "credential has expired; renewal requires verification"
            )
        claims = schema.normalize_claims(credential_source["claims"])
        expires_at = payload.get("expiresAt", old_expires_at)
        if type(expires_at) is not int or not 0 <= expires_at < 2**64:
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED", "renewal expiry must be a u64 integer"
            )
        if expires_at <= now:
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED", "renewal expiry must be in the future"
            )
        provider_expires_at = issued["providerExpiresAt"]
        if provider_expires_at != 0 and expires_at > provider_expires_at:
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED", "renewal expiry exceeds provider-verified expiry"
            )
        self._admit_code_space(schema, {"claims": claims, "expiresAt": expires_at})
        holder_commitment = hex_to_field(holder_commitment_hex)
        new_credential_id = self._new_credential_id()

        retained_source = {
            "claims": schema.normalize_claims(claims), "expiresAt": expires_at, **legacy_layout
        }
        digest = schema.compute_digest(holder_commitment, new_credential_id, claims, expires_at)
        signature = self._signing_key.sign_digest(digest)
        rebind_window = self._rebind_window(claims, expires_at)
        rebind_attestation = self._rebind_attestation_for(
            schema, holder_commitment_hex, new_credential_id, rebind_window
        )

        record = {
            "schemaId": schema.schema_id,
            "issuedAt": now,
            "renewedFrom": field_to_hex(old_credential_id),
            "sessionIdentity": issued["sessionIdentity"],
            "providerRef": issued["providerRef"],
            "providerExpiresAt": provider_expires_at,
            "credential": retained_source,
            "holderCommitment": holder_commitment_hex,
            "rebindWindow": rebind_window,
        }
        # Write ahead: a durable ledger reconciles a crash at any later point.
        self._save_ledger(pending=(new_credential_id, record))
        # ATOMIC: register the new slot + revoke the old slot in ONE epoch
        # transition (both-or-neither; validated before any mutation).
        self._accumulator.replace(old_credential_id, new_credential_id)
        self._issued[new_credential_id] = record
        self._subject_credentials[(issued["providerRef"], schema.schema_id)] = new_credential_id
        self._save_ledger()
        witness = self._accumulator.witness(new_credential_id)

        credential = {
            "credentialType": schema.credential_type,
            "proofType": schema.proof_type,
            "issuerId": self.issuer_id,
            "holderCommitment": holder_commitment_hex,
            "credentialId": field_to_hex(new_credential_id),
            "claims": claims,
            "expiresAt": expires_at,
            "signature": "0x" + signature.hex(),
            "witness": witness,
            "rebindAttestation": rebind_attestation,
            **legacy_layout,
        }
        revocation = self._accumulator.metadata()
        revocation["credentialId"] = field_to_hex(new_credential_id)
        return {
            "version": CREDENTIAL_ENVELOPE_VERSION,
            "issuer": {
                "issuerId": self.issuer_id,
                "keyId": self._signing_key.key_id,
                "scheme": self._signing_key.scheme,
            },
            "credential": credential,
            "revocation": revocation,
            "renewal": {"renewedFrom": field_to_hex(old_credential_id)},
        }

    def issuer_metadata(self) -> dict:
        """The /.well-known/zkc-issuer.json registry document."""
        return build_issuer_metadata(
            issuer_id=self.issuer_id,
            display_name=self.display_name,
            signing_keys=[self._signing_key],
            schemas=[SUPPORTED_SCHEMAS[schema_id] for schema_id in sorted(self.supported_schema_ids)],
            accumulator=self._accumulator,
            base_url=self._base_url,
            service_levels=self._service_levels or DEFAULT_SERVICE_LEVELS,
            schema_code_space_ids=self.schema_code_space_ids,
        )

    def publish_well_known(self, directory):
        """Write the metadata document under `<directory>/.well-known/`."""
        return write_well_known(directory, self.issuer_metadata())


class SandboxIssuerAdapter(BaseIssuerAdapter):
    """Reference issuer adapter backed by bundled sandbox subject fixtures."""

    conformance_subject_payload = {"fixtureId": "sandbox-alice-basic"}
    conformance_schema_id = "zkc:cred:kyc:v1"
    supported_schema_ids: frozenset[str] = _SANDBOX_SCHEMA_IDS
    schema_required_privacy_profiles: Mapping[str, frozenset[str]] = _SANDBOX_PRIVACY_PROFILES
    schema_code_space_ids: Mapping[str, frozenset[str]] = _SANDBOX_CODE_SPACE_IDS

    def __init__(
        self,
        issuer_id: str = "zkc:issuer:sandbox",
        display_name: str = "ZKC Sandbox Issuer",
        fixtures: dict = None,
        **kwargs,
    ):
        kwargs.setdefault("session_identity", _reference_session_identity)
        if self.schema_code_space_ids is _SANDBOX_CODE_SPACE_IDS:
            # A sandbox subclass may narrow its capabilities without inheriting
            # declarations for schemas it no longer offers.
            self.schema_code_space_ids = MappingProxyType({
                schema_id: ids for schema_id, ids in _SANDBOX_CODE_SPACE_IDS.items()
                if schema_id in self.supported_schema_ids
            })
        signing_key = kwargs.get("signing_key")
        if (
            signing_key is None
            and type(self.supported_schema_ids) is frozenset
            and ATTRIBUTE_SET_V1_SCHEMA_ID in self.supported_schema_ids
        ):
            kwargs["signing_key"] = IssuerSigningKey.test_issuer(
                attribute_layout_id=SANDBOX_ATTRIBUTE_LAYOUT_ID
            )
        elif (
            signing_key is not None
            and getattr(signing_key, "attribute_layout_id", None) is None
            and self.supported_schema_ids is _SANDBOX_SCHEMA_IDS
            and self.schema_required_privacy_profiles is _SANDBOX_PRIVACY_PROFILES
        ):
            # The stock sandbox capability set can omit legacy issuance for a
            # custom unpinned key. Explicit declarations remain authoritative.
            self.supported_schema_ids = _SANDBOX_SCHEMA_IDS - {ATTRIBUTE_SET_V1_SCHEMA_ID}
            self.schema_required_privacy_profiles = MappingProxyType({
                schema_id: profiles
                for schema_id, profiles in self.schema_required_privacy_profiles.items()
                if schema_id in self.supported_schema_ids
            })
        super().__init__(issuer_id=issuer_id, display_name=display_name, **kwargs)
        self._fixtures = fixtures if fixtures is not None else SANDBOX_FIXTURES
        self._fixture_refs = {key: secrets.token_hex(32) for key in self._fixtures}

    def _resolve_subject(self, schema, payload: dict) -> dict:
        fixture_id = payload.get("fixtureId")
        fixture = self._fixtures.get(fixture_id)
        if fixture is None:
            raise AdapterError("PROVIDER_VERIFICATION_FAILED", "unknown sandbox subject fixture")
        if schema.schema_id not in fixture:
            raise AdapterError(
                "PROVIDER_VERIFICATION_FAILED",
                "sandbox subject did not pass verification for the requested schema",
            )
        return {"providerRef": self._fixture_refs[fixture_id], "credential": fixture[schema.schema_id]}
