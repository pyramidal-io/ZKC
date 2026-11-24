"""ZKC agent compliance client (spec §5.4).

Automates proof-request handling WITHIN an explicit principal-authored
policy, and never beyond it:

- deny by default: no policy → no response; untrusted verifier → no
  response; un-ruled proof type → no response;
- auto-responses are planned through the minimal-disclosure planner with the
  policy's disclosure ceiling as a hard consent scope;
- approval-required requests become queued :class:`ApprovalRequest` objects
  surfaced through the principal notification hook — the agent holds them
  until the principal explicitly approves or denies;
- every decision is recorded in a redacting audit log (no credential
  payloads, seeds, witnesses, signatures, or proof bodies);
- replayed nonces and wrong-verifier contexts are rejected before any
  policy evaluation.

Non-goals (by construction): the agent cannot disclose without a policy
that allows it, and it holds no spending authority of any kind — it wraps a
holder whose only powers are proof generation and verification.

Outward rejections are CONSTANT-SHAPE (:data:`zkc_holder.REFUSAL_MESSAGE`):
the wire response never reveals whether the block came from policy, consent,
or a missing credential.
"""

from __future__ import annotations

import copy
import json
import secrets
import time
from dataclasses import dataclass, field

from zkc_holder import HolderClient
from zkc_holder.ceilings import exact_member_opted_in
from zkc_holder.errors import HolderError
from zkc_holder.client import _apr_context_matches_request
from zkc_holder.rebind_secret import refuse_secret_parameters
from zkc_crypto.apr import (
    LEGACY_MAX_PROOF_AGE, VERIFICATION_CONTEXT_EXTENSION, apr_freshness,
    apr_signer_pubkey, verify_apr_signature,
)
from zkc_crypto import (
    PURPOSE_BOUND_PROFILE, VERIFIER_SESSION_PROFILE, ProofContext, field_to_hex,
    string_to_field,
)
from zkc_holder.planner import (
    REFUSAL_MESSAGE,
    NegotiationRequest,
    PlanReport,
    ProofPlanner,
)
from zkc_crypto.delegation import (  # noqa: F401  (re-exported for the agent API)
    DelegatedProver,
    DelegationError,
    DelegationToken,
    ViewingScope,
)
from zkc_crypto.poseidon2 import FIELD_MODULUS

from .audit import AuditLog
from .errors import ApprovalNotFoundError, PolicyConfigurationError
from .policy import (
    ACTION_AUTO_APPROVE,
    ACTION_BLOCK,
    ACTION_REQUIRE_PRINCIPAL_APPROVAL,
    AgentCompliancePolicy,
)

__all__ = [
    "AgentDecision",
    "ApprovalRequest",
    "ZKCAgentClient",
    "DelegationToken",
    "ViewingScope",
    "DelegatedProver",
    "BLOCK_UNAUTHENTICATED_REQUEST",
    "BLOCK_NO_POLICY",
    "BLOCK_UNTRUSTED_VERIFIER",
    "BLOCK_POLICY",
    "BLOCK_REPLAYED_REQUEST",
    "BLOCK_CONTEXT_MISMATCH",
    "BLOCK_NO_PUBLISHED_POLICY",
    "BLOCK_PLANNING_REFUSED",
    "BLOCK_GENERATION_FAILED",
    "BLOCK_PRINCIPAL_DENIED",
]

BLOCK_UNAUTHENTICATED_REQUEST = "UNAUTHENTICATED_REQUEST"
BLOCK_NO_POLICY = "NO_POLICY"
BLOCK_UNTRUSTED_VERIFIER = "UNTRUSTED_VERIFIER"
BLOCK_POLICY = "BLOCKED_BY_POLICY"
BLOCK_REPLAYED_REQUEST = "REPLAYED_REQUEST"
BLOCK_CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
BLOCK_NO_PUBLISHED_POLICY = "NO_PUBLISHED_VERIFIER_POLICY"
BLOCK_PLANNING_REFUSED = "PLANNING_REFUSED"
BLOCK_GENERATION_FAILED = "GENERATION_FAILED"
BLOCK_PRINCIPAL_DENIED = "PRINCIPAL_DENIED"


def _principal_key_bytes(principal):
    """Coerce a principal public key to ``(x_bytes, y_bytes)``.

    Accepts a ``(x, y)`` pair of 32-byte values or ``0x``-hex strings, or an
    object exposing ``.x`` / ``.y`` in either form.
    """
    if hasattr(principal, "x") and hasattr(principal, "y"):
        x, y = principal.x, principal.y
    else:
        try:
            x, y = principal
        except (TypeError, ValueError) as exc:
            raise PolicyConfigurationError(
                "principal must be a (key_x, key_y) public key pair"
            ) from exc

    def _coerce(value):
        if isinstance(value, str):
            return bytes.fromhex(value.removeprefix("0x"))
        return bytes(value)

    return _coerce(x), _coerce(y)


@dataclass(frozen=True)
class AgentDecision:
    """Outcome of handling one proof request."""

    status: str  # "responded" | "queued" | "blocked"
    nonce: str
    reason_code: str = ""  # internal/audit reason for queued/blocked
    envelope: dict = None  # present when status == "responded"
    approval_id: str = ""  # present when status == "queued"
    receipt: dict = None  # holder-custodied Disclosure Receipt; never put in audit logs

    def to_wire(self) -> dict:
        """The response sent to the requesting verifier.

        Blocked responses are constant-shape: status "rejected" with the
        same message whatever the private cause (policy, consent, planning,
        or credential availability)."""
        if self.status == "responded":
            return {
                "version": "zkc:agent-response:v1",
                "type": "agent-response",
                "nonce": self.nonce,
                "status": "proof",
                "envelope": self.envelope,
            }
        if self.status == "queued":
            return {
                "version": "zkc:agent-response:v1",
                "type": "agent-response",
                "nonce": self.nonce,
                "status": "pending",
                "message": "request pending",
            }
        return {
            "version": "zkc:agent-response:v1",
            "type": "agent-response",
            "nonce": self.nonce,
            "status": "rejected",
            "message": REFUSAL_MESSAGE,
        }


@dataclass
class ApprovalRequest:
    """A proof request awaiting explicit principal approval."""

    approval_id: str
    request: NegotiationRequest
    context: object  # ProofContext
    plan: PlanReport
    created_at: int
    status: str = "pending"  # "pending" | "approved" | "denied"
    current_epochs: dict = field(default_factory=dict)
    apr: dict = None
    allow_unauthenticated: bool = False

    def summary(self) -> dict:
        """Principal-facing summary (no proof material; plan only)."""
        return {
            "approvalId": self.approval_id,
            "verifierId": self.request.verifier_id,
            "proofTypes": list(self.plan.proof_types),
            "plan": self.plan.to_dict(),
            # Holder-local overbreadth notes (narrow or undeterminable set
            # predicates) so the principal sees how narrow a set proof is.
            "warnings": [dict(warning) for warning in self.plan.warnings],
            "createdAt": self.created_at,
            "status": self.status,
        }


class ZKCAgentClient:
    """Reference agent-native compliance client (spec §5.4).

    Wraps a :class:`zkc_holder.HolderClient`. `policy_documents` maps
    verifier id → PUBLISHED verifier policy document
    (``zkc_registry.VerifierPolicyDocument``, duck-typed) used for
    minimal-disclosure planning and for deriving the holder-side trust
    policy. `counterparty_verifier` is an optional ``zkc_verifier.ZKCVerifier``
    for :meth:`verify_counterparty`.
    """

    def __init__(
        self,
        holder: HolderClient,
        registry,
        policy_documents: dict = None,
        compliance_policy: AgentCompliancePolicy = None,
        principal_notifier=None,
        audit_log: AuditLog = None,
        counterparty_verifier=None,
    ):
        self._holder = holder
        self._registry = registry
        self._policy_documents = dict(policy_documents or {})
        self._compliance_policy = copy.deepcopy(compliance_policy)
        self._principal_notifier = principal_notifier
        self.audit_log = audit_log if audit_log is not None else AuditLog()
        self._counterparty_verifier = counterparty_verifier
        self._seen_nonces = set()
        self._pending_approvals = {}
        self._pending_audit_exports = {}
        self._proof_cache = {}

    # --- configuration -----------------------------------------------------

    def set_compliance_policy(self, policy: AgentCompliancePolicy) -> None:
        if not isinstance(policy, AgentCompliancePolicy):
            raise PolicyConfigurationError("policy must be an AgentCompliancePolicy")
        self._compliance_policy = copy.deepcopy(policy)
        self.audit_log.record(
            "policy_configured",
            trusted_verifiers=sorted(policy.trusted_verifiers),
            proof_types=sorted(policy.actions),
        )

    def register_verifier_policy(self, verifier_id: str, policy_document) -> None:
        self._policy_documents[verifier_id] = policy_document

    # --- principal delegation (spec §5.4 delegateViewing) --------------------

    def delegateViewing(
        self, principal, scope: ViewingScope, *, issued_at, nonce=None,
        requests=None, consents=None,
    ):
        """Delegate scoped, non-custodial proving to ``principal`` (spec §5.4).

        Mints a holder-signed :class:`DelegationToken` authorizing ``principal``
        (a public key) to exercise ``scope`` — a fixed proof-type set bound to one
        context value, one predicate source, and one expiry (spec §5.3). The
        master seed never leaves the wrapped holder; only the capability token is
        returned. ``issued_at`` is an explicit u64 Unix timestamp; ``nonce``
        defaults to a fresh canonical scalar-field integer. The wrapped holder
        derives the token's signing key and commitment from the same authenticated
        local seed; token-carried key coordinates are not an authorization anchor.
        """
        principal_x, principal_y = _principal_key_bytes(principal)
        if nonce is None:
            nonce = secrets.randbelow(FIELD_MODULUS)
        token = self._holder.delegate_viewing(
            principal_x, principal_y, scope, issued_at=issued_at, nonce=nonce,
            requests=requests, consents=consents,
        )
        self.audit_log.record(
            "viewing_delegated",
            proof_types=sorted(scope.proof_types),
            verifier_id=scope.verifier_id,
            expires_at=int(scope.expires_at),
            max_uses=int(scope.max_uses),
        )
        self._notify(
            "viewing_delegated",
            {
                "verifier_id": scope.verifier_id,
                "proof_types": sorted(scope.proof_types),
                "expires_at": int(scope.expires_at),
            },
        )
        return token

    def authorize_delegated_material(
        self, token: DelegationToken, requests, *, now=None, principal_signature=None,
        authorization_nonce=None, consents=None, allow_unauthenticated=False,
        allow_opaque=False, allow_linkable=False, exact_member_consents: dict = None,
    ):
        """Pre-authorize the in-scope proof material a delegate may present.

        Thin holder passthrough (spec §5.3 property 2): the wrapped holder
        generates the scoped proof envelopes in its own seed-custodying
        environment and returns ``{proof_type: envelope}`` viewing-limited
        material. The delegate exercises it through :class:`DelegatedProver`.
        The wrapped holder verifies the token under the delegation key resolved
        from its authenticated local seed before generating any proof material;
        it never trusts the token's holder-key coordinates as that anchor.
        Delegated requests carry no APR, so the holder refuses them unless
        ``allow_unauthenticated=True`` is passed (Safeguard 6, recorded as an
        ``UNAUTHENTICATED`` override). Output is ``zkc:proof:v2`` unless the
        reviewed request selects the linkable profile and the holder passes
        ``allow_linkable=True``; an unaccepted review status needs
        ``allow_opaque=True``. Request-level refusals and credential selection
        run before any use is reserved; witness refresh, revocation, backend
        and proving failures still consume reserved uses.
        Fixed inclusion paths require holder-local ``exact_member_consents``.
        """
        material = self._holder.authorize_delegated_material(
            token, requests, now=now, principal_signature=principal_signature,
            authorization_nonce=authorization_nonce, consents=consents,
            allow_unauthenticated=allow_unauthenticated,
            allow_opaque=allow_opaque, allow_linkable=allow_linkable,
            exact_member_consents=exact_member_consents,
        )
        self.audit_log.record(
            "delegated_material_authorized",
            proof_types=sorted(material.keys()),
            verifier_id=token.scope.verifier_id,
        )
        return material

    # --- notification hook ---------------------------------------------------

    def _notify(self, event: str, payload: dict) -> None:
        if self._principal_notifier is not None:
            self._principal_notifier(event, payload)

    # --- request handling ----------------------------------------------------

    def handle_proof_request(
        self, request: NegotiationRequest, context, current_epochs: dict = None,
        *, apr: dict = None, now: int = None, allow_unauthenticated: bool = False,
    ) -> AgentDecision:
        """Answer a pinned, signed APR under the principal's consent policy.

        ``request.nonce`` must equal the APR's canonical nonce. ``now`` is a
        trusted local admission clock; omission uses wall-clock seconds.
        Unsigned requests need the explicit, logged unauthenticated override.
        """
        request, context, apr = copy.deepcopy((request, context, apr))
        now = int(time.time()) if now is None else now
        decision = self._gate(request, context)
        if decision is not None:
            return decision
        apr = self._request_apr(request, context, apr, now)
        reason, signer = self._admit(request, context, apr, now, allow_unauthenticated)
        if reason:
            return self._block(request, reason)
        self._seen_nonces.add(request.nonce)

        verifier_id = request.verifier_id
        action = self._compliance_policy.decision_for(request.proof_types, verifier_id)
        if action == ACTION_BLOCK:
            reason = (
                BLOCK_UNTRUSTED_VERIFIER
                if not self._compliance_policy.trusts_verifier(verifier_id)
                else BLOCK_POLICY
            )
            return self._block(request, reason)

        policy_document = self._policy_documents.get(verifier_id)
        if policy_document is None:
            return self._block(request, BLOCK_NO_PUBLISHED_POLICY)

        planner = ProofPlanner(self._registry, policy_document)
        try:
            plan = planner.plan(
                request, consent_scope=self._compliance_policy.disclosure_ceiling
            )
        except HolderError as exc:
            return self._block(request, BLOCK_PLANNING_REFUSED, detail=exc.code)

        if action == ACTION_REQUIRE_PRINCIPAL_APPROVAL:
            approval = ApprovalRequest(
                approval_id=secrets.token_hex(8),
                request=request,
                context=context,
                plan=plan,
                created_at=int(context.timestamp),
                current_epochs=copy.deepcopy(current_epochs or {}),
                apr=apr,
                allow_unauthenticated=allow_unauthenticated,
            )
            self._pending_approvals[approval.approval_id] = approval
            self.audit_log.record(
                "approval_required",
                nonce=request.nonce,
                verifier_id=verifier_id,
                proof_types=list(plan.proof_types),
                approval_id=approval.approval_id,
            )
            self._notify("approval_required", approval.summary())
            return AgentDecision(
                status="queued",
                nonce=request.nonce,
                reason_code=ACTION_REQUIRE_PRINCIPAL_APPROVAL,
                approval_id=approval.approval_id,
            )

        assert action == ACTION_AUTO_APPROVE
        return self._respond(
            request, context, plan, policy_document, current_epochs,
            apr, now, allow_unauthenticated, signer,
        )

    def _gate(self, request: NegotiationRequest, context):
        """Pre-policy gates: policy presence, replay, context binding."""
        if self._compliance_policy is None:
            return self._block(request, BLOCK_NO_POLICY)
        if request.nonce in self._seen_nonces:
            return self._block(request, BLOCK_REPLAYED_REQUEST)
        # Only known recomputable profiles can bind the requesting verifier.
        # An opaque value is not evidence of the claimed context preimage.
        if self._context_invalid(request, context):
            return self._block(request, BLOCK_CONTEXT_MISMATCH)
        return None

    @staticmethod
    def _context_invalid(request, context):
        try:
            return (
                type(context) is not ProofContext
                or context.profile not in (VERIFIER_SESSION_PROFILE, PURPOSE_BOUND_PROFILE)
                or not context.reconstructs() or context.value == 0
                or (context.profile != PURPOSE_BOUND_PROFILE and (context.purpose or context.purpose_tag))
                or context.verifier_id != request.verifier_id
            )
        except (AttributeError, TypeError, ValueError):
            return True

    @staticmethod
    def _request_apr(request, context, apr, now):
        if apr is not None:
            return apr
        # A receipt still binds the exact unauthenticated demand when the
        # principal explicitly opts in. Its empty signature cannot authenticate.
        return {
            "verifierId": request.verifier_id, "nonce": field_to_hex(string_to_field(request.nonce)),
            "issuedAt": now, "expiresAt": now + 3600,
            "request": {"proofTypes": list(request.proof_types),
                        "parameters": copy.deepcopy(request.parameters), "context": context.to_metadata()},
            "signature": {"value": "0x"},
        }

    def _admit(self, request, context, apr, now, allow_unauthenticated):
        """No generation or policy planning until identity and context agree."""
        if self._compliance_policy is None:
            return BLOCK_NO_POLICY, ""
        if self._context_invalid(request, context):
            return BLOCK_CONTEXT_MISMATCH, ""
        if not self._compliance_policy.trusts_verifier(request.verifier_id):
            return BLOCK_UNTRUSTED_VERIFIER, ""
        try:
            refuse_secret_parameters(request.parameters, "agent request")
            signed = apr["request"]
            age = signed.get("extensions", {}).get(VERIFICATION_CONTEXT_EXTENSION, {}).get(
                "maxProofAge", LEGACY_MAX_PROOF_AGE
            )
            if not _apr_context_matches_request(signed, context, age):
                return BLOCK_CONTEXT_MISMATCH, ""
            if (apr["verifierId"] != request.verifier_id
                or json.dumps([signed["proofTypes"], signed.get("parameters", {})], sort_keys=True, allow_nan=False)
                != json.dumps([list(request.proof_types), request.parameters], sort_keys=True, allow_nan=False)):
                return BLOCK_UNAUTHENTICATED_REQUEST, ""
            valid = verify_apr_signature(apr)
            if valid:
                signer = apr_signer_pubkey(apr)
                if signer not in self._compliance_policy.verifier_signing_keys.get(request.verifier_id, ()):
                    return BLOCK_UNAUTHENTICATED_REQUEST, ""
                fresh, _ = apr_freshness(apr, now)
                if not fresh or apr["issuedAt"] > now or apr["nonce"] != request.nonce:
                    return BLOCK_UNAUTHENTICATED_REQUEST, ""
                return "", "0x" + signer.hex()
            if allow_unauthenticated is True:
                # Check all receipt members before invoking any generate method.
                from zkc_crypto.apr import apr_digest_from_dict
                apr_digest_from_dict(apr)
                if not isinstance(apr["signature"]["value"], str):
                    return BLOCK_UNAUTHENTICATED_REQUEST, ""
                return "", ""
        except HolderError as exc:
            return exc.code, ""
        except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
            pass
        return BLOCK_UNAUTHENTICATED_REQUEST, ""

    def _block(self, request: NegotiationRequest, reason: str, detail: str = "") -> AgentDecision:
        self.audit_log.record(
            "request_blocked",
            nonce=request.nonce,
            verifier_id=request.verifier_id,
            proof_types=list(request.proof_types),
            reason=reason,
            detail=detail,
        )
        self._notify(
            "request_blocked",
            {"nonce": request.nonce, "verifierId": request.verifier_id, "reason": reason},
        )
        return AgentDecision(status="blocked", nonce=request.nonce, reason_code=reason)

    def _materialize(self, plan, context, policy_document, current_epochs, apr):
        from zkc_registry import to_holder_trust_policy
        from zkc_registry.predicate_v2 import parse_request_selectors

        signed = apr["request"]
        age = signed.get("extensions", {}).get(VERIFICATION_CONTEXT_EXTENSION, {}).get(
            "maxProofAge", LEGACY_MAX_PROOF_AGE
        )
        proof_request = plan.to_proof_request(
            context, to_holder_trust_policy(policy_document), max_proof_age=age,
            current_epochs=copy.deepcopy(current_epochs or {}),
        )
        proof_request.binding_selectors = parse_request_selectors(signed.get("extensions"), signed["proofTypes"])
        return proof_request

    def _exact_member_consents(self, proof_types):
        ceiling = self._compliance_policy.disclosure_ceiling
        return {
            proof_type: True
            for proof_type in proof_types
            if exact_member_opted_in(ceiling.get(proof_type))
        }

    def _respond(
        self, request, context, plan, policy_document, current_epochs,
        apr, now, allow_unauthenticated, signer,
    ) -> AgentDecision:
        try:
            proof_request = self._materialize(plan, context, policy_document, current_epochs, apr)
            # A narrower counter-plan needs a newly signed APR. Never silently
            # reinterpret the authenticated demand or bypass holder admission.
            if (list(plan.proof_types) != apr["request"]["proofTypes"]
                or proof_request.parameters != apr["request"].get("parameters", {})):
                return self._block(request, BLOCK_UNAUTHENTICATED_REQUEST)
            cache_key = self._cache_key(apr, proof_request, signer)
            result = self._proof_cache.pop(cache_key, None)
            served_from_cache = result is not None
            if result is None:
                result = self._holder.generate_authenticated_proof(
                    apr, proof_request, now=now, allow_unauthenticated=allow_unauthenticated,
                    consents={proof_type: True for proof_type in plan.proof_types},
                    exact_member_consents=self._exact_member_consents(plan.proof_types),
                )
        except (HolderError, KeyError, TypeError, ValueError) as exc:
            return self._block(request, BLOCK_GENERATION_FAILED, detail=getattr(exc, "code", "MALFORMED_REQUEST"))
        self.audit_log.record(
            "proof_disclosed", nonce=request.nonce, verifier_id=request.verifier_id,
            verifier_key=signer, authentication="AUTHENTICATED" if signer else "UNAUTHENTICATED",
            proof_types=list(plan.proof_types), plan_narrowed=[dict(element) for element in plan.narrowed],
            plan_warnings=[dict(warning) for warning in plan.warnings],
            context_value=context.to_metadata()["value"], from_cache=served_from_cache,
        )
        self._notify("proof_disclosed", {"nonce": request.nonce, "verifierId": request.verifier_id,
                                         "proofTypes": list(plan.proof_types),
                                         "warnings": [dict(warning) for warning in plan.warnings]})
        return AgentDecision(status="responded", nonce=request.nonce,
                             envelope=result["envelope"], receipt=result["receipt"])

    # --- principal approval --------------------------------------------------

    def pending_approvals(self) -> tuple:
        return tuple(
            copy.deepcopy(approval)
            for approval in self._pending_approvals.values()
            if approval.status == "pending"
        )

    def approve(self, approval_id: str, *, now: int = None) -> AgentDecision:
        """Explicit principal approval: generate and release the proof."""
        approval = self._pending_approvals.get(approval_id)
        if approval is None or approval.status != "pending":
            raise ApprovalNotFoundError(f"no pending approval {approval_id!r}")
        now = int(time.time()) if now is None else now
        reason, signer = self._admit(
            approval.request, approval.context, approval.apr, now, approval.allow_unauthenticated
        )
        if reason:
            approval.status = "denied"
            return self._block(approval.request, reason)
        if self._compliance_policy.decision_for(approval.request.proof_types, approval.request.verifier_id) == ACTION_BLOCK:
            approval.status = "denied"
            return self._block(approval.request, BLOCK_POLICY)
        approval.status = "approved"
        self.audit_log.record(
            "approval_granted", approval_id=approval_id, nonce=approval.request.nonce
        )
        policy_document = self._policy_documents.get(approval.request.verifier_id)
        if policy_document is None:
            return self._block(approval.request, BLOCK_NO_PUBLISHED_POLICY)
        try:
            plan = ProofPlanner(self._registry, policy_document).plan(
                approval.request, consent_scope=self._compliance_policy.disclosure_ceiling
            )
        except HolderError as exc:
            return self._block(approval.request, BLOCK_PLANNING_REFUSED, detail=exc.code)
        return self._respond(
            approval.request,
            approval.context,
            plan,
            policy_document,
            approval.current_epochs,
            approval.apr, now, approval.allow_unauthenticated, signer,
        )

    def deny(self, approval_id: str) -> AgentDecision:
        approval = self._pending_approvals.get(approval_id)
        if approval is None or approval.status != "pending":
            raise ApprovalNotFoundError(f"no pending approval {approval_id!r}")
        approval.status = "denied"
        self.audit_log.record(
            "approval_denied", approval_id=approval_id, nonce=approval.request.nonce
        )
        return AgentDecision(
            status="blocked",
            nonce=approval.request.nonce,
            reason_code=BLOCK_PRINCIPAL_DENIED,
        )

    # --- batch warm path -------------------------------------------------------

    @staticmethod
    def _cache_key(apr, proof_request, signer):
        # Bind the complete signed demand, identity, epochs and effective plan.
        return json.dumps({"apr": apr, "signer": signer,
                           "types": proof_request.proof_types, "parameters": proof_request.parameters,
                           "epochs": proof_request.current_epochs,
                           "trust": repr(proof_request.trust_policy)}, sort_keys=True, allow_nan=False)

    def precompute_proofs(self, anticipated_requests, *, now: int = None,
                          allow_unauthenticated: bool = False) -> dict:
        """Warm (request, context, apr) triples after the same admission checks.

        Legacy pairs have no APR and are refused unless explicitly opted in.
        Warming reserves no disclosure nonce; actual release rechecks admission.
        """
        now = int(time.time()) if now is None else now
        cached, skipped = 0, []
        for entry in anticipated_requests:
            request, context = copy.deepcopy(entry[:2])
            apr = copy.deepcopy(entry[2]) if len(entry) == 3 else None
            decision = self._gate(request, context)
            if decision is not None:
                skipped.append({"nonce": request.nonce, "reason": decision.reason_code})
                continue
            apr = self._request_apr(request, context, apr, now)
            reason, signer = self._admit(request, context, apr, now, allow_unauthenticated)
            if reason:
                skipped.append({"nonce": request.nonce, "reason": reason})
                continue
            if self._compliance_policy.decision_for(request.proof_types, request.verifier_id) != ACTION_AUTO_APPROVE:
                skipped.append({"nonce": request.nonce, "reason": BLOCK_POLICY})
                continue
            policy_document = self._policy_documents.get(request.verifier_id)
            if policy_document is None:
                skipped.append({"nonce": request.nonce, "reason": BLOCK_NO_PUBLISHED_POLICY})
                continue
            try:
                plan = ProofPlanner(self._registry, policy_document).plan(
                    request, consent_scope=self._compliance_policy.disclosure_ceiling
                )
                proof_request = self._materialize(plan, context, policy_document, {}, apr)
                if (list(plan.proof_types) != apr["request"]["proofTypes"]
                    or proof_request.parameters != apr["request"].get("parameters", {})):
                    skipped.append({"nonce": request.nonce, "reason": BLOCK_UNAUTHENTICATED_REQUEST})
                    continue
                result = self._holder.generate_authenticated_proof(
                    apr, proof_request, now=now, allow_unauthenticated=allow_unauthenticated,
                    consents={proof_type: True for proof_type in plan.proof_types},
                    exact_member_consents=self._exact_member_consents(plan.proof_types),
                )
                self._proof_cache[self._cache_key(apr, proof_request, signer)] = result
            except (HolderError, KeyError, TypeError, ValueError) as exc:
                skipped.append({"nonce": request.nonce, "reason": getattr(exc, "code", "MALFORMED_REQUEST")})
                continue
            cached += 1
        self.audit_log.record("proofs_precomputed", cached=cached, skipped=skipped)
        return {"cached": cached, "skipped": skipped}

    # --- holder-authorized audit export -------------------------------------------

    def request_audit_export(
        self,
        exporter,
        proofs: list,
        *,
        auditor_key_id: str,
        valid_from: int,
        valid_until: int,
        purpose: str,
    ) -> str:
        """Queue an audit-bundle export for EXPLICIT principal authorization.

        Audit exports are never auto-approved: whatever the compliance
        policy says about proof requests, releasing compliance evidence to
        an auditor always requires the principal. Returns the export id."""
        export_id = secrets.token_hex(8)
        self._pending_audit_exports[export_id] = {
            "exporter": exporter,
            "proofs": list(proofs),
            "auditor_key_id": auditor_key_id,
            "valid_from": int(valid_from),
            "valid_until": int(valid_until),
            "purpose": purpose,
            "status": "pending",
        }
        summary = {
            "exportId": export_id,
            "auditorKeyId": auditor_key_id,
            "proofCount": len(proofs),
            "validFrom": int(valid_from),
            "validUntil": int(valid_until),
            "purpose": purpose,
        }
        self.audit_log.record("audit_export_requested", **summary)
        self._notify("audit_export_requested", summary)
        return export_id

    def approve_audit_export(self, export_id: str) -> dict:
        """Principal approval: build and release the audit bundle."""
        pending = self._pending_audit_exports.get(export_id)
        if pending is None or pending["status"] != "pending":
            raise ApprovalNotFoundError(f"no pending audit export {export_id!r}")
        pending["status"] = "approved"
        bundle = pending["exporter"].export(
            pending["proofs"],
            auditor_key_id=pending["auditor_key_id"],
            valid_from=pending["valid_from"],
            valid_until=pending["valid_until"],
            purpose=pending["purpose"],
        )
        self.audit_log.record(
            "audit_export_released",
            export_id=export_id,
            auditor_key_id=pending["auditor_key_id"],
            bundle_hash=bundle["bundleHash"],
            proof_refs=list(bundle["authorization"]["proofRefs"]),
        )
        return bundle

    def deny_audit_export(self, export_id: str) -> None:
        pending = self._pending_audit_exports.get(export_id)
        if pending is None or pending["status"] != "pending":
            raise ApprovalNotFoundError(f"no pending audit export {export_id!r}")
        pending["status"] = "denied"
        self.audit_log.record("audit_export_denied", export_id=export_id)

    # --- counterparty verification ----------------------------------------------

    def verify_counterparty(self, counterparty_envelope: dict, requirements) -> object:
        """Verify a counterparty's compliance proof before transacting.

        Drives the configured ``zkc_verifier.ZKCVerifier`` against the
        counterparty's envelope; returns its VerificationResult."""
        if self._counterparty_verifier is None:
            raise PolicyConfigurationError(
                "no counterparty verifier configured (pass counterparty_verifier=...)"
            )
        result = self._counterparty_verifier.verify(counterparty_envelope, requirements)
        self.audit_log.record(
            "counterparty_verified",
            valid=result.valid,
            error_codes=result.codes(),
            warning_codes=result.warning_codes(),
            proof_types=list(requirements.proof_types),
        )
        return result
