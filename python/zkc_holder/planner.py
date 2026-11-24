"""Minimal-disclosure proof planning and verifier policy negotiation.

A holder should never disclose more than a verifier's PUBLISHED policy
actually needs. This module turns a published verifier trust policy (a
``zkc_registry.VerifierPolicyDocument``, duck-typed) plus a concrete proof
request into the MINIMAL satisfying proof plan:

- the smallest predicate set (requested predicates the policy does not list
  as required are dropped),
- the narrowest parameters (e.g. KYC level 1, not level 3, when the policy's
  published minimum is level 1; no verified attribute the policy does not
  require),
- a structured :class:`PlanReport` mapping every disclosed element to the
  policy clause that requires it.

Overbroad requests — asking beyond the published policy, or beyond the
holder's explicit consent scope — are REJECTED with a structured refusal
listing the overbroad elements (:class:`OverbroadRequestError`). Opaque or
unreviewed predicates ride the existing Safeguard-4 refusal path
(:class:`~zkc_holder.errors.OpaquePredicateError`).

A small request / counter-offer negotiation protocol is included: the
verifier sends a :class:`NegotiationRequest`, the holder answers with a
:class:`NegotiationCounterOffer` (a minimal plan, or a structured refusal),
and the verifier closes with a :class:`NegotiationDecision`. All three are
plain in-process objects with stable JSON wire shapes (``zkc:negotiation:v1``)
— there is deliberately no network server here.

Refusals are CONSTANT-SHAPE at the wire level: a refusal never reveals
whether the holder actually holds a matching credential (metadata-leakage
mitigation). Planning is a pure policy computation; it never touches the
credential store.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from zkc_crypto.presentation import ANONYMOUS_PROFILE, LINKABLE_PROFILE, SCOPED_PROFILE

from .ceilings import (
    BOUND_CEILING,
    BOUND_MINIMUM,
    EXACT_MEMBER,
    SET_UNKNOWN,
    WITNESS_PATH,
    comparator_for,
    compare_parameters,
    exact_member_opted_in,
    narrow_parameters,
    set_disclosure,
)
from .credential import ProofRequest
from .errors import (
    CanonicalSetMismatchError,
    ConstraintViolationError,
    HolderError,
    OpaquePredicateError,
    OverbroadRequestError,
    SecretInRequestError,
)
from .predicates import request_contract_proof_types
from .rebind_secret import refuse_secret_parameters
from .registry import DEFAULT_ACCEPTED_STATUSES

__all__ = [
    "NEGOTIATION_VERSION",
    "REFUSAL_MESSAGE",
    "PlanItem",
    "PlanReport",
    "ProofPlanner",
    "NegotiationRequest",
    "NegotiationCounterOffer",
    "NegotiationDecision",
    "evaluate_counter_offer",
    "parameter_excesses",
]

NEGOTIATION_VERSION = "zkc:negotiation:v1"

# Constant-shape refusal text: identical for "no such credential", "policy
# refusal", and "consent refusal" so the wire message leaks nothing about
# what the holder holds. Details stay holder-local (in the exception object
# / refusal elements the holder chooses to share).
REFUSAL_MESSAGE = "cannot satisfy this proof request"


def parameter_excesses(
    proof_type: str, requested: dict, minimum: dict, circuit: str = None, role: str = BOUND_MINIMUM
) -> list:
    """Elements where `requested` asks MORE than `minimum` (a published
    minimum or a holder consent ceiling).

    The bound is the complete statement of what may be disclosed: a parameter
    it does not state takes its documented default. Comparison is typed per
    predicate (:mod:`zkc_holder.ceilings`): thresholds and flags in the
    direction that discloses more, set roots, mode codes and other unordered
    values pinned. Witness paths are not compared value by value; the planner
    governs them through :func:`zkc_holder.ceilings.set_disclosure`. A proof
    type with no comparator, a malformed or out-of-domain value, or a key with
    no rule is always reported.
    """
    narrowable, hard = compare_parameters(
        proof_type, requested, minimum, circuit=circuit, role=role
    )
    return narrowable + hard


@dataclass(frozen=True)
class PlanItem:
    """One predicate in a disclosure plan, with its policy justification."""

    proof_type: str
    parameters: dict
    predicate_id: str = ""
    entry_version: str = ""
    circuit: str = ""
    # requirement → policy clause mapping: why each element is disclosed.
    justification: tuple = ()

    def to_dict(self) -> dict:
        return {
            "proofType": self.proof_type,
            "parameters": self.parameters,
            "predicateId": self.predicate_id,
            "entryVersion": self.entry_version,
            "circuit": self.circuit,
            "justification": [dict(clause) for clause in self.justification],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PlanItem":
        return cls(
            proof_type=data["proofType"],
            parameters=dict(data["parameters"]),
            predicate_id=data.get("predicateId", ""),
            entry_version=data.get("entryVersion", ""),
            circuit=data.get("circuit", ""),
            justification=tuple(dict(clause) for clause in data.get("justification", [])),
        )


@dataclass(frozen=True)
class PlanReport:
    """A minimal disclosure plan: what is disclosed, and why each element
    is required (requirement → policy clause mapping)."""

    verifier_id: str
    items: tuple  # of PlanItem
    # Elements the plan narrowed relative to the original request.
    narrowed: tuple = ()
    # Holder-local overbreadth notes for the principal (narrow or
    # undeterminable set predicates, zkc_holder.ceilings.set_disclosure).
    # Never serialized into the zkc:negotiation:v1 wire shape, and excluded
    # from equality so a wire round trip compares equal.
    warnings: tuple = field(default=(), compare=False)

    @property
    def proof_types(self) -> tuple:
        return tuple(item.proof_type for item in self.items)

    def item(self, proof_type: str):
        for entry in self.items:
            if entry.proof_type == proof_type:
                return entry
        return None

    def to_dict(self) -> dict:
        return {
            "verifierId": self.verifier_id,
            "items": [item.to_dict() for item in self.items],
            "narrowed": [dict(element) for element in self.narrowed],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PlanReport":
        return cls(
            verifier_id=data["verifierId"],
            items=tuple(PlanItem.from_dict(item) for item in data["items"]),
            narrowed=tuple(dict(element) for element in data.get("narrowed", [])),
        )

    def to_proof_request(
        self, context, trust_policy, max_proof_age: int = 3600, current_epochs: dict = None
    ) -> ProofRequest:
        """Materialize the plan as a holder ProofRequest for generate_authenticated_proof."""
        return ProofRequest(
            proof_types=list(self.proof_types),
            parameters={item.proof_type: dict(item.parameters) for item in self.items},
            context=context,
            trust_policy=trust_policy,
            max_proof_age=max_proof_age,
            current_epochs=dict(current_epochs or {}),
        )


class ProofPlanner:
    """Compute minimal disclosure plans against a PUBLISHED verifier policy.

    `policy` is duck-typed (``zkc_registry.VerifierPolicyDocument``): it must
    expose ``verifier_id``, ``accepted_proof_types`` and
    ``proof_requirements()``. Planning never reads the credential store —
    the plan depends only on the request, the policy, and the predicate
    registry, so producing (or refusing) a plan leaks nothing about which
    credentials the holder actually has.
    """

    def __init__(self, registry, policy, accepted_review_statuses: tuple = None):
        self._registry = registry
        self._policy = policy
        # Same Safeguard-4 gate (and same default) as HolderClient: see
        # zkc_holder.registry.DEFAULT_ACCEPTED_STATUSES.
        self._accepted_review_statuses = tuple(
            DEFAULT_ACCEPTED_STATUSES
            if accepted_review_statuses is None
            else accepted_review_statuses
        )

    # ------------------------------------------------------------------

    def _assess(self, request: "NegotiationRequest", consent_scope: dict = None):
        """Classify every requested element: kept, narrowable, or refused."""
        # A request or published policy naming holder secret material (a
        # rebind's new seed/key) is refused outright, before any reasoning
        # that could echo the value back in a counter-offer (spec 7.4.4).
        refuse_secret_parameters(request.parameters, "negotiation request")
        refuse_secret_parameters(getattr(self._policy, "raw", {}), "verifier policy")
        refuse_secret_parameters(
            self._policy.proof_requirements(), "verifier policy proofRequirements"
        )
        # Closed parameter vocabulary (spec 6.2.1), after the secret checks so
        # their SECRET_IN_REQUEST refusal keeps precedence. Planning does not
        # know the presentation profile the answer will use, so every
        # identity the request could be answered under must accept the keys.
        self._registry.refuse_unknown_request_parameters(
            request.proof_types,
            request.parameters,
            "negotiation request",
            resolve=lambda proof_type: request_contract_proof_types(
                proof_type, (LINKABLE_PROFILE, ANONYMOUS_PROFILE, SCOPED_PROFILE)
            ),
        )
        accepted = tuple(self._policy.accepted_proof_types)
        requirements = dict(self._policy.proof_requirements())
        hard = []  # overbroad beyond repair: refuse
        narrowable = []  # overbroad but reducible: counter-offer narrows
        kept = []  # (proof_type, parameters, justification)

        for proof_type in request.proof_types:
            requested_parameters = dict(request.parameters.get(proof_type, {}))

            # Safeguard 4: opaque predicates, and predicates whose review
            # status is outside the accepted set, ride the existing refusal
            # path before any policy reasoning.
            entry = self._registry.resolve(
                proof_type, accepted_statuses=self._accepted_review_statuses
            )
            if entry is None:
                raise OpaquePredicateError(REFUSAL_MESSAGE)
            if entry.review_status not in self._accepted_review_statuses:
                raise OpaquePredicateError(REFUSAL_MESSAGE)

            if proof_type not in accepted:
                hard.append(
                    {
                        "proofType": proof_type,
                        "element": "proofType",
                        "requested": proof_type,
                        "permitted": list(accepted),
                        "kind": "predicate_not_accepted",
                    }
                )
                continue

            scope = None
            if consent_scope is not None:
                scope = consent_scope.get(proof_type)
                if scope is None or comparator_for(proof_type, entry.circuit) is None:
                    # Outside the ceiling, or a proof type whose parameters
                    # have no typed comparator: a ceiling cannot be shown to
                    # bound it, so it is refused (fail closed).
                    hard.append(
                        {
                            "proofType": proof_type,
                            "element": "proofType",
                            "requested": proof_type,
                            "permitted": sorted(consent_scope) if scope is None else None,
                            "kind": "beyond_consent",
                        }
                    )
                    continue
                consent_narrowable, consent_hard = compare_parameters(
                    proof_type,
                    requested_parameters,
                    scope,
                    circuit=entry.circuit,
                    role=BOUND_CEILING,
                )
                consent_excesses = consent_narrowable + consent_hard
                if consent_excesses:
                    for excess in consent_excesses:
                        excess["kind"] = "beyond_consent"
                    hard.extend(consent_excesses)
                    continue
                set_warnings, outcome = set_disclosure(
                    proof_type, requested_parameters, circuit=entry.circuit
                )
                if outcome == SET_UNKNOWN or (
                    outcome == EXACT_MEMBER and not exact_member_opted_in(scope)
                ):
                    # The principal cannot have consented to how narrow the
                    # set proof is: its size is unknown, or the witness is
                    # fixed by the request so the proof is an equality test
                    # on the holder's exact code (fail closed, unless the
                    # ceiling explicitly opts in to exact-member disclosure).
                    hard.extend(
                        {
                            "proofType": proof_type,
                            "element": warning["element"],
                            "requested": None,
                            "permitted": None,
                            "kind": "beyond_consent",
                        }
                        for warning in set_warnings
                        if warning["kind"] in ("set_size_unknown", "narrow_set")
                    )
                    continue

            minimum = requirements.get(proof_type)
            if requirements and minimum is None:
                # The policy publishes its needs and this predicate is not
                # among them: requesting it is overbroad; a counter-offer
                # simply drops it.
                narrowable.append(
                    {
                        "proofType": proof_type,
                        "element": "proofType",
                        "requested": proof_type,
                        "permitted": sorted(requirements),
                        "kind": "unnecessary_predicate",
                    }
                )
                continue

            if minimum is not None:
                policy_narrowable, policy_hard = compare_parameters(
                    proof_type, requested_parameters, minimum, circuit=entry.circuit
                )
                if policy_hard:
                    # A pinned value (set root, mode, claim type) that differs
                    # from the published one, a malformed value, or a key
                    # the published minimum cannot govern: no narrower
                    # statement exists, so a counter-offer cannot repair it.
                    hard.extend(policy_hard)
                    continue
                narrowable.extend(policy_narrowable)
                # Keep the predicate's own parameters; lower only the
                # ordered values toward the published minimum.
                parameters = narrow_parameters(
                    proof_type, requested_parameters, minimum, circuit=entry.circuit
                )
                if scope is not None and parameter_excesses(
                    proof_type, parameters, scope, circuit=entry.circuit, role=BOUND_CEILING
                ):  # pragma: no cover - narrowing is monotone; defence in depth
                    hard.append(
                        {
                            "proofType": proof_type,
                            "element": "parameters",
                            "requested": None,
                            "permitted": None,
                            "kind": "beyond_consent",
                        }
                    )
                    continue
                rules = comparator_for(proof_type, entry.circuit).rules
                justification = tuple(
                    {
                        "element": key,
                        "value": parameters[key],
                        "policyClause": f"proofRequirements[{proof_type!r}].{key}",
                    }
                    for key, rule in rules.items()
                    if key in parameters and rule.kind != WITNESS_PATH
                )
            else:
                # No published minimums: nothing to narrow against; the
                # accepted request is the best available statement of need.
                parameters = requested_parameters
                justification = (
                    {
                        "element": "proofType",
                        "value": proof_type,
                        "policyClause": "acceptedProofTypes",
                    },
                )
            warnings, _outcome = set_disclosure(proof_type, parameters, circuit=entry.circuit)
            kept.append((proof_type, parameters, justification, entry, tuple(warnings)))
        return kept, narrowable, hard

    def _build_report(self, kept, narrowed) -> PlanReport:
        items = tuple(
            PlanItem(
                proof_type=proof_type,
                parameters=parameters,
                predicate_id=entry.predicate_id,
                entry_version=entry.entry_version,
                circuit=entry.circuit,
                justification=justification,
            )
            for proof_type, parameters, justification, entry, _warnings in kept
        )
        return PlanReport(
            verifier_id=self._policy.verifier_id,
            items=items,
            narrowed=tuple(narrowed),
            warnings=tuple(warning for *_rest, warnings in kept for warning in warnings),
        )

    # ------------------------------------------------------------------

    def plan(self, request: "NegotiationRequest", consent_scope: dict = None) -> PlanReport:
        """STRICT minimal plan: any overbroad element is a refusal.

        Raises :class:`OverbroadRequestError` listing every overbroad element
        when the request asks beyond the published policy or beyond the
        holder consent scope; :class:`OpaquePredicateError` for opaque or
        unreviewed predicates.
        """
        kept, narrowable, hard = self._assess(request, consent_scope)
        overbroad = hard + narrowable
        if overbroad:
            raise OverbroadRequestError(REFUSAL_MESSAGE, elements=overbroad)
        if not kept:
            raise OverbroadRequestError(
                REFUSAL_MESSAGE,
                elements=[
                    {
                        "proofType": "",
                        "element": "proofTypes",
                        "requested": list(request.proof_types),
                        "permitted": list(self._policy.accepted_proof_types),
                        "kind": "empty_plan",
                    }
                ],
            )
        return self._build_report(kept, narrowed=())

    def counter_offer(
        self, request: "NegotiationRequest", consent_scope: dict = None
    ) -> "NegotiationCounterOffer":
        """Negotiate: answer a request with a minimal counter-plan, or a
        structured refusal when the request is overbroad beyond repair."""
        try:
            kept, narrowable, hard = self._assess(request, consent_scope)
        except (
            OpaquePredicateError,
            SecretInRequestError,
            ConstraintViolationError,
            CanonicalSetMismatchError,
        ) as exc:
            # A request outside the closed parameter vocabulary is a
            # structured refusal like any other, never an exception here.
            return NegotiationCounterOffer(
                nonce=request.nonce,
                status="refusal",
                refusal_code=exc.code,
                refusal_elements=(),
            )
        if hard or not kept:
            return NegotiationCounterOffer(
                nonce=request.nonce,
                status="refusal",
                refusal_code=OverbroadRequestError.code,
                refusal_elements=tuple(hard),
            )
        return NegotiationCounterOffer(
            nonce=request.nonce,
            status="counter",
            plan=self._build_report(kept, narrowed=narrowable),
        )


# ---------------------------------------------------------------------------
# Negotiation protocol wire objects (zkc:negotiation:v1)
# ---------------------------------------------------------------------------


def _require_wire(data: dict, expected_type: str) -> None:
    if not isinstance(data, dict):
        raise HolderError(f"negotiation message must be a JSON object, got {type(data).__name__}")
    if data.get("version") != NEGOTIATION_VERSION:
        raise HolderError(f"unsupported negotiation version {data.get('version')!r}")
    if data.get("type") != expected_type:
        raise HolderError(
            f"unexpected negotiation message type {data.get('type')!r} (wanted {expected_type!r})"
        )


@dataclass(frozen=True)
class NegotiationRequest:
    """Verifier → holder: a proof request referencing the published policy."""

    verifier_id: str
    proof_types: tuple
    parameters: dict = field(repr=False)
    nonce: str

    @classmethod
    def new(cls, verifier_id: str, proof_types, parameters: dict) -> "NegotiationRequest":
        return cls(
            verifier_id=verifier_id,
            proof_types=tuple(proof_types),
            parameters=dict(parameters),
            nonce=secrets.token_hex(16),
        )

    def to_dict(self) -> dict:
        return {
            "version": NEGOTIATION_VERSION,
            "type": "proof-request",
            "verifierId": self.verifier_id,
            "proofTypes": list(self.proof_types),
            "parameters": self.parameters,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NegotiationRequest":
        _require_wire(data, "proof-request")
        return cls(
            verifier_id=data["verifierId"],
            proof_types=tuple(data["proofTypes"]),
            parameters=dict(data["parameters"]),
            nonce=str(data["nonce"]),
        )


@dataclass(frozen=True)
class NegotiationCounterOffer:
    """Holder → verifier: a minimal counter-plan, or a structured refusal.

    The wire-level refusal message is constant-shape (:data:`REFUSAL_MESSAGE`
    semantics): it never says whether the holder holds a credential.
    """

    nonce: str
    status: str  # "counter" | "refusal"
    plan: PlanReport = None
    refusal_code: str = ""
    refusal_elements: tuple = ()

    def __post_init__(self):
        if self.status not in ("counter", "refusal"):
            raise HolderError(f"unknown counter-offer status {self.status!r}")
        if self.status == "counter" and self.plan is None:
            raise HolderError("a counter-offer must carry a plan")

    def to_dict(self) -> dict:
        data = {
            "version": NEGOTIATION_VERSION,
            "type": "counter-offer",
            "nonce": self.nonce,
            "status": self.status,
            "message": REFUSAL_MESSAGE if self.status == "refusal" else "counter-offer",
        }
        if self.status == "counter":
            data["plan"] = self.plan.to_dict()
        else:
            data["refusal"] = {
                "code": self.refusal_code,
                "elements": [dict(element) for element in self.refusal_elements],
            }
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "NegotiationCounterOffer":
        _require_wire(data, "counter-offer")
        status = data.get("status")
        if status == "counter":
            return cls(
                nonce=str(data["nonce"]),
                status="counter",
                plan=PlanReport.from_dict(data["plan"]),
            )
        refusal = data.get("refusal", {})
        return cls(
            nonce=str(data["nonce"]),
            status="refusal",
            refusal_code=str(refusal.get("code", "")),
            refusal_elements=tuple(dict(element) for element in refusal.get("elements", [])),
        )


@dataclass(frozen=True)
class NegotiationDecision:
    """Verifier → holder: accept or reject the holder's counter-offer."""

    nonce: str
    status: str  # "accept" | "reject"
    reason: str = ""

    def __post_init__(self):
        if self.status not in ("accept", "reject"):
            raise HolderError(f"unknown negotiation decision status {self.status!r}")

    def to_dict(self) -> dict:
        return {
            "version": NEGOTIATION_VERSION,
            "type": "decision",
            "nonce": self.nonce,
            "status": self.status,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NegotiationDecision":
        _require_wire(data, "decision")
        return cls(
            nonce=str(data["nonce"]), status=str(data["status"]), reason=str(data.get("reason", ""))
        )


def evaluate_counter_offer(policy, counter: NegotiationCounterOffer) -> NegotiationDecision:
    """Verifier-side: accept a counter-offer iff it satisfies the verifier's
    OWN published policy minimums — no more (over-disclosure is the holder's
    loss, but a verifier must not solicit it) and no less.

    `policy` is the verifier's own published policy document (duck-typed as
    in :class:`ProofPlanner`).
    """
    if counter.status == "refusal":
        return NegotiationDecision(
            nonce=counter.nonce, status="reject", reason="holder refused the request"
        )
    plan = counter.plan
    accepted = tuple(policy.accepted_proof_types)
    requirements = dict(policy.proof_requirements())
    for item in plan.items:
        if item.proof_type not in accepted:
            return NegotiationDecision(
                nonce=counter.nonce,
                status="reject",
                reason=f"plan offers a proof type outside the published policy: {item.proof_type}",
            )
    if requirements:
        for proof_type, minimum in requirements.items():
            item = plan.item(proof_type)
            if item is None:
                return NegotiationDecision(
                    nonce=counter.nonce,
                    status="reject",
                    reason=f"plan does not cover required proof type {proof_type}",
                )
            # Under-disclosure: the published minimum must not exceed the
            # offer (typed per predicate; pinned values must match). The
            # holder-supplied PlanItem.circuit is not trusted here: the
            # comparator is chosen from the proof type alone.
            if parameter_excesses(proof_type, minimum, dict(item.parameters)):
                return NegotiationDecision(
                    nonce=counter.nonce,
                    status="reject",
                    reason=f"plan for {proof_type} does not cover the published minimum",
                )
        # Over-disclosure relative to the published need: the verifier must
        # not silently accept more than it asked for.
        for item in plan.items:
            minimum = requirements.get(item.proof_type)
            if minimum is None:
                return NegotiationDecision(
                    nonce=counter.nonce,
                    status="reject",
                    reason=(
                        "plan discloses a predicate the published policy does not "
                        f"require: {item.proof_type}"
                    ),
                )
            if parameter_excesses(item.proof_type, dict(item.parameters), minimum):
                return NegotiationDecision(
                    nonce=counter.nonce,
                    status="reject",
                    reason=f"plan over-discloses for {item.proof_type} beyond the published minimum",
                )
    return NegotiationDecision(nonce=counter.nonce, status="accept")
