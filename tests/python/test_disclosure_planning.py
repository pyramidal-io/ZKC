"""Minimal-disclosure planning + verifier policy negotiation tests.

Covers: plan minimality (including a seeded property-style sweep over
generated policies), overbroad-request rejection, consent-scope rejection,
the opaque-predicate refusal path, the request/counter-offer/decision flow
(with JSON wire round-trips), and verifier-side over-disclosure warnings.
"""

import copy
import json
import random
import unittest

from _path import REPO_ROOT
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402

from holder_fixtures import (
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    issue_kyc_credential,
    trusted_test_issuer,
)
from zkc_crypto import ProofContext
from zkc_holder import (
    REFUSAL_MESSAGE,
    HolderClient,
    LocalAccumulatorProvider,
    NegotiationCounterOffer,
    NegotiationDecision,
    NegotiationRequest,
    OpaquePredicateError,
    OverbroadRequestError,
    PlanReport,
    PredicateRegistry,
    ProofPlanner,
    StubBackend,
    TrustPolicy,
    evaluate_counter_offer,
)
from zkc_registry import DiscoveryRegistry, RegistryValidationError
from zkc_registry.store import _policy_from_document, validate_verifier_policy
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    TrustedIssuer,
    VerificationRequest,
    VerificationWarningCode as Warn,
    VerifierTrustPolicy,
    ZKCVerifier,
    disclosure_warnings,
)

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
JURISDICTION_PROOF_TYPE = "zkc:proof:jurisdiction:v3"
CONTEXT = ProofContext.verifier_session("verifier.example", 555, 1_700_000_000)


def make_policy_document(
    accepted=(KYC_PROOF_TYPE, JURISDICTION_PROOF_TYPE),
    proof_requirements=None,
    verifier_id="did:zkc:verifier:test",
):
    document = {
        "version": "zkc:registry:verifier-policy:v1",
        "verifierId": verifier_id,
        "displayName": "Test Verifier",
        "acceptedProofTypes": list(accepted),
        "requiredReviewStatuses": ["reviewed"],
        "trustedIssuers": [],
        "acceptsOutOfRegistryIssuers": False,
        "requiredContextProfile": "",
        "maxEpochLag": 10,
        "updatedAt": "2026-06-11T00:00:00Z",
    }
    if proof_requirements is not None:
        document["proofRequirements"] = proof_requirements
    validate_verifier_policy(document, "<test>")
    return _policy_from_document(document, "<test>")


KYC_MINIMUM = {
    "requiredLevel": 1,
    "requiredAttributes": [True, False, False, False, False],
}
POLICY = make_policy_document(proof_requirements={KYC_PROOF_TYPE: KYC_MINIMUM})


def make_request(proof_types=(KYC_PROOF_TYPE,), parameters=None):
    return NegotiationRequest.new(
        POLICY.verifier_id,
        proof_types,
        parameters if parameters is not None else {KYC_PROOF_TYPE: dict(KYC_MINIMUM)},
    )


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.planner = ProofPlanner(REGISTRY, POLICY)

    def test_plan_matches_policy_minimum(self):
        report = self.planner.plan(make_request())
        self.assertEqual(report.proof_types, (KYC_PROOF_TYPE,))
        item = report.item(KYC_PROOF_TYPE)
        self.assertEqual(item.parameters["requiredLevel"], 1)
        self.assertEqual(item.parameters["requiredAttributes"], KYC_MINIMUM["requiredAttributes"])
        # Every disclosed element maps to a policy clause.
        clauses = {entry["element"]: entry["policyClause"] for entry in item.justification}
        self.assertIn("proofRequirements", clauses["requiredLevel"])
        self.assertIn("proofRequirements", clauses["requiredAttributes"])
        self.assertEqual(report.verifier_id, POLICY.verifier_id)

    def test_plan_rejects_level_above_policy(self):
        request = make_request(
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 3,
                    "requiredAttributes": KYC_MINIMUM["requiredAttributes"],
                }
            }
        )
        with self.assertRaises(OverbroadRequestError) as caught:
            self.planner.plan(request)
        elements = caught.exception.elements
        self.assertEqual(len(elements), 1)
        self.assertEqual(elements[0]["element"], "requiredLevel")
        self.assertEqual(elements[0]["requested"], 3)
        self.assertEqual(elements[0]["permitted"], 1)
        self.assertEqual(elements[0]["kind"], "parameter_exceeds_policy")

    def test_plan_rejects_attributes_beyond_policy(self):
        request = make_request(
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 1,
                    "requiredAttributes": [True, True, True, False, False],
                }
            }
        )
        with self.assertRaises(OverbroadRequestError) as caught:
            self.planner.plan(request)
        (element,) = caught.exception.elements
        self.assertEqual(element["element"], "requiredAttributes")
        self.assertEqual(element["requested"], [1, 2])

    def test_plan_rejects_unaccepted_proof_type(self):
        policy = make_policy_document(accepted=(JURISDICTION_PROOF_TYPE,))
        planner = ProofPlanner(REGISTRY, policy)
        with self.assertRaises(OverbroadRequestError) as caught:
            planner.plan(make_request())
        (element,) = caught.exception.elements
        self.assertEqual(element["kind"], "predicate_not_accepted")
        self.assertEqual(element["requested"], KYC_PROOF_TYPE)

    def test_plan_rejects_unnecessary_predicate(self):
        request = make_request(
            proof_types=(KYC_PROOF_TYPE, JURISDICTION_PROOF_TYPE),
            parameters={
                KYC_PROOF_TYPE: dict(KYC_MINIMUM),
                JURISDICTION_PROOF_TYPE: {},
            },
        )
        with self.assertRaises(OverbroadRequestError) as caught:
            self.planner.plan(request)
        (element,) = caught.exception.elements
        self.assertEqual(element["kind"], "unnecessary_predicate")
        self.assertEqual(element["proofType"], JURISDICTION_PROOF_TYPE)

    def test_plan_rejects_beyond_consent_scope(self):
        consent = {KYC_PROOF_TYPE: {"requiredLevel": 1, "requiredAttributes": [False] * 5}}
        with self.assertRaises(OverbroadRequestError) as caught:
            self.planner.plan(make_request(), consent_scope=consent)
        (element,) = caught.exception.elements
        self.assertEqual(element["kind"], "beyond_consent")

    def test_opaque_predicate_rides_existing_refusal_path(self):
        policy = make_policy_document(accepted=("zkc:proof:secret-scoring:v1",))
        planner = ProofPlanner(REGISTRY, policy)
        request = NegotiationRequest.new(
            policy.verifier_id, ("zkc:proof:secret-scoring:v1",), {}
        )
        with self.assertRaises(OpaquePredicateError):
            planner.plan(request)

    def test_refusals_are_constant_shape(self):
        """A refusal must read identically whatever its private cause —
        the wire message never reveals whether the holder HAS a credential."""
        messages = set()
        policy = make_policy_document(accepted=("zkc:proof:secret-scoring:v1", KYC_PROOF_TYPE))
        planner = ProofPlanner(REGISTRY, policy)
        try:
            planner.plan(
                NegotiationRequest.new(policy.verifier_id, ("zkc:proof:secret-scoring:v1",), {})
            )
        except OpaquePredicateError as exc:
            messages.add(exc.message)
        try:
            self.planner.plan(
                make_request(
                    parameters={KYC_PROOF_TYPE: {"requiredLevel": 3, "requiredAttributes": []}}
                )
            )
        except OverbroadRequestError as exc:
            messages.add(exc.message)
        self.assertEqual(messages, {REFUSAL_MESSAGE})

    def test_plan_without_published_minimums_keeps_request(self):
        policy = make_policy_document(proof_requirements=None)
        planner = ProofPlanner(REGISTRY, policy)
        parameters = {
            KYC_PROOF_TYPE: {"requiredLevel": 2, "requiredAttributes": [True] * 5}
        }
        report = planner.plan(make_request(parameters=parameters))
        self.assertEqual(
            report.item(KYC_PROOF_TYPE).parameters, parameters[KYC_PROOF_TYPE]
        )


class NegotiationFlowTests(unittest.TestCase):
    def setUp(self):
        self.planner = ProofPlanner(REGISTRY, POLICY)

    def test_counter_offer_narrows_to_policy_minimum(self):
        request = make_request(
            proof_types=(KYC_PROOF_TYPE, JURISDICTION_PROOF_TYPE),
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 3,
                    "requiredAttributes": [True, True, True, False, False],
                },
                JURISDICTION_PROOF_TYPE: {},
            },
        )
        counter = self.planner.counter_offer(request)
        self.assertEqual(counter.status, "counter")
        self.assertEqual(counter.nonce, request.nonce)
        self.assertEqual(counter.plan.proof_types, (KYC_PROOF_TYPE,))
        item = counter.plan.item(KYC_PROOF_TYPE)
        self.assertEqual(item.parameters["requiredLevel"], 1)
        self.assertEqual(item.parameters["requiredAttributes"], KYC_MINIMUM["requiredAttributes"])
        narrowed_kinds = {element["kind"] for element in counter.plan.narrowed}
        self.assertEqual(narrowed_kinds, {"parameter_exceeds_policy", "unnecessary_predicate"})
        decision = evaluate_counter_offer(POLICY, counter)
        self.assertEqual(decision.status, "accept")

    def test_counter_offer_refuses_hard_overbroad(self):
        policy = make_policy_document(accepted=(JURISDICTION_PROOF_TYPE,))
        planner = ProofPlanner(REGISTRY, policy)
        counter = planner.counter_offer(make_request())
        self.assertEqual(counter.status, "refusal")
        self.assertEqual(counter.refusal_code, OverbroadRequestError.code)
        self.assertEqual(counter.refusal_elements[0]["kind"], "predicate_not_accepted")
        decision = evaluate_counter_offer(policy, counter)
        self.assertEqual(decision.status, "reject")

    def test_counter_offer_refusal_is_constant_shape_for_opaque(self):
        policy = make_policy_document(accepted=("zkc:proof:secret-scoring:v1",))
        planner = ProofPlanner(REGISTRY, policy)
        counter = planner.counter_offer(
            NegotiationRequest.new(policy.verifier_id, ("zkc:proof:secret-scoring:v1",), {})
        )
        self.assertEqual(counter.status, "refusal")
        self.assertEqual(counter.to_dict()["message"], REFUSAL_MESSAGE)
        # Same wire message as a policy refusal.
        hard_policy = make_policy_document(accepted=(JURISDICTION_PROOF_TYPE,))
        hard_counter = ProofPlanner(REGISTRY, hard_policy).counter_offer(make_request())
        self.assertEqual(hard_counter.to_dict()["message"], REFUSAL_MESSAGE)

    def test_wire_round_trips(self):
        request = make_request()
        self.assertEqual(
            NegotiationRequest.from_dict(json.loads(json.dumps(request.to_dict()))), request
        )
        counter = self.planner.counter_offer(request)
        round_tripped = NegotiationCounterOffer.from_dict(
            json.loads(json.dumps(counter.to_dict()))
        )
        self.assertEqual(round_tripped.plan.to_dict(), counter.plan.to_dict())
        self.assertEqual(round_tripped.nonce, counter.nonce)
        decision = evaluate_counter_offer(POLICY, counter)
        self.assertEqual(
            NegotiationDecision.from_dict(json.loads(json.dumps(decision.to_dict()))), decision
        )

    def test_wire_rejects_bad_version_and_type(self):
        data = make_request().to_dict()
        bad_version = dict(data, version="zkc:negotiation:v999")
        with self.assertRaises(Exception):
            NegotiationRequest.from_dict(bad_version)
        with self.assertRaises(Exception):
            NegotiationCounterOffer.from_dict(data)  # wrong type

    def test_verifier_rejects_under_disclosing_plan(self):
        counter = self.planner.counter_offer(make_request())
        plan = counter.plan.to_dict()
        plan["items"][0]["parameters"]["requiredAttributes"] = [False] * 5
        weakened = NegotiationCounterOffer(
            nonce=counter.nonce, status="counter", plan=PlanReport.from_dict(plan)
        )
        decision = evaluate_counter_offer(POLICY, weakened)
        self.assertEqual(decision.status, "reject")

    def test_verifier_rejects_over_disclosing_plan(self):
        counter = self.planner.counter_offer(make_request())
        plan = counter.plan.to_dict()
        plan["items"][0]["parameters"]["requiredLevel"] = 3
        inflated = NegotiationCounterOffer(
            nonce=counter.nonce, status="counter", plan=PlanReport.from_dict(plan)
        )
        decision = evaluate_counter_offer(POLICY, inflated)
        self.assertEqual(decision.status, "reject")


class MinimalityPropertyTests(unittest.TestCase):
    """Property-style sweep: over generated policies and overbroad requests,
    the counter-plan is exactly the policy minimum — and any strictly weaker
    plan no longer satisfies the policy."""

    def test_counter_plan_is_exactly_minimal(self):
        rng = random.Random(20260611)
        for _ in range(50):
            minimum_level = rng.randint(1, 3)
            minimum_attributes = [rng.random() < 0.4 for _ in range(5)]
            policy = make_policy_document(
                accepted=(KYC_PROOF_TYPE,),
                proof_requirements={
                    KYC_PROOF_TYPE: {
                        "requiredLevel": minimum_level,
                        "requiredAttributes": minimum_attributes,
                    }
                },
            )
            planner = ProofPlanner(REGISTRY, policy)
            requested_level = rng.randint(minimum_level, 3)
            requested_attributes = [
                needed or (rng.random() < 0.5) for needed in minimum_attributes
            ]
            request = NegotiationRequest.new(
                policy.verifier_id,
                (KYC_PROOF_TYPE,),
                {
                    KYC_PROOF_TYPE: {
                        "requiredLevel": requested_level,
                        "requiredAttributes": requested_attributes,
                    }
                },
            )
            counter = planner.counter_offer(request)
            self.assertEqual(counter.status, "counter")
            item = counter.plan.item(KYC_PROOF_TYPE)
            # The plan equals the policy minimum exactly.
            self.assertEqual(item.parameters["requiredLevel"], minimum_level)
            self.assertEqual(item.parameters["requiredAttributes"], minimum_attributes)
            self.assertEqual(evaluate_counter_offer(policy, counter).status, "accept")
            # No strictly weaker plan satisfies the policy.
            for weaker_parameters in self._weaker(item.parameters):
                plan_dict = counter.plan.to_dict()
                plan_dict["items"][0]["parameters"] = weaker_parameters
                weaker = NegotiationCounterOffer(
                    nonce=counter.nonce,
                    status="counter",
                    plan=PlanReport.from_dict(plan_dict),
                )
                self.assertEqual(
                    evaluate_counter_offer(policy, weaker).status,
                    "reject",
                    f"weaker plan {weaker_parameters} unexpectedly satisfied "
                    f"minimum {item.parameters}",
                )

    @staticmethod
    def _weaker(parameters):
        """All single-step weakenings of a KYC parameter set."""
        weaker = []
        if parameters["requiredLevel"] > 1:
            weaker.append(
                {
                    "requiredLevel": parameters["requiredLevel"] - 1,
                    "requiredAttributes": list(parameters["requiredAttributes"]),
                }
            )
        for index, flag in enumerate(parameters["requiredAttributes"]):
            if flag:
                attributes = list(parameters["requiredAttributes"])
                attributes[index] = False
                weaker.append(
                    {"requiredLevel": parameters["requiredLevel"], "requiredAttributes": attributes}
                )
        return weaker


class EndToEndTests(unittest.TestCase):
    """Plan → generate → verify, plus the verifier over-disclosure warning."""

    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.client = HolderClient.from_seed(
            42, REGISTRY, StubBackend(), accumulator_provider=self.provider
        )
        self.credential = issue_kyc_credential(
            master_seed=42, credential_id=7, provider=self.provider, expires_at=2_000_000_000
        )
        self.client.store_credential(self.credential)
        self.accumulator_states = {
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                roots=self.provider.roots(TEST_ISSUER_ID),
            )
        }

    def make_verifier(self):
        from holder_fixtures import TEST_ISSUER_KEY_X, TEST_ISSUER_KEY_Y

        policy = VerifierTrustPolicy(
            issuers=(
                TrustedIssuer(
                    issuer_id=TEST_ISSUER_ID,
                    public_key_x=TEST_ISSUER_KEY_X,
                    public_key_y=TEST_ISSUER_KEY_Y,
                    proof_types=(KYC_PROOF_TYPE,),
                ),
            )
        )
        return ZKCVerifier(REPO_ROOT, policy, StubVerifyBackend())

    def test_planned_proof_verifies(self):
        planner = ProofPlanner(REGISTRY, POLICY)
        counter = planner.counter_offer(
            make_request(
                parameters={
                    KYC_PROOF_TYPE: {
                        "requiredLevel": 2,
                        "requiredAttributes": [True, True, False, False, False],
                    }
                }
            )
        )
        proof_request = counter.plan.to_proof_request(
            CONTEXT, TrustPolicy(issuers=(trusted_test_issuer(),))
        )
        envelope = generate_unauthenticated_linkable(self.client, proof_request)
        request = VerificationRequest(
            proof_types=list(counter.plan.proof_types),
            parameters={pt: dict(counter.plan.item(pt).parameters) for pt in counter.plan.proof_types},
            context=CONTEXT,
            accumulator_states=dict(self.accumulator_states),
        )
        result = self.make_verifier().verify(envelope, request)
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(result.warnings, [])

    def test_over_disclosure_warning_does_not_affect_validity(self):
        proof_request = make_request().to_dict()
        envelope = generate_unauthenticated_linkable(
            self.client, PlanReport.from_dict(
                ProofPlanner(REGISTRY, POLICY).plan(make_request()).to_dict()
            ).to_proof_request(CONTEXT, TrustPolicy(issuers=(trusted_test_issuer(),)))
        )
        del proof_request  # only the envelope matters below
        # Simulate a holder disclosing an EXTRA proof the request never asked for.
        inflated = copy.deepcopy(envelope)
        extra = copy.deepcopy(inflated["proofs"][0])
        extra["proofType"] = JURISDICTION_PROOF_TYPE
        inflated["proofs"].append(extra)
        request = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={KYC_PROOF_TYPE: dict(KYC_MINIMUM)},
            context=CONTEXT,
            accumulator_states=dict(self.accumulator_states),
        )
        result = self.make_verifier().verify(inflated, request)
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(result.warning_codes(), [Warn.OVER_DISCLOSURE])
        self.assertEqual(result.warnings[0].proof_type, JURISDICTION_PROOF_TYPE)
        self.assertIn("warnings", result.to_dict())


class DisclosureAuditTests(unittest.TestCase):
    """disclosure_warnings: the verifier audits ITS OWN requests + received
    envelopes against its published policy."""

    def test_request_beyond_published_minimums_warns(self):
        request = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 3,
                    "requiredAttributes": [True, True, False, False, False],
                }
            },
            context=CONTEXT,
        )
        warnings = disclosure_warnings(request, POLICY)
        self.assertEqual(
            {warning.code for warning in warnings}, {Warn.OVERBROAD_REQUEST}
        )
        self.assertEqual(len(warnings), 2)  # level + attributes

    def test_request_within_policy_is_clean(self):
        request = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={KYC_PROOF_TYPE: dict(KYC_MINIMUM)},
            context=CONTEXT,
        )
        self.assertEqual(disclosure_warnings(request, POLICY), [])

    def test_published_repo_policy_supports_planning(self):
        registry = DiscoveryRegistry.from_repo(REPO_ROOT)
        policy = registry.verifier_policy("did:zkc:verifier:example-exchange")
        self.assertIsNotNone(policy)
        requirements = policy.proof_requirements()
        self.assertIn(KYC_PROOF_TYPE, requirements)
        planner = ProofPlanner(REGISTRY, policy)
        counter = planner.counter_offer(
            NegotiationRequest.new(
                policy.verifier_id,
                (KYC_PROOF_TYPE,),
                {KYC_PROOF_TYPE: {"requiredLevel": 3, "requiredAttributes": [True] * 5}},
            )
        )
        self.assertEqual(counter.status, "counter")
        self.assertEqual(
            counter.plan.item(KYC_PROOF_TYPE).parameters,
            {
                "requiredLevel": requirements[KYC_PROOF_TYPE]["requiredLevel"],
                "requiredAttributes": requirements[KYC_PROOF_TYPE]["requiredAttributes"],
            },
        )


class PolicyValidationTests(unittest.TestCase):
    def test_proof_requirements_must_reference_accepted_types(self):
        with self.assertRaises(RegistryValidationError):
            make_policy_document(
                accepted=(JURISDICTION_PROOF_TYPE,),
                proof_requirements={KYC_PROOF_TYPE: {"requiredLevel": 1}},
            )

    def test_proof_requirements_reject_bad_level(self):
        with self.assertRaises(RegistryValidationError):
            make_policy_document(proof_requirements={KYC_PROOF_TYPE: {"requiredLevel": 0}})

    def test_proof_requirements_reject_non_boolean_attributes(self):
        with self.assertRaises(RegistryValidationError):
            make_policy_document(
                proof_requirements={KYC_PROOF_TYPE: {"requiredAttributes": [1, 0, 1]}}
            )


if __name__ == "__main__":
    unittest.main()
