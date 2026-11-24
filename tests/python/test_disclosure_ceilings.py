"""Typed disclosure ceilings (security review 2026-10-04, R3.6).

The planner compared consent-ceiling VALUES only for KYC ``requiredLevel`` /
``requiredAttributes``; for every other parameter it checked key presence,
so the agent's hard ceiling failed open for accreditation, source, tax,
sanctions and jurisdiction. The review PoC: ceiling
``accreditation:v7 required0 = 100000``, request ``required0 = 10000000000``
was planned unchanged. These tests pin:

* coverage: every proof type the repository's encoders declare has a typed
  comparator with a rule for every key of its closed request-parameter set,
  or its family is explicitly refused under a ceiling;
* the PoC request is refused as ``beyond_consent`` (planner and agent);
* a table over every proof type with a comparator: a more-disclosing value is
  refused, an equal or less-disclosing value is accepted, pinned values must
  match, threshold values outside the circuit's unsigned domain are refused,
  and a proof type with no comparator is refused under a ceiling;
* planning against a non-KYC published minimum keeps that predicate's
  parameters (it used to return a KYC-shaped object), and counter-offer
  evaluation and the verifier audit accept an honest request for every family;
* set predicates: an inclusion proof whose witness the request fixes is an
  exact-member disclosure (review probe F1), refused under a ceiling unless
  the principal opts in; narrow sets and shipped inclusion paths warn;
* published minimums state only governed, well-formed keys.
"""

import copy
import unittest

from _path import REPO_ROOT
from _inventory import IS_PUBLIC_SNAPSHOT

from holder_fixtures import (
    DRAFT_OPT_IN_REVIEW_STATUSES,
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
)
from zkc_crypto import LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES, ProofContext, field_to_hex
from zkc_crypto.presentation import ANONYMOUS_PROFILE, LINKABLE_PROFILE, SCOPED_PROFILE
from zkc_crypto.request_parameters import REQUEST_ONLY_PARAMETERS, circuit_family
from zkc_holder import NegotiationRequest, OverbroadRequestError, PredicateRegistry, ProofPlanner
from zkc_holder.ceilings import (
    CANONICAL_SET,
    CEILING_COMPARATORS,
    EXACT_MEMBER,
    EXACT_MEMBER_OPT_IN,
    FLAG,
    FLAG_VECTOR,
    NARROW_SET_THRESHOLD,
    PINNED,
    REFUSED_UNDER_CEILING,
    SET_DETERMINED,
    SET_UNKNOWN,
    SUBSET,
    THRESHOLD,
    WITNESS_PATH,
    comparator_for,
    compare_parameters,
    set_disclosure,
)
from zkc_holder.planner import PlanReport, evaluate_counter_offer
from zkc_holder.predicates import request_contract_proof_types
from zkc_registry import RegistryValidationError
from zkc_registry.encoder_resolution import encoder_circuits
from zkc_registry.store import _policy_from_document, validate_verifier_policy
from zkc_verifier import VerificationRequest, disclosure_warnings
from zkc_verifier import VerificationWarningCode as Warn
from zkc_crypto.code_spaces import CODE_SPACES, CODE_SPACE_PROOF_TO_KIND

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
CIRCUITS, CIRCUIT_ERRORS = encoder_circuits(REPO_ROOT)
CONTRACTS, CONTRACT_ERRORS = REGISTRY.request_parameter_contracts()
ALL_STATUSES = DRAFT_OPT_IN_REVIEW_STATUSES + ("deprecated",)
PROFILES = (LINKABLE_PROFILE, ANONYMOUS_PROFILE, SCOPED_PROFILE)
VERIFIER_ID = "did:zkc:verifier:ceiling-test"

POC_PROOF_TYPE = "zkc:proof:accreditation:v7"
POC_CEILING = {POC_PROOF_TYPE: {"required0": 100_000, "required1": 0, "flagRequired": False}}
CANONICAL_CODES = [10, 20, 30, 40, 50, 60]
CONTEXT = ProofContext.verifier_session(VERIFIER_ID, 555, 1_700_000_000)
JURISDICTION = "zkc:proof:jurisdiction:v3"
SOURCE = "zkc:proof:source:v8"
TAX = "zkc:proof:tax:v8"
VERIFIER_PATH = {"membershipPathIndex": 5, "membershipSiblings": [0] * 32}
LAYOUT_ID = field_to_hex(1)


def make_policy(accepted, proof_requirements=None, verifier_id=VERIFIER_ID):
    document = {
        "version": "zkc:registry:verifier-policy:v1",
        "verifierId": verifier_id,
        "displayName": "Ceiling Test Verifier",
        "acceptedProofTypes": list(accepted),
        "requiredReviewStatuses": ["reviewed"],
        "trustedIssuers": [
            {
                "issuerId": TEST_ISSUER_ID,
                "publicKeyX": "0x" + TEST_ISSUER_KEY_X.hex(),
                "publicKeyY": "0x" + TEST_ISSUER_KEY_Y.hex(),
                "proofTypes": list(accepted),
            }
        ],
        "acceptsOutOfRegistryIssuers": True,
        "requiredContextProfile": "",
        "maxEpochLag": 10,
        "updatedAt": "2026-06-11T00:00:00Z",
    }
    if LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES.intersection(accepted):
        document["trustedIssuers"][0]["attributeLayoutId"] = LAYOUT_ID
    if proof_requirements is not None:
        document["proofRequirements"] = proof_requirements
    validate_verifier_policy(document, "<test>")
    return _policy_from_document(document, "<test>")


def planner_for(proof_type, requirements=None):
    return ProofPlanner(
        REGISTRY, make_policy([proof_type], requirements), accepted_review_statuses=ALL_STATUSES
    )


def plan(proof_type, parameters, ceiling=None, requirements=None):
    request = NegotiationRequest.new(VERIFIER_ID, [proof_type], {proof_type: parameters})
    return planner_for(proof_type, requirements).plan(
        request, consent_scope=None if ceiling is None else {proof_type: ceiling}
    )


def refused_elements(test, proof_type, parameters, ceiling):
    with test.assertRaises(OverbroadRequestError) as caught:
        plan(proof_type, parameters, ceiling)
    return caught.exception.elements


def governed_keys(proof_type):
    """Keys the holder admits for this request under every emitted identity."""
    keys = None
    for identity in request_contract_proof_types(proof_type, PROFILES):
        contract = CONTRACTS.get(identity, frozenset())
        keys = set(contract) if keys is None else keys & contract
    return keys or set()


def sample(key, rule):
    """A ceiling value for one rule (equal requests must plan)."""
    if rule.kind == THRESHOLD:
        return 5
    if rule.kind == FLAG:
        return True
    if rule.kind == FLAG_VECTOR:
        return [True, False, True, False, False][: rule.length]
    if rule.kind == SUBSET:
        return [0, 2]
    if rule.kind == CANONICAL_SET:
        return list(CANONICAL_CODES)
    if rule.default is not None:
        return copy.deepcopy(rule.default)
    if key == "membershipType":
        return 0
    if key == "requiredClaimType":
        return 1
    if key == "layoutId":
        return LAYOUT_ID
    return 12345


def base_request(proof_type):
    comparator = comparator_for(proof_type, CIRCUITS[proof_type])
    keys = governed_keys(proof_type)
    request = {
        key: sample(key, rule)
        for key, rule in comparator.rules.items()
        if key in keys and rule.kind != WITNESS_PATH
    }
    kind = CODE_SPACE_PROOF_TO_KIND.get(proof_type)
    if kind is not None:
        space = next(space for space in CODE_SPACES.values() if space.kind == kind)
        request["codeSpaceId"] = space.id
        codes_key = comparator.set_semantics.canonical_key
        request[codes_key] = list(space.codes.values())[: 1 if kind == "sanctions" else 2]
        if kind == "jurisdiction":
            request["requiredVerificationMethod"] = 1
    return request


def base_ceiling(proof_type):
    """The request itself, plus the exact-member opt-in where the protocol
    gives the holder no canonical list (source of funds, tax residency)."""
    ceiling = base_request(proof_type)
    _warnings, outcome = set_disclosure(proof_type, ceiling, circuit=CIRCUITS[proof_type])
    if outcome == EXACT_MEMBER:
        ceiling[EXACT_MEMBER_OPT_IN] = True
    return ceiling


def plannable(proof_type):
    """Proof types the planner can resolve and whose comparator exists."""
    if comparator_for(proof_type, CIRCUITS[proof_type]) is None:
        return False
    return REGISTRY.resolve(proof_type, accepted_statuses=ALL_STATUSES) is not None


def kinds(warnings):
    return sorted(warning["kind"] for warning in warnings)


class ComparatorCoverageTests(unittest.TestCase):
    """Every proof type the holder can emit is covered or explicitly refused."""

    def test_encoders_resolve(self):
        self.assertEqual(CIRCUIT_ERRORS, ())
        self.assertEqual(CONTRACT_ERRORS, {})
        self.assertTrue(CIRCUITS)

    def test_every_proof_type_has_a_comparator_or_is_refused(self):
        for proof_type, circuit in sorted(CIRCUITS.items()):
            with self.subTest(proof_type=proof_type):
                family = circuit_family(circuit)
                comparator = comparator_for(proof_type, circuit)
                if family in REFUSED_UNDER_CEILING:
                    self.assertIsNone(comparator)
                    continue
                self.assertIsNotNone(comparator, f"{proof_type} ({circuit}) has no comparator")
                missing = set(CONTRACTS[proof_type]) - set(comparator.rules)
                self.assertFalse(missing, f"{proof_type}: no ceiling rule for {sorted(missing)}")

    def test_no_stale_rules_or_families(self):
        used_keys = {}
        used_families = set()
        for proof_type, circuit in CIRCUITS.items():
            used_families.add(circuit_family(circuit))
            comparator = comparator_for(proof_type, circuit)
            if comparator is not None:
                used_keys.setdefault(id(comparator), (comparator, set()))[1].update(
                    CONTRACTS[proof_type]
                )
        for comparator, keys in used_keys.values():
            with self.subTest(family=comparator.family, meaning=comparator.meaning):
                self.assertEqual(set(comparator.rules) - keys, set())
        registered_families = set(CEILING_COMPARATORS) | set(REFUSED_UNDER_CEILING)
        # The public snapshot retains runtime support for the unpublished
        # community successor but exports no encoder from that circuit family.
        unpublished_families = {"zkc_community_kyc"} if IS_PUBLIC_SNAPSHOT else set()
        self.assertEqual(registered_families - used_families, unpublished_families)
        self.assertLessEqual(used_families, registered_families)
        self.assertFalse(set(CEILING_COMPARATORS) & set(REFUSED_UNDER_CEILING))
        self.assertLessEqual(
            set(REQUEST_ONLY_PARAMETERS), set(CEILING_COMPARATORS) | set(REFUSED_UNDER_CEILING)
        )

    def test_meaning_lookup_agrees_with_the_encoder_circuit(self):
        """Callers without a registry (verifier audit, counter-offer
        evaluation) select by proof type alone: never a looser comparator."""
        for proof_type, circuit in sorted(CIRCUITS.items()):
            with self.subTest(proof_type=proof_type):
                by_meaning = comparator_for(proof_type)
                by_circuit = comparator_for(proof_type, circuit)
                if proof_type.split(":")[2] in ("credential_rebind", "rebind"):
                    # Rebind meanings span authenticated and unauthenticated
                    # generations: the meaning-level comparator pins every key
                    # any generation accepts and orders none.
                    self.assertLessEqual(set(CONTRACTS[proof_type]), set(by_meaning.rules))
                    self.assertEqual({rule.kind for rule in by_meaning.rules.values()}, {PINNED})
                elif by_meaning is not None:
                    self.assertIs(by_meaning, by_circuit)
        # A circuit from another family never selects a comparator.
        self.assertIsNone(comparator_for(POC_PROOF_TYPE, "zkc_kyc_v2"))
        self.assertIsNone(comparator_for("zkc:proof:foo:v1", "zkc_kyc_v3"))
        self.assertIsNone(comparator_for("zkc:proof:kyc:v1", "zkc_community_kyc_v2"))
        self.assertIsNone(comparator_for("zkc:proof:rebind:v2", "zkc_credential_rebind_v2"))

    def test_witness_path_rules_are_only_paths(self):
        path_keys = {
            key
            for by_meaning in CEILING_COMPARATORS.values()
            for comparator in by_meaning.values()
            for key, rule in comparator.rules.items()
            if rule.kind == WITNESS_PATH
        }
        self.assertTrue(
            all(
                key.endswith(("PathIndex", "Siblings", "Code")) or key in ("pathIndex", "siblings")
                for key in path_keys
            ),
            sorted(path_keys),
        )

    def test_threshold_rules_state_their_circuit_domain(self):
        bits = {
            (comparator.family, comparator.meaning, key): rule.bits
            for by_meaning in CEILING_COMPARATORS.values()
            for comparator in by_meaning.values()
            for key, rule in comparator.rules.items()
            if rule.kind == THRESHOLD
        }
        self.assertEqual(
            bits,
            {
                ("zkc_kyc", "*", "requiredLevel"): 8,
                ("zkc_community_kyc", "*", "requiredLevel"): 8,
                ("zkc_remaining_predicates", "accreditation", "required0"): 8,
                ("zkc_remaining_predicates", "tax", "required1"): 64,
            },
        )


class PocRegressionTests(unittest.TestCase):
    """lane5/poc_planner_ceiling.py, accreditation:v7 (self_attested)."""

    def planner(self):
        return ProofPlanner(REGISTRY, make_policy([POC_PROOF_TYPE]))

    def request(self, required0):
        return NegotiationRequest.new(
            VERIFIER_ID,
            [POC_PROOF_TYPE],
            {POC_PROOF_TYPE: {"required0": required0, "required1": 0, "flagRequired": False}},
        )

    def test_request_above_ceiling_is_beyond_consent(self):
        with self.assertRaises(OverbroadRequestError) as caught:
            self.planner().plan(self.request(10_000_000_000), consent_scope=POC_CEILING)
        (element,) = caught.exception.elements
        self.assertEqual(element["kind"], "beyond_consent")
        self.assertEqual(element["element"], "required0")
        self.assertEqual(element["requested"], 10_000_000_000)
        counter = self.planner().counter_offer(
            self.request(10_000_000_000), consent_scope=POC_CEILING
        )
        self.assertEqual(counter.status, "refusal")
        self.assertEqual(counter.refusal_elements[0]["kind"], "beyond_consent")

    def test_request_within_ceiling_is_planned(self):
        ceiling = {POC_PROOF_TYPE: {"required0": 200, "required1": 0, "flagRequired": False}}
        report = self.planner().plan(self.request(200), consent_scope=ceiling)
        self.assertEqual(report.item(POC_PROOF_TYPE).parameters["required0"], 200)
        with self.assertRaises(OverbroadRequestError):
            self.planner().plan(self.request(201), consent_scope=ceiling)

    def test_out_of_domain_threshold_is_refused(self):
        """The circuit casts required0 to u8: -253 would be compared as 3."""
        ceiling = {POC_PROOF_TYPE: {"required0": 1, "required1": 0, "flagRequired": False}}
        for asked in (-253, 256, 1 << 254):
            with self.subTest(asked=asked), self.assertRaises(OverbroadRequestError):
                self.planner().plan(self.request(asked), consent_scope=ceiling)
        # The PoC's own ceiling (100000) is outside u8, so even an equal
        # request is refused: the bound itself is malformed.
        with self.assertRaises(OverbroadRequestError):
            self.planner().plan(self.request(100_000), consent_scope=POC_CEILING)


_ABSENT = object()


class TypedCeilingTableTests(unittest.TestCase):
    """For every proof type with a comparator, at the planner."""

    def test_table_over_every_proof_type(self):
        covered = [proof_type for proof_type in sorted(CIRCUITS) if plannable(proof_type)]
        self.assertGreater(len(covered), 40)
        for proof_type in covered:
            comparator = comparator_for(proof_type, CIRCUITS[proof_type])
            request0 = base_request(proof_type)
            ceiling = base_ceiling(proof_type)
            keys = governed_keys(proof_type)
            with self.subTest(proof_type=proof_type, case="equal"):
                report = plan(proof_type, copy.deepcopy(request0), ceiling)
                self.assertEqual(report.item(proof_type).parameters, request0)
            for key, rule in comparator.rules.items():
                if key not in keys:
                    continue
                for case, asked, limit, accepted in self._cases(key, rule, ceiling):
                    with self.subTest(proof_type=proof_type, key=key, case=case):
                        request = dict(request0)
                        if asked is _ABSENT:
                            request.pop(key, None)
                        else:
                            request[key] = asked
                        bound = dict(ceiling, **{key: limit})
                        if accepted:
                            plan(proof_type, request, bound)
                        else:
                            elements = refused_elements(self, proof_type, request, bound)
                            self.assertEqual(
                                {(e["element"], e["kind"]) for e in elements},
                                {(key, "beyond_consent")},
                            )

    @staticmethod
    def _cases(key, rule, ceiling):
        value = ceiling.get(key)
        if rule.kind == THRESHOLD:
            return [
                ("more", value + 1, value, False),
                ("less", value - 1, value, True),
                ("bool alias", True, 1, False),
                ("negative", -1, value, False),
                ("beyond domain", 1 << rule.bits, value, False),
            ]
        if rule.kind == FLAG:
            return [("more", True, False, False), ("less", False, True, True)]
        if rule.kind == FLAG_VECTOR:
            return [
                ("more", [True] * rule.length, value, False),
                ("less", [False] * rule.length, value, True),
                ("short", [True], value, False),
            ]
        if rule.kind == SUBSET:
            return [("more", [0, 1], value, False), ("less", [2], value, True)]
        if rule.kind == PINNED:
            other = (value + 1) if type(value) is int else (not value)
            return [("mismatch", other, value, False)]
        if rule.kind == CANONICAL_SET:
            # Without the list the holder cannot derive its own witness: an
            # inclusion set becomes exact-member, an exclusion set unknown.
            return [
                ("superset", value + [70], value, False),
                ("subset", value[1:], value, False),
                ("same set", list(reversed(value)) + value[:1], value, True),
                ("absent: no holder-derived witness", _ABSENT, value, False),
            ]
        if rule.kind == WITNESS_PATH:
            return [("path value is not compared", 7 if "Index" in key or "Code" in key else [], None, True)]
        raise AssertionError(rule.kind)

    def test_pinned_absent_from_ceiling_is_refused(self):
        """A ceiling that does not state a pinned set root consents to none."""
        ceiling = base_ceiling(SOURCE)
        del ceiling["setRoot"]
        elements = refused_elements(self, SOURCE, base_request(SOURCE), ceiling)
        self.assertEqual([e["element"] for e in elements], ["setRoot"])

    def test_proof_type_without_comparator_is_refused_under_ceiling(self):
        for proof_type, circuit in sorted(CIRCUITS.items()):
            if comparator_for(proof_type, circuit) is not None:
                continue
            if REGISTRY.resolve(proof_type, accepted_statuses=ALL_STATUSES) is None:
                continue
            with self.subTest(proof_type=proof_type):
                elements = refused_elements(self, proof_type, {}, {})
                self.assertEqual(
                    [(e["element"], e["kind"]) for e in elements],
                    [("proofType", "beyond_consent")],
                )

    def test_comparator_refuses_unknown_proof_type(self):
        narrowable, hard = compare_parameters("zkc:proof:secret-scoring:v1", {}, {})
        self.assertEqual(narrowable, [])
        self.assertEqual([e["kind"] for e in hard], ["unknown_parameter"])


class NonKycMinimumTests(unittest.TestCase):
    """_narrow_parameters used to return a KYC-shaped object for any type."""

    def test_accreditation_minimum_keeps_its_parameters(self):
        minimum = {"required0": 2, "flagRequired": False}
        report = ProofPlanner(
            REGISTRY, make_policy([POC_PROOF_TYPE], {POC_PROOF_TYPE: minimum})
        ).counter_offer(
            NegotiationRequest.new(
                VERIFIER_ID,
                [POC_PROOF_TYPE],
                {POC_PROOF_TYPE: {"required0": 4, "required1": 0, "flagRequired": True}},
            )
        )
        self.assertEqual(report.status, "counter")
        parameters = report.plan.item(POC_PROOF_TYPE).parameters
        self.assertEqual(parameters, {"required0": 2, "required1": 0, "flagRequired": False})
        self.assertNotIn("requiredLevel", parameters)
        self.assertEqual(
            {(e["element"], e["kind"]) for e in report.plan.narrowed},
            {("required0", "parameter_exceeds_policy"), ("flagRequired", "parameter_exceeds_policy")},
        )
        clauses = {e["element"] for e in report.plan.item(POC_PROOF_TYPE).justification}
        self.assertEqual(clauses, {"required0", "required1", "flagRequired"})
        policy = make_policy([POC_PROOF_TYPE], {POC_PROOF_TYPE: minimum})
        self.assertEqual(evaluate_counter_offer(policy, report).status, "accept")

    def test_tax_minimum_keeps_root_and_paths(self):
        minimum = {"required1": 2020, "setRoot": 12345}
        request = {"required1": 2025, "setRoot": 12345, "pathIndex": 3, "siblings": []}
        counter = ProofPlanner(REGISTRY, make_policy([TAX], {TAX: minimum})).counter_offer(
            NegotiationRequest.new(VERIFIER_ID, [TAX], {TAX: request})
        )
        self.assertEqual(counter.status, "counter")
        self.assertEqual(
            counter.plan.item(TAX).parameters,
            {"required1": 2020, "setRoot": 12345, "pathIndex": 3, "siblings": []},
        )

    def test_pinned_mismatch_with_minimum_is_not_narrowed(self):
        """Substituting the published root would plan a statement no ceiling
        check saw, so a root mismatch is a hard refusal."""
        counter = ProofPlanner(
            REGISTRY, make_policy([SOURCE], {SOURCE: {"setRoot": 1}})
        ).counter_offer(NegotiationRequest.new(VERIFIER_ID, [SOURCE], {SOURCE: {"setRoot": 2}}))
        self.assertEqual(counter.status, "refusal")
        self.assertEqual(counter.refusal_elements[0]["element"], "setRoot")

    def test_requested_list_is_accepted_when_the_minimum_states_only_the_root(self):
        minimum = {"membershipType": 0, "requiredClaimType": 1, "jurisdictionSetRoot": 12345}
        request = dict(minimum, jurisdictionCanonicalSet=list(CANONICAL_CODES))
        policy = make_policy([JURISDICTION], {JURISDICTION: minimum})
        counter = ProofPlanner(REGISTRY, policy).counter_offer(
            NegotiationRequest.new(VERIFIER_ID, [JURISDICTION], {JURISDICTION: request})
        )
        self.assertEqual(counter.status, "counter")
        self.assertEqual(counter.plan.item(JURISDICTION).parameters, request)
        self.assertEqual(evaluate_counter_offer(policy, counter).status, "accept")
        # Both sides state a list: they must agree.
        policy = make_policy(
            [JURISDICTION], {JURISDICTION: dict(minimum, jurisdictionCanonicalSet=[1, 2, 3, 4, 5])}
        )
        counter = ProofPlanner(REGISTRY, policy).counter_offer(
            NegotiationRequest.new(VERIFIER_ID, [JURISDICTION], {JURISDICTION: request})
        )
        self.assertEqual(counter.status, "refusal")

    def test_counter_offer_evaluation_rejects_non_kyc_shortfall(self):
        policy = make_policy([POC_PROOF_TYPE], {POC_PROOF_TYPE: {"required0": 3}})
        counter = ProofPlanner(REGISTRY, policy).counter_offer(
            NegotiationRequest.new(VERIFIER_ID, [POC_PROOF_TYPE], {POC_PROOF_TYPE: {"required0": 3}})
        )
        self.assertEqual(evaluate_counter_offer(policy, counter).status, "accept")
        lower = ProofPlanner(REGISTRY, policy).counter_offer(
            NegotiationRequest.new(VERIFIER_ID, [POC_PROOF_TYPE], {POC_PROOF_TYPE: {"required0": 1}})
        )
        self.assertEqual(evaluate_counter_offer(policy, lower).status, "reject")

    def test_honest_request_equal_to_minimum_for_every_family(self):
        """Review finding: rebind counters equal to the published minimum were
        rejected, and the verifier audit flagged its own honest request."""
        cases = {
            "zkc:proof:kyc:v1": {"requiredLevel": 2, "requiredAttributes": [True] + [False] * 4},
            "zkc:proof:community_kyc:v2": {
                "requiredLevel": 1,
                "requiredAttributes": [False] * 5,
            },
            "zkc:proof:selective_disclosure:v2": {"disclosedPositions": [0, 2], "layoutId": LAYOUT_ID},
            JURISDICTION: {
                "membershipType": 0,
                "requiredClaimType": 1,
                "jurisdictionSetRoot": 12345,
                "jurisdictionCanonicalSet": list(CANONICAL_CODES),
            },
            POC_PROOF_TYPE: {"required0": 3, "flagRequired": True},
            SOURCE: {"setRoot": 12345},
            TAX: {"required1": 2024, "setRoot": 12345},
            "zkc:proof:sanctions:v8": {"setRoot": 12345, "canonicalSet": [7, 8, 9]},
            "zkc:proof:credential_rebind:v3": {"credentialId": 11, "schemaIdHash": 22},
            "zkc:proof:rebind:v4": {"credentialId": 11, "schemaIdHash": 22},
        }
        if IS_PUBLIC_SNAPSHOT:
            # Preserve every published family, using its published identity.
            # Community's successor family has no public encoder.
            del cases["zkc:proof:community_kyc:v2"]
            cases["zkc:proof:selective_disclosure:v1"] = cases.pop(
                "zkc:proof:selective_disclosure:v2"
            )
        families = {
            circuit_family(CIRCUITS[proof_type])
            + (":" + proof_type.split(":")[2] if "remaining" in CIRCUITS[proof_type] else "")
            for proof_type in cases
        }
        expected = set()
        for family, by_meaning in CEILING_COMPARATORS.items():
            expected |= {
                family + ("" if meaning == "*" else ":" + meaning) for meaning in by_meaning
            }
        if IS_PUBLIC_SNAPSHOT:
            expected.remove("zkc_community_kyc")
        self.assertEqual(families, expected)
        for proof_type, parameters in cases.items():
            with self.subTest(proof_type=proof_type):
                policy = make_policy([proof_type], {proof_type: dict(parameters)})
                counter = ProofPlanner(
                    REGISTRY, policy, accepted_review_statuses=ALL_STATUSES
                ).counter_offer(
                    NegotiationRequest.new(VERIFIER_ID, [proof_type], {proof_type: dict(parameters)})
                )
                self.assertEqual(counter.status, "counter")
                self.assertEqual(evaluate_counter_offer(policy, counter).status, "accept")
                request = VerificationRequest(
                    proof_types=[proof_type], parameters={proof_type: dict(parameters)}, context=CONTEXT
                )
                self.assertEqual(disclosure_warnings(request, policy), [])

    def test_unauthenticated_rebind_is_still_refused_under_a_ceiling(self):
        for proof_type in ("zkc:proof:rebind:v2", "zkc:proof:credential_rebind:v1"):
            with self.subTest(proof_type=proof_type):
                elements = refused_elements(self, proof_type, {}, {"schemaIdHash": 1})
                self.assertEqual(
                    [(e["element"], e["kind"]) for e in elements], [("proofType", "beyond_consent")]
                )


class SetPredicateTests(unittest.TestCase):
    def jurisdiction(self, codes, membership_type=0, **extra):
        parameters = {
            "membershipType": membership_type,
            "requiredClaimType": 1,
            "jurisdictionSetRoot": 12345,
        }
        if codes is not None:
            parameters["jurisdictionCanonicalSet"] = codes
        parameters.update(extra)
        return parameters

    def test_probe_f1_verifier_path_is_exact_member(self):
        """Review probe F1: the ceiling lists six jurisdictions; the request
        carries the same root and a verifier path for ONE leaf. Only the holder
        whose code sits at that leaf can prove, so the answer reveals it."""
        ceiling = self.jurisdiction(list(CANONICAL_CODES))
        request = self.jurisdiction(None, **VERIFIER_PATH)
        elements = refused_elements(self, JURISDICTION, request, ceiling)
        self.assertEqual(
            {(e["element"], e["kind"]) for e in elements},
            {("membershipPathIndex", "beyond_consent")},
        )
        # The ceiling's list never sizes a set the holder does not prove over.
        warnings, outcome = set_disclosure(JURISDICTION, request)
        self.assertEqual(outcome, EXACT_MEMBER)
        self.assertEqual(kinds(warnings), ["narrow_set", "verifier_inclusion_path"])
        (narrow,) = [w for w in warnings if w["kind"] == "narrow_set"]
        self.assertEqual(narrow["anonymitySetSize"], 1)
        # The principal may opt in explicitly; the plan still warns.
        report = plan(JURISDICTION, request, dict(ceiling, **{EXACT_MEMBER_OPT_IN: True}))
        self.assertEqual(kinds(report.warnings), ["narrow_set", "verifier_inclusion_path"])

    def test_bare_root_without_path_is_exact_member(self):
        """Without a list or a path the holder proves along the default path:
        still one provable leaf."""
        bare = self.jurisdiction(None)
        self.assertEqual(set_disclosure(JURISDICTION, bare)[1], EXACT_MEMBER)
        refused_elements(self, JURISDICTION, bare, self.jurisdiction(list(CANONICAL_CODES)))

    def test_source_and_tax_are_exact_member(self):
        for proof_type in (SOURCE, TAX):
            for with_path in (False, True):
                with self.subTest(proof_type=proof_type, path=with_path):
                    request = base_request(proof_type)
                    if with_path:
                        request.update(pathIndex=3, siblings=[7] * 32)
                    ceiling = base_request(proof_type)
                    elements = refused_elements(self, proof_type, request, ceiling)
                    self.assertEqual({e["kind"] for e in elements}, {"beyond_consent"})
                    report = plan(proof_type, request, dict(ceiling, **{EXACT_MEMBER_OPT_IN: True}))
                    expected = ["narrow_set"] + (["verifier_inclusion_path"] if with_path else [])
                    self.assertEqual(kinds(report.warnings), expected)

    def test_opt_in_is_exact_true_only(self):
        request = base_request(SOURCE)
        for value in (1, "true", False, None):
            with self.subTest(value=value):
                refused_elements(self, SOURCE, request, dict(request, **{EXACT_MEMBER_OPT_IN: value}))
        # The key is ceiling-only: a request naming it is outside the closed
        # request vocabulary.
        with self.assertRaises(Exception):
            plan(SOURCE, dict(request, **{EXACT_MEMBER_OPT_IN: True}))

    def test_holder_derived_inclusion_is_sized_by_the_request_list(self):
        listed = self.jurisdiction([840], **VERIFIER_PATH)
        warnings, outcome = set_disclosure(JURISDICTION, listed)
        self.assertEqual(outcome, SET_DETERMINED)
        self.assertEqual(kinds(warnings), ["narrow_set", "verifier_inclusion_path"])
        # Under a ceiling pinning the same list: planned, still warned.
        report = plan(JURISDICTION, listed, self.jurisdiction([840]))
        self.assertEqual(kinds(report.warnings), ["narrow_set", "verifier_inclusion_path"])
        self.assertNotIn("warnings", report.to_dict())

    def test_threshold_boundary(self):
        below = list(range(1, NARROW_SET_THRESHOLD))
        self.assertEqual(kinds(plan(JURISDICTION, self.jurisdiction(below)).warnings), ["narrow_set"])
        at = list(range(1, NARROW_SET_THRESHOLD + 1))
        self.assertEqual(plan(JURISDICTION, self.jurisdiction(at)).warnings, ())

    def test_exclusion_without_a_list_is_unknown_and_refused(self):
        bare = self.jurisdiction(None, membership_type=1)
        self.assertEqual(set_disclosure(JURISDICTION, bare)[1], SET_UNKNOWN)
        elements = refused_elements(self, JURISDICTION, bare, copy.deepcopy(bare))
        self.assertEqual(
            [(e["element"], e["kind"]) for e in elements],
            [("jurisdictionCanonicalSet", "beyond_consent")],
        )

    def test_unknown_mode_is_refused(self):
        request = self.jurisdiction(list(CANONICAL_CODES), membership_type=2)
        self.assertEqual(set_disclosure(JURISDICTION, request)[1], SET_UNKNOWN)
        refused_elements(self, JURISDICTION, request, copy.deepcopy(request))

    def test_plan_round_trip_ignores_holder_local_warnings(self):
        report = plan(JURISDICTION, self.jurisdiction([840]))
        self.assertTrue(report.warnings)
        self.assertEqual(PlanReport.from_dict(report.to_dict()), report)

    def test_verifier_audit_flags_narrow_sets_and_shipped_paths(self):
        policy = make_policy([JURISDICTION])

        def audit(parameters):
            request = VerificationRequest(
                proof_types=[JURISDICTION], parameters={JURISDICTION: parameters}, context=CONTEXT
            )
            return [w.code for w in disclosure_warnings(request, policy)]

        self.assertEqual(audit(self.jurisdiction([840])), [Warn.OVERBROAD_REQUEST])
        self.assertEqual(audit(self.jurisdiction(None, **VERIFIER_PATH)), [Warn.OVERBROAD_REQUEST])
        self.assertEqual(audit(self.jurisdiction(list(CANONICAL_CODES))), [])
        source_policy = make_policy([SOURCE])
        request = VerificationRequest(
            proof_types=[SOURCE],
            parameters={SOURCE: {"setRoot": 1, "pathIndex": 0, "siblings": [0] * 32}},
            context=CONTEXT,
        )
        self.assertEqual(
            [w.code for w in disclosure_warnings(request, source_policy)], [Warn.OVERBROAD_REQUEST]
        )


class PublishedMinimumValidationTests(unittest.TestCase):
    def test_minimums_state_only_governed_well_formed_keys(self):
        bad = {
            "ungoverned key": (SOURCE, {"setRoot": 1, "rootHint": 2}),
            "witness path": (SOURCE, {"setRoot": 1, "pathIndex": 0}),
            "kyc short attributes": (KYC_PROOF_TYPE, {"requiredAttributes": [True, False, True]}),
            "kyc bool level": (KYC_PROOF_TYPE, {"requiredLevel": True}),
            "kyc level beyond u8": (KYC_PROOF_TYPE, {"requiredLevel": 256}),
            "accreditation negative": (POC_PROOF_TYPE, {"required0": -1}),
            "no comparator": ("zkc:proof:aggregation:v1", {}),
        }
        for case, (proof_type, minimum) in bad.items():
            with self.subTest(case=case), self.assertRaises(RegistryValidationError):
                make_policy([proof_type], {proof_type: minimum})
        make_policy([KYC_PROOF_TYPE], {KYC_PROOF_TYPE: {"requiredLevel": 255}})


if __name__ == "__main__":
    unittest.main()
