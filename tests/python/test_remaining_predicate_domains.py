"""Host containment of frozen remaining-predicate truncating comparisons.

A matching transcript is essential: merely changing the request would also
fail the pre-existing binding check and would not test the integer domain.
Frozen circuit identities are not claimed to acquire range constraints.
"""

import copy
import unittest
from unittest import mock

import _path  # noqa: F401
from _inventory import IS_PUBLIC_SNAPSHOT
from predicate_fixtures import (
    TEST_ISSUER_ID, issue_accreditation_credential, issue_tax_credential,
    issue_sanctions_credential, trusted_predicate_issuer,
)
from test_request_binding import _build, _verifier, _HISTORICAL_OPT_IN
from zkc_crypto import (
    ANONYMOUS_PROFILE, LINKABLE_PROFILE, SCOPED_PROFILE, FIELD_MODULUS,
    ProofContext, compute_claim_binding_3, compute_claim_binding_4,
    derive_credential_binding_key, field_to_hex, sign_apr,
)
from zkc_crypto.stub import stub_proof_payload
from zkc_holder import (
    HolderClient, HolderError, ConstraintViolationError, LocalAccumulatorProvider,
    PredicateRegistry, ProofRequest, StubBackend, TrustPolicy,
)
from zkc_holder.client import _Presentation
from zkc_holder import predicates
from zkc_holder.backend import _CONSTRAINT_CHECKS
from zkc_verifier import VerificationRequest, VerificationResult, VerificationErrorCode as Code
from zkc_verifier.verifier import _REQUEST_BINDINGS
from zkc_issuer.schemas import get_schema
from zkc_issuer.errors import AdapterError


CONTEXT = ProofContext.verifier_session("verifier.example", 555, 1_700_000)
# The snapshot publishes generations 1–8; the private source also publishes 9.
# This expected inventory never depends on which files happen to exist.
REGISTERED_GENERATIONS = range(1, 9 if IS_PUBLIC_SNAPSHOT else 10)
BAD_LEVELS = (-1, 256, 258, 300, FIELD_MODULUS, True, "2", 2.0)
BAD_YEARS = (-1, 1 << 64, (1 << 64) + 2026, FIELD_MODULUS, False, "2026", 2026.0)


def domain_result(family, generation, value):
    """Exercise the shared request-binding gate with a MATCHING transcript."""
    proof_type = f"zkc:proof:{family}:v{generation}"
    selector = 1 if family == "accreditation" else 3
    params = {"required0": 0, "required1": 0, "setRoot": 0}
    params["required0" if selector == 1 else "required1"] = value
    # Non-integer aliases cannot be committed by strict host hashing; use a
    # canonical counterpart so their rejection must name the bad parameter.
    committed = dict(params)
    if type(value) is not int or not 0 <= value < FIELD_MODULUS:
        committed["required0" if selector == 1 else "required1"] = 0
    args = (selector, committed["required0"], committed["required1"])
    claim_binding = (
        compute_claim_binding_3(*args, CONTEXT.value, CONTEXT.timestamp)
        if generation < 3 else
        compute_claim_binding_4(*args, False, CONTEXT.value, CONTEXT.timestamp)
    )
    verifier = _verifier()
    result = VerificationResult()
    verifier._verify_predicate_requirements(
        proof_type, _REQUEST_BINDINGS[proof_type].predicate,
        {"predicate_type": selector, "set_root": field_to_hex(0)},
        VerificationRequest([proof_type], {proof_type: params}, CONTEXT),
        claim_binding, result,
    )
    return result


class RemainingRequestDomainTests(unittest.TestCase):
    def test_every_generation_rejects_matching_out_of_domain_bindings(self):
        for family, values, key in (("accreditation", BAD_LEVELS, "required0"),
                                    ("tax", BAD_YEARS, "required1")):
            for generation in REGISTERED_GENERATIONS:
                for value in values:
                    with self.subTest(family=family, generation=generation, value=value):
                        result = domain_result(family, generation, value)
                        self.assertEqual([Code.REQUIREMENTS_NOT_MET], result.codes(), result.to_dict())
                        self.assertIn(key, result.errors[0].message)

    def test_inclusive_zero_and_maximum_controls_every_generation(self):
        for family, maximum in (("accreditation", 255), ("tax", (1 << 64) - 1)):
            for generation in REGISTERED_GENERATIONS:
                for value in (0, maximum):
                    with self.subTest(family=family, generation=generation, value=value):
                        result = domain_result(family, generation, value)
                        self.assertTrue(result.valid, result.to_dict())

    def test_authenticated_exchange_rejects_matching_attack_all_generations(self):
        for family, key, bad in (("accreditation", "required0", 258),
                                  ("tax", "required1", (1 << 64) + 2026)):
            for generation in REGISTERED_GENERATIONS:
                with self.subTest(family=family, generation=generation):
                    presentation = generation % 2 == 0 or generation == 9
                    envelope, request, _, params, _ = _build(
                        family, "v2" if presentation else "v1", credential_id=8800 + generation,
                    )
                    proof_type = f"zkc:proof:{family}:v{generation}"
                    circuit = "zkc_remaining_predicates" + (f"_v{generation}" if generation > 1 else "")
                    entry = envelope["proofs"][0]
                    entry["proofType"] = proof_type
                    request.proof_types = [proof_type]
                    request.parameters = {proof_type: copy.deepcopy(params)}
                    if generation < 3:
                        entry["publicInputs"]["claim_binding"] = field_to_hex(compute_claim_binding_3(
                            1 if family == "accreditation" else 3, params["required0"], params["required1"],
                            CONTEXT.value, CONTEXT.timestamp,
                        ))
                    entry["proof"] = stub_proof_payload(circuit, entry["publicInputs"])
                    profile = ANONYMOUS_PROFILE if presentation else LINKABLE_PROFILE
                    def verify(nonce):
                        apr = sign_apr({
                            "request": {"proofTypes": [proof_type], "parameters": request.parameters,
                                        "context": {"profile": CONTEXT.profile,
                                                    "verifierId": "verifier.example", "sessionId": field_to_hex(555),
                                                    "timestamp": CONTEXT.timestamp},
                                        "trustPolicy": {"issuers": []}, "presentation": {"profile": profile}},
                            "verifierId": "verifier.example", "nonce": field_to_hex(nonce),
                            "issuedAt": CONTEXT.timestamp, "expiresAt": CONTEXT.timestamp + 3600,
                        }, 0xA9701)
                        return _verifier(proof_types=(proof_type,), accepted_review_statuses=_HISTORICAL_OPT_IN).verify_authenticated(
                            apr, envelope, request, now=CONTEXT.timestamp,
                        )
                    control = verify(9000 + generation)
                    self.assertTrue(control.valid, control.to_dict())
                    request.parameters[proof_type][key] = bad
                    p = request.parameters[proof_type]
                    args = (1 if family == "accreditation" else 3, p["required0"], p["required1"])
                    binding = (compute_claim_binding_3(*args, CONTEXT.value, CONTEXT.timestamp)
                               if generation < 3 else compute_claim_binding_4(*args, False, CONTEXT.value, CONTEXT.timestamp))
                    entry["publicInputs"]["claim_binding"] = field_to_hex(binding)
                    entry["proof"] = stub_proof_payload(circuit, entry["publicInputs"])
                    attack = verify(10000 + generation)
                    self.assertIn(Code.REQUIREMENTS_NOT_MET, attack.codes(), attack.to_dict())
                    self.assertTrue(any(key in error.message for error in attack.errors), attack.to_dict())

    def test_holder_refuses_before_resolution_selection_or_proving(self):
        for family, values in (("accreditation", BAD_LEVELS), ("tax", BAD_YEARS)):
            for generation in range(1, 10):
                for profile in (None, ANONYMOUS_PROFILE, SCOPED_PROFILE):
                    for value in values:
                        with self.subTest(family=family, generation=generation, profile=profile, value=value):
                            backend = mock.Mock(spec=StubBackend)
                            registry = mock.Mock(spec=PredicateRegistry)
                            holder = HolderClient.from_seed(4242, registry, backend)
                            proof_type = f"zkc:proof:{family}:v{generation}"
                            key = "required0" if family == "accreditation" else "required1"
                            request = ProofRequest([proof_type], {proof_type: {key: value}}, CONTEXT, TrustPolicy(issuers=()))
                            with self.assertRaisesRegex(HolderError, key):
                                holder._generate_envelope(request, _Presentation(
                                    profile or LINKABLE_PROFILE,
                                    123 if profile == SCOPED_PROFILE else 0,
                                ))
                            registry.resolve.assert_not_called()
                            backend.prove.assert_not_called()


class RemainingClaimDomainTests(unittest.TestCase):
    def test_all_witness_builders_and_backend_guards_reject_wide_claims(self):
        for generation in range(1, 10):
            builder = getattr(predicates, "build_profile_witness" + (f"_v{generation}" if 1 < generation < 9 else "_v8" if generation == 9 else ""))
            circuit = "zkc_remaining_predicates" + (f"_v{generation}" if generation > 1 else "")
            for issue, selector, slot, bad in (
                (issue_accreditation_credential, 1, "claim0", 256),
                (issue_tax_credential, 3, "claim1", 1 << 64),
                (issue_sanctions_credential, 4, "claim0", 65536),
            ):
                with self.subTest(generation=generation, selector=selector):
                    provider = LocalAccumulatorProvider()
                    credential = issue(master_seed=4242, credential_id=900, provider=provider)
                    kwargs = dict(predicate_type=selector, credential_binding_key=derive_credential_binding_key(4242),
                                  credential=credential, issuer=trusted_predicate_issuer(),
                                  witness=provider.witness(TEST_ISSUER_ID, 900), required_0=0, required_1=0,
                                  flag_required=False, set_root=0, path_index=0, siblings=[0]*32,
                                  predecessor_code=0, predecessor_path_index=0, predecessor_siblings=[0]*32,
                                  successor_code=65535, successor_path_index=1, successor_siblings=[0]*32,
                                  proof_context=CONTEXT.value, timestamp=CONTEXT.timestamp, current_epoch=1)
                    witness = builder(**kwargs)
                    witness["claim_0" if slot == "claim0" else "claim_1"] = bad
                    with self.assertRaisesRegex(ConstraintViolationError, "claim_[01].*u"):
                        _CONSTRAINT_CHECKS[circuit](witness)
                    credential.claims[slot] = bad
                    with self.assertRaisesRegex(ConstraintViolationError, "claim_[01].*u"):
                        builder(**kwargs)

    def test_direct_builder_and_backend_refuse_request_aliases(self):
        provider = LocalAccumulatorProvider()
        credential = issue_accreditation_credential(
            master_seed=4242, credential_id=901, provider=provider,
        )
        kwargs = dict(
            predicate_type=1, credential_binding_key=derive_credential_binding_key(4242),
            credential=credential, issuer=trusted_predicate_issuer(),
            witness=provider.witness(TEST_ISSUER_ID, 901), required_0=2, required_1=0,
            flag_required=False, set_root=0, path_index=0, siblings=[0] * 32,
            predecessor_code=0, predecessor_path_index=0, predecessor_siblings=[0] * 32,
            successor_code=0, successor_path_index=0, successor_siblings=[0] * 32,
            proof_context=CONTEXT.value, timestamp=CONTEXT.timestamp, current_epoch=1,
        )
        control = predicates.build_profile_witness_v7(**kwargs)
        _CONSTRAINT_CHECKS["zkc_remaining_predicates_v7"](control)
        for bad in BAD_LEVELS:
            with self.subTest(value=bad):
                with self.assertRaisesRegex(ConstraintViolationError, "required0"):
                    predicates.build_profile_witness_v7(**{**kwargs, "required_0": bad})
                with self.assertRaisesRegex(ConstraintViolationError, "required0"):
                    StubBackend().prove("zkc_remaining_predicates_v7", {**control, "required_0": bad})

    def test_reference_issuers_enforce_the_same_domains(self):
        for name, key, bad, claims in (
            ("accreditation", "accreditationLevel", 256, {"institutional": False}),
            ("tax", "taxYear", 1 << 64, {"taxResidencyCode": 840}),
            ("sanctions", "screeningCode", 65536, {}),
        ):
            schema = get_schema(f"zkc:cred:{name}:v2")
            values = {**claims, "validFrom": 1000, "validUntil": 2000, key: bad}
            with self.subTest(name=name), self.assertRaises(AdapterError):
                schema.normalize_claims(values)


if __name__ == "__main__":
    unittest.main()
