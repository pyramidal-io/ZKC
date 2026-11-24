"""Closed request-parameter vocabulary (security review 2026-10-04, R2.4).

The verifier read exact parameter names and defaulted absent ones, so a
misspelled key was ignored: on accreditation:v8 the request
``{'required0': 2, 'flagrequired': True}`` verified while
``{'required0': 2, 'flagRequired': True}`` did not, and the signed APR
carried the misspelling. Each proof type now accepts only its binding
sidecar's ``param:`` references plus the documented request-only keys
(spec 6.2.1). These tests pin:

* derivation: the closed sets come from the sidecars, cover every proof type
  the verifier dispatches, and a synthetic successor identity takes its set
  from its own sidecar;
* drift: every key the verifier reads is in the set, every key in the set is
  read by the verifier or is a documented holder-only input, every key the
  holder reads is in some set, and the specification table equals the code
  table;
* verifier: a table over every dispatched proof type rejects an unknown key
  with REQUIREMENTS_NOT_MET, and end-to-end ``verify()`` and
  ``verify_authenticated()`` reject it for every predicate family while the
  honest requests still verify (the PoC is the accreditation:v8 case);
* holder: ``generate_proof``, ``generate_authenticated_proof``, the planner
  and the agent refuse an unknown key before proving, and a secret key keeps
  its SECRET_IN_REQUEST precedence.
"""

import copy
import json
import pathlib
import re
import shutil
import tempfile
import types
import unittest
from unittest import mock

import _path  # noqa: F401  (sys.path side effect)
from _path import REPO_ROOT
from holder_fixtures import (
    generate_unauthenticated_linkable,
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    apr_verifier_identity,
    issue_kyc_credential,
    trusted_test_issuer,
)
from test_agent_compliance import (
    AgentTestBase,
    make_context as agent_context,
    make_request as agent_request,
)
from test_disclosure_planning import POLICY, make_request as planning_request
from predicate_fixtures import trusted_predicate_issuer
from test_request_binding import (
    _CASE_BUILDERS,
    _HISTORICAL_OPT_IN,
    _build,
    _context,
    _make_holder,
    _verifier,
    _verifier_session_context_fixture,
    APR_VERIFIER_PRIVATE_KEY,
    MASTER_SEED,
)
from zkc_agent import BLOCK_PLANNING_REFUSED
from zkc_crypto import field_to_hex, sign_apr
from zkc_crypto.code_spaces import CODE_SPACE_PROOF_TO_KIND
from zkc_crypto.encoders import PublicInputBindings
from zkc_crypto.presentation import ANONYMOUS_PROFILE, LINKABLE_PROFILE, SCOPED_PROFILE
from zkc_crypto.request_parameters import (
    ANY_MEANING,
    EXCLUSION_NEIGHBOUR_HINTS,
    INCLUSION_PATH_HINTS,
    JURISDICTION_INCLUSION_PATH_HINTS,
    REQUEST_ONLY_PARAMETERS,
    circuit_family,
    request_only_parameters,
    request_parameter_contracts,
)
from zkc_holder import (
    ConstraintViolationError,
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofPlanner,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_holder.client import _Presentation
from zkc_holder import registry as holder_registry
from zkc_holder.errors import CanonicalSetMismatchError, SecretInRequestError
from zkc_holder.predicates import request_contract_proof_types
from zkc_registry.encoder_resolution import encoder_circuits
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationErrorCode as Code,
    VerificationRequest,
    VerificationResult,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier.trust_policy import TrustedIssuer as VerifierTrustedIssuer
from zkc_verifier.verifier import (
    _BoolParam,
    _CanonicalSetRoot,
    _FixedBool,
    _FixedValue,
    _HANDLER_KYC,
    _HANDLER_PREDICATE,
    _HANDLER_REBIND,
    _HANDLER_REBIND_AUTH,
    _HANDLER_SELECTIVE_DISCLOSURE,
    _LEGACY_REBIND_PROOF_TYPES,
    _Param,
    _PublicComparison,
    _REQUEST_BINDINGS,
)

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
ENCODER_CIRCUITS, ENCODER_ERRORS = encoder_circuits(REPO_ROOT)
CONTRACTS, CONTRACT_ERRORS = request_parameter_contracts(REPO_ROOT, ENCODER_CIRCUITS)
# Every proof type the verifier dispatches AND can resolve in this tree. The
# public snapshot omits the draft beta.25 identities (their encoders are not
# exported), which the verifier then refuses earlier as UNKNOWN_PROOF_TYPE.
DISPATCHED = tuple(sorted(set(_REQUEST_BINDINGS) & set(ENCODER_CIRCUITS)))

# Keys a request may carry for the holder only; the verifier never reads them.
HOLDER_ONLY_KEYS = frozenset(
    INCLUSION_PATH_HINTS
    + JURISDICTION_INCLUSION_PATH_HINTS
    + EXCLUSION_NEIGHBOUR_HINTS
    + ("credentialId",)
)
FAMILY_PROOF_TYPES = {
    "jurisdiction": ("zkc:proof:jurisdiction:v3", "zkc:proof:jurisdiction:v4"),
    "accreditation": ("zkc:proof:accreditation:v7", "zkc:proof:accreditation:v8"),
    "source": ("zkc:proof:source:v7", "zkc:proof:source:v8"),
    "tax": ("zkc:proof:tax:v7", "zkc:proof:tax:v8"),
    "sanctions": ("zkc:proof:sanctions:v7", "zkc:proof:sanctions:v8"),
}
UNKNOWN = "zkcUndefinedRequirement"


def _misspellings(accepted):
    """Plausible operator mistakes for one closed set, none of them accepted."""
    candidates = {UNKNOWN, "institutionalRequired", "flagrequired"}
    for key in accepted:
        candidates.update((key.lower(), key + "s", key[:1].upper() + key[1:]))
    return sorted(candidate for candidate in candidates if candidate not in accepted)


def _verifier_read_keys(proof_type, verifier) -> set:
    """Every request key the verifier's step-4e contract for ``proof_type`` reads."""
    contract = _REQUEST_BINDINGS[proof_type]
    keys = set()

    def walk(source):
        if isinstance(source, (_Param, _BoolParam)):
            keys.add(source.key)
        elif isinstance(source, (_FixedValue, _FixedBool)):
            keys.add(source.request_key)
        elif isinstance(source, _CanonicalSetRoot):
            keys.update((source.codes_key, source.root_key))
            for nested in (source.claim_type_source, source.mode_source):
                if nested is not None:
                    walk(nested)
        elif isinstance(source, _PublicComparison):
            walk(source.source)

    if contract.handler == _HANDLER_PREDICATE:
        binding = contract.predicate
        for source in binding.claim_slots + binding.public_comparisons:
            walk(source)
        keys.update(binding.legacy_fail_closed_bools)
        keys.update(binding.unbindable)
    elif contract.handler == "code_space":
        keys.add("codeSpaceId")
        if CODE_SPACE_PROOF_TO_KIND[proof_type] == "jurisdiction":
            keys.update(("jurisdictionCanonicalSet", "jurisdictionSetRoot", "membershipType",
                         "requiredClaimType", "requiredVerificationMethod"))
        else:
            keys.update(("canonicalSet", "setRoot", "required0", "required1", "flagRequired"))
    elif contract.handler == _HANDLER_KYC:
        keys.update(("requiredLevel", "requiredAttributes"))
    elif contract.handler == _HANDLER_SELECTIVE_DISCLOSURE:
        keys.update(("disclosedPositions", "layoutId"))
    elif contract.handler == _HANDLER_REBIND and proof_type in _LEGACY_REBIND_PROOF_TYPES:
        keys.update(("issuerIdHash", "schemaIdHash"))
    elif contract.handler in (_HANDLER_REBIND, _HANDLER_REBIND_AUTH):
        keys.update(parameter for _name, parameter in verifier._conditional_pins_by_proof_type[proof_type])
    else:  # pragma: no cover - a new handler must teach this oracle its keys
        raise AssertionError(f"unknown handler {contract.handler!r} for {proof_type}")
    return keys


class ClosedKeyDerivationTests(unittest.TestCase):
    def test_every_encoder_proof_type_has_a_derived_contract(self):
        self.assertEqual(ENCODER_ERRORS, ())
        self.assertEqual(CONTRACT_ERRORS, {})
        self.assertEqual(set(CONTRACTS), set(ENCODER_CIRCUITS))
        self.assertTrue(CONTRACTS)

    def test_dispatch_table_is_covered_and_spans_every_family(self):
        verifier = _verifier()
        dispatched = DISPATCHED
        self.assertTrue(dispatched)
        for proof_type in dispatched:
            with self.subTest(proof_type=proof_type):
                self.assertIn(proof_type, verifier._request_parameter_keys)
        families = {circuit_family(ENCODER_CIRCUITS[proof_type]) for proof_type in dispatched}
        # Every dispatched family is documented; aggregation never dispatches.
        self.assertLessEqual(families, set(REQUEST_ONLY_PARAMETERS) - {"zkc_aggregation"})
        for family in ("zkc_kyc", "zkc_jurisdiction", "zkc_remaining_predicates",
                       "zkc_selective_disclosure", "zkc_credential_rebind",
                       "zkc_credential_rebind_auth"):
            self.assertIn(family, families)
        self.assertIn("zkc:proof:accreditation:v8", dispatched)  # the PoC identity

    def test_aggregation_identities_accept_no_parameters_and_are_never_dispatched(self):
        aggregates = sorted(
            proof_type for proof_type, circuit in ENCODER_CIRCUITS.items()
            if circuit_family(circuit) == "zkc_aggregation"
        )
        self.assertGreaterEqual(len(aggregates), 2)
        for proof_type in aggregates:
            with self.subTest(proof_type=proof_type):
                self.assertEqual(CONTRACTS[proof_type], frozenset())
                self.assertNotIn(proof_type, _REQUEST_BINDINGS)

    def test_contract_is_sidecar_references_plus_documented_request_only_keys(self):
        for proof_type, circuit in sorted(ENCODER_CIRCUITS.items()):
            with self.subTest(proof_type=proof_type):
                bindings = PublicInputBindings.for_circuit(REPO_ROOT, circuit)
                sidecar = bindings.request_parameters()
                request_only = request_only_parameters(
                    circuit, proof_type, multiplexed=bool(bindings.predicate_types)
                )
                self.assertEqual(CONTRACTS[proof_type], sidecar | request_only)

    def test_verifier_reads_only_contract_keys_and_contract_has_no_dead_keys(self):
        verifier = _verifier()
        for proof_type in DISPATCHED:
            with self.subTest(proof_type=proof_type):
                read = _verifier_read_keys(proof_type, verifier)
                accepted = verifier._request_parameter_keys[proof_type]
                self.assertLessEqual(read, accepted, "the verifier reads an undocumented key")
                self.assertLessEqual(
                    accepted - read, HOLDER_ONLY_KEYS,
                    "a closed-set key the verifier ignores must be a holder-only input",
                )

    def test_every_key_the_holder_reads_is_in_some_contract(self):
        union = frozenset().union(*CONTRACTS.values())
        pattern = re.compile(r"parameters(?:\.get\(|\[)\"([A-Za-z0-9_]+)\"")
        read = set()
        for module in ("client.py", "planner.py"):
            read.update(pattern.findall((REPO_ROOT / "python/zkc_holder" / module).read_text()))
        self.assertIn("credentialId", read)
        self.assertIn("predecessorSiblings", read)
        self.assertLessEqual(read, union)

    def test_specification_table_matches_the_code_table(self):
        spec = (REPO_ROOT / "docs/zkc_specification.md").read_text(encoding="utf-8")
        documented = [line for line in spec.splitlines() if re.match(r"^\| `zkc_[a-z0-9_]+` \| ", line)]
        expected = []
        for family, by_meaning in REQUEST_ONLY_PARAMETERS.items():
            for meaning, keys in by_meaning.items():
                expected.append(
                    f"| `{family}` | {'any' if meaning == ANY_MEANING else f'`{meaning}`'} | "
                    f"{', '.join(f'`{key}`' for key in sorted(keys)) or 'none'} |"
                )
        self.assertEqual(documented, expected)

    def test_successor_identity_derives_its_keys_from_its_own_sidecar(self):
        # Models a future additive generation (e.g. a v10 identity) from the
        # published v8 sidecar; no reference to unpublished identities.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "schemas/public-inputs").mkdir(parents=True)
            (root / "schemas/public-input-bindings").mkdir(parents=True)
            encoder = json.loads((REPO_ROOT / "schemas/public-inputs/zkc_remaining_predicates_v8.json").read_text())
            sidecar = json.loads(
                (REPO_ROOT / "schemas/public-input-bindings/zkc_remaining_predicates_v8.json").read_text()
            )
            successor = "zkc_remaining_predicates_v10"
            renamed = {name: name.replace(":v8", ":v10") for name in encoder["proofTypes"]}
            encoder["circuit"] = successor
            encoder["proofTypes"] = [renamed[name] for name in encoder["proofTypes"]]
            sidecar["circuit"] = successor
            sidecar["encoder"] = f"schemas/public-inputs/{successor}.json"
            sidecar["predicateTypes"] = {renamed[k]: v for k, v in sidecar["predicateTypes"].items()}
            (root / f"schemas/public-inputs/{successor}.json").write_text(json.dumps(encoder))
            sidecar_path = root / f"schemas/public-input-bindings/{successor}.json"
            sidecar_path.write_text(json.dumps(sidecar))
            circuits = {renamed[name]: successor for name in renamed}

            contracts, errors = request_parameter_contracts(root, circuits)
            self.assertEqual(errors, {})
            for v8, v10 in renamed.items():
                self.assertEqual(contracts[v10], CONTRACTS[v8])

            # A new requirement in the successor sidecar extends ITS set only.
            claim_binding = next(entry for entry in sidecar["bindings"] if entry["name"] == "claim_binding")
            claim_binding["from"].append("param:minimumTenure")
            sidecar_path.write_text(json.dumps(sidecar))
            contracts, errors = request_parameter_contracts(root, circuits)
            self.assertEqual(errors, {})
            for v8, v10 in renamed.items():
                self.assertEqual(contracts[v10], CONTRACTS[v8] | {"minimumTenure"})

            # A malformed reference fails closed: no set, an explicit error.
            claim_binding["from"].append("param:minimum.tenure")
            sidecar_path.write_text(json.dumps(sidecar))
            contracts, errors = request_parameter_contracts(root, circuits)
            self.assertEqual(contracts, {})
            self.assertEqual(set(errors), set(circuits))

    def test_missing_sidecar_is_unbound_at_the_verifier(self):
        verifier = _verifier()
        proof_type = "zkc:proof:accreditation:v8"
        verifier._request_parameter_keys = {
            key: value for key, value in verifier._request_parameter_keys.items() if key != proof_type
        }
        verifier._request_parameter_contract_errors = {proof_type: "sidecar unreadable"}
        result = VerificationResult()
        request = VerificationRequest([proof_type], {proof_type: {"required0": 2}}, _context())
        verifier._verify_type_specific_requirements(proof_type, {}, request, 0, 0, 0, result)
        self.assertEqual(result.codes(), [Code.UNBOUND_PROOF_TYPE], result.to_dict())


class VerifierUnknownKeyTableTests(unittest.TestCase):
    def test_chokepoint_rejects_an_unknown_key_for_every_dispatched_proof_type(self):
        verifier = _verifier()
        for proof_type in DISPATCHED:
            accepted = verifier._request_parameter_keys[proof_type]
            for unknown in _misspellings(accepted):
                with self.subTest(proof_type=proof_type, unknown=unknown):
                    parameters = {key: None for key in accepted}
                    parameters[unknown] = True
                    request = VerificationRequest([proof_type], {proof_type: parameters}, _context())
                    result = VerificationResult()
                    verifier._verify_type_specific_requirements(
                        proof_type, {}, request, 0, 0, 0, result
                    )
                    self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                    message = result.errors[0].message
                    self.assertIn(repr(unknown), message)
                    self.assertIn(proof_type, message)


def _authenticated(envelope, request, proof_type, profile, nonce):
    """verify_authenticated over an APR that signs exactly ``request``."""
    apr = sign_apr({
        "request": {
            "proofTypes": [proof_type],
            "parameters": copy.deepcopy(request.parameters),
            "context": _verifier_session_context_fixture(),
            "trustPolicy": {"issuers": []},
            "presentation": {"profile": profile},
        },
        "verifierId": "verifier.example",
        "nonce": field_to_hex(nonce),
        "issuedAt": request.context.timestamp,
        "expiresAt": request.context.timestamp + 3600,
    }, APR_VERIFIER_PRIVATE_KEY)
    return _verifier(
        proof_types=(proof_type,), accepted_review_statuses=_HISTORICAL_OPT_IN
    ).verify_authenticated(apr, envelope, request, now=request.context.timestamp)


class VerifierEndToEndTests(unittest.TestCase):
    """Honest envelopes for every predicate family, v1 and v2 envelopes."""

    def test_verify_and_verify_authenticated_reject_unknown_keys_per_family(self):
        nonce = 0x5100
        for index, family in enumerate(FAMILY_PROOF_TYPES):
            for version, profile in (("v1", LINKABLE_PROFILE), ("v2", ANONYMOUS_PROFILE)):
                if REGISTRY.resolve(FAMILY_PROOF_TYPES[family][0]) is None:
                    # The public snapshot omits some registry entries; the
                    # chokepoint table above still covers these proof types.
                    continue
                envelope, request, proof_type, params, _provider = _build(
                    family, version, credential_id=7100 + 2 * index + (version == "v2"),
                )
                self.assertIn(proof_type, FAMILY_PROOF_TYPES[family])
                verifier = _verifier(proof_types=(proof_type,))
                with self.subTest(family=family, version=version, control="honest"):
                    self.assertTrue(verifier.verify(envelope, request).valid)
                    nonce += 1
                    control = _authenticated(envelope, request, proof_type, profile, nonce)
                    self.assertTrue(control.valid, control.to_dict())
                for unknown in ("flagrequired", "institutionalRequired", UNKNOWN):
                    with self.subTest(family=family, version=version, unknown=unknown):
                        attack = copy.deepcopy(request)
                        attack.parameters[proof_type][unknown] = True
                        for result in (
                            verifier.verify(envelope, attack),
                            _authenticated(envelope, attack, proof_type, profile, nonce := nonce + 1),
                        ):
                            self.assertFalse(result.valid)
                            self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                            self.assertIn(repr(unknown), result.errors[0].message)
                            self.assertIn(proof_type, result.errors[0].message)

    def test_security_review_poc_accreditation_v8(self):
        """R2.4 PoC: a misspelled optional key used to verify as VALID."""
        envelope, request, proof_type, _params, _provider = _build(
            "accreditation", "v2", credential_id=7300,
        )
        self.assertEqual(proof_type, "zkc:proof:accreditation:v8")
        verifier = _verifier(proof_types=(proof_type,))

        def verify(parameters):
            changed = copy.deepcopy(request)
            changed.parameters = {proof_type: parameters}
            return verifier.verify(envelope, changed)

        self.assertTrue(verify({"required0": 2}).valid)
        # Correct spelling: the proof was made with flagRequired=false.
        self.assertEqual(verify({"required0": 2, "flagRequired": True}).codes(), [Code.REQUIREMENTS_NOT_MET])
        for unknown in ("flagrequired", "institutionalRequired"):
            with self.subTest(unknown=unknown):
                result = verify({"required0": 2, unknown: True})
                self.assertFalse(result.valid)
                self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                self.assertIn(repr(unknown), result.errors[0].message)

    def test_kyc_verify_and_verify_authenticated_reject_unknown_keys(self):
        provider = LocalAccumulatorProvider()
        holder = _make_holder(provider)
        holder.store_credential(issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=7400, provider=provider, expires_at=2_000_000_000,
        ))
        params = {"requiredLevel": 1, "requiredAttributes": [True, False, False, False, False]}
        holder_request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE], parameters={KYC_PROOF_TYPE: copy.deepcopy(params)},
            context=_context(), trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
        )
        envelope = generate_unauthenticated_linkable(holder, holder_request)
        verifier = ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                **apr_verifier_identity(),
                issuers=(VerifierTrustedIssuer(
                    issuer_id=TEST_ISSUER_ID, public_key_x=TEST_ISSUER_KEY_X,
                    public_key_y=TEST_ISSUER_KEY_Y, proof_types=(KYC_PROOF_TYPE,),
                ),),
            ),
            StubVerifyBackend(),
        )
        states = {TEST_ISSUER_ID: IssuerAccumulatorState(
            current_epoch=provider.current_epoch(TEST_ISSUER_ID), roots=provider.roots(TEST_ISSUER_ID),
        )}

        def run(parameters, nonce):
            request = VerificationRequest(
                [KYC_PROOF_TYPE], {KYC_PROOF_TYPE: parameters}, _context(), accumulator_states=states,
            )
            apr = sign_apr({
                "request": {
                    "proofTypes": [KYC_PROOF_TYPE], "parameters": {KYC_PROOF_TYPE: parameters},
                    "context": _verifier_session_context_fixture(), "trustPolicy": {"issuers": []},
                    "presentation": {"profile": LINKABLE_PROFILE},
                },
                "verifierId": "verifier.example", "nonce": field_to_hex(nonce),
                "issuedAt": request.context.timestamp, "expiresAt": request.context.timestamp + 3600,
            }, APR_VERIFIER_PRIVATE_KEY)
            return (
                verifier.verify(envelope, request),
                verifier.verify_authenticated(apr, envelope, request, now=request.context.timestamp),
            )

        for result in run(copy.deepcopy(params), 0x5400):
            self.assertTrue(result.valid, result.to_dict())
        for nonce, unknown in enumerate(("requiredlevel", "requiredAttribute", UNKNOWN), start=0x5401):
            with self.subTest(unknown=unknown):
                for result in run({**copy.deepcopy(params), unknown: 3}, nonce):
                    self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                    self.assertIn(repr(unknown), result.errors[0].message)


class HolderUnknownKeyTests(unittest.TestCase):
    def _holder(self, backend=None):
        return HolderClient.from_seed(
            MASTER_SEED, REGISTRY, backend or mock.Mock(spec=StubBackend),
            accumulator_provider=LocalAccumulatorProvider(),
        )

    def test_generate_proof_refuses_an_unknown_key_for_every_proof_type(self):
        contracts, errors = REGISTRY.request_parameter_contracts()
        self.assertEqual(errors, {})
        self.assertEqual(set(contracts), set(CONTRACTS))
        for proof_type in sorted(contracts):
            for presentation in (None, _Presentation(ANONYMOUS_PROFILE, 0)):
                with self.subTest(proof_type=proof_type, v2=presentation is not None):
                    backend = mock.Mock(spec=StubBackend)
                    request = ProofRequest(
                        [proof_type], {proof_type: {UNKNOWN: True}}, _context(),
                        TrustPolicy(issuers=(trusted_test_issuer(),)),
                    )
                    with self.assertRaises(ConstraintViolationError) as caught:
                        self._holder(backend)._generate_envelope(
                            request, presentation or _Presentation(LINKABLE_PROFILE, 0)
                        )
                    profile = presentation.profile if presentation else LINKABLE_PROFILE
                    governing = request_contract_proof_types(proof_type, (profile,))
                    # The public snapshot omits some emitted identities; their
                    # blocks are then refused as underivable (fail closed).
                    expected = (
                        repr(UNKNOWN) if all(item in contracts for item in governing)
                        else "is unavailable"
                    )
                    self.assertIn(expected, str(caught.exception))
                    self.assertIn(proof_type, str(caught.exception))
                    backend.prove.assert_not_called()

    def test_every_documented_key_passes_the_holder_gate(self):
        contracts, _errors = REGISTRY.request_parameter_contracts()
        for proof_type, accepted in sorted(contracts.items()):
            with self.subTest(proof_type=proof_type):
                REGISTRY.refuse_unknown_request_parameters(
                    [proof_type], {proof_type: {key: None for key in accepted}}
                )

    def test_unrequested_parameter_blocks_are_refused(self):
        honest = {"requiredLevel": 1, "requiredAttributes": [False] * 5}
        for extra in ("zkc:proof:kyc:v2", "zkc:proof:accreditaton:v8", "zkc:proof:sanctions:v8"):
            with self.subTest(extra=extra):
                request = ProofRequest(
                    [KYC_PROOF_TYPE], {KYC_PROOF_TYPE: dict(honest), extra: {"flagRequired": True}},
                    _context(), TrustPolicy(issuers=(trusted_test_issuer(),)),
                )
                with self.assertRaisesRegex(ConstraintViolationError, f"does not request: '{extra}'"):
                    generate_unauthenticated_linkable(self._holder(), request)

    def test_mapping_tables_are_checked_and_non_mappings_refused(self):
        proof_type = "zkc:proof:accreditation:v7"
        block = {"required0": 2, "flagrequired": True}
        for label, parameters in (
            ("inner proxy", {proof_type: types.MappingProxyType(block)}),
            ("outer proxy", types.MappingProxyType({proof_type: block})),
        ):
            with self.subTest(label=label):
                request = ProofRequest([proof_type], parameters, _context(),
                                       TrustPolicy(issuers=(trusted_test_issuer(),)))
                with self.assertRaisesRegex(ConstraintViolationError, "'flagrequired'"):
                    generate_unauthenticated_linkable(self._holder(), request)
        for outer in (None, [(proof_type, block)], "required0=2"):
            with self.subTest(outer=outer), self.assertRaisesRegex(
                ConstraintViolationError, "must be a JSON object"
            ):
                REGISTRY.refuse_unknown_request_parameters([proof_type], outer)

    def test_misplaced_canonical_set_key_keeps_its_canonical_set_refusal(self):
        proof_type = "zkc:proof:source:v7"
        request = ProofRequest(
            [proof_type], {proof_type: {"setRoot": 1, "canonicalSet": [7], UNKNOWN: 1}},
            _context(), TrustPolicy(issuers=(trusted_test_issuer(),)),
        )
        with self.assertRaises(CanonicalSetMismatchError):
            generate_unauthenticated_linkable(self._holder(), request)

    def test_secret_key_keeps_secret_in_request_precedence(self):
        for proof_type in ("zkc:proof:rebind:v5", KYC_PROOF_TYPE, "zkc:proof:accreditation:v8"):
            for secret in ("newMasterSeed", "newCredentialBindingKey"):
                with self.subTest(proof_type=proof_type, secret=secret):
                    request = ProofRequest(
                        [proof_type], {proof_type: {secret: 1, UNKNOWN: 1}}, _context(),
                        TrustPolicy(issuers=(trusted_test_issuer(),)),
                    )
                    with self.assertRaises(SecretInRequestError):
                        generate_unauthenticated_linkable(self._holder(), request)

    def _apr(self, parameters, nonce):
        return sign_apr({
            "request": {
                "proofTypes": [KYC_PROOF_TYPE], "parameters": {KYC_PROOF_TYPE: parameters},
                "context": _verifier_session_context_fixture(), "trustPolicy": {"issuers": []},
                "presentation": {"profile": ANONYMOUS_PROFILE},
            },
            "verifierId": "verifier.example", "nonce": field_to_hex(nonce),
            "issuedAt": _context().timestamp, "expiresAt": _context().timestamp + 3600,
        }, APR_VERIFIER_PRIVATE_KEY)

    def _authenticated_exchange(self, parameters, nonce):
        provider = LocalAccumulatorProvider()
        holder = _make_holder(provider)
        holder.store_credential(issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=7500, provider=provider, expires_at=2_000_000_000,
        ))
        request = ProofRequest(
            [KYC_PROOF_TYPE], {KYC_PROOF_TYPE: copy.deepcopy(parameters)}, _context(),
            TrustPolicy(issuers=(trusted_test_issuer((KYC_PROOF_TYPE, "zkc:proof:kyc:v2")),)),
            presentation_profile=ANONYMOUS_PROFILE,
        )
        return holder.generate_authenticated_proof(
            self._apr(parameters, nonce), request, now=request.context.timestamp,
        )

    def test_generate_authenticated_proof_refuses_a_signed_unknown_key(self):
        honest = {"requiredLevel": 1, "requiredAttributes": [True, False, True, False, False]}
        self.assertIn("envelope", self._authenticated_exchange(honest, 0x5500))
        with self.assertRaisesRegex(ConstraintViolationError, "requiredlevel"):
            self._authenticated_exchange({**honest, "requiredlevel": 3}, 0x5501)
        with self.assertRaises(SecretInRequestError):
            self._authenticated_exchange({**honest, "requiredlevel": 3, "newMasterSeed": 1}, 0x5502)

    def test_planner_refuses_unknown_key_after_secret_check(self):
        planner = ProofPlanner(REGISTRY, POLICY)
        honest = {"requiredLevel": 1, "requiredAttributes": [True, False, False, False, False]}
        planner.plan(planning_request(parameters={KYC_PROOF_TYPE: dict(honest)}))
        with self.assertRaisesRegex(ConstraintViolationError, "requiredAttribute'"):
            planner.plan(planning_request(parameters={KYC_PROOF_TYPE: {**honest, "requiredAttribute": []}}))
        with self.assertRaises(SecretInRequestError):
            planner.plan(planning_request(
                parameters={KYC_PROOF_TYPE: {**honest, "requiredAttribute": [], "holderSecret": 1}}
            ))


class AgentUnknownKeyTests(AgentTestBase):
    def test_agent_blocks_unknown_key_through_planning(self):
        honest = self.agent.handle_proof_request(agent_request(), agent_context())
        self.assertEqual(honest.status, "responded")
        parameters = {KYC_PROOF_TYPE: {
            "requiredLevel": 1, "requiredAttributes": [True, False, False, False, False],
            "flagrequired": True,
        }}
        decision = self.agent.handle_proof_request(agent_request(parameters=parameters), agent_context())
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_PLANNING_REFUSED)
        blocked = [event for event in self.agent.audit_log.events if event["event"] == "request_blocked"]
        self.assertEqual(blocked[-1]["detail"], ConstraintViolationError.code)

    def test_agent_secret_key_keeps_precedence_over_unknown_key(self):
        parameters = {KYC_PROOF_TYPE: {
            "requiredLevel": 1, "requiredAttributes": [True, False, False, False, False],
            "flagrequired": True, "newMasterSeed": 1,
        }}
        decision = self.agent.handle_proof_request(agent_request(parameters=parameters), agent_context())
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, SecretInRequestError.code)


class ReviewFollowUpTests(unittest.TestCase):
    """PR #61 review: unrequested blocks, aliases, counter-offers, fail-closed derivation."""

    def test_verifier_rejects_unrequested_parameter_blocks(self):
        for version in ("v1", "v2"):
            envelope, request, proof_type, params, _provider = _build(
                "accreditation", version, credential_id=7600 + (version == "v2"),
            )
            verifier = _verifier(proof_types=(proof_type,))
            self.assertTrue(verifier.verify(envelope, request).valid)
            for label, extra in (
                ("misspelled proof type", {proof_type.replace("accreditation", "accreditaton"): {"flagRequired": True}}),
                ("unlisted predicate", {"zkc:proof:sanctions:v8": {"setRoot": 1}}),
                ("non-string key", {7: {}}),
            ):
                with self.subTest(version=version, case=label):
                    attack = copy.deepcopy(request)
                    attack.parameters = {proof_type: dict(params), **extra}
                    result = verifier.verify(envelope, attack)
                    self.assertFalse(result.valid)
                    self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                    self.assertIn("does not request", result.errors[0].message)
                    self.assertIn(repr(next(iter(extra))), result.errors[0].message)

    def test_aliased_request_is_governed_by_the_emitted_identity(self):
        """``source:v1`` + ``flagRequired: false`` is answered as v7 and verifies."""
        for family, requested in (
            ("source", "zkc:proof:source:v1"),
            ("tax", "zkc:proof:tax:v1"),
            ("sanctions", "zkc:proof:sanctions:v2"),
        ):
            with self.subTest(requested=requested):
                credential, params = _CASE_BUILDERS[family](7700 + len(requested))
                params = dict(params, flagRequired=False)
                self.assertNotIn("flagRequired", CONTRACTS[requested])
                provider = LocalAccumulatorProvider()
                holder = _make_holder(provider)
                provider.register(TEST_ISSUER_ID, credential.credential_id)
                holder.store_credential(credential)
                epoch = provider.current_epoch(TEST_ISSUER_ID)
                envelope = generate_unauthenticated_linkable(holder, ProofRequest(
                    [requested], {requested: copy.deepcopy(params)}, _context(),
                    TrustPolicy(issuers=(trusted_predicate_issuer(),)),
                    current_epochs={TEST_ISSUER_ID: epoch},
                ), exact_member_consents={requested: True} if family in ("source", "tax") else {})
                emitted = envelope["proofs"][0]["proofType"]
                self.assertIn("flagRequired", CONTRACTS[emitted])
                result = _verifier().verify(envelope, VerificationRequest(
                    [emitted], {emitted: copy.deepcopy(params)}, _context(),
                    accumulator_states={TEST_ISSUER_ID: IssuerAccumulatorState(
                        current_epoch=epoch, roots=provider.roots(TEST_ISSUER_ID),
                    )},
                ))
                self.assertTrue(result.valid, result.to_dict())
                # The planner's every-profile resolution admits it too, and a
                # misspelling under the alias is still refused.
                every_profile = lambda pt: request_contract_proof_types(  # noqa: E731
                    pt, (LINKABLE_PROFILE, ANONYMOUS_PROFILE, SCOPED_PROFILE)
                )
                REGISTRY.refuse_unknown_request_parameters(
                    [requested], {requested: params}, resolve=every_profile
                )
                with self.assertRaisesRegex(ConstraintViolationError, "answered as"):
                    REGISTRY.refuse_unknown_request_parameters(
                        [requested], {requested: {**params, "flagrequired": False}},
                        resolve=every_profile,
                    )

    def test_counter_offer_returns_structured_refusals(self):
        planner = ProofPlanner(REGISTRY, POLICY)
        honest = {"requiredLevel": 1, "requiredAttributes": [True, False, False, False, False]}
        for parameters, code in (
            ({KYC_PROOF_TYPE: {**honest, "requiredlevel": 3}}, ConstraintViolationError.code),
            ({KYC_PROOF_TYPE: dict(honest), "zkc:proof:kyc:v2": dict(honest)}, ConstraintViolationError.code),
            ({KYC_PROOF_TYPE: {**honest, "canonicalSet": [7]}}, CanonicalSetMismatchError.code),
            ({KYC_PROOF_TYPE: {**honest, "requiredlevel": 3, "newBindingKey": 1}}, SecretInRequestError.code),
        ):
            with self.subTest(code=code, keys=sorted(map(str, parameters[KYC_PROOF_TYPE]))):
                offer = planner.counter_offer(planning_request(parameters=parameters))
                self.assertEqual((offer.status, offer.refusal_code), ("refusal", code))

    def test_holder_contract_derivation_fails_closed(self):
        entries = [entry for listed in REGISTRY._by_proof_type.values() for entry in listed]
        proof_type = "zkc:proof:accreditation:v8"
        bad = {proof_type: {"required0": 2, "flagrequired": True}}
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(holder_registry, "_REFERENCE_REPO_ROOT", pathlib.Path(tmp)):
                in_memory = PredicateRegistry(entries)
            registries = {
                "fallback root without schemas": in_memory,
                "explicit root without schemas": PredicateRegistry(entries, repo_root=tmp),
                "circuit map without sidecars": PredicateRegistry(
                    entries, circuit_map={proof_type: "zkc_remaining_predicates_v8"}, repo_root=tmp,
                ),
            }
            for label, registry in registries.items():
                with self.subTest(registry=label):
                    self.assertIsNotNone(registry.resolve(proof_type))
                    for parameters in (bad, {proof_type: {"required0": 2}}):
                        with self.assertRaisesRegex(ConstraintViolationError, "unavailable"):
                            registry.refuse_unknown_request_parameters([proof_type], parameters)
                    # An absent or empty block names no key to drop.
                    registry.refuse_unknown_request_parameters([proof_type], {})
                    registry.refuse_unknown_request_parameters([proof_type], {proof_type: {}})
            # End to end: the in-memory holder refuses before proving.
            backend = mock.Mock(spec=StubBackend)
            holder = HolderClient.from_seed(MASTER_SEED, in_memory, backend)
            pt7 = "zkc:proof:accreditation:v7"
            with self.assertRaises(ConstraintViolationError):
                generate_unauthenticated_linkable(holder, ProofRequest(
                    [pt7], {pt7: {"required0": 2, "flagrequired": True}}, _context(),
                    TrustPolicy(issuers=(trusted_predicate_issuer(),)),
                ))
            backend.prove.assert_not_called()

    def test_encoder_resolution_errors_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            shutil.copytree(REPO_ROOT / "schemas", root / "schemas")
            duplicate = json.loads((root / "schemas/public-inputs/zkc_kyc.json").read_text())
            (root / "schemas/public-inputs/zkc_kyc_copy.json").write_text(json.dumps(duplicate))
            registry = PredicateRegistry([], repo_root=root)
            for proof_type in (KYC_PROOF_TYPE, "zkc:proof:accreditation:v8"):
                with self.subTest(proof_type=proof_type), self.assertRaisesRegex(
                    ConstraintViolationError, "encoder resolution"
                ):
                    registry.refuse_unknown_request_parameters([proof_type], {proof_type: {"required0": 2}})

    def test_rebind_auth_credential_id_is_flagged_unbindable(self):
        verifier = _verifier()
        proof_type = "zkc:proof:rebind:v4"
        for parameters, warnings in (({}, []), ({"credentialId": 42}, ["UNBINDABLE_PARAMETER"])):
            with self.subTest(parameters=parameters):
                result = VerificationResult()
                request = VerificationRequest([proof_type], {proof_type: parameters}, _context())
                verifier._verify_type_specific_requirements(proof_type, {}, request, 0, 0, 0, result)
                self.assertEqual(result.codes(), [], result.to_dict())
                self.assertEqual(result.warning_codes(), warnings)


if __name__ == "__main__":
    unittest.main()
