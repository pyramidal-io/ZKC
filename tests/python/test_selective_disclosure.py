"""Issuer-authoritative selective-disclosure statement tests."""

import copy
import datetime
from dataclasses import replace
import json
import unittest

import _path  # noqa: F401

from zkc_crypto import (
    compute_selective_disclosure_binding,
    compute_selective_disclosure_credential_digest,
    compute_selective_disclosure_credential_digest_v2,
    compute_merkle_root,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
    ProofContext,
    PublicInputEncoder,
    field_to_hex,
    sign_apr,
)
from zkc_crypto.ecdsa_secp256k1 import sign
from zkc_holder import (
    ConstraintViolationError,
    Credential,
    HolderClient,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_holder.disclosure import (
    DISCLOSURE_CIRCUIT,
    DISCLOSURE_V3_PROOF_TYPE,
    build_selective_disclosure_witness,
    selective_disclosure_public_inputs,
)
from zkc_holder.errors import NoMatchingCredentialError, UnauthenticatedRequestError

from zkc_revocation.chain import AnnouncementKeyPin
from holder_fixtures import (
    apr_verifier_identity,
    DRAFT_OPT_IN_REVIEW_STATUSES,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    TEST_ISSUER_PRIVATE_KEY,
    trusted_test_issuer,
)
from zkc_holder import AccumulatorWitness, LocalAccumulatorProvider
from zkc_issuer import AdapterError, IssuerSigningKey, get_schema
from zkc_revocation import (
    InMemoryVerifierCheckpointStore,
    RevocationAccumulatorService,
    VerifierAccumulatorCache,
)
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    TrustedIssuer as VerifierTrustedIssuer,
    VerificationErrorCode as Code,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from _path import REPO_ROOT


LAYOUT_A = field_to_hex(1)
LAYOUT_B = field_to_hex(2)


class SelectiveDisclosureStatementTests(unittest.TestCase):
    def setUp(self):
        self.seed = 42
        self.credential_id = 707
        self.attributes = [0, 11, 22, 33, 0, 0, 0, 0]
        self.attribute_count = 4
        self.expires_at = 2_000_000
        self.context = ProofContext.verifier_session("verifier.example", 55, 12345)
        holder_commitment = derive_holder_commitment_from_seed(self.seed)
        digest = compute_selective_disclosure_credential_digest(
            holder_commitment,
            self.credential_id,
            self.attribute_count,
            self.attributes,
            self.expires_at,
        )
        self.provider = LocalAccumulatorProvider()
        self.provider.register(TEST_ISSUER_ID, self.credential_id)
        accumulator = self.provider.witness(TEST_ISSUER_ID, self.credential_id)
        self.credential = Credential(
            credential_type="zkc:cred:attribute-set:v1",
            proof_type="zkc:proof:selective_disclosure:v1",
            issuer_id=TEST_ISSUER_ID,
            holder_commitment=holder_commitment,
            credential_id=self.credential_id,
            claims={
                "attributeCount": self.attribute_count,
                "attributes": list(self.attributes),
            },
            expires_at=self.expires_at,
            attribute_layout_id=LAYOUT_A,
            signature=sign(digest_to_message_bytes(digest), TEST_ISSUER_PRIVATE_KEY),
            witness=AccumulatorWitness(
                path_index=accumulator.path_index,
                siblings=list(accumulator.siblings),
                accumulator_root=accumulator.accumulator_root,
                accumulator_epoch=accumulator.accumulator_epoch,
            ),
        )
        self.issuer = trusted_test_issuer(("zkc:proof:selective_disclosure:v1",))
        revocation_key = IssuerSigningKey(
            key_id="test-issuer-revocation-2026",
            private_key=TEST_ISSUER_PRIVATE_KEY,
        )
        revocation = RevocationAccumulatorService(
            "test-issuer-active-credentials",
            "https://test-issuer.example/v1/revocation/updates",
            revocation_key,
            clock=lambda: 1_770_000_000,
        )
        revocation.register(self.credential_id)
        cache = VerifierAccumulatorCache(
            {
                TEST_ISSUER_ID: {
                    revocation_key.key_id: AnnouncementKeyPin.from_signing_key_entry(
                        revocation_key.metadata_entry()
                    )
                }
            },
            accumulator_ids={TEST_ISSUER_ID: "test-issuer-active-credentials"},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: 1_770_000_000,
        )
        cache.ingest_metadata(
            TEST_ISSUER_ID,
            {
                "version": "zkc:issuer-metadata:v2",
                "issuerId": TEST_ISSUER_ID,
                "revocation": revocation.metadata(),
            },
        )
        self.authenticated_accumulator_state = cache.state(TEST_ISSUER_ID)

    def witness(self, positions=(0, 2)):
        return build_selective_disclosure_witness(
            master_seed=self.seed,
            credential=self.credential,
            issuer=self.issuer,
            witness=self.credential.witness,
            disclosed_positions=positions,
            proof_context=self.context.value,
            timestamp=self.context.timestamp,
            current_epoch=self.credential.witness.accumulator_epoch,
            scope_id=0,
        )

    def assert_rejected(self, witness, message):
        with self.assertRaisesRegex(ConstraintViolationError, message):
            StubBackend().prove(DISCLOSURE_CIRCUIT, witness)

    def test_valid_statement_binds_issuer_state_positions_and_count(self):
        witness = self.witness()
        StubBackend().prove(DISCLOSURE_CIRCUIT, witness)
        public = selective_disclosure_public_inputs(witness)
        self.assertEqual(public["credential_attribute_count"], 4)
        self.assertEqual(public["disclosure_count"], 2)
        self.assertEqual(public["disclosed_flags"], [True, False, True, False, False, False, False, False])
        self.assertEqual(public["disclosed_attributes"][0], "0x" + "0" * 64)

    def test_disclosed_zero_is_distinct_from_hidden_zero(self):
        disclosed = self.witness((0,))
        hidden = self.witness(())
        self.assertNotEqual(disclosed["claim_binding"], hidden["claim_binding"])
        self.assertTrue(disclosed["disclosed_flags"][0])
        self.assertFalse(hidden["disclosed_flags"][0])
        self.assertEqual(disclosed["disclosed_attributes"][0], 0)
        self.assertEqual(hidden["disclosed_attributes"][0], 0)

    def test_rejects_self_chosen_unissued_attribute(self):
        witness = self.witness()
        witness["credential_attributes"][2] = 999
        witness["disclosed_attributes"][2] = 999
        witness["claim_binding"] = compute_selective_disclosure_binding(
            witness["credential_attribute_count"],
            witness["disclosed_flags"],
            witness["disclosed_attributes"],
            witness["proof_context"],
            witness["timestamp"],
        )
        self.assert_rejected(witness, "invalid issuer signature")

    def test_rejects_altered_disclosure_position(self):
        witness = self.witness((0,))
        witness["disclosed_flags"][0] = False
        witness["disclosed_flags"][1] = True
        witness["disclosed_attributes"][1] = witness["credential_attributes"][1]
        self.assert_rejected(witness, "selective disclosure binding mismatch")

    def test_rejects_wrong_issuer_state(self):
        witness = self.witness()
        witness["accumulator_root"] += 1
        self.assert_rejected(witness, "credential is revoked or accumulator epoch is stale")

    def test_rejects_cross_context_replay(self):
        witness = self.witness()
        witness["proof_context"] += 1
        self.assert_rejected(witness, "selective disclosure binding mismatch")

    def test_rejects_noncanonical_hidden_slot_and_bad_counts(self):
        witness = self.witness()
        witness["disclosed_attributes"][1] = 11
        self.assert_rejected(witness, "hidden disclosed-attribute slot must be zero")

        witness = self.witness()
        witness["disclosure_count"] += 1
        self.assert_rejected(witness, "disclosure count does not match flags")

        witness = self.witness()
        witness["credential_attributes"][7] = 1
        self.assert_rejected(witness, "credential padding attribute must be zero")

        witness = self.witness(())
        self.assert_rejected(witness, "must reveal at least one position")

    def test_builder_rejects_ambiguous_position_types(self):
        for positions in ([True], [1.0], ["1"]):
            with self.subTest(positions=positions), self.assertRaisesRegex(
                ConstraintViolationError, "positions must be integers"
            ):
                self.witness(positions)


class SelectiveDisclosureIssuerSchemaTests(unittest.TestCase):
    def test_schema_normalizes_active_attributes_and_pads_signed_shape(self):
        schema = get_schema("zkc:cred:attribute-set:v1")
        claims = schema.normalize_claims(
            {"attributeCount": 4, "attributes": [0, 11, 22, 33]}
        )
        self.assertEqual(claims["attributeCount"], 4)
        self.assertEqual(claims["attributes"], [0, 11, 22, 33, 0, 0, 0, 0])
        self.assertEqual(schema.normalize_claims(claims), claims)
        self.assertEqual(schema.proof_type, "zkc:proof:selective_disclosure:v1")
        self.assertEqual(schema.circuit, DISCLOSURE_CIRCUIT)

    def test_schema_rejects_count_mismatch_and_noncanonical_fields(self):
        schema = get_schema("zkc:cred:attribute-set:v1")
        for claims in (
            {"attributeCount": 2, "attributes": [1]},
            {"attributeCount": 1, "attributes": [-1]},
            {"attributeCount": 9, "attributes": list(range(9))},
            {"attributeCount": 2, "attributes": [1, 2, 0, 0, 0, 0, 0, 9]},
        ):
            with self.subTest(claims=claims), self.assertRaises(AdapterError):
                schema.normalize_claims(claims)


class SelectiveDisclosureEnvelopeTests(SelectiveDisclosureStatementTests):
    def setUp(self):
        super().setUp()
        witness = self.witness()
        public_inputs = selective_disclosure_public_inputs(witness)
        proof = StubBackend().prove(DISCLOSURE_CIRCUIT, witness)
        generated = datetime.datetime.fromtimestamp(
            self.context.timestamp, tz=datetime.timezone.utc
        )
        expires = generated + datetime.timedelta(hours=1)
        self.envelope = {
            "version": "zkc:proof:v2",
            "metadata": {
                "generatedAt": generated.isoformat().replace("+00:00", "Z"),
                "expiresAt": expires.isoformat().replace("+00:00", "Z"),
                "context": self.context.to_metadata(),
            },
            "proofs": [
                {
                    "proofType": "zkc:proof:selective_disclosure:v1",
                    "proof": proof,
                    "publicInputs": public_inputs,
                    "principalConsent": True,
                }
            ],
            "presentationBinding": {"profile": "zkc:presentation:anonymous:v1"},
        }
        trusted = VerifierTrustedIssuer(
            issuer_id=TEST_ISSUER_ID,
            public_key_x=TEST_ISSUER_KEY_X,
            public_key_y=TEST_ISSUER_KEY_Y,
            proof_types=("zkc:proof:selective_disclosure:v1",),
            attribute_layout_id=LAYOUT_A,
        )
        self.verifier = ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(issuers=(trusted,)),
            StubVerifyBackend(),
        )

    def request(self, positions=(0, 2), *, context=None, roots=None):
        epoch = self.credential.witness.accumulator_epoch
        state = self.authenticated_accumulator_state
        if roots is not None:
            state = IssuerAccumulatorState(current_epoch=epoch, roots=roots)
        return VerificationRequest(
            proof_types=["zkc:proof:selective_disclosure:v1"],
            parameters={
                "zkc:proof:selective_disclosure:v1": {
                    "disclosedPositions": list(positions),
                    "layoutId": LAYOUT_A
                }
            },
            context=context or self.context,
            accumulator_states={TEST_ISSUER_ID: state},
        )

    def test_registry_and_encoder_publish_versioned_consumer_contract(self):
        # The entry is draft, so inspecting it needs an explicit opt-in.
        entry = PredicateRegistry.from_repo(REPO_ROOT).resolve(
            "zkc:proof:selective_disclosure:v1", allow_unaccepted=True
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.circuit, DISCLOSURE_CIRCUIT)
        self.assertEqual(
            [name for name, _abi, _fields in entry.public_inputs][-4:],
            [
                "credential_attribute_count",
                "disclosure_count",
                "disclosed_flags",
                "disclosed_attributes",
            ],
        )

    def test_public_input_encoder_flattens_disclosure_arrays(self):
        encoder = PublicInputEncoder.load(
            REPO_ROOT / "schemas" / "public-inputs" / "zkc_selective_disclosure_v1.json"
        )
        fields = encoder.field_elements(
            self.envelope["proofs"][0]["publicInputs"]
        )
        self.assertEqual(len(fields), 90)
        self.assertEqual(fields[74:82], [1, 0, 1, 0, 0, 0, 0, 0])
        self.assertEqual(fields[82:90], [0, 0, 22, 0, 0, 0, 0, 0])

    def test_type_specific_proof_entry_schema_is_versioned(self):
        schema = json.loads(
            (REPO_ROOT / "schemas" / "selective-disclosure-proof-v1.schema.json").read_text()
        )
        self.assertEqual(
            schema["properties"]["proofType"]["const"],
            "zkc:proof:selective_disclosure:v1",
        )
        required = schema["properties"]["publicInputs"]["required"]
        self.assertEqual(
            required[-4:],
            [
                "credential_attribute_count",
                "disclosure_count",
                "disclosed_flags",
                "disclosed_attributes",
            ],
        )

    def test_valid_envelope_verifies_without_consumer_side_issuer_logic(self):
        result = self.verifier.verify(self.envelope, self.request())
        self.assertTrue(result.valid, result.to_dict())

    def test_zka_and_afp_consumers_delegate_the_versioned_envelope_to_zkc(self):
        carriers = {
            "zka": {"version": "zka:bundle:v1", "zkcProof": self.envelope},
            "afp": {
                "version": "afp:envelope:v1",
                "messageType": "afp.disclose.response",
                "payload": {"zkcProof": self.envelope},
            },
        }
        extracted = (
            carriers["zka"]["zkcProof"],
            carriers["afp"]["payload"]["zkcProof"],
        )
        for consumer, envelope in zip(("zka", "afp"), extracted):
            with self.subTest(consumer=consumer):
                self.assertEqual(envelope["version"], "zkc:proof:v2")
                result = self.verifier.verify(envelope, self.request())
                self.assertTrue(result.valid, result.to_dict())

    def test_holder_emits_versioned_disclosure_in_anonymous_envelope(self):
        holder = HolderClient.from_seed(
            self.seed,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=self.provider,
            # selective_disclosure:v1 is a draft entry (Safeguard 4).
            accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        holder.store_credential(self.credential)
        proof_type = "zkc:proof:selective_disclosure:v1"
        request = ProofRequest(
            proof_types=[proof_type],
            parameters={proof_type: {"disclosedPositions": [0, 2], "layoutId": LAYOUT_A}},
            context=self.context,
            trust_policy=TrustPolicy(issuers=(self.issuer,)),
        )
        unsigned_apr = {
            "request": {
                "proofTypes": [proof_type],
                "parameters": request.parameters,
                "context": {
                    "profile": self.context.profile,
                    "verifierId": self.context.verifier_id,
                    "sessionId": field_to_hex(self.context.session_id),
                    "timestamp": self.context.timestamp,
                },
                "trustPolicy": {"issuers": []},
            },
            "verifierId": self.context.verifier_id,
            "nonce": field_to_hex(991),
            "issuedAt": self.context.timestamp,
            "expiresAt": self.context.timestamp + 3600,
        }
        envelope = holder.generate_authenticated_proof(
            sign_apr(unsigned_apr, 12345), request,
            now=request.context.timestamp
        )["envelope"]
        self.assertEqual(envelope["version"], "zkc:proof:v2")
        self.assertEqual(envelope["proofs"][0]["proofType"], proof_type)
        result = self.verifier.verify(envelope, self.request())
        self.assertTrue(result.valid, result.to_dict())

    def test_authenticated_apr_cannot_be_substituted_with_broader_positions(self):
        holder = HolderClient.from_seed(
            self.seed,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=self.provider,
        )
        holder.store_credential(self.credential)
        proof_type = "zkc:proof:selective_disclosure:v1"
        request = ProofRequest(
            proof_types=[proof_type],
            parameters={proof_type: {"disclosedPositions": [0, 2], "layoutId": LAYOUT_A}},
            context=self.context,
            trust_policy=TrustPolicy(issuers=(self.issuer,)),
        )
        unsigned_apr = {
            "request": {
                "proofTypes": [proof_type],
                "parameters": {proof_type: {"disclosedPositions": [0], "layoutId": LAYOUT_A}},
                "context": {
                    "profile": self.context.profile,
                    "verifierId": self.context.verifier_id,
                    "sessionId": field_to_hex(self.context.session_id),
                    "timestamp": self.context.timestamp,
                },
                "trustPolicy": {"issuers": []},
            },
            "verifierId": self.context.verifier_id,
            "nonce": field_to_hex(992),
            "issuedAt": self.context.timestamp,
            "expiresAt": self.context.timestamp + 3600,
        }
        with self.assertRaisesRegex(
            UnauthenticatedRequestError, "proof types or parameters"
        ):
            holder.generate_authenticated_proof(sign_apr(unsigned_apr, 12345), request, now=request.context.timestamp)

    def test_authenticated_apr_parameter_types_must_match_exactly(self):
        holder = HolderClient.from_seed(
            self.seed,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=self.provider,
        )
        holder.store_credential(self.credential)
        proof_type = "zkc:proof:selective_disclosure:v1"
        for nonce, signed_positions, effective_positions in (
            (993, [False], [0]),
            (994, [True], [1]),
            (995, [1.0], [1]),
        ):
            with self.subTest(
                signed_positions=signed_positions,
                effective_positions=effective_positions,
            ):
                request = ProofRequest(
                    proof_types=[proof_type],
                    parameters={
                        proof_type: {"disclosedPositions": effective_positions, "layoutId": LAYOUT_A}
                    },
                    context=self.context,
                    trust_policy=TrustPolicy(issuers=(self.issuer,)),
                )
                unsigned_apr = {
                    "request": {
                        "proofTypes": [proof_type],
                        "parameters": {
                            proof_type: {"disclosedPositions": signed_positions, "layoutId": LAYOUT_A}
                        },
                        "context": {
                            "profile": self.context.profile,
                            "verifierId": self.context.verifier_id,
                            "sessionId": field_to_hex(self.context.session_id),
                            "timestamp": self.context.timestamp,
                        },
                        "trustPolicy": {"issuers": []},
                    },
                    "verifierId": self.context.verifier_id,
                    "nonce": field_to_hex(nonce),
                    "issuedAt": self.context.timestamp,
                    "expiresAt": self.context.timestamp + 3600,
                }
                with self.assertRaisesRegex(
                    UnauthenticatedRequestError, "proof types or parameters"
                ):
                    holder.generate_authenticated_proof(
                        sign_apr(unsigned_apr, 12345), request,
                        now=request.context.timestamp
                    )

    def test_verifier_rejects_position_policy_change(self):
        result = self.verifier.verify(self.envelope, self.request((1, 2)))
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())

    def test_verifier_rejects_non_mapping_parameters_without_crashing(self):
        request = self.request()
        request.parameters["zkc:proof:selective_disclosure:v1"] = None
        result = self.verifier.verify(self.envelope, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())

    def test_verifier_rejects_wrong_issuer_accumulator_state(self):
        root = self.credential.witness.accumulator_root
        epoch = self.credential.witness.accumulator_epoch
        result = self.verifier.verify(self.envelope, self.request(roots={epoch: root + 1}))
        self.assertIn(Code.UNAUTHENTICATED_ACCUMULATOR, result.codes())

    def test_verifier_rejects_missing_authenticated_accumulator_root(self):
        result = self.verifier.verify(self.envelope, self.request(roots={}))
        self.assertIn(Code.UNAUTHENTICATED_ACCUMULATOR, result.codes())

    def test_verifier_rejects_caller_constructed_accumulator_state(self):
        epoch = self.credential.witness.accumulator_epoch
        request = self.request()
        request.accumulator_states[TEST_ISSUER_ID] = IssuerAccumulatorState(
            current_epoch=epoch,
            roots={epoch: self.credential.witness.accumulator_root},
        )
        result = self.verifier.verify(self.envelope, request)
        self.assertIn(Code.UNAUTHENTICATED_ACCUMULATOR, result.codes())

    def test_verifier_rejects_self_chosen_accumulator_root(self):
        witness = self.witness()
        witness["nonrevocation_siblings"][0] = 1
        witness["accumulator_root"] = compute_merkle_root(
            witness["credential_id"],
            witness["nonrevocation_path_index"],
            witness["nonrevocation_siblings"],
        )
        forged = copy.deepcopy(self.envelope)
        forged["proofs"][0]["proof"] = StubBackend().prove(DISCLOSURE_CIRCUIT, witness)
        forged["proofs"][0]["publicInputs"] = selective_disclosure_public_inputs(witness)
        result = self.verifier.verify(forged, self.request())
        self.assertIn(Code.STALE_ACCUMULATOR, result.codes())

    def test_verifier_enforces_type_specific_proof_entry_schema(self):
        cases = []
        false_consent = copy.deepcopy(self.envelope)
        false_consent["proofs"][0]["principalConsent"] = False
        cases.append(false_consent)

        extra_entry = copy.deepcopy(self.envelope)
        extra_entry["proofs"][0]["unsupported"] = True
        cases.append(extra_entry)

        extra_public = copy.deepcopy(self.envelope)
        extra_public["proofs"][0]["publicInputs"]["unsupported"] = 1
        cases.append(extra_public)

        for bad_count in ("2", 2.0, True):
            bad_integer = copy.deepcopy(self.envelope)
            bad_integer["proofs"][0]["publicInputs"]["disclosure_count"] = bad_count
            cases.append(bad_integer)

        for envelope in cases:
            with self.subTest(envelope=envelope):
                result = self.verifier.verify(envelope, self.request())
                self.assertIn(Code.MALFORMED_PROOF, result.codes())

    def test_verifier_rejects_cross_context_replay(self):
        other = ProofContext.verifier_session(
            "verifier.example", 56, self.context.timestamp
        )
        result = self.verifier.verify(self.envelope, self.request(context=other))
        self.assertIn(Code.CONTEXT_MISMATCH, result.codes())

    def test_legacy_requires_an_unambiguous_local_pin(self):
        policy = self.verifier._trust_policy
        issuer, = policy.issuers
        for issuers in (
            (replace(issuer, attribute_layout_id=None),),
            (issuer, replace(issuer, attribute_layout_id=LAYOUT_B)),
        ):
            verifier = ZKCVerifier(REPO_ROOT, replace(policy, issuers=issuers), StubVerifyBackend())
            result = verifier.verify(self.envelope, self.request())
            self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())
        request = self.request()
        request.parameters[request.proof_types[0]]["layoutId"] = LAYOUT_B
        self.assertIn(Code.REQUIREMENTS_NOT_MET, self.verifier.verify(self.envelope, request).codes())

    def test_legacy_holder_does_not_use_the_verifiers_layout_as_credential_metadata(self):
        proof_type = self.credential.proof_type
        request = ProofRequest(
            [proof_type], {proof_type: {"disclosedPositions": [0], "layoutId": LAYOUT_B}},
            self.context, TrustPolicy(issuers=(self.issuer,)),
        )
        holder = HolderClient.from_seed(
            self.seed, PredicateRegistry.from_repo(REPO_ROOT), StubBackend(),
            accumulator_provider=self.provider, accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        holder.store_credential(Credential.from_dict(self.credential.to_dict()))
        with self.assertRaisesRegex(NoMatchingCredentialError, "layoutId"):
            holder.generate_proof(request, allow_unauthenticated=True)

    def _check_layout_bound_request(self, proof_type):
        digest = compute_selective_disclosure_credential_digest_v2(
            self.credential.holder_commitment, self.credential_id, 2,
            self.attribute_count, self.attributes, self.expires_at,
        )
        credential = replace(
            self.credential, credential_type="zkc:cred:attribute-set:v2", proof_type=DISCLOSURE_V3_PROOF_TYPE,
            claims={**self.credential.claims, "layoutId": LAYOUT_B}, attribute_layout_id=None,
            signature=sign(digest_to_message_bytes(digest), TEST_ISSUER_PRIVATE_KEY),
        )
        holder = HolderClient.from_seed(
            self.seed, PredicateRegistry.from_repo(REPO_ROOT), StubBackend(),
            accumulator_provider=self.provider, accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        holder.store_credential(credential)
        verifier = ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                **apr_verifier_identity(12345),
                issuers=(replace(self.verifier._trust_policy.issuers[0],
                                 proof_types=(proof_type,), attribute_layout_id=None),),
                accepted_review_statuses=("draft",),
            ),
            StubVerifyBackend(),
        )
        parameters = {proof_type: {"disclosedPositions": [0, 2], "layoutId": LAYOUT_B}}
        request = ProofRequest(
            [proof_type], parameters, self.context,
            TrustPolicy(issuers=(trusted_test_issuer((proof_type,)),)),
        )
        verification = VerificationRequest(
            [proof_type], parameters, self.context,
            accumulator_states={TEST_ISSUER_ID: self.authenticated_accumulator_state},
        )

        def signed_request(nonce):
            return sign_apr({
                "request": {
                    "proofTypes": [proof_type], "parameters": parameters,
                    "context": {
                        "profile": self.context.profile, "verifierId": self.context.verifier_id,
                        "sessionId": field_to_hex(self.context.session_id),
                        "timestamp": self.context.timestamp,
                    },
                    "trustPolicy": {"issuers": []},
                },
                "verifierId": self.context.verifier_id, "nonce": field_to_hex(nonce),
                "issuedAt": self.context.timestamp, "expiresAt": self.context.timestamp + 3600,
            }, 12345)

        now = self.context.timestamp
        apr = signed_request(1101)
        envelope = holder.generate_authenticated_proof(apr, request, now=now)["envelope"]
        self.assertEqual(envelope["proofs"][0]["proofType"], proof_type)
        self.assertEqual(envelope["proofs"][0]["publicInputs"]["layout_id"], LAYOUT_B)
        result = verifier.verify_authenticated(apr, envelope, verification, now=now)
        self.assertTrue(result.valid, result.to_dict())

        class UpdatingBackend(StubVerifyBackend):
            def verify(self, *args, **kwargs):
                result = super().verify(*args, **kwargs)
                verification.parameters[proof_type]["layoutId"] = LAYOUT_A
                return result

        updating_verifier = ZKCVerifier(REPO_ROOT, verifier._trust_policy, UpdatingBackend())
        result = updating_verifier.verify_authenticated(apr, envelope, verification, now=now)
        self.assertTrue(result.valid, result.to_dict())

        parameters[proof_type]["layoutId"] = LAYOUT_A
        apr = signed_request(1102)
        with self.assertRaisesRegex(NoMatchingCredentialError, "layoutId"):
            holder.generate_authenticated_proof(apr, request, now=now)
        result = verifier.verify_authenticated(apr, envelope, verification, now=now)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes(), result.to_dict())

        for invalid_layout in (None, "0x2", field_to_hex(0), LAYOUT_B[:-1] + "A", True):
            with self.subTest(layout=invalid_layout):
                parameters[proof_type]["layoutId"] = invalid_layout
                self.assertIn(Code.REQUIREMENTS_NOT_MET, verifier.verify(envelope, verification).codes())


if __name__ == "__main__":
    unittest.main()
