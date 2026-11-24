"""Verifier enforcement for the issuer-authenticated rebind successors.

Spec section 7.4.5: a successor proof is accepted ONLY when its exact issuer
public key is trusted for that proof type, its authenticated issuer identity
matches that trusted issuer, and the verifier holds an AUTHENTICATED
(metadata-v2 announcement-chain) accumulator state whose current epoch, lag
window and recorded root all admit the proof's revocation claim. Request pins
are applied afterwards and can only narrow acceptance.

The accumulator state here is genuinely authenticated: it is produced by
``VerifierAccumulatorCache.ingest_metadata`` over a real signed issuer
announcement, not hand-built, so "the verifier requires authenticated
revocation state" is tested against the real ingestion path.

Every rejection asserts a specific ``VerificationErrorCode`` and has an honest
control proving the fixture can accept when nothing is tampered with.
"""

import copy
import datetime
import unittest

import _path  # noqa: F401  (sys.path side effect)
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import apr_verifier_identity
from _path import REPO_ROOT

from zkc_revocation.chain import AnnouncementKeyPin

from zkc_crypto import (
    ProofContext,
    compute_claim_binding_3,
    compute_rebind_attestation_digest,
    derive_credential_binding_key,
    derive_holder_commitment,
    digest_to_message_bytes,
    field_to_hex,
    hex_to_field,
    string_to_field,
)
from zkc_crypto.ecdsa_secp256k1 import sign
from zkc_crypto.presentation import (
    ANONYMOUS_PROFILE,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
    derive_presentation_pseudonym,
)
from zkc_crypto.stub import stub_proof_payload
from zkc_holder.rebind_secret import RebindSecret
from zkc_holder import AccumulatorWitness, Credential, StubBackend
from zkc_holder.credential import RebindAttestation
from zkc_holder.predicates import (
    REBIND_AUTH_CIRCUIT,
    REBIND_AUTH_PROOF_TYPE,
    REBIND_AUTH_V2_CIRCUIT,
    REBIND_AUTH_V2_PROOF_TYPE,
    build_rebind_auth_witness,
    build_rebind_auth_witness_v2,
)
from zkc_issuer import IssuerSigningKey, SandboxIssuerAdapter
from zkc_revocation import (
    InMemoryVerifierCheckpointStore,
    RevocationAccumulatorService,
    VerifierAccumulatorCache,
)
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer
from zkc_verifier.errors import VerificationErrorCode as Code

ISSUER_ID = "zkc:issuer:sandbox"
ACCUMULATOR_ID = "sandbox-active-credentials"
SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
MASTER_SEED = 4242
NEW_SEED = 99
CREDENTIAL_ID = 4242_0001
SCHEMA_ID = "zkc:cred:kyc:v1"
VALID_FROM = 1_000
VALID_UNTIL = 2_000_000_000
TIMESTAMP = 1_770_000_000
SESSION_ID = 555
SCOPE_ID = 0x5C0DE


def _context() -> ProofContext:
    return ProofContext.verifier_session("verifier.example", SESSION_ID, TIMESTAMP)


def _rfc3339(timestamp: int) -> str:
    return (
        datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


class RebindAuthVerifierBase(unittest.TestCase):
    """One live credential, one authenticated accumulator state, two proofs."""

    def setUp(self):
        self.service = RevocationAccumulatorService(
            ACCUMULATOR_ID,
            "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
            SIGNING_KEY,
            clock=lambda: TIMESTAMP,
        )
        self.service.register(CREDENTIAL_ID)
        self.adapter = SandboxIssuerAdapter(
            signing_key=SIGNING_KEY, accumulator=self.service, clock=lambda: TIMESTAMP
        )
        self.cache = VerifierAccumulatorCache(
            {ISSUER_ID: {SIGNING_KEY.key_id: AnnouncementKeyPin.from_signing_key_entry(
                SIGNING_KEY.metadata_entry()
            )}},
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: TIMESTAMP,
            max_announcement_age=3600,
        )
        self.cache.ingest_metadata(ISSUER_ID, self.adapter.issuer_metadata())
        self.authenticated_state = self.cache.state(ISSUER_ID)

        witness_dict = self.service.witness(CREDENTIAL_ID)
        self.witness = AccumulatorWitness.from_dict(witness_dict)
        self.current_epoch = self.authenticated_state.current_epoch

        self.old_cbk = derive_credential_binding_key(MASTER_SEED)
        self.new_cbk = derive_credential_binding_key(NEW_SEED)
        self.credential = self._credential()
        self.backend = StubBackend()
        self.context = _context()

    def _credential(self, **overrides) -> Credential:
        holder = derive_holder_commitment(self.old_cbk)
        digest = compute_rebind_attestation_digest(
            string_to_field(overrides.get("issuer_id", ISSUER_ID)),
            string_to_field(SCHEMA_ID),
            holder,
            CREDENTIAL_ID,
            VALID_FROM,
            VALID_UNTIL,
        )
        return Credential(
            credential_type="zkc:cred:kyc:v1",
            proof_type=REBIND_AUTH_PROOF_TYPE,
            issuer_id=overrides.get("issuer_id", ISSUER_ID),
            holder_commitment=holder,
            credential_id=CREDENTIAL_ID,
            claims={"validFrom": VALID_FROM, "validUntil": VALID_UNTIL},
            expires_at=VALID_UNTIL,
            signature=bytes(64),
            witness=self.witness,
            rebind_attestation=RebindAttestation(
                schema_id=SCHEMA_ID,
                valid_from=VALID_FROM,
                valid_until=VALID_UNTIL,
                signature=sign(
                    digest_to_message_bytes(digest),
                    overrides.get("signing_key", SIGNING_KEY.private_key),
                ),
            ),
        )

    # --- witnesses and envelopes ------------------------------------------

    def witness_for(self, *, scoped=False, credential=None, **overrides):
        common = {
            "old_credential_binding_key": self.old_cbk,
            "new_credential_binding_key": self.new_cbk,
            "credential": credential or self.credential,
            "issuer_public_key_x": KEY_X,
            "issuer_public_key_y": KEY_Y,
            "accumulator_witness": self.witness,
            "current_epoch": self.current_epoch,
            "proof_context": self.context.value,
            "timestamp": self.context.timestamp,
        }
        common.update(overrides)
        if scoped:
            return build_rebind_auth_witness_v2(scope_id=SCOPE_ID, **common)
        return build_rebind_auth_witness(**common)

    def envelope(self, *, scoped=False, witness=None, **overrides):
        witness = witness or self.witness_for(scoped=scoped)
        circuit = REBIND_AUTH_V2_CIRCUIT if scoped else REBIND_AUTH_CIRCUIT
        proof_type = REBIND_AUTH_V2_PROOF_TYPE if scoped else REBIND_AUTH_PROOF_TYPE
        entry = {
            "proofType": proof_type,
            "proof": self.backend.prove(circuit, witness),
            "publicInputs": self.backend.public_inputs(circuit, witness),
            "principalConsent": True,
        }
        metadata = {
            # Freshness is derived from the context timestamp so the envelope is
            # never incidentally stale: this suite tests credential
            # authentication, not the (separately covered) freshness rules.
            "generatedAt": _rfc3339(TIMESTAMP),
            "expiresAt": _rfc3339(TIMESTAMP + 86_400),
            "context": self.context.to_metadata(),
        }
        if scoped:
            return {
                "version": "zkc:proof:v2",
                "metadata": metadata,
                "proofs": [entry],
                "presentationBinding": {
                    "profile": SCOPED_PROFILE,
                    "pseudonym": field_to_hex(witness["old_presentation_pseudonym"]),
                    "scopeId": field_to_hex(SCOPE_ID),
                },
            }
        return {
            "version": "zkc:proof:v1",
            "metadata": metadata,
            "proofs": [entry],
            "holderBinding": {"commitment": field_to_hex(witness["old_holder_commitment"])},
        }

    def reseal(self, envelope, *, scoped=False):
        """Re-sign the stub proof so a mutated publicInputs still passes the
        backend: the rejection under test must be the verifier's own."""
        entry = envelope["proofs"][0]
        circuit = REBIND_AUTH_V2_CIRCUIT if scoped else REBIND_AUTH_CIRCUIT
        entry["proof"] = stub_proof_payload(circuit, entry["publicInputs"])
        return envelope

    # --- verifier and request ----------------------------------------------

    def policy(self, *, proof_types=None, issuer_id=ISSUER_ID, key=(KEY_X, KEY_Y)):
        proof_types = proof_types or (REBIND_AUTH_PROOF_TYPE, REBIND_AUTH_V2_PROOF_TYPE)
        return VerifierTrustPolicy(
            **apr_verifier_identity(),
            issuers=(
                VerifierTrustedIssuer(
                    issuer_id=issuer_id,
                    public_key_x=key[0],
                    public_key_y=key[1],
                    proof_types=tuple(proof_types),
                ),
            ),
            accepted_profiles=(ANONYMOUS_PROFILE, SCOPED_PROFILE, LINKABLE_PROFILE),
        )

    def verifier(self, policy=None):
        return ZKCVerifier(REPO_ROOT, policy or self.policy(), StubVerifyBackend())

    def request(self, *, scoped=False, parameters=None, states=None):
        proof_type = REBIND_AUTH_V2_PROOF_TYPE if scoped else REBIND_AUTH_PROOF_TYPE
        return VerificationRequest(
            proof_types=[proof_type],
            parameters={proof_type: {} if parameters is None else parameters},
            context=self.context,
            max_proof_age=3600,
            accumulator_states=(
                {ISSUER_ID: self.authenticated_state} if states is None else states
            ),
        )

    def assert_codes(self, result, codes):
        self.assertEqual(sorted(set(result.codes())), sorted(set(codes)), result.to_dict())


class AcceptanceTests(RebindAuthVerifierBase):
    """The honest controls: a live, issuer-authenticated, non-revoked
    credential verifies under both profiles."""

    def test_linkable_successor_verifies(self):
        result = self.verifier().verify(self.envelope(), self.request())
        self.assertTrue(result.valid, result.to_dict())

    def test_scoped_successor_verifies(self):
        result = self.verifier().verify(
            self.envelope(scoped=True), self.request(scoped=True)
        )
        self.assertTrue(result.valid, result.to_dict())

    def test_optional_schema_pin_narrows_but_does_not_authenticate(self):
        envelope = self.envelope()
        verifier = self.verifier()
        matching = self.request(parameters={"schemaIdHash": string_to_field(SCHEMA_ID)})
        self.assertTrue(verifier.verify(envelope, matching).valid)
        wrong = self.request(parameters={"schemaIdHash": string_to_field(SCHEMA_ID) + 1})
        self.assert_codes(verifier.verify(envelope, wrong), [Code.REQUIREMENTS_NOT_MET])


class IssuerTrustTests(RebindAuthVerifierBase):
    def test_empty_trust_policy_rejects(self):
        verifier = ZKCVerifier(
            REPO_ROOT, VerifierTrustPolicy(**apr_verifier_identity(), issuers=()), StubVerifyBackend()
        )
        self.assert_codes(
            verifier.verify(self.envelope(), self.request()), [Code.UNTRUSTED_ISSUER]
        )

    def test_untrusted_key_rejects(self):
        other_x = bytes([KEY_X[0] ^ 0x01]) + KEY_X[1:]
        policy = self.policy(key=(other_x, KEY_Y))
        self.assert_codes(
            self.verifier(policy).verify(self.envelope(), self.request()),
            [Code.UNTRUSTED_ISSUER],
        )

    def test_key_trusted_for_a_different_proof_type_rejects(self):
        policy = self.policy(proof_types=("zkc:proof:kyc:v1",))
        self.assert_codes(
            self.verifier(policy).verify(self.envelope(), self.request()),
            [Code.UNTRUSTED_ISSUER],
        )

    def test_issuer_identity_must_match_the_trusted_issuer(self):
        """A trusted KEY carrying an attestation labelled with a different
        issuer identity is rejected: the label is authenticated, so a mismatch
        means the verifier is not looking at the issuer it thinks it is."""
        policy = self.policy(issuer_id="zkc:issuer:someone-else")
        result = self.verifier(policy).verify(self.envelope(), self.request())
        self.assertIn(Code.UNTRUSTED_ISSUER, result.codes())

    def test_request_pins_never_rescue_an_untrusted_proof(self):
        """AC4: a matching pin cannot make an otherwise untrusted proof valid."""
        verifier = ZKCVerifier(
            REPO_ROOT, VerifierTrustPolicy(**apr_verifier_identity(), issuers=()), StubVerifyBackend()
        )
        result = verifier.verify(
            self.envelope(),
            self.request(parameters={"schemaIdHash": string_to_field(SCHEMA_ID)}),
        )
        self.assertFalse(result.valid)
        self.assertIn(Code.UNTRUSTED_ISSUER, result.codes())


class AuthenticatedRevocationTests(RebindAuthVerifierBase):
    def test_missing_accumulator_state_rejects(self):
        self.assert_codes(
            self.verifier().verify(self.envelope(), self.request(states={})),
            [Code.STALE_ACCUMULATOR],
        )

    def test_unauthenticated_accumulator_state_rejects(self):
        """A bare epoch view is not revocation authentication, even when its
        numbers agree with the proof."""
        unauthenticated = IssuerAccumulatorState(
            current_epoch=self.current_epoch,
            roots={self.witness.accumulator_epoch: self.witness.accumulator_root},
        )
        self.assertFalse(unauthenticated.authenticated)
        self.assert_codes(
            self.verifier().verify(
                self.envelope(), self.request(states={ISSUER_ID: unauthenticated})
            ),
            [Code.UNAUTHENTICATED_ACCUMULATOR],
        )

    def test_root_not_recorded_by_the_authenticated_state_rejects(self):
        envelope = self.envelope()
        entry = envelope["proofs"][0]
        entry["publicInputs"]["accumulator_root"] = field_to_hex(
            hex_to_field(entry["publicInputs"]["accumulator_root"]) + 1
        )
        self.reseal(envelope)
        self.assert_codes(
            self.verifier().verify(envelope, self.request()), [Code.STALE_ACCUMULATOR]
        )

    def test_stale_and_future_epochs_reject(self):
        for delta, label in ((+1, "future"), (-1, "stale")):
            with self.subTest(case=label):
                envelope = self.envelope()
                entry = envelope["proofs"][0]
                entry["publicInputs"]["current_epoch"] = self.current_epoch + delta
                self.reseal(envelope)
                result = self.verifier().verify(envelope, self.request())
                self.assertIn(Code.STALE_ACCUMULATOR, result.codes())

    def test_accumulator_epoch_ahead_of_the_verifier_view_rejects(self):
        envelope = self.envelope()
        entry = envelope["proofs"][0]
        entry["publicInputs"]["accumulator_epoch"] = self.current_epoch + 5
        self.reseal(envelope)
        result = self.verifier().verify(envelope, self.request())
        self.assertIn(Code.STALE_ACCUMULATOR, result.codes())


class EnvelopeBindingTests(RebindAuthVerifierBase):
    def test_linkable_envelope_must_bind_the_old_holder(self):
        envelope = self.envelope()
        envelope["holderBinding"]["commitment"] = field_to_hex(
            derive_holder_commitment(self.new_cbk)
        )
        self.assert_codes(
            self.verifier().verify(envelope, self.request()), [Code.INVALID_BINDING]
        )

    def test_scoped_envelope_must_bind_the_old_pseudonym_and_scope(self):
        envelope = self.envelope(scoped=True)
        envelope["presentationBinding"]["pseudonym"] = field_to_hex(
            derive_presentation_pseudonym(self.new_cbk, SCOPE_ID)
        )
        result = self.verifier().verify(envelope, self.request(scoped=True))
        self.assertIn(Code.PROFILE_MISMATCH, result.codes())

        envelope = self.envelope(scoped=True)
        envelope["presentationBinding"]["scopeId"] = field_to_hex(SCOPE_ID + 1)
        result = self.verifier().verify(envelope, self.request(scoped=True))
        self.assertIn(Code.PROFILE_MISMATCH, result.codes())

    def test_context_and_timestamp_must_match_the_request(self):
        envelope = self.envelope()
        entry = envelope["proofs"][0]
        entry["publicInputs"]["proof_context"] = field_to_hex(
            hex_to_field(entry["publicInputs"]["proof_context"]) + 1
        )
        self.reseal(envelope)
        result = self.verifier().verify(envelope, self.request())
        self.assertIn(Code.CONTEXT_MISMATCH, result.codes())

    def test_claim_binding_must_attest_the_public_inputs(self):
        envelope = self.envelope()
        entry = envelope["proofs"][0]
        entry["publicInputs"]["credential_id"] = field_to_hex(
            hex_to_field(entry["publicInputs"]["credential_id"]) + 1
        )
        self.reseal(envelope)
        result = self.verifier().verify(envelope, self.request())
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())

    def test_no_op_rebind_rejects(self):
        envelope = self.envelope()
        entry = envelope["proofs"][0]
        old = entry["publicInputs"]["old_holder_commitment"]
        entry["publicInputs"]["new_holder_commitment"] = old
        entry["publicInputs"]["claim_binding"] = field_to_hex(
            compute_claim_binding_3(
                hex_to_field(old),
                hex_to_field(old),
                hex_to_field(entry["publicInputs"]["credential_id"]),
                self.context.value,
                self.context.timestamp,
            )
        )
        self.reseal(envelope)
        result = self.verifier().verify(envelope, self.request())
        self.assertIn(Code.INVALID_BINDING, result.codes())

    def test_malformed_public_inputs_fail_closed(self):
        envelope = self.envelope()
        del envelope["proofs"][0]["publicInputs"]["issuer_public_key_x"]
        self.reseal(envelope)
        self.assert_codes(
            self.verifier().verify(envelope, self.request()), [Code.MALFORMED_PROOF]
        )


class RelabellingAndDowngradeTests(RebindAuthVerifierBase):
    def test_successor_relabelled_as_a_deprecated_identity_is_contained(self):
        """A downgrade attempt hits the containment gate, not a structural check."""
        for deprecated in (
            "zkc:proof:credential_rebind:v1",
            "zkc:proof:credential_rebind:v2",
        ):
            with self.subTest(deprecated=deprecated):
                envelope = copy.deepcopy(self.envelope())
                envelope["proofs"][0]["proofType"] = deprecated
                request = VerificationRequest(
                    proof_types=[deprecated],
                    parameters={deprecated: {}},
                    context=self.context,
                    max_proof_age=3600,
                    accumulator_states={ISSUER_ID: self.authenticated_state},
                )
                self.assert_codes(
                    self.verifier().verify(envelope, request),
                    [Code.UNAUTHENTICATED_CREDENTIAL],
                )

    def test_cross_profile_relabelling_rejects(self):
        envelope = copy.deepcopy(self.envelope())
        envelope["proofs"][0]["proofType"] = REBIND_AUTH_V2_PROOF_TYPE
        result = self.verifier().verify(envelope, self.request(scoped=True))
        self.assertFalse(result.valid, result.to_dict())
        self.assertNotIn(Code.UNAUTHENTICATED_CREDENTIAL, result.codes())

    def test_scoped_successor_presented_in_a_linkable_envelope_rejects(self):
        witness = self.witness_for(scoped=True)
        envelope = self.envelope(scoped=False, witness=self.witness_for())
        envelope["proofs"][0]["proofType"] = REBIND_AUTH_V2_PROOF_TYPE
        envelope["proofs"][0]["publicInputs"] = self.backend.public_inputs(
            REBIND_AUTH_V2_CIRCUIT, witness
        )
        self.reseal(envelope, scoped=True)
        result = self.verifier().verify(envelope, self.request(scoped=True))
        self.assertFalse(result.valid, result.to_dict())


class EntryPointParityTests(RebindAuthVerifierBase):
    """AC3: verify() and verify_authenticated() apply the same credential
    authentication and revocation semantics."""

    def _apr(self, proof_type, parameters, presentation=None):
        from zkc_crypto import sign_apr

        request = {
            "proofTypes": [proof_type],
            "parameters": {proof_type: dict(parameters)},
            "context": {
                "profile": self.context.profile,
                "verifierId": "verifier.example",
                "sessionId": field_to_hex(SESSION_ID),
                "timestamp": TIMESTAMP,
            },
            "trustPolicy": {"issuers": []},
        }
        if presentation is not None:
            request["presentation"] = presentation
        return sign_apr(
            {
                "request": request,
                "verifierId": "verifier.example",
                "nonce": field_to_hex(0xABC123),
                "issuedAt": TIMESTAMP,
                "expiresAt": TIMESTAMP + 3600,
            },
            0xA9701,
        )

    def test_authenticated_entry_point_accepts_the_same_live_credential(self):
        result = self.verifier().verify_authenticated(
            self._apr(REBIND_AUTH_PROOF_TYPE, {}), self.envelope(), self.request(),
            now=self.request().context.timestamp
        )
        self.assertTrue(result.valid, result.to_dict())

    def test_apr_does_not_substitute_for_issuer_trust(self):
        """An APR authenticates the REQUESTER; it never authenticates a
        credential, so an empty trust policy still rejects."""
        verifier = ZKCVerifier(
            REPO_ROOT, VerifierTrustPolicy(**apr_verifier_identity(), issuers=()), StubVerifyBackend()
        )
        result = verifier.verify_authenticated(
            self._apr(REBIND_AUTH_PROOF_TYPE, {}), self.envelope(), self.request(),
            now=self.request().context.timestamp
        )
        self.assertFalse(result.valid)
        self.assertIn(Code.UNTRUSTED_ISSUER, result.codes())

    def test_apr_does_not_substitute_for_authenticated_revocation(self):
        result = self.verifier().verify_authenticated(
            self._apr(REBIND_AUTH_PROOF_TYPE, {}),
            self.envelope(),
            self.request(states={}),
            now=self.request(states={}).context.timestamp,
        )
        self.assertFalse(result.valid)
        self.assertIn(Code.STALE_ACCUMULATOR, result.codes())

    def test_both_entry_points_agree_on_the_rejection_matrix(self):
        cases = {
            "untrusted": (
                ZKCVerifier(REPO_ROOT, VerifierTrustPolicy(**apr_verifier_identity(), issuers=()), StubVerifyBackend()),
                self.request(),
            ),
            "no-accumulator-state": (self.verifier(), self.request(states={})),
        }
        for label, (verifier, request) in cases.items():
            with self.subTest(case=label):
                envelope = self.envelope()
                unauthenticated = verifier.verify(envelope, request)
                authenticated = verifier.verify_authenticated(
                    self._apr(REBIND_AUTH_PROOF_TYPE, {}), envelope, request,
                    now=request.context.timestamp
                )
                self.assertFalse(unauthenticated.valid)
                self.assertFalse(authenticated.valid)
                self.assertEqual(
                    sorted(set(unauthenticated.codes())),
                    sorted(set(authenticated.codes())),
                )


class PublicApiRoundTripTests(RebindAuthVerifierBase):
    """AC1: the shipped holder API routes a rebind to the successors and the
    reference verifier accepts the result -- no test-only witness assembly."""

    def _holder(self, proof_types=(REBIND_AUTH_PROOF_TYPE, REBIND_AUTH_V2_PROOF_TYPE), **holder_options):
        from zkc_holder import HolderClient, PredicateRegistry, TrustPolicy
        from zkc_holder import TrustedIssuer as HolderTrustedIssuer

        holder = HolderClient.from_seed(
            MASTER_SEED, PredicateRegistry.from_repo(REPO_ROOT), StubBackend(), **holder_options
        )
        holder.store_credential(self.credential)
        trust_policy = TrustPolicy(
            issuers=(
                HolderTrustedIssuer(
                    issuer_id=ISSUER_ID,
                    public_key_x=KEY_X,
                    public_key_y=KEY_Y,
                    proof_types=proof_types,
                ),
            )
        )
        return holder, trust_policy

    def _request(self, proof_type, trust_policy, profile=LINKABLE_PROFILE):
        from zkc_holder import ProofRequest

        return ProofRequest(
            proof_types=[proof_type],
            parameters={proof_type: {"credentialId": CREDENTIAL_ID}},
            context=self.context,
            trust_policy=trust_policy,
            presentation_profile=profile,
            rebind_secret=RebindSecret(self.new_cbk),
        )

    def test_linkable_round_trip_through_generate_proof(self):
        holder, trust_policy = self._holder()
        envelope = generate_unauthenticated_linkable(
            holder, self._request(REBIND_AUTH_PROOF_TYPE, trust_policy)
        )
        self.assertEqual(envelope["proofs"][0]["proofType"], REBIND_AUTH_PROOF_TYPE)
        # The holder refreshed nothing it could not authenticate: the envelope
        # binds the old holder commitment the issuer signed for.
        self.assertEqual(
            envelope["holderBinding"]["commitment"],
            field_to_hex(derive_holder_commitment(self.old_cbk)),
        )
        result = self.verifier().verify(envelope, self.request())
        self.assertTrue(result.valid, result.to_dict())

    def test_scoped_round_trip_through_generate_proof(self):
        from zkc_holder.client import _Presentation

        holder, trust_policy = self._holder()
        envelope = holder._generate_envelope(
            self._request(REBIND_AUTH_PROOF_TYPE, trust_policy, SCOPED_PROFILE),
            _Presentation(SCOPED_PROFILE, SCOPE_ID),
        )
        self.assertEqual(envelope["proofs"][0]["proofType"], REBIND_AUTH_V2_PROOF_TYPE)
        self.assertEqual(
            envelope["presentationBinding"]["pseudonym"],
            field_to_hex(derive_presentation_pseudonym(self.old_cbk, SCOPE_ID)),
        )
        result = self.verifier().verify(envelope, self.request(scoped=True))
        self.assertTrue(result.valid, result.to_dict())

    def test_holder_refuses_a_credential_without_an_attestation(self):
        from zkc_holder.errors import NoMatchingCredentialError

        holder, trust_policy = self._holder()
        bare = self._credential()
        bare.rebind_attestation = None
        holder.store_credential(bare)
        with self.assertRaises(NoMatchingCredentialError):
            generate_unauthenticated_linkable(holder, self._request(REBIND_AUTH_PROOF_TYPE, trust_policy))

    def test_holder_requires_the_request_to_name_the_credential(self):
        from zkc_holder import ProofRequest
        from zkc_holder.errors import HolderError

        holder, trust_policy = self._holder()
        request = ProofRequest(
            proof_types=[REBIND_AUTH_PROOF_TYPE],
            parameters={REBIND_AUTH_PROOF_TYPE: {}},
            context=self.context,
            trust_policy=trust_policy,
            rebind_secret=RebindSecret(self.new_cbk),
        )
        with self.assertRaises(HolderError) as ctx:
            generate_unauthenticated_linkable(holder, request)
        self.assertIn("credentialId", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
