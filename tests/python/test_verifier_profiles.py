"""Verifier presentation-profile gate + anti-replay shape checks (design §6
rules 1-2).

``ZKCVerifier.verify()`` version-dispatches on the envelope: a ``zkc:proof:v1``
envelope (``holderBinding``) takes the existing, FROZEN v1 path unchanged and is
never gated; a ``zkc:proof:v2`` envelope (``presentationBinding``) runs the
presentation-profile machinery:

1. Policy gate — ``presentationBinding.profile`` must be in
   ``TrustPolicy.accepted_profiles`` (default {anonymous, scoped}), else
   ``PROFILE_NOT_ACCEPTED``.
2. Shape consistency (anti-replay) — every proof entry's public inputs must
   match the envelope binding's profile: anonymous ⇒ both handles are the
   anonymous sentinel; scoped ⇒ pseudonym/scopeId equal the binding's. Any
   mismatch ⇒ ``PROFILE_MISMATCH``. This replaces the v1 holder_commitment
   envelope-vs-proof check for v2 envelopes.
"""

import copy
import dataclasses
import unittest
from unittest.mock import patch

import _path  # noqa: F401  (sys.path side effect)
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import apr_verifier_identity

from holder_fixtures import (
    DRAFT_OPT_IN_REVIEW_STATUSES,
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_kyc_credential,
    trusted_test_issuer,
)
from zkc_crypto import ProofContext, field_to_hex, hex_to_field, sign_apr
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes
from zkc_crypto.apr import (
    VERIFICATION_CONTEXT_EXTENSION,
    apr_digest_from_dict,
    verification_context_extension,
    verify_apr_signature,
)
from holder_fixtures import verify_receipt_as_holder
from zkc_crypto.presentation import (
    ANONYMOUS_PROFILE,
    SCOPED_PROFILE,
)
from zkc_holder.rebind_secret import RebindSecret
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_holder.errors import UnauthenticatedRequestError
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    TrustedIssuer,
    VerificationErrorCode as Code,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)

from _path import REPO_ROOT

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
MASTER_SEED = 42
SESSION_ID = 555
TIMESTAMP = 1_700_000_000

KYC_V1_PROOF_TYPE = "zkc:proof:kyc:v1"
KYC_V2_PROOF_TYPE = "zkc:proof:kyc:v2"

KYC_PARAMETERS = {
    KYC_PROOF_TYPE: {
        "requiredLevel": 1,
        "requiredAttributes": [True, False, True, False, False],
    }
}

# A well-known APR verifier signing key (TEST-ONLY, public material).
APR_VERIFIER_PRIVATE_KEY = 0xA9701 % N or 1
APR_VERIFIER_KEY_X, APR_VERIFIER_KEY_Y = public_key_bytes(APR_VERIFIER_PRIVATE_KEY)


def verifier_session_context_fixture() -> dict:
    return {
        "profile": "zkc:context:verifier-session:v1",
        "verifierId": "verifier.example",
        "sessionId": field_to_hex(SESSION_ID),
        "timestamp": TIMESTAMP,
    }


def issuer_entry(proof_types=(KYC_V2_PROOF_TYPE,)):
    return TrustedIssuer(
        issuer_id=TEST_ISSUER_ID,
        public_key_x=TEST_ISSUER_KEY_X,
        public_key_y=TEST_ISSUER_KEY_Y,
        proof_types=tuple(proof_types),
    )


class ProfileVerifierBase(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.holder = HolderClient.from_seed(
            MASTER_SEED,
            REGISTRY,
            StubBackend(),
            accumulator_provider=self.provider,
            accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        self.credential = issue_kyc_credential(
            master_seed=MASTER_SEED,
            credential_id=7,
            provider=self.provider,
            expires_at=2_000_000_000,
        )
        self.holder.store_credential(self.credential)
        self.context = ProofContext.verifier_session("verifier.example", SESSION_ID, TIMESTAMP)
        self.accumulator_states = {
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                roots=self.provider.roots(TEST_ISSUER_ID),
            )
        }

    def make_request(self, *, presentation_profile=ANONYMOUS_PROFILE,
                     allow_protocol_scope=False):
        return ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=copy.deepcopy(KYC_PARAMETERS),
            context=self.context,
            trust_policy=TrustPolicy(
                issuers=(trusted_test_issuer((KYC_V2_PROOF_TYPE,)),)
            ),
            presentation_profile=presentation_profile,
            allow_protocol_scope=allow_protocol_scope,
        )

    def make_apr(self, *, presentation=None, nonce=0xABC123,
                 private_key=APR_VERIFIER_PRIVATE_KEY):
        request = {
            "proofTypes": [KYC_PROOF_TYPE],
            "parameters": copy.deepcopy(KYC_PARAMETERS),
            "context": verifier_session_context_fixture(),
            "trustPolicy": {"issuers": []},
        }
        if presentation is not None:
            request["presentation"] = presentation
        unsigned = {
            "request": request,
            "verifierId": "verifier.example",
            "nonce": field_to_hex(nonce),
            "issuedAt": TIMESTAMP,
            "expiresAt": TIMESTAMP + 3600,
        }
        return sign_apr(unsigned, private_key)

    def anonymous_envelope(self):
        apr = self.make_apr(presentation=None)
        request = self.make_request(presentation_profile=ANONYMOUS_PROFILE)
        return self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)["envelope"]

    def scoped_envelope(self):
        apr = self.make_apr(
            presentation={"profile": SCOPED_PROFILE, "scopePolicy": "verifier",
                          "rotationEpochSeconds": 0}
        )
        request = self.make_request(presentation_profile=SCOPED_PROFILE)
        return self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)["envelope"]

    def make_verifier(self, policy=None):
        return ZKCVerifier(
            REPO_ROOT,
            policy or VerifierTrustPolicy(**apr_verifier_identity(), issuers=(issuer_entry(),)),
            StubVerifyBackend(),
        )

    def make_verification_request(self, proof_types=(KYC_V2_PROOF_TYPE,)):
        return VerificationRequest(
            proof_types=list(proof_types),
            parameters={pt: copy.deepcopy(KYC_PARAMETERS[KYC_PROOF_TYPE]) for pt in proof_types},
            context=self.context,
            max_proof_age=3600,
            accumulator_states=dict(self.accumulator_states),
        )


class AcceptanceTests(ProfileVerifierBase):
    def test_valid_anonymous_v2_verifies(self):
        envelope = self.anonymous_envelope()
        result = self.make_verifier().verify(envelope, self.make_verification_request())
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)

    def test_valid_scoped_v2_verifies(self):
        envelope = self.scoped_envelope()
        result = self.make_verifier().verify(envelope, self.make_verification_request())
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)


class ProfileMismatchTests(ProfileVerifierBase):
    def test_scoped_proof_entries_under_anonymous_binding(self):
        # The replay case: an anonymous presentationBinding, but the proof
        # public inputs carry a scoped pseudonym/scope_id — shape inconsistency.
        scoped = self.scoped_envelope()
        anonymous = self.anonymous_envelope()
        forged = copy.deepcopy(anonymous)
        # Splice the scoped proof entries under the anonymous binding.
        forged["proofs"] = copy.deepcopy(scoped["proofs"])
        result = self.make_verifier().verify(forged, self.make_verification_request())
        self.assertIn(Code.PROFILE_MISMATCH, result.codes())
        self.assertFalse(result.valid)

    def test_proof_pseudonym_differs_from_binding(self):
        # A scoped envelope whose per-proof pseudonym no longer matches the
        # envelope binding pseudonym — anti-replay shape check. The proof itself
        # stays valid (the stub backend digests the public inputs); it is the
        # ENVELOPE binding that is swapped, exactly the replay the shape check
        # must catch without relying on proof invalidity.
        envelope = self.scoped_envelope()
        forged = copy.deepcopy(envelope)
        forged["presentationBinding"]["pseudonym"] = field_to_hex(0xDEAD)
        result = self.make_verifier().verify(forged, self.make_verification_request())
        self.assertIn(Code.PROFILE_MISMATCH, result.codes())
        self.assertFalse(result.valid)


class ProfileNotAcceptedTests(ProfileVerifierBase):
    def test_v2_profile_not_in_accepted_profiles(self):
        # A verifier policy that accepts only the anonymous profile rejects a
        # scoped v2 envelope with PROFILE_NOT_ACCEPTED (the gate is v2-only).
        policy = VerifierTrustPolicy(
            **apr_verifier_identity(),
            issuers=(issuer_entry(),),
            accepted_profiles=(ANONYMOUS_PROFILE,),
        )
        envelope = self.scoped_envelope()
        result = self.make_verifier(policy=policy).verify(
            envelope, self.make_verification_request()
        )
        self.assertIn(Code.PROFILE_NOT_ACCEPTED, result.codes())
        self.assertFalse(result.valid)


class V1BackwardCompatTests(ProfileVerifierBase):
    """A v1 envelope must verify EXACTLY as before — never gated by the v2
    profile machinery (design §6 correction: v1 is implicitly linkable and is
    not gated at verify time)."""

    def v1_envelope(self):
        return generate_unauthenticated_linkable(
            self.holder, ProofRequest(
                proof_types=[KYC_V1_PROOF_TYPE],
                parameters=copy.deepcopy(KYC_PARAMETERS),
                context=self.context,
                trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
            )
        )

    def test_v1_envelope_verifies_ungated_by_default(self):
        envelope = self.v1_envelope()
        self.assertEqual(envelope["version"], "zkc:proof:v1")
        self.assertIn("holderBinding", envelope)
        policy = VerifierTrustPolicy(**apr_verifier_identity(), issuers=(issuer_entry(proof_types=(KYC_V1_PROOF_TYPE,)),))
        request = self.make_verification_request(proof_types=(KYC_V1_PROOF_TYPE,))
        result = self.make_verifier(policy=policy).verify(envelope, request)
        # v1 is ungated: no profile error surfaces regardless of accepted_profiles.
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)


# A SECOND, distinct APR verifier signing key (TEST-ONLY, public material). Used
# to model "the same scoped envelope presented to a DIFFERENT authenticated
# verifier": its scope recomputes to a different scope_id.
APR_VERIFIER_B_PRIVATE_KEY = 0xB0B0B % N or 2
APR_VERIFIER_B_KEY_X, APR_VERIFIER_B_KEY_Y = public_key_bytes(APR_VERIFIER_B_PRIVATE_KEY)


class ScopeRecomputationTests(ProfileVerifierBase):
    """Scope recomputation on the authenticated path (design §6 rule 3).

    ``verify_authenticated`` recomputes ``scope_id`` from the verifier's OWN
    authenticated identity (``derive_verifier_identity`` of the APR signer key)
    + the APR ``scopePolicy`` + the rotation epoch, and compares it to
    ``presentationBinding.scopeId``. A verifier cannot accept a scoped proof for
    a scope not derived from its own pinned identity. Named protocol scopes
    additionally require a verifier declaration.
    """

    def scoped_apr(self, *, private_key=APR_VERIFIER_PRIVATE_KEY,
                   scope_policy="verifier", rotation_epoch_seconds=0):
        return self.make_apr(
            presentation={
                "profile": SCOPED_PROFILE,
                "scopePolicy": scope_policy,
                "rotationEpochSeconds": rotation_epoch_seconds,
            },
            private_key=private_key,
        )

    def scoped_envelope_for(self, apr, *, allow_protocol_scope=False):
        request = self.make_request(
            presentation_profile=SCOPED_PROFILE,
            allow_protocol_scope=allow_protocol_scope,
        )
        return self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)["envelope"]

    def test_scoped_scope_matches_own_recomputation(self):
        # A scoped envelope whose scopeId equals the verifier's OWN recomputation
        # (its own APR signer identity + scopePolicy + rotation epoch) verifies.
        apr = self.scoped_apr()
        envelope = self.scoped_envelope_for(apr)
        result = self.make_verifier().verify_authenticated(
            apr, envelope, self.make_verification_request(),
            now=self.make_verification_request().context.timestamp
        )
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)

    def test_scope_for_verifier_a_presented_to_verifier_b(self):
        # The holder derived scope from verifier A's authenticated identity; the
        # same envelope presented under verifier B's (validly signed) APR
        # recomputes to a DIFFERENT scope_id -> SCOPE_MISMATCH.
        apr_a = self.scoped_apr(private_key=APR_VERIFIER_PRIVATE_KEY)
        envelope = self.scoped_envelope_for(apr_a)
        apr_b = self.scoped_apr(private_key=APR_VERIFIER_B_PRIVATE_KEY)
        policy = VerifierTrustPolicy(issuers=(issuer_entry(),),
                                     **apr_verifier_identity(APR_VERIFIER_B_PRIVATE_KEY))
        result = self.make_verifier(policy).verify_authenticated(
            apr_b, envelope, self.make_verification_request(),
            now=self.make_verification_request().context.timestamp
        )
        self.assertIn(Code.SCOPE_MISMATCH, result.codes())
        self.assertFalse(result.valid)

    def test_protocol_scope_accepted_only_when_policy_declares_it(self):
        # A named protocol scope includes the pinned signing identity and
        # additionally requires explicit declaration -> SCOPE_MISMATCH otherwise.
        apr = self.scoped_apr(scope_policy="protocol:demo")
        envelope = self.scoped_envelope_for(apr, allow_protocol_scope=True)

        # (i) policy does NOT declare the protocol scope -> refused.
        undeclared = VerifierTrustPolicy(**apr_verifier_identity(), issuers=(issuer_entry(),))
        result = self.make_verifier(policy=undeclared).verify_authenticated(
            apr, envelope, self.make_verification_request(),
            now=self.make_verification_request().context.timestamp
        )
        self.assertIn(Code.SCOPE_MISMATCH, result.codes())
        self.assertFalse(result.valid)

        # (ii) policy declares the protocol scope -> accepted.
        declared = VerifierTrustPolicy(
            **apr_verifier_identity(),
            issuers=(issuer_entry(),),
            declared_protocol_scopes=("protocol:demo",),
        )
        result = self.make_verifier(policy=declared).verify_authenticated(
            apr, envelope, self.make_verification_request(),
            now=self.make_verification_request().context.timestamp
        )
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)


# --- Scoped rebind and v2 aggregation rejection (spec §5.9.4 rule 4) ----------

from predicate_fixtures import (  # noqa: E402
    issue_rebindable_credential,
    new_rebind_binding_key,
    trusted_predicate_issuer,
)
from zkc_crypto.kdc import derive_credential_binding_key  # noqa: E402
from zkc_crypto.presentation import derive_presentation_pseudonym  # noqa: E402
from zkc_holder import StubBackend as HolderStubBackend  # noqa: E402
from zkc_holder.aggregation import (  # noqa: E402
    aggregate_commitments,
    aggregated_claim_binding,
    commitment_for_envelope_proof,
)
from zkc_holder.backend import REBIND_V2_CIRCUIT  # noqa: E402
from zkc_holder.client import _Presentation  # noqa: E402
from zkc_holder.predicates import build_rebind_witness_v2  # noqa: E402
from zkc_holder.predicates import (  # noqa: E402
    REBIND_BINDING_V2_PROOF_TYPE,
    REBIND_V2_BINDING_V2_CIRCUIT,
    REBIND_V2_BINDING_V2_PROOF_TYPE,
    REBIND_V2_BINDING_V2_STATEMENT_DOMAIN,
)

REBIND_V2_PROOF_TYPE = "zkc:proof:rebind:v2"
AGGREGATE_V2_PROOF_TYPE = "zkc:proof:aggregate:v2"


class RebindV2Base(ProfileVerifierBase):
    """Builds a real, scoped v2 rebind proof entry + a matching scoped v2
    envelope. Rebind is verifier-facing continuity, so the v2 rebind circuit is
    scoped-only (design §4.2): the envelope binding is SCOPED, and the proof
    carries old/new presentation pseudonyms sharing one scope_id."""

    REBIND_ISSUER_ID_HASH = 1001
    REBIND_SCHEMA_ID_HASH = 2002

    def setUp(self):
        super().setUp()
        self.backend = HolderStubBackend()
        self.old_cbk = derive_credential_binding_key(MASTER_SEED)
        self.new_cbk = new_rebind_binding_key(MASTER_SEED + 1)
        self.rebind_credential = issue_rebindable_credential(
            master_seed=MASTER_SEED, credential_id=61
        )
        # A concrete non-zero scope_id (the value never has to match a specific
        # verifier here: unauthenticated verify() does not recompute scope, so
        # the shape/binding checks are what this exercises).
        self.scope_id = 0x5C0DE

    def build_rebind_witness(self, *, scope_id=None):
        return build_rebind_witness_v2(
            old_credential_binding_key=self.old_cbk,
            new_credential_binding_key=self.new_cbk,
            credential=self.rebind_credential,
            issuer_id_hash=self.REBIND_ISSUER_ID_HASH,
            schema_id_hash=self.REBIND_SCHEMA_ID_HASH,
            proof_context=self.context.value,
            timestamp=self.context.timestamp,
            scope_id=self.scope_id if scope_id is None else scope_id,
        )

    def rebind_proof_entry(self, witness):
        return {
            "proofType": REBIND_V2_PROOF_TYPE,
            "proof": self.backend.prove(REBIND_V2_CIRCUIT, witness),
            "publicInputs": self.backend.public_inputs(REBIND_V2_CIRCUIT, witness),
            "principalConsent": True,
        }

    def reseal_proof_entry(self, entry):
        """Re-sign the stub proof so a mutated ``publicInputs`` still passes the
        stub backend's digest check — used to model a forged proof whose public
        inputs the circuit would reject but whose envelope the verifier must
        catch on its own (the anti-tamper case)."""
        from zkc_crypto.stub import stub_proof_payload

        entry["proof"] = stub_proof_payload(REBIND_V2_CIRCUIT, entry["publicInputs"])
        return entry

    def scoped_rebind_envelope(self, witness=None):
        if witness is None:
            witness = self.build_rebind_witness()
        old_pseudonym = witness["old_presentation_pseudonym"]
        return {
            "version": "zkc:proof:v2",
            "metadata": {
                "generatedAt": "2023-11-14T22:13:20+00:00",
                "expiresAt": "2033-05-18T03:33:20+00:00",
                "context": self.context.to_metadata(),
            },
            "proofs": [self.rebind_proof_entry(witness)],
            "presentationBinding": {
                "profile": SCOPED_PROFILE,
                "pseudonym": field_to_hex(old_pseudonym),
                "scopeId": field_to_hex(witness["scope_id"]),
            },
        }

    def rebind_verification_request(self):
        return VerificationRequest(
            proof_types=[REBIND_V2_PROOF_TYPE],
            parameters={
                REBIND_V2_PROOF_TYPE: {
                    "issuerIdHash": self.REBIND_ISSUER_ID_HASH,
                    "schemaIdHash": self.REBIND_SCHEMA_ID_HASH,
                }
            },
            context=self.context,
            max_proof_age=3600,
            accumulator_states={},
        )

    def rebind_verifier(self):
        # Rebind carries no issuer public key or accumulator witness, so a bare
        # issuer entry trusting the rebind v2 proof type is enough.
        return ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(**apr_verifier_identity(), issuers=(issuer_entry(proof_types=(REBIND_V2_PROOF_TYPE,)),)),
            StubVerifyBackend(),
        )


class RebindV2Tests(RebindV2Base):
    """Security containment (spec section 4.5): the scoped rebind identities
    ``zkc:proof:rebind:v2`` / ``zkc:proof:rebind:v3`` authenticate no
    credential, so the v2 verifier path rejects them unconditionally and the
    holder never negotiates them. The fixture still builds real stub proofs so
    the rejection is demonstrably independent of proof validity."""

    def _scoped_successor_envelope(self):
        witness = self.build_rebind_witness()
        witness["statement_domain"] = REBIND_V2_BINDING_V2_STATEMENT_DOMAIN
        envelope = self.scoped_rebind_envelope(witness)
        entry = envelope["proofs"][0]
        entry["proofType"] = REBIND_V2_BINDING_V2_PROOF_TYPE
        entry["proof"] = self.backend.prove(REBIND_V2_BINDING_V2_CIRCUIT, witness)
        entry["publicInputs"] = self.backend.public_inputs(
            REBIND_V2_BINDING_V2_CIRCUIT, witness
        )
        return envelope

    def _request_for(self, proof_type, parameters=None):
        return VerificationRequest(
            proof_types=[proof_type],
            parameters={
                proof_type: {
                    "issuerIdHash": self.REBIND_ISSUER_ID_HASH,
                    "schemaIdHash": self.REBIND_SCHEMA_ID_HASH,
                }
                if parameters is None
                else parameters
            },
            context=self.context,
            max_proof_age=3600,
            accumulator_states={},
        )

    def test_scoped_rebind_envelopes_are_rejected_regardless_of_validity(self):
        cases = (
            (REBIND_V2_PROOF_TYPE, self.scoped_rebind_envelope()),
            (REBIND_V2_BINDING_V2_PROOF_TYPE, self._scoped_successor_envelope()),
        )
        policies = (
            ("empty", VerifierTrustPolicy(**apr_verifier_identity(), issuers=())),
            ("configured", VerifierTrustPolicy(**apr_verifier_identity(), issuers=(issuer_entry(proof_types=(
                REBIND_V2_PROOF_TYPE, REBIND_V2_BINDING_V2_PROOF_TYPE)),))),
        )
        for proof_type, envelope in cases:
            # The stub proof itself is valid: rejection is semantic, not cryptographic.
            entry = envelope["proofs"][0]
            self.assertTrue(
                StubVerifyBackend().verify(
                    REBIND_V2_CIRCUIT
                    if proof_type == REBIND_V2_PROOF_TYPE
                    else REBIND_V2_BINDING_V2_CIRCUIT,
                    entry["proof"],
                    entry["publicInputs"],
                    None,
                )
            )
            for label, policy in policies:
                for parameters in (None, {}):
                    with self.subTest(proof_type=proof_type, policy=label, parameters=parameters):
                        verifier = ZKCVerifier(REPO_ROOT, policy, StubVerifyBackend())
                        result = verifier.verify(envelope, self._request_for(proof_type, parameters))
                        self.assertFalse(result.valid)
                        self.assertEqual(result.codes(), [Code.UNAUTHENTICATED_CREDENTIAL])
                        self.assertEqual(result.errors[0].proof_type, proof_type)

    def test_relabelling_between_scoped_rebind_identities_stays_rejected(self):
        """Neither cross-wiring the successor as the predecessor nor the reverse
        reaches INVALID_PROOF: containment precedes backend verification."""
        cross_wired = copy.deepcopy(self._scoped_successor_envelope())
        cross_wired["proofs"][0]["proofType"] = REBIND_V2_PROOF_TYPE
        result = self.rebind_verifier().verify(cross_wired, self.rebind_verification_request())
        self.assertEqual(result.codes(), [Code.UNAUTHENTICATED_CREDENTIAL])

    def test_holder_refuses_to_negotiate_the_scoped_binding_v2_successor(self):
        from zkc_holder.errors import UnauthenticatedProofTypeError

        holder = HolderClient.from_seed(
            MASTER_SEED,
            REGISTRY,
            HolderStubBackend(),
            accepted_review_statuses=("draft",),
        )
        holder.store_credential(self.rebind_credential)
        request = ProofRequest(
            proof_types=[REBIND_BINDING_V2_PROOF_TYPE],
            parameters={
                REBIND_BINDING_V2_PROOF_TYPE: {
                    "issuerIdHash": self.REBIND_ISSUER_ID_HASH,
                    "schemaIdHash": self.REBIND_SCHEMA_ID_HASH,
                }
            },
            rebind_secret=RebindSecret(self.new_cbk),
            context=self.context,
            trust_policy=TrustPolicy(
                issuers=(
                    trusted_predicate_issuer((REBIND_BINDING_V2_PROOF_TYPE,)),
                )
            ),
        )
        with self.assertRaises(UnauthenticatedProofTypeError):
            holder._generate_envelope(
                request, _Presentation(SCOPED_PROFILE, self.scope_id)
            )

    def test_rebind_parses_old_new_pseudonyms(self):
        """The frozen builder/extractor pair still documents the historical
        pseudonym-keyed public-input shape (byte-pinned circuit record)."""
        witness = self.build_rebind_witness()
        entry = self.rebind_proof_entry(witness)
        public = entry["publicInputs"]
        old_p = derive_presentation_pseudonym(self.old_cbk, self.scope_id)
        new_p = derive_presentation_pseudonym(self.new_cbk, self.scope_id)
        self.assertEqual(hex_to_field(public["old_presentation_pseudonym"]), old_p)
        self.assertEqual(hex_to_field(public["new_presentation_pseudonym"]), new_p)
        self.assertEqual(hex_to_field(public["scope_id"]), self.scope_id)
        self.assertNotIn("old_holder_commitment", public)
        self.assertNotIn("new_holder_commitment", public)


class AggregationV2Tests(ProfileVerifierBase):
    def _component_commitments(self, envelope):
        import json as _json

        from zkc_crypto import string_to_field as _string_to_field

        manifest = _json.loads((REPO_ROOT / "artifacts" / "manifest.json").read_text())
        vk_hashes = {
            circuit["name"]: bytes.fromhex(circuit["vkHash"].removeprefix("0x"))
            for circuit in manifest["circuits"]
        }
        commitments = []
        type_fields = []
        consent_flags = []
        for proof_entry in envelope["proofs"]:
            circuit = self.make_verifier()._circuit_by_proof_type[proof_entry["proofType"]]
            commitments.append(commitment_for_envelope_proof(proof_entry, vk_hashes[circuit]))
            type_fields.append(_string_to_field(proof_entry["proofType"]))
            consent_flags.append(True)
            proof_entry["principalConsent"] = True
        return commitments, type_fields, consent_flags

    def _aggregation_block(self, envelope, keying_value):
        commitments, type_fields, consent_flags = self._component_commitments(envelope)
        commitment = aggregate_commitments(
            self.context.value, keying_value, commitments, type_fields, consent_flags
        )
        claim = aggregated_claim_binding(commitment, self.context.value)
        return {
            "proof": "zkc:stub:v1:aggregation",
            "inputProofCommitments": [field_to_hex(c) for c in commitments],
            "aggregationCommitment": field_to_hex(commitment),
            "aggregatedClaimBinding": field_to_hex(claim),
        }

    def test_scoped_aggregation_rejected_even_when_commitments_match(self):
        apr = self.make_apr(presentation={"profile": SCOPED_PROFILE, "scopePolicy": "verifier",
                                          "rotationEpochSeconds": 0})
        holder_request = self.make_request(presentation_profile=SCOPED_PROFILE)
        now = holder_request.context.timestamp
        envelope = self.holder.generate_authenticated_proof(apr, holder_request, now=now)["envelope"]
        pseudonym = hex_to_field(envelope["presentationBinding"]["pseudonym"])
        envelope["aggregation"] = self._aggregation_block(envelope, pseudonym)
        request = self.make_verification_request()
        verifier = self.make_verifier()
        result = verifier.verify(envelope, request)
        self.assertEqual(result.codes(), [Code.INVALID_AGGREGATION], result.to_dict())
        result = verifier.verify_authenticated(apr, envelope, request, now=now)
        self.assertEqual(result.codes(), [Code.INVALID_AGGREGATION], result.to_dict())

    def test_anonymous_aggregation_rejected(self):
        envelope = self.anonymous_envelope()
        envelope["aggregation"] = {
            "proof": "zkc:stub:v1:aggregation",
            "inputProofCommitments": [field_to_hex(1)],
            "aggregationCommitment": field_to_hex(2),
            "aggregatedClaimBinding": field_to_hex(3),
        }
        result = self.make_verifier().verify(envelope, self.make_verification_request())
        self.assertEqual(result.codes(), [Code.INVALID_AGGREGATION], result.to_dict())


class AuthenticatedIdentityTests(ProfileVerifierBase):
    """Regressions for the externally supplied APR key/context and replay PoC."""

    def own_verifier(self, **overrides):
        policy = apr_verifier_identity()
        policy.update(overrides)
        return ZKCVerifier(REPO_ROOT, VerifierTrustPolicy(issuers=(issuer_entry(),), **policy),
                           StubVerifyBackend())

    def resign(self, apr, key=APR_VERIFIER_PRIVATE_KEY):
        return sign_apr(copy.deepcopy(apr), key)

    def assert_unsigned(self, apr, request=None, verifier=None, envelope=None):
        verifier = self.own_verifier() if verifier is None else verifier
        with patch.object(verifier._backend, "verify", side_effect=AssertionError("backend reached")):
            result = verifier.verify_authenticated(
                apr, {} if envelope is None else envelope,
                request or self.make_verification_request(),
                now=(request or self.make_verification_request()).context.timestamp)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())

    def test_self_signed_keys_and_missing_own_configuration_refused(self):
        for key in (0xBAD1, 0xBAD2):
            for profile in (ANONYMOUS_PROFILE, SCOPED_PROFILE):
                with self.subTest(key=key, profile=profile):
                    block = {"profile": profile, "scopePolicy": "verifier"}
                    apr = self.make_apr(private_key=key, presentation=block)
                    envelope = self.holder.generate_authenticated_proof(
                        apr, self.make_request(presentation_profile=profile),
                        now=self.make_request(presentation_profile=profile).context.timestamp)["envelope"]
                    self.assert_unsigned(apr, envelope=envelope)
        self.assert_unsigned(self.make_apr(), verifier=self.own_verifier(verifier_signing_keys=()))
        self.assert_unsigned(self.make_apr(), verifier=self.own_verifier(verifier_id="", verifier_signing_keys=()))

    def test_configured_rotation_key_and_id(self):
        other = 0xBADC0DE
        pins = apr_verifier_identity()["verifier_signing_keys"] + apr_verifier_identity(other)["verifier_signing_keys"]
        apr = self.make_apr(private_key=other)
        result = self.own_verifier(verifier_signing_keys=pins).verify_authenticated(
            apr, self.anonymous_envelope(), self.make_verification_request(),
            now=self.make_verification_request().context.timestamp)
        self.assertTrue(result.valid, result.to_dict())
        apr["verifierId"] = "another.example"
        self.assert_unsigned(self.resign(apr))

    def test_session_one_apr_cannot_authenticate_session_555(self):
        apr = self.make_apr()
        apr["request"]["context"]["sessionId"] = field_to_hex(1)
        self.assert_unsigned(self.resign(apr))

    def test_full_context_strictness(self):
        mutations = (
            ("value", field_to_hex(1)), ("timestamp", str(TIMESTAMP)),
            ("timestamp", TIMESTAMP + 1), ("timestamp", True),
            ("verifierId", "another.example"), ("sessionId", field_to_hex(2)),
            ("profile", "deployment:opaque"), ("extra", "unsigned"),
            ("purposeTag", field_to_hex(3)),
        )
        for name, value in mutations:
            with self.subTest(name=name, value=value):
                apr = self.make_apr()
                apr["request"]["context"]["value"] = field_to_hex(self.context.value)
                apr["request"]["context"][name] = value
                if name == "timestamp" and type(value) is not int:
                    with self.assertRaises(ValueError):
                        self.resign(apr)
                    self.assert_unsigned(apr)
                else:
                    self.assert_unsigned(self.resign(apr))

    def test_nondefault_age_requires_signed_constraints(self):
        from dataclasses import replace
        from zkc_crypto import verification_context_extension
        for age in (60, 7200, True, "3600", -1):
            with self.subTest(age=age):
                self.assert_unsigned(self.make_apr(), replace(self.make_verification_request(), max_proof_age=age))
        apr = self.make_apr()
        apr["request"]["maxProofAge"] = 60
        self.assert_unsigned(self.resign(apr), replace(self.make_verification_request(), max_proof_age=60))
        apr["request"]["extensions"] = verification_context_extension(self.context, 60)
        apr = self.resign(apr)
        req = replace(self.make_verification_request(), max_proof_age=60)
        result = self.own_verifier().verify_authenticated(apr, self.anonymous_envelope(), req, now=req.context.timestamp)
        self.assertTrue(result.valid, result.to_dict())
        apr["request"]["extensions"]["zkc:request:verification-context:v1"]["maxProofAge"] = 7200
        self.assert_unsigned(apr, req)

    def test_opaque_context_requires_complete_signed_extension(self):
        from zkc_crypto import verification_context_extension
        self.context = ProofContext("deployment:opaque", 0xC0FFEE, TIMESTAMP)
        apr = self.make_apr()
        apr["request"]["context"] = self.context.to_metadata()
        self.assert_unsigned(self.resign(apr))
        apr["request"]["extensions"] = verification_context_extension(self.context)
        apr = self.resign(apr)
        envelope = self.holder.generate_authenticated_proof(apr, self.make_request(), now=self.make_request().context.timestamp)["envelope"]
        result = self.own_verifier().verify_authenticated(apr, envelope, self.make_verification_request(), now=self.make_verification_request().context.timestamp)
        self.assertTrue(result.valid, result.to_dict())
        apr["request"]["context"]["profile"] = "another:opaque"
        self.assert_unsigned(apr, envelope=envelope)

    def test_same_instance_and_explicit_shared_store_replay(self):
        apr = self.make_apr()
        envelope = self.anonymous_envelope()
        req = self.make_verification_request()
        verifier = self.own_verifier()
        self.assertTrue(verifier.verify_authenticated(apr, envelope, req, now=req.context.timestamp).valid)
        self.assert_unsigned(apr, verifier=verifier, envelope=envelope)
        seen = set()
        self.assertTrue(self.own_verifier().verify_authenticated(apr, envelope, req, seen_nonces=seen, now=req.context.timestamp).valid)
        self.assertIn(apr["nonce"], seen)
        result = self.own_verifier().verify_authenticated(apr, envelope, req, seen_nonces=seen, now=req.context.timestamp)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST])

    def test_nonce_alias_and_unwritable_store_refused(self):
        from zkc_crypto import verify_apr_signature
        apr = self.make_apr()
        apr["nonce"] = hex(hex_to_field(apr["nonce"]))
        self.assertTrue(verify_apr_signature(apr))  # same signed field, different wire spelling
        self.assert_unsigned(apr)
        apr = self.make_apr()
        class ReadOnlySet(set):
            def add(self, value):
                raise OSError("store unavailable")
        for store in (frozenset(), ReadOnlySet()):
            with self.subTest(store=type(store)):
                result = self.own_verifier().verify_authenticated(
                    apr, self.anonymous_envelope(), self.make_verification_request(), seen_nonces=store,
                    now=self.make_verification_request().context.timestamp)
                self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST])

    def test_failed_proof_does_not_consume_nonce(self):
        apr = self.make_apr()
        envelope = self.anonymous_envelope()
        bad = copy.deepcopy(envelope)
        bad["proofs"][0]["proof"] = "0x00"
        verifier = self.own_verifier()
        self.assertFalse(verifier.verify_authenticated(apr, bad, self.make_verification_request(), now=self.make_verification_request().context.timestamp).valid)
        self.assertTrue(verifier.verify_authenticated(apr, envelope, self.make_verification_request(), now=self.make_verification_request().context.timestamp).valid)

    def test_concurrent_replay_is_reserved_before_backend(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor
        entered, release = threading.Event(), threading.Event()
        apr, envelope, req = self.make_apr(), self.anonymous_envelope(), self.make_verification_request()
        first, second, seen = self.own_verifier(), self.own_verifier(), set()
        original = first._verify_authenticated_reserved
        def blocked(*args):
            entered.set()
            if not release.wait(10):
                raise AssertionError("reservation test timed out")
            return original(*args)
        with patch.object(first, "_verify_authenticated_reserved", side_effect=blocked):
            with ThreadPoolExecutor(max_workers=2) as pool:
                pending = pool.submit(first.verify_authenticated, apr, envelope, req,
                                      seen_nonces=seen, now=req.context.timestamp)
                try:
                    self.assertTrue(entered.wait(10))
                    replay = second.verify_authenticated(apr, envelope, req, seen_nonces=seen, now=req.context.timestamp)
                    self.assertEqual(replay.codes(), [Code.UNSIGNED_REQUEST])
                finally:
                    release.set()
                self.assertTrue(pending.result().valid)

    def test_named_protocol_scope_still_separates_signer_keys(self):
        from zkc_crypto import scope_from_apr_presentation
        block = {"profile": SCOPED_PROFILE, "scopePolicy": "protocol:demo"}
        a = self.make_apr(presentation=block)
        b = self.make_apr(presentation=block, private_key=0xBAD2)
        self.assertNotEqual(scope_from_apr_presentation(a, block, TIMESTAMP),
                            scope_from_apr_presentation(b, block, TIMESTAMP))


class HolderOpaqueContextTests(ProfileVerifierBase):
    def setUp(self):
        super().setUp()
        self.context = ProofContext(
            "deployment:opaque", 0xC0FFEE, TIMESTAMP, "verifier.example", SESSION_ID
        )

    def opaque_apr(self, context=None):
        context = self.context if context is None else context
        apr = self.make_apr()
        apr["request"]["context"] = context.to_metadata()
        apr["request"]["extensions"] = verification_context_extension(context)
        return sign_apr(apr, APR_VERIFIER_PRIVATE_KEY)

    def assert_context_refused(self, apr, request=None):
        self.assertTrue(verify_apr_signature(apr))
        request = self.make_request() if request is None else request
        for entry in (self.holder.generate_authenticated_proof, self.holder.answer_as_hosted_service):
            for override in (False, True):
                with self.subTest(entry=entry.__name__, override=override):
                    before = list(self.holder.override_log)
                    with patch.object(self.holder, "_generate_envelope", side_effect=AssertionError("proof reached")) as prove:
                        with self.assertRaises(UnauthenticatedRequestError):
                            entry(apr, request, now=TIMESTAMP, allow_unauthenticated=override)
                        prove.assert_not_called()
                    self.assertEqual(self.holder.override_log, before)

    def assert_roundtrip(self, apr, context, *, max_age=3600):
        request = dataclasses.replace(self.make_request(), context=context, max_proof_age=max_age)
        verification = dataclasses.replace(
            self.make_verification_request(), context=context, max_proof_age=max_age
        )
        for entry in (self.holder.generate_authenticated_proof, self.holder.answer_as_hosted_service):
            with self.subTest(entry=entry.__name__, profile=context.profile):
                output = entry(apr, request, now=TIMESTAMP)
                self.assertTrue(verify_receipt_as_holder(output["receipt"])["valid"])
                result = self.make_verifier().verify_authenticated(
                    apr, output["envelope"], verification, now=TIMESTAMP
                )
                self.assertTrue(result.valid, result.to_dict())

    def test_honest_opaque_roundtrip_and_published_digest_bytes(self):
        apr = self.opaque_apr()
        # Observed before the fix on Forgejo main d276abe with these inputs.
        self.assertEqual(
            apr_digest_from_dict(apr),
            int("27029278258f2f80c3a527ca0d74c140fc8a607242aa33fe86308c874289addb", 16),
        )
        self.assert_roundtrip(apr, self.context)
        context = ProofContext("deployment:opaque", self.context.value, TIMESTAMP)
        self.assert_roundtrip(self.opaque_apr(context), context)

    def test_original_same_value_timestamp_substitution_refused(self):
        apr = self.opaque_apr()
        apr["request"]["context"]["timestamp"] += 7200
        request = dataclasses.replace(
            self.make_request(), context=dataclasses.replace(self.context, timestamp=TIMESTAMP + 7200)
        )
        self.assert_context_refused(apr, request)

    def test_apr_context_metadata_cannot_disagree_with_signed_extension(self):
        for field, value in (
            ("timestamp", TIMESTAMP + 1), ("profile", "another:opaque"),
            ("value", field_to_hex(1)), ("verifierId", "another.example"),
            ("sessionId", field_to_hex(SESSION_ID + 1)), ("extra", "unsigned"),
        ):
            with self.subTest(field=field):
                apr = self.opaque_apr()
                apr["request"]["context"][field] = value
                # Even a newly signed outer context must agree with its extension.
                self.assert_context_refused(sign_apr(apr, APR_VERIFIER_PRIVATE_KEY))

    def test_supplied_context_cannot_disagree_with_signed_apr(self):
        for changes in (
            {"timestamp": TIMESTAMP + 1}, {"profile": "another:opaque"},
            {"value": 1}, {"verifier_id": "another.example"}, {"session_id": SESSION_ID + 1},
        ):
            with self.subTest(changes=changes):
                request = dataclasses.replace(
                    self.make_request(), context=dataclasses.replace(self.context, **changes)
                )
                self.assert_context_refused(self.opaque_apr(), request)

    def test_extension_context_cannot_disagree_with_outer_apr(self):
        for field, value in (
            ("timestamp", TIMESTAMP + 1), ("profile", "another:opaque"),
            ("value", field_to_hex(1)), ("verifierId", "another.example"),
            ("sessionId", field_to_hex(SESSION_ID + 1)), ("extra", "unsigned"),
        ):
            with self.subTest(field=field):
                apr = self.opaque_apr()
                apr["request"]["extensions"][VERIFICATION_CONTEXT_EXTENSION]["context"][field] = value
                self.assert_context_refused(sign_apr(apr, APR_VERIFIER_PRIVATE_KEY))

    def test_missing_and_malformed_signed_context_extensions_refused(self):
        good = verification_context_extension(self.context)[VERIFICATION_CONTEXT_EXTENSION]
        malformed = (
            None, [], "context", {}, {"context": good["context"]}, {"maxProofAge": 3600},
            {**good, "extra": 1}, {**good, "context": None}, {**good, "context": []},
            {**good, "maxProofAge": True}, {**good, "maxProofAge": "3600"},
            {**good, "maxProofAge": 3600.0}, {**good, "maxProofAge": -1},
        )
        for constraints in malformed:
            with self.subTest(constraints=constraints):
                apr = self.opaque_apr()
                apr["request"]["extensions"][VERIFICATION_CONTEXT_EXTENSION] = copy.deepcopy(constraints)
                self.assert_context_refused(sign_apr(apr, APR_VERIFIER_PRIVATE_KEY))
        for extensions in (None, {}, {"app:hint": "unrelated"}):
            apr = self.opaque_apr()
            if extensions is None:
                del apr["request"]["extensions"]
            else:
                apr["request"]["extensions"] = extensions
            self.assert_context_refused(sign_apr(apr, APR_VERIFIER_PRIVATE_KEY))

    def test_known_opaque_profile_relabeling_cannot_preserve_authorization(self):
        known = ProofContext.verifier_session("verifier.example", SESSION_ID, TIMESTAMP)
        apr = self.make_apr()
        apr["request"]["context"] = {
            **known.to_metadata(), "profile": "deployment:opaque"
        }
        opaque = dataclasses.replace(known, profile="deployment:opaque")
        self.assert_context_refused(apr, dataclasses.replace(self.make_request(), context=opaque))
        apr = self.opaque_apr(opaque)
        apr["request"]["context"] = known.to_metadata()
        self.assert_context_refused(apr, dataclasses.replace(self.make_request(), context=known))

    def test_context_fields_cannot_disappear_during_serialization(self):
        for changes in ({"purpose": "hidden"}, {"purpose_tag": 1}):
            request = dataclasses.replace(
                self.make_request(), context=dataclasses.replace(self.context, **changes)
            )
            self.assert_context_refused(self.opaque_apr(), request)
        context = ProofContext("deployment:opaque", self.context.value, TIMESTAMP)
        request = dataclasses.replace(self.make_request(), context=dataclasses.replace(context, session_id=7))
        self.assert_context_refused(self.opaque_apr(context), request)

    def test_known_profiles_keep_legacy_and_derived_field_normalization(self):
        contexts = (
            ProofContext.verifier_session("verifier.example", SESSION_ID, TIMESTAMP),
            ProofContext.purpose_bound("verifier.example", SESSION_ID, "caf\u00e9", TIMESTAMP),
        )
        for context in contexts:
            apr = self.make_apr()
            apr["request"]["context"] = context.to_metadata()
            digest = apr_digest_from_dict(apr)
            for field in ("value", "purposeTag"):
                apr["request"]["context"].pop(field, None)
            apr["request"]["context"]["sessionId"] = hex(SESSION_ID)
            if "purpose" in apr["request"]["context"]:
                apr["request"]["context"]["purpose"] = "cafe\u0301"
            self.assertEqual(apr_digest_from_dict(apr), digest)
            self.assert_roundtrip(sign_apr(apr, APR_VERIFIER_PRIVATE_KEY), context)
            apr["request"]["extensions"] = verification_context_extension(context, 60)
            apr["request"]["extensions"]["app:hint"] = {"accepted": True}
            self.assert_roundtrip(sign_apr(apr, APR_VERIFIER_PRIVATE_KEY), context, max_age=60)

    def test_explicit_unauthenticated_override_remains_logged(self):
        apr = self.opaque_apr()
        apr["signature"]["value"] = "0x" + "00" * 64
        for entry in (self.holder.generate_authenticated_proof, self.holder.answer_as_hosted_service):
            before = len(self.holder.override_log)
            output = entry(apr, self.make_request(), now=TIMESTAMP, allow_unauthenticated=True)
            self.assertIn("envelope", output)
            self.assertEqual(len(self.holder.override_log), before + 1)
            self.assertEqual(self.holder.override_log[-1]["kind"], "UNAUTHENTICATED")

    def test_caller_mutation_after_authentication_cannot_relabel_context(self):
        for entry in (self.holder.generate_authenticated_proof, self.holder.answer_as_hosted_service):
            apr, request = self.opaque_apr(), self.make_request()
            authenticate = self.holder._authenticate_request

            def mutate_after_authentication(*args, **kwargs):
                authenticated = authenticate(*args, **kwargs)
                self.assertTrue(authenticated)
                apr["request"]["context"]["timestamp"] += 7200
                request.context = dataclasses.replace(self.context, timestamp=TIMESTAMP + 7200)
                return authenticated

            with patch.object(self.holder, "_authenticate_request", side_effect=mutate_after_authentication):
                output = entry(apr, request, now=TIMESTAMP)
            self.assertEqual(output["envelope"]["metadata"]["context"], self.context.to_metadata())
            self.assertEqual(output["receipt"]["apr"]["request"]["context"], self.context.to_metadata())
            self.assertTrue(verify_receipt_as_holder(output["receipt"])["valid"])
            self.assertEqual(apr["request"]["context"]["timestamp"], TIMESTAMP + 7200)


if __name__ == "__main__":
    unittest.main()
