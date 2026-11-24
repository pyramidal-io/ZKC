"""Effective presentation reporting + the continuity-required verifier policy
(spec section 5.9.4; security review 2026-10-04 R2.5).

A holder may answer a scoped APR anonymously (section 5.9.2 rule 4), and a
default verifier accepts that downgrade. Before this fix the result did not say
so: a verifier relying on scoped continuity (one claim per holder) could not
tell an honest scoped answer from an anonymous one, and plain ``verify()``
accepted any holder-chosen scope without saying it never recomputed it.

These tests pin:

* ``VerificationResult`` reports the effective profile, the holder handle
  (scoped pseudonym / linkable commitment / none) and whether ``scope_id`` was
  recomputed from the verifier's own identity;
* ``VerifierTrustPolicy.require_presentation_continuity`` rejects an anonymous
  answer with PROFILE_MISMATCH on both entry points, refuses a scoped answer
  whose scope was not recomputed (plain ``verify()``) with SCOPE_MISMATCH,
  accepts a linkable answer (its global commitment is a continuity handle),
  and requires exactly one handle-bearing accepted profile;
* a handle is reported (and can satisfy continuity) only when a requested
  proof was checked against the envelope binding.
"""

import copy
import json
import unittest

import _path  # noqa: F401  (sys.path side effect)
from _path import REPO_ROOT
from holder_fixtures import (
    DRAFT_OPT_IN_REVIEW_STATUSES,
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    apr_verifier_identity,
    issue_kyc_credential,
    trusted_test_issuer,
)
from zkc_crypto import ProofContext, field_to_hex, hex_to_field, sign_apr
from zkc_crypto.ecdsa_secp256k1 import N
from zkc_crypto.presentation import ANONYMOUS_PROFILE, LINKABLE_PROFILE, SCOPED_PROFILE
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    TrustedIssuer,
    VerificationErrorCode as Code,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
MASTER_SEED = 0x5EED
SESSION_ID = 0x99
TIMESTAMP = 1_700_000_000
VERIFIER_ID = "verifier.example"

KYC_V1 = KYC_PROOF_TYPE
KYC_V2 = "zkc:proof:kyc:v2"
KYC_PARAMETERS = {"requiredLevel": 1, "requiredAttributes": [True, False, True, False, False]}

# TEST-ONLY verifier signing keys (public material), as in test_verifier_profiles.
VERIFIER_A_KEY = 0xA9701 % N or 1
VERIFIER_B_KEY = 0xB0B0B % N or 2

SCOPED_PRESENTATION = {"profile": SCOPED_PROFILE, "scopePolicy": "verifier", "rotationEpochSeconds": 0}

# Continuity policies admit exactly one handle-bearing profile. Anonymous is
# listed in the scoped one so that its rejection comes from the continuity
# rule (PROFILE_MISMATCH), not from the profile gate.
SCOPED_CONTINUITY = {
    "require_presentation_continuity": True,
    "accepted_profiles": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
}
LINKABLE_CONTINUITY = {
    "require_presentation_continuity": True,
    "accepted_profiles": (LINKABLE_PROFILE,),
}


class ContinuityBase(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.holder = HolderClient.from_seed(
            MASTER_SEED,
            REGISTRY,
            StubBackend(),
            accumulator_provider=self.provider,
            accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        self.holder.store_credential(
            issue_kyc_credential(
                master_seed=MASTER_SEED,
                credential_id=7,
                provider=self.provider,
                expires_at=2_000_000_000,
            )
        )
        self.context = ProofContext.verifier_session(VERIFIER_ID, SESSION_ID, TIMESTAMP)

    # -- holder side -------------------------------------------------------

    def make_apr(self, presentation=None, *, private_key=VERIFIER_A_KEY, nonce=0xABC):
        request = {
            "proofTypes": [KYC_V1],
            "parameters": {KYC_V1: copy.deepcopy(KYC_PARAMETERS)},
            "context": {
                "profile": "zkc:context:verifier-session:v1",
                "verifierId": VERIFIER_ID,
                "sessionId": field_to_hex(SESSION_ID),
                "timestamp": TIMESTAMP,
            },
            "trustPolicy": {"issuers": []},
        }
        if presentation is not None:
            request["presentation"] = copy.deepcopy(presentation)
        return sign_apr(
            {
                "request": request,
                "verifierId": VERIFIER_ID,
                "nonce": field_to_hex(nonce),
                "issuedAt": TIMESTAMP,
                "expiresAt": TIMESTAMP + 3600,
            },
            private_key,
        )

    def answer(self, apr, holder_profile):
        """The holder's authenticated answer under its own profile ceiling."""
        request = ProofRequest(
            proof_types=[KYC_V1],
            parameters={KYC_V1: copy.deepcopy(KYC_PARAMETERS)},
            context=self.context,
            trust_policy=TrustPolicy(issuers=(trusted_test_issuer((KYC_V1, KYC_V2)),)),
            presentation_profile=holder_profile,
        )
        return self.holder.generate_authenticated_proof(apr, request, now=TIMESTAMP)["envelope"]

    # -- verifier side -----------------------------------------------------

    def make_verifier(self, *, private_key=VERIFIER_A_KEY, **policy):
        issuer = TrustedIssuer(
            issuer_id=TEST_ISSUER_ID,
            public_key_x=TEST_ISSUER_KEY_X,
            public_key_y=TEST_ISSUER_KEY_Y,
            proof_types=(KYC_V1, KYC_V2),
        )
        return ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(issuers=(issuer,), **apr_verifier_identity(private_key), **policy),
            StubVerifyBackend(),
        )

    def verification_request(self, envelope):
        proof_type = envelope["proofs"][0]["proofType"]
        return VerificationRequest(
            proof_types=[proof_type],
            parameters={proof_type: copy.deepcopy(KYC_PARAMETERS)},
            context=self.context,
            accumulator_states={
                TEST_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                    roots=self.provider.roots(TEST_ISSUER_ID),
                )
            },
        )

    def verify_authenticated(self, apr, envelope, **policy):
        return self.make_verifier(**policy).verify_authenticated(
            apr, envelope, self.verification_request(envelope), now=TIMESTAMP
        )

    def verify(self, envelope, **policy):
        return self.make_verifier(**policy).verify(envelope, self.verification_request(envelope))

    def honest_scoped(self):
        apr = self.make_apr(SCOPED_PRESENTATION)
        envelope = self.answer(apr, SCOPED_PROFILE)
        self.assertEqual(envelope["presentationBinding"]["profile"], SCOPED_PROFILE)
        return apr, envelope

    def downgraded_anonymous(self):
        # The verifier signs a SCOPED request; the holder answers anonymously.
        apr = self.make_apr(SCOPED_PRESENTATION)
        envelope = self.answer(apr, ANONYMOUS_PROFILE)
        self.assertEqual(envelope["presentationBinding"]["profile"], ANONYMOUS_PROFILE)
        return apr, envelope

    def linkable(self):
        apr = self.make_apr(None)
        envelope = self.answer(apr, LINKABLE_PROFILE)
        self.assertEqual(envelope["version"], "zkc:proof:v1")
        return apr, envelope


class EffectivePresentationReportTests(ContinuityBase):
    def test_honest_scoped_reports_recomputed_scope_and_pseudonym(self):
        apr, envelope = self.honest_scoped()
        result = self.verify_authenticated(apr, envelope)
        self.assertEqual(result.codes(), [], result.to_dict())
        binding = envelope["presentationBinding"]
        self.assertEqual(result.presentation_profile, SCOPED_PROFILE)
        self.assertEqual(result.presentation_handle, field_to_hex(hex_to_field(binding["pseudonym"])))
        self.assertEqual(result.scope_id, field_to_hex(hex_to_field(binding["scopeId"])))
        self.assertTrue(result.scope_recomputed)
        self.assertEqual(
            result.to_dict()["presentation"],
            {
                "profile": SCOPED_PROFILE,
                "scopeRecomputed": True,
                "pseudonym": result.presentation_handle,
                "scopeId": result.scope_id,
            },
        )

    def test_plain_verify_never_claims_scope_recomputation(self):
        _, envelope = self.honest_scoped()
        result = self.verify(envelope)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertEqual(result.presentation_profile, SCOPED_PROFILE)
        self.assertIsNotNone(result.presentation_handle)
        self.assertFalse(result.scope_recomputed)
        self.assertIs(result.to_dict()["presentation"]["scopeRecomputed"], False)

    def test_downgraded_anonymous_is_accepted_but_reported_as_anonymous(self):
        # PoC R2.5: the default policy accepts the downgrade (section 5.9.2
        # rule 4), and the result now SAYS no continuity handle exists.
        apr, envelope = self.downgraded_anonymous()
        result = self.verify_authenticated(apr, envelope)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertEqual(result.presentation_profile, ANONYMOUS_PROFILE)
        self.assertIsNone(result.presentation_handle)
        self.assertIsNone(result.scope_id)
        self.assertFalse(result.scope_recomputed)
        self.assertEqual(
            result.to_dict()["presentation"],
            {"profile": ANONYMOUS_PROFILE, "scopeRecomputed": False},
        )

    def test_linkable_reports_commitment_and_keeps_legacy_wire_shape(self):
        apr, envelope = self.linkable()
        result = self.verify_authenticated(apr, envelope)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertEqual(result.presentation_profile, LINKABLE_PROFILE)
        self.assertEqual(
            result.presentation_handle,
            field_to_hex(hex_to_field(envelope["holderBinding"]["commitment"])),
        )
        self.assertIsNone(result.scope_id)
        self.assertFalse(result.scope_recomputed)
        # The v1 wire result is byte-identical to the pre-existing shape.
        self.assertEqual(result.to_dict(), {"valid": True, "errors": [], "warnings": []})

    def test_linkable_answer_to_scoped_request_stays_rejected(self):
        # PoC R2.5 third row: a v1 answer is MORE linkable than a scoped APR.
        # The v1 spelling already disagrees with the scoped APR's resolution
        # (UNSIGNED_REQUEST); asked by its v2 spelling, profile agreement
        # rejects it (PROFILE_MISMATCH).
        apr = self.make_apr(SCOPED_PRESENTATION)
        _, envelope = self.linkable()
        result = self.verify_authenticated(apr, envelope)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())
        request = self.verification_request(envelope)
        request = VerificationRequest(
            proof_types=[KYC_V2],
            parameters={KYC_V2: copy.deepcopy(KYC_PARAMETERS)},
            context=request.context,
            accumulator_states=request.accumulator_states,
        )
        result = self.make_verifier().verify_authenticated(apr, envelope, request, now=TIMESTAMP)
        self.assertIn(Code.PROFILE_MISMATCH, result.codes())
        self.assertFalse(result.valid)

    def test_unparsed_envelope_reports_no_presentation(self):
        _, envelope = self.honest_scoped()
        broken = copy.deepcopy(envelope)
        del broken["presentationBinding"]
        result = self.verify(broken)
        self.assertIn(Code.MALFORMED_PROOF, result.codes())
        self.assertIsNone(result.presentation_profile)
        self.assertNotIn("presentation", result.to_dict())


class ContinuityRequiredTests(ContinuityBase):
    def test_policy_flag_is_off_by_default_and_strictly_boolean(self):
        self.assertFalse(VerifierTrustPolicy(issuers=()).require_presentation_continuity)
        for alias in (1, "true", None):
            with self.subTest(alias=alias):
                with self.assertRaises(ValueError):
                    VerifierTrustPolicy(
                        issuers=(), require_presentation_continuity=alias,
                        accepted_profiles=(SCOPED_PROFILE,),
                    )

    def test_policy_requires_exactly_one_handle_bearing_profile(self):
        # The unset default admits scoped v2 AND (for compatibility) linkable
        # v1, i.e. two handles per holder: refused, as are explicit sets with
        # two or zero handle-bearing profiles.
        refused = (
            {},
            {"accepted_profiles": (ANONYMOUS_PROFILE, SCOPED_PROFILE, LINKABLE_PROFILE)},
            {"accepted_profiles": (SCOPED_PROFILE, LINKABLE_PROFILE)},
            {"accepted_profiles": (ANONYMOUS_PROFILE,)},
        )
        for extra in refused:
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(ValueError, "exactly one handle-bearing profile"):
                    VerifierTrustPolicy(issuers=(), require_presentation_continuity=True, **extra)
        for profiles, handle in (
            ((SCOPED_PROFILE,), SCOPED_PROFILE),
            ((ANONYMOUS_PROFILE, SCOPED_PROFILE), SCOPED_PROFILE),
            ((LINKABLE_PROFILE,), LINKABLE_PROFILE),
            ((ANONYMOUS_PROFILE, LINKABLE_PROFILE), LINKABLE_PROFILE),
        ):
            with self.subTest(profiles=profiles):
                policy = VerifierTrustPolicy(
                    issuers=(), require_presentation_continuity=True, accepted_profiles=profiles
                )
                self.assertEqual(policy.accepted_handle_profiles, (handle,))

    def test_anonymous_downgrade_fails_with_profile_mismatch_authenticated(self):
        apr, envelope = self.downgraded_anonymous()
        verifier = self.make_verifier(**SCOPED_CONTINUITY)
        seen = set()
        result = verifier.verify_authenticated(
            apr, envelope, self.verification_request(envelope), now=TIMESTAMP, seen_nonces=seen
        )
        self.assertEqual(result.codes(), [Code.PROFILE_MISMATCH], result.to_dict())
        self.assertFalse(result.valid)
        self.assertEqual(result.presentation_profile, ANONYMOUS_PROFILE)
        # A rejected answer does not consume the APR nonce.
        self.assertEqual(seen, set())

    def test_anonymous_fails_with_profile_mismatch_on_plain_verify(self):
        _, envelope = self.downgraded_anonymous()
        result = self.verify(envelope, **SCOPED_CONTINUITY)
        self.assertEqual(result.codes(), [Code.PROFILE_MISMATCH], result.to_dict())

    def test_honest_scoped_passes_on_authenticated_path(self):
        apr, envelope = self.honest_scoped()
        result = self.verify_authenticated(apr, envelope, **SCOPED_CONTINUITY)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.scope_recomputed)

    def test_scoped_on_plain_verify_fails_closed_with_scope_mismatch(self):
        # plain verify() cannot recompute the scope, so a holder-chosen scope
        # is never accepted as continuity.
        _, envelope = self.honest_scoped()
        result = self.verify(envelope, **SCOPED_CONTINUITY)
        self.assertEqual(result.codes(), [Code.SCOPE_MISMATCH], result.to_dict())
        self.assertFalse(result.scope_recomputed)

    def test_foreign_scope_reports_one_scope_mismatch(self):
        # A scope derived for verifier A, presented under verifier B's APR.
        apr_a, envelope = self.honest_scoped()
        apr_b = self.make_apr(SCOPED_PRESENTATION, private_key=VERIFIER_B_KEY)
        result = self.make_verifier(
            private_key=VERIFIER_B_KEY, **SCOPED_CONTINUITY
        ).verify_authenticated(apr_b, envelope, self.verification_request(envelope), now=TIMESTAMP)
        self.assertEqual(result.codes(), [Code.SCOPE_MISMATCH], result.to_dict())
        self.assertFalse(result.scope_recomputed)

    def test_linkable_answer_provides_continuity(self):
        apr, envelope = self.linkable()
        result = self.verify_authenticated(apr, envelope, **LINKABLE_CONTINUITY)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertIsNotNone(result.presentation_handle)
        result = self.verify(envelope, **LINKABLE_CONTINUITY)
        self.assertEqual(result.codes(), [], result.to_dict())

    def test_linkable_continuity_refuses_scoped_and_anonymous(self):
        _, scoped = self.honest_scoped()
        result = self.verify(scoped, **LINKABLE_CONTINUITY)
        self.assertIn(Code.PROFILE_NOT_ACCEPTED, result.codes(), result.to_dict())
        self.assertFalse(result.valid)
        _, anonymous = self.downgraded_anonymous()
        result = self.verify(anonymous, **LINKABLE_CONTINUITY)
        self.assertIn(Code.PROFILE_NOT_ACCEPTED, result.codes(), result.to_dict())
        self.assertIn(Code.PROFILE_MISMATCH, result.codes(), result.to_dict())

    def test_scoped_continuity_refuses_linkable(self):
        apr, envelope = self.linkable()
        result = self.verify_authenticated(apr, envelope, **SCOPED_CONTINUITY)
        self.assertEqual(result.codes(), [Code.PROFILE_NOT_ACCEPTED], result.to_dict())

    def test_one_holder_gets_one_handle_under_scoped_continuity(self):
        # Review of PR #63: with both handle-bearing profiles admitted, one
        # holder could claim twice (scoped pseudonym, then linkable
        # commitment). Under a single-profile policy only one is valid.
        verifier = self.make_verifier(**SCOPED_CONTINUITY)
        seen = set()
        apr_scoped = self.make_apr(SCOPED_PRESENTATION, nonce=0x501)
        scoped = self.answer(apr_scoped, SCOPED_PROFILE)
        apr_linkable = self.make_apr(None, nonce=0x502)
        linkable = self.answer(apr_linkable, LINKABLE_PROFILE)
        first = verifier.verify_authenticated(
            apr_scoped, scoped, self.verification_request(scoped), now=TIMESTAMP, seen_nonces=seen
        )
        second = verifier.verify_authenticated(
            apr_linkable, linkable, self.verification_request(linkable), now=TIMESTAMP,
            seen_nonces=seen,
        )
        self.assertTrue(first.valid, first.to_dict())
        self.assertEqual(second.codes(), [Code.PROFILE_NOT_ACCEPTED], second.to_dict())

    def test_wire_result_stays_json(self):
        apr, envelope = self.honest_scoped()
        result = self.verify_authenticated(apr, envelope, **SCOPED_CONTINUITY)
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())


class UnboundHandleTests(ContinuityBase):
    """Review of PR #63: a request that lists no proof types skips every
    envelope entry, so nothing checks the binding handle against a proof."""

    def empty_request(self, envelope):
        base = self.verification_request(envelope)
        return VerificationRequest(
            proof_types=[], parameters={}, context=base.context,
            accumulator_states=base.accumulator_states,
        )

    def forged_linkable(self):
        _, envelope = self.linkable()
        forged = copy.deepcopy(envelope)
        forged["holderBinding"]["commitment"] = field_to_hex(12345)
        return forged

    def empty_scoped_apr_and_forged_envelope(self):
        _, envelope = self.honest_scoped()
        forged = copy.deepcopy(envelope)
        forged["presentationBinding"]["pseudonym"] = field_to_hex(777)
        apr = self.make_apr(SCOPED_PRESENTATION, nonce=0xDEF)
        unsigned = {key: copy.deepcopy(value) for key, value in apr.items() if key != "signature"}
        unsigned["request"]["proofTypes"] = []
        unsigned["request"]["parameters"] = {}
        return sign_apr(unsigned, VERIFIER_A_KEY), forged

    def test_empty_request_reports_no_handle_when_continuity_is_off(self):
        # Pre-existing behaviour kept: an empty request is accepted, but the
        # unproven binding handle is no longer reported.
        forged = self.forged_linkable()
        result = self.make_verifier().verify(forged, self.empty_request(forged))
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertEqual(result.presentation_profile, LINKABLE_PROFILE)
        self.assertIsNone(result.presentation_handle)

        apr, forged = self.empty_scoped_apr_and_forged_envelope()
        result = self.make_verifier().verify_authenticated(
            apr, forged, self.empty_request(forged), now=TIMESTAMP
        )
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertEqual(result.presentation_profile, SCOPED_PROFILE)
        self.assertIsNone(result.presentation_handle)
        self.assertIsNone(result.scope_id)
        self.assertFalse(result.scope_recomputed)
        self.assertEqual(
            result.to_dict()["presentation"],
            {"profile": SCOPED_PROFILE, "scopeRecomputed": False},
        )

    def test_forged_v1_commitment_with_empty_request_fails_continuity(self):
        forged = self.forged_linkable()
        result = self.make_verifier(**LINKABLE_CONTINUITY).verify(
            forged, self.empty_request(forged)
        )
        self.assertEqual(result.codes(), [Code.PROFILE_MISMATCH], result.to_dict())
        self.assertIsNone(result.presentation_handle)

    def test_forged_scoped_pseudonym_with_empty_apr_fails_continuity(self):
        apr, forged = self.empty_scoped_apr_and_forged_envelope()
        result = self.make_verifier(**SCOPED_CONTINUITY).verify_authenticated(
            apr, forged, self.empty_request(forged), now=TIMESTAMP
        )
        self.assertEqual(result.codes(), [Code.PROFILE_MISMATCH], result.to_dict())
        self.assertFalse(result.scope_recomputed)
        self.assertIsNone(result.presentation_handle)


if __name__ == "__main__":
    unittest.main()
