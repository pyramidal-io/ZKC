"""Same-holder binding of composite presentations (security review 2026-10-04, R1.3).

Under the anonymous profile no public input derives from the holder's binding
key, and the envelope-level shape check (pseudonym == scope == 0) carries no
holder information, so a conjunctive request (KYC AND accreditation) could be
satisfied by splicing honest single-predicate proofs from different holders.

The verifier now rejects an anonymous envelope answering two or more requested
proofs with UNBOUND_COMPOSITE unless its policy declares the proofs
independent. Same-holder composites use the scoped profile; the new ``session``
scope policy derives the scope from the APR's own context value, so one
session's proofs share one in-circuit pseudonym while sessions stay unlinkable.

The holder refuses, before proving, to answer two or more proof types
anonymously (ANONYMOUS_COMPOSITE_REFUSED, spec 5.9.2 rule 5): the default
verifier can only reject that answer, so producing it would just disclose which
predicates the holder satisfies. ``ProofRequest.allow_unlinked_composite`` is
the holder's explicit opt-in for verifiers that declare the proofs independent.
"""

import copy
import sys
import unittest
from unittest import mock

import _path  # noqa: F401  (sys.path side effect)
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from _path import REPO_ROOT

if str(REPO_ROOT / "conformance") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "conformance"))

from presentation_vectors import (  # noqa: E402
    ACCREDITATION_PROOF_TYPE,
    ANONYMOUS,
    KYC_PROOF_TYPE,
    SESSION_SCOPED,
    CompositePipeline,
    _splice,
    _trusted_issuer_holder,
)
from zkc_crypto import sign_apr  # noqa: E402
from zkc_crypto.apr import SESSION_SCOPE_POLICY, scope_from_apr_presentation  # noqa: E402
from zkc_crypto.ecdsa_secp256k1 import N  # noqa: E402
from zkc_crypto.presentation import (  # noqa: E402
    ANONYMOUS_PROFILE,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
)
from zkc_holder import HolderClient, TrustPolicy  # noqa: E402
from zkc_holder.client import _Presentation  # noqa: E402
from zkc_holder.errors import AnonymousCompositeRefusedError, HolderError  # noqa: E402
from zkc_verifier.errors import VerificationErrorCode as Code  # noqa: E402

SESSION = 2001
TIMESTAMP = 1_700_000_000


class AnonymousCompositeTests(unittest.TestCase):
    def setUp(self):
        self.pipe = CompositePipeline()
        self.request = self.pipe.verification_request(session_id=SESSION, timestamp=TIMESTAMP)

    def anonymous(self, holder, proof_types, nonce, **kwargs):
        return self.pipe.generate(
            holder, proof_types, presentation=ANONYMOUS,
            session_id=SESSION, timestamp=TIMESTAMP, nonce=nonce, **kwargs,
        )

    def pooled(self):
        return _splice(
            self.anonymous(self.pipe.alice, (KYC_PROOF_TYPE,), 0x61),
            self.anonymous(self.pipe.bob, (ACCREDITATION_PROOF_TYPE,), 0x62),
        )

    def composite_apr(self, presentation=ANONYMOUS, nonce=0x63):
        return self.pipe.apr(
            self.pipe.TYPES, session_id=SESSION, timestamp=TIMESTAMP, nonce=nonce,
            presentation=presentation,
        )

    def test_pooled_envelope_is_rejected_on_both_entry_points(self):
        pooled = self.pooled()
        result = self.pipe.verifier().verify(pooled, self.request)
        self.assertEqual(result.codes(), [Code.UNBOUND_COMPOSITE], result.to_dict())
        result = self.pipe.verifier().verify_authenticated(
            self.composite_apr(), pooled, self.request,
            now=self.request.context.timestamp
        )
        self.assertEqual(result.codes(), [Code.UNBOUND_COMPOSITE], result.to_dict())

    def test_honest_anonymous_composite_is_rejected_too(self):
        """The anonymous profile cannot attest one holder even when one holder
        answered: nothing in it distinguishes this from the pooled envelope.
        (The reference holder produces it only on its explicit opt-in.)"""
        carol = self.anonymous(
            self.pipe.carol, self.pipe.TYPES, 0x64, allow_unlinked_composite=True
        )
        result = self.pipe.verifier().verify(carol, self.request)
        self.assertEqual(result.codes(), [Code.UNBOUND_COMPOSITE], result.to_dict())

    def test_explicit_independence_policy_accepts(self):
        verifier = self.pipe.verifier(accept_independent_anonymous_proofs=True)
        self.assertEqual(verifier.verify(self.pooled(), self.request).codes(), [])
        self.assertTrue(verifier.verify_authenticated(
            self.composite_apr(), self.pooled(), self.request,
            now=self.request.context.timestamp).valid)

    def test_independence_policy_requires_an_actual_boolean(self):
        for value in ("false", "true", 0, 1, None, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.pipe.verifier(accept_independent_anonymous_proofs=value)

    def test_duplicate_single_predicate_is_not_a_second_distinct_conjunct(self):
        single = self.anonymous(self.pipe.alice, (KYC_PROOF_TYPE,), 0x66)
        single["proofs"].append(copy.deepcopy(single["proofs"][0]))
        request = self.pipe.verification_request(session_id=SESSION, timestamp=TIMESTAMP)
        request.proof_types = request.proof_types[:1]
        request.parameters = {request.proof_types[0]: request.parameters[request.proof_types[0]]}
        self.assertTrue(self.pipe.verifier().verify(single, request).valid)
        missing = self.pipe.verifier().verify(single, self.request)
        self.assertFalse(missing.valid)
        self.assertIn(Code.MISSING_PROOF, missing.codes())

    def test_unknown_type_cannot_turn_pooling_into_acceptance(self):
        pooled = self.pooled()
        unknown = "zkc:proof:unknown-composite:v2"
        pooled["proofs"][1]["proofType"] = unknown
        self.request.proof_types[1] = unknown
        result = self.pipe.verifier().verify(pooled, self.request)
        self.assertFalse(result.valid)
        self.assertIn(Code.UNKNOWN_PROOF_TYPE, result.codes())

    def test_signed_family_aliases_cannot_bypass_composite_checks(self):
        apr = self.composite_apr()
        raw = apr["request"]
        raw["proofTypes"] = [KYC_PROOF_TYPE, "zkc:proof:kyc:v2"]
        raw["parameters"] = {pt: copy.deepcopy(raw["parameters"][KYC_PROOF_TYPE])
                             for pt in raw["proofTypes"]}
        from presentation_vectors import APR_VERIFIER_A_PRIVATE_KEY
        apr = sign_apr(apr, APR_VERIFIER_A_PRIVATE_KEY)
        result = self.pipe.verifier().verify_authenticated(apr, self.pooled(), self.request, now=self.request.context.timestamp)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST])

    def test_single_anonymous_answer_is_unaffected(self):
        single = self.anonymous(self.pipe.alice, (KYC_PROOF_TYPE,), 0x65)
        request = self.pipe.verification_request(session_id=SESSION, timestamp=TIMESTAMP)
        request.proof_types = request.proof_types[:1]
        request.parameters = {request.proof_types[0]: request.parameters[request.proof_types[0]]}
        self.assertEqual(self.pipe.verifier().verify(single, request).codes(), [])

    def test_unrequested_extra_proof_does_not_count(self):
        """Over-disclosure is a warning, never a second answer."""
        pooled = self.pooled()
        request = self.pipe.verification_request(session_id=SESSION, timestamp=TIMESTAMP)
        request.proof_types = request.proof_types[:1]
        request.parameters = {request.proof_types[0]: request.parameters[request.proof_types[0]]}
        result = self.pipe.verifier().verify(pooled, request)
        self.assertEqual(result.codes(), [])
        self.assertIn("OVER_DISCLOSURE", result.warning_codes())


class SessionScopedCompositeTests(unittest.TestCase):
    def setUp(self):
        self.pipe = CompositePipeline()

    def test_one_holder_session_scoped_composite_verifies(self):
        envelope = self.pipe.generate(
            self.pipe.carol, self.pipe.TYPES, presentation=SESSION_SCOPED,
            session_id=SESSION, timestamp=TIMESTAMP, nonce=0x71,
        )
        apr = self.pipe.apr(
            self.pipe.TYPES, session_id=SESSION, timestamp=TIMESTAMP, nonce=0x71,
            presentation=SESSION_SCOPED,
        )
        request = self.pipe.verification_request(session_id=SESSION, timestamp=TIMESTAMP)
        self.assertEqual(self.pipe.verifier().verify(envelope, request).codes(), [])
        result = self.pipe.verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [], result.to_dict())

    def test_pooling_under_the_session_scope_is_profile_mismatch(self):
        alice = self.pipe.generate(
            self.pipe.alice, (KYC_PROOF_TYPE,), presentation=SESSION_SCOPED,
            session_id=SESSION, timestamp=TIMESTAMP, nonce=0x72,
        )
        bob = self.pipe.generate(
            self.pipe.bob, (ACCREDITATION_PROOF_TYPE,), presentation=SESSION_SCOPED,
            session_id=SESSION, timestamp=TIMESTAMP, nonce=0x73,
        )
        self.assertEqual(
            alice["presentationBinding"]["scopeId"], bob["presentationBinding"]["scopeId"]
        )
        request = self.pipe.verification_request(session_id=SESSION, timestamp=TIMESTAMP)
        result = self.pipe.verifier().verify(_splice(alice, bob), request)
        self.assertIn(Code.PROFILE_MISMATCH, result.codes(), result.to_dict())


class HolderAnonymousCompositeRefusalTests(unittest.TestCase):
    """The holder refuses, before proving, an anonymous answer to two or more
    proof types (spec 5.9.2 rule 5): under the default verifier policy it can
    only be rejected (UNBOUND_COMPOSITE), so producing it would just disclose
    which predicates the holder satisfies."""

    def setUp(self):
        self.pipe = CompositePipeline()

    def generate(self, holder, proof_types, presentation, nonce, **kwargs):
        return self.pipe.generate(
            holder, proof_types, presentation=presentation,
            session_id=SESSION, timestamp=TIMESTAMP, nonce=nonce, **kwargs,
        )

    def assert_refused_before_proving(self, call):
        with mock.patch.object(
            HolderClient, "_generate_individual_proof_v2",
            side_effect=AssertionError("proved before refusing"),
        ):
            with self.assertRaises(AnonymousCompositeRefusedError) as caught:
                call()
        error = caught.exception
        self.assertEqual(error.code, "ANONYMOUS_COMPOSITE_REFUSED")
        self.assertIsInstance(error, HolderError)
        self.assertIn("'session'", error.message)
        self.assertIn(SCOPED_PROFILE, error.message)
        self.assertIn("allow_unlinked_composite", error.message)
        return error

    def test_anonymous_composite_is_refused_before_proving(self):
        self.assert_refused_before_proving(
            lambda: self.generate(self.pipe.carol, self.pipe.TYPES, ANONYMOUS, 0x81)
        )

    def test_refusal_precedes_the_consent_prompt(self):
        """No consent is asked for an answer that cannot succeed."""
        self.assert_refused_before_proving(
            lambda: self.generate(
                self.pipe.carol, self.pipe.TYPES, ANONYMOUS, 0x82, consents={}
            )
        )

    def test_downgrade_of_a_session_scoped_request_is_refused(self):
        """A verifier asking for the session scope does not lift the holder's
        anonymous ceiling (no silent upgrade); the downgrade is refused."""
        self.assert_refused_before_proving(
            lambda: self.generate(
                self.pipe.carol, self.pipe.TYPES, SESSION_SCOPED, 0x83,
                holder_profile=ANONYMOUS_PROFILE,
            )
        )

    def test_direct_anonymous_generation_is_refused_too(self):
        request = self.pipe.proof_request(
            self.pipe.TYPES, session_id=SESSION, timestamp=TIMESTAMP,
            profile=ANONYMOUS_PROFILE,
        )
        self.assert_refused_before_proving(
            lambda: self.pipe.carol._generate_envelope(
                request,
                _Presentation(ANONYMOUS_PROFILE, 0),
                consents={pt: True for pt in self.pipe.TYPES},
            )
        )

    def test_explicit_opt_in_answers_and_the_verifier_policy_decides(self):
        envelope = self.generate(
            self.pipe.carol, self.pipe.TYPES, ANONYMOUS, 0x84,
            allow_unlinked_composite=True,
        )
        self.assertEqual(envelope["presentationBinding"], {"profile": ANONYMOUS_PROFILE})
        self.assertEqual(len(envelope["proofs"]), 2)
        request = self.pipe.verification_request(session_id=SESSION, timestamp=TIMESTAMP)
        self.assertEqual(
            self.pipe.verifier().verify(envelope, request).codes(), [Code.UNBOUND_COMPOSITE]
        )
        independent = self.pipe.verifier(accept_independent_anonymous_proofs=True)
        self.assertEqual(independent.verify(envelope, request).codes(), [])

    def test_single_anonymous_answer_needs_no_opt_in(self):
        envelope = self.generate(self.pipe.alice, (KYC_PROOF_TYPE,), ANONYMOUS, 0x85)
        self.assertEqual(envelope["presentationBinding"], {"profile": ANONYMOUS_PROFILE})
        self.assertEqual(len(envelope["proofs"]), 1)

    def test_scoped_and_linkable_composites_are_unaffected(self):
        scoped = self.generate(self.pipe.carol, self.pipe.TYPES, SESSION_SCOPED, 0x86)
        self.assertEqual(scoped["presentationBinding"]["profile"], SCOPED_PROFILE)
        self.assertEqual(len(scoped["proofs"]), 2)
        # The linkable (zkc:proof:v1) path binds every proof to one
        # holderCommitment, so it needs no opt-in either.
        request = self.pipe.proof_request(
            self.pipe.TYPES, session_id=SESSION, timestamp=TIMESTAMP,
            profile=LINKABLE_PROFILE,
        )
        request.trust_policy = TrustPolicy(
            issuers=(_trusted_issuer_holder(list(self.pipe.TYPES)),)
        )
        linkable = generate_unauthenticated_linkable(
            self.pipe.carol, request, consents={pt: True for pt in self.pipe.TYPES}
        )
        self.assertEqual(linkable["version"], "zkc:proof:v1")
        self.assertEqual(len(linkable["proofs"]), 2)

    def test_opt_in_is_visible_in_the_request_repr(self):
        request = self.pipe.proof_request(
            self.pipe.TYPES, session_id=SESSION, timestamp=TIMESTAMP,
            profile=ANONYMOUS_PROFILE, allow_unlinked_composite=True,
        )
        self.assertIn("allow_unlinked_composite=True", repr(request))

    def test_holder_opt_in_requires_an_actual_boolean_and_survives_mutation(self):
        for value in ("false", "true", 0, 1, None, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.pipe.proof_request(
                    self.pipe.TYPES, session_id=SESSION, timestamp=TIMESTAMP,
                    profile=ANONYMOUS_PROFILE, allow_unlinked_composite=value)
        request = self.pipe.proof_request(
            self.pipe.TYPES, session_id=SESSION, timestamp=TIMESTAMP, profile=ANONYMOUS_PROFILE)
        request.allow_unlinked_composite = "false"
        self.assert_refused_before_proving(lambda: self.pipe.carol._generate_envelope(
            request, _Presentation(ANONYMOUS_PROFILE, 0),
            consents={pt: True for pt in self.pipe.TYPES}))

    def test_independence_opt_in_still_requires_each_predicate_consent(self):
        from zkc_holder import ConsentRequiredError
        with self.assertRaises(ConsentRequiredError):
            self.generate(self.pipe.carol, self.pipe.TYPES, ANONYMOUS, 0x87,
                          allow_unlinked_composite=True, consents={KYC_PROOF_TYPE: True})


class SessionScopeDerivationTests(unittest.TestCase):
    KEY_A = 0x5E5510A % N or 1
    KEY_B = 0x5E5510B % N or 2

    def apr(self, key, session, timestamp, policy=SESSION_SCOPE_POLICY):
        presentation = {"profile": SCOPED_PROFILE, "scopePolicy": policy}
        return sign_apr(
            {
                "request": {
                    "proofTypes": [KYC_PROOF_TYPE],
                    "parameters": {KYC_PROOF_TYPE: {}},
                    "context": {
                        "profile": "zkc:context:verifier-session:v1",
                        "verifierId": "verifier.example",
                        "sessionId": hex(session),
                        "timestamp": timestamp,
                    },
                    "trustPolicy": {"issuers": []},
                    "presentation": presentation,
                },
                "verifierId": "verifier.example",
                "nonce": hex(0x77),
                "issuedAt": timestamp,
                "expiresAt": timestamp + 3600,
            },
            key,
        ), presentation

    def scope(self, key, session, timestamp, policy=SESSION_SCOPE_POLICY):
        apr, block = self.apr(key, session, timestamp, policy)
        return scope_from_apr_presentation(apr, block, timestamp)

    def test_session_scope_is_unique_per_context_and_verifier(self):
        base = self.scope(self.KEY_A, 1, TIMESTAMP)
        self.assertEqual(base, self.scope(self.KEY_A, 1, TIMESTAMP))
        self.assertNotEqual(base, self.scope(self.KEY_A, 2, TIMESTAMP))
        self.assertNotEqual(base, self.scope(self.KEY_A, 1, TIMESTAMP + 1))
        self.assertNotEqual(base, self.scope(self.KEY_B, 1, TIMESTAMP))
        # Contrast: the verifier scope is stable across sessions by design.
        self.assertEqual(
            self.scope(self.KEY_A, 1, TIMESTAMP, "verifier"),
            self.scope(self.KEY_A, 2, TIMESTAMP + 5, "verifier"),
        )

    def test_reserved_session_prefix_is_refused(self):
        with self.assertRaises(ValueError):
            self.scope(self.KEY_A, 1, TIMESTAMP, "session:0x01")

    def test_holder_refuses_a_reserved_session_label(self):
        pipe = CompositePipeline()
        with self.assertRaises(HolderError):
            pipe.generate(
                pipe.carol, pipe.TYPES,
                presentation={"profile": SCOPED_PROFILE, "scopePolicy": "session:0x01"},
                session_id=SESSION, timestamp=TIMESTAMP, nonce=0x78,
            )


if __name__ == "__main__":
    unittest.main()
