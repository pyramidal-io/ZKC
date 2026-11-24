"""Rebind continuity-vs-migration state rules (security review 2026-10-04, R4.3).

Nothing in an authenticated rebind is exclusive or one-time: the credential
digest stays bound to the old holder forever, so the new key can never present
the credential or rebind it again, the old key keeps full power, and one old key
yields accepted rebinds to any number of new keys. These tests mirror the
review's fan-out PoC: the verifier ALONE accepts every rebind (it is a valid
continuity claim each time), and the reference ``RebindLedger`` applies the
spec 7.4.7 state rules on top -- one-time per credential, retire the old handle,
freeze on conflict.

They also pin the holder/verifier mapping fix: a scoped APR naming the linkable
spelling ``credential_rebind:v3`` is answered with ``rebind:v4``, which the
verifier now accepts instead of demanding the linkable spelling verbatim (the
holder used to disclose a proof that could only be rejected).
"""

import copy
import unittest

import _path  # noqa: F401  (sys.path side effect)
from _path import REPO_ROOT

from test_rebind_auth_verifier import (
    CREDENTIAL_ID,
    ISSUER_ID,
    KEY_X,
    KEY_Y,
    MASTER_SEED,
    SCOPE_ID,
    SESSION_ID,
    TIMESTAMP,
    RebindAuthVerifierBase,
)
from zkc_crypto import derive_credential_binding_key, field_to_hex, sign_apr, string_to_field
from zkc_crypto.presentation import SCOPED_PROFILE
from zkc_holder import HolderClient, PredicateRegistry, ProofRequest, RebindSecret, StubBackend
from zkc_holder import TrustedIssuer as HolderTrustedIssuer
from zkc_holder import TrustPolicy
from zkc_holder.errors import ConstraintViolationError
from zkc_holder.predicates import (
    REBIND_AUTH_PROOF_TYPE,
    REBIND_AUTH_V2_PROOF_TYPE,
    build_rebind_auth_witness,
)
from zkc_verifier import (
    RebindClaim,
    RebindLedger,
    RebindOutcome,
    VerificationRequest,
    VerificationResult,
    rebind_claims,
)

ISSUER_HASH = string_to_field(ISSUER_ID)


class FanOutTests(RebindAuthVerifierBase):
    """The review PoC: one old key, several new keys."""

    def rebind(self, new_seed, *, scoped=False):
        witness = self.witness_for(
            scoped=scoped, new_credential_binding_key=derive_credential_binding_key(new_seed)
        )
        envelope = self.envelope(scoped=scoped, witness=witness)
        request = self.request(scoped=scoped)
        result = self.verifier().verify(envelope, request)
        return envelope, request, result

    def test_every_fan_out_rebind_verifies_but_the_ledger_honours_one(self):
        ledger = RebindLedger()
        outcomes = []
        for new_seed in (99, 0xF00D, 0xBEEF):  # owner, thief, "after migration"
            envelope, request, result = self.rebind(new_seed)
            self.assertTrue(result.valid, result.to_dict())  # each is a valid continuity claim
            outcomes.append(ledger.apply(envelope, request, result)[0][1])
        self.assertEqual(
            outcomes, [RebindOutcome.ACCEPTED, RebindOutcome.CONFLICT, RebindOutcome.CONFLICT]
        )
        self.assertTrue(ledger.is_frozen(ISSUER_HASH, CREDENTIAL_ID))
        self.assertIsNone(ledger.holder_for(ISSUER_HASH, CREDENTIAL_ID))

    def test_accept_retires_the_old_handle_and_replay_is_idempotent(self):
        ledger = RebindLedger()
        envelope, request, result = self.rebind(99)
        (claim, outcome), = ledger.apply(envelope, request, result)
        self.assertEqual(outcome, RebindOutcome.ACCEPTED)
        self.assertEqual(ledger.holder_for(ISSUER_HASH, CREDENTIAL_ID), claim.new_handle)
        self.assertTrue(ledger.is_retired(ISSUER_HASH, CREDENTIAL_ID, claim.old_handle))
        self.assertFalse(ledger.is_retired(ISSUER_HASH, CREDENTIAL_ID, claim.new_handle))
        self.assertEqual(ledger.apply(envelope, request, result)[0][1], RebindOutcome.REPLAYED)
        self.assertEqual(ledger.holder_for(ISSUER_HASH, CREDENTIAL_ID), claim.new_handle)

    def test_the_new_key_can_never_rebind_the_credential(self):
        with self.assertRaises(ConstraintViolationError):
            build_rebind_auth_witness(
                old_credential_binding_key=derive_credential_binding_key(99),
                new_credential_binding_key=derive_credential_binding_key(0xCAFE),
                credential=self.credential,
                issuer_public_key_x=KEY_X,
                issuer_public_key_y=KEY_Y,
                accumulator_witness=self.witness,
                current_epoch=self.current_epoch,
                proof_context=self.context.value,
                timestamp=self.context.timestamp,
            )

    def test_another_scope_or_statement_cannot_dodge_the_conflict(self):
        """Exclusivity is per verifier: the owner's scoped rebind and a thief's
        linkable rebind from the same old key conflict."""
        ledger = RebindLedger()
        envelope, request, result = self.rebind(99, scoped=True)
        (claim, outcome), = ledger.apply(envelope, request, result)
        self.assertEqual(outcome, RebindOutcome.ACCEPTED)
        self.assertEqual(claim.scope_id, SCOPE_ID)
        self.assertEqual(ledger.accepted_claim(ISSUER_HASH, CREDENTIAL_ID), claim)
        envelope, request, result = self.rebind(0xF00D)
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(ledger.apply(envelope, request, result)[0][1], RebindOutcome.CONFLICT)
        self.assertTrue(ledger.is_frozen(ISSUER_HASH, CREDENTIAL_ID))

    def test_unrequested_rebind_entries_are_never_recorded(self):
        """Both reviewers' attack: a forged, unrequested rebind entry rides on a
        valid envelope (verification skips it with OVER_DISCLOSURE only)."""
        ledger = RebindLedger()
        envelope, request, result = self.rebind(99)
        forged = copy.deepcopy(self.envelope(scoped=True)["proofs"][0])
        forged["proof"] = "0xforged"
        forged["publicInputs"]["new_presentation_pseudonym"] = field_to_hex(0x2222)
        malformed = {
            "proofType": REBIND_AUTH_V2_PROOF_TYPE,
            "proof": "0x",
            "publicInputs": {"scope_id": "not-hex"},
            "principalConsent": True,
        }
        for extra in (forged, malformed):
            with self.subTest(extra=extra["proof"]):
                poisoned = copy.deepcopy(envelope)
                poisoned["proofs"].append(extra)
                verdict = self.verifier().verify(poisoned, request)
                self.assertTrue(verdict.valid, verdict.to_dict())
                self.assertIn("OVER_DISCLOSURE", verdict.warning_codes())
                recorded = RebindLedger().apply(poisoned, request, verdict)
                self.assertEqual(
                    [claim.proof_type for claim, _ in recorded], [REBIND_AUTH_PROOF_TYPE]
                )
        ledger.apply(envelope, request, result)
        self.assertIsNone(ledger.accepted_claim(ISSUER_HASH, 0xDEAD0001))

    def test_ledger_refuses_an_unaccepted_envelope_or_missing_request(self):
        envelope, request, result = self.rebind(99)
        rejected = VerificationResult()
        rejected.add("STALE_ACCUMULATOR", "not verified")
        with self.assertRaises(ValueError):
            RebindLedger().apply(envelope, request, rejected)
        with self.assertRaises(ValueError):
            RebindLedger().apply(envelope, None, result)

    def test_claims_parse_only_authenticated_rebind_statements(self):
        envelope, request, _ = self.rebind(99)
        (claim,) = rebind_claims(envelope, request)
        self.assertIsInstance(claim, RebindClaim)
        self.assertEqual(claim.credential_id, CREDENTIAL_ID)
        self.assertEqual(claim.issuer_id_hash, ISSUER_HASH)
        other = copy.deepcopy(envelope)
        other["proofs"][0]["proofType"] = "zkc:proof:kyc:v1"
        self.assertEqual(rebind_claims(other, request), ())


class ScopedAprLinkableSpellingTests(RebindAuthVerifierBase):
    """A scoped APR naming credential_rebind:v3 no longer yields a doomed proof."""

    def test_scoped_apr_naming_the_linkable_spelling_is_answered_and_accepted(self):
        parameters = {"credentialId": CREDENTIAL_ID}
        presentation = {"profile": SCOPED_PROFILE, "scopePolicy": "verifier", "rotationEpochSeconds": 0}
        apr = sign_apr(
            {
                "request": {
                    "proofTypes": [REBIND_AUTH_PROOF_TYPE],
                    "parameters": {REBIND_AUTH_PROOF_TYPE: dict(parameters)},
                    "context": {
                        "profile": self.context.profile,
                        "verifierId": "verifier.example",
                        "sessionId": field_to_hex(SESSION_ID),
                        "timestamp": TIMESTAMP,
                    },
                    "trustPolicy": {"issuers": []},
                    "presentation": presentation,
                },
                "verifierId": "verifier.example",
                "nonce": field_to_hex(0xABC124),
                "issuedAt": TIMESTAMP,
                "expiresAt": TIMESTAMP + 3600,
            },
            0xA9701,
        )
        holder = HolderClient.from_seed(
            MASTER_SEED, PredicateRegistry.from_repo(REPO_ROOT), StubBackend()
        )
        holder.store_credential(self.credential)
        request = ProofRequest(
            proof_types=[REBIND_AUTH_PROOF_TYPE],
            parameters={REBIND_AUTH_PROOF_TYPE: dict(parameters)},
            context=self.context,
            trust_policy=TrustPolicy(
                issuers=(
                    HolderTrustedIssuer(
                        issuer_id=ISSUER_ID,
                        public_key_x=KEY_X,
                        public_key_y=KEY_Y,
                        proof_types=(REBIND_AUTH_PROOF_TYPE, REBIND_AUTH_V2_PROOF_TYPE),
                    ),
                )
            ),
            presentation_profile=SCOPED_PROFILE,
            rebind_secret=RebindSecret(self.new_cbk),
        )
        envelope = holder.generate_authenticated_proof(apr, request, now=TIMESTAMP)["envelope"]
        self.assertEqual(envelope["proofs"][0]["proofType"], REBIND_AUTH_V2_PROOF_TYPE)
        result = self.verifier().verify_authenticated(
            apr,
            envelope,
            VerificationRequest(
                proof_types=[REBIND_AUTH_V2_PROOF_TYPE],
                parameters={REBIND_AUTH_V2_PROOF_TYPE: dict(parameters)},
                context=self.context,
                max_proof_age=3600,
                accumulator_states={ISSUER_ID: self.authenticated_state},
            ),
            now=TIMESTAMP,
        )
        self.assertTrue(result.valid, result.to_dict())

    def test_only_the_rebind_family_gains_a_scoped_answer(self):
        """An anonymous APR keeps the verbatim comparison (no rebind is ever
        accepted anonymously); the scoped and linkable APRs accept the
        holder's scoped answer."""
        from zkc_crypto.presentation import ANONYMOUS_PROFILE, LINKABLE_PROFILE
        from zkc_verifier.verifier import _apr_presentation_proof_types

        def resolved(profile):
            return _apr_presentation_proof_types(
                {"proofTypes": [REBIND_AUTH_PROOF_TYPE], "presentation": {"profile": profile}}
            ).get(REBIND_AUTH_PROOF_TYPE)

        self.assertIsNone(resolved(ANONYMOUS_PROFILE))
        self.assertEqual(resolved(SCOPED_PROFILE), (REBIND_AUTH_V2_PROOF_TYPE,))
        self.assertEqual(
            resolved(LINKABLE_PROFILE), (REBIND_AUTH_PROOF_TYPE, REBIND_AUTH_V2_PROOF_TYPE)
        )


if __name__ == "__main__":
    unittest.main()
