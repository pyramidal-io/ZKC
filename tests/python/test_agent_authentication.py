"""Agent requester authentication: R3.3 impersonation/relay and release paths."""

import dataclasses
import unittest
from unittest.mock import patch

from test_agent_compliance import (
    AgentTestBase, KYC_PROOF_TYPE, VERIFIER_ID, OTHER_VERIFIER_ID, TIMESTAMP,
    make_apr, make_request, make_context, make_policy_document, make_compliance_policy,
    signing_pin,
)
from zkc_agent import (
    ZKCAgentClient, ACTION_BLOCK, ACTION_REQUIRE_PRINCIPAL_APPROVAL,
    BLOCK_UNAUTHENTICATED_REQUEST, BLOCK_CONTEXT_MISMATCH, BLOCK_POLICY,
)
from zkc_crypto import ProofContext, sign_apr, verify_receipt
from holder_fixtures import verify_receipt_as_holder
from zkc_crypto.apr import verification_context_extension


class AgentAuthenticationTests(AgentTestBase):
    def setUp(self):
        super().setUp()
        # Use the production class, without the honest fixture's APR adapter.
        self.agent = ZKCAgentClient(
            self.holder, self.agent._registry,
            policy_documents={VERIFIER_ID: make_policy_document()},
            compliance_policy=make_compliance_policy(),
        )

    def handle(self, request, context, apr=None, **kwargs):
        return self.agent.handle_proof_request(request, context, apr=apr, now=TIMESTAMP, **kwargs)

    def assert_no_generation(self, request, context, apr, reason, **kwargs):
        with patch.object(self.holder, "generate_authenticated_proof") as authenticated:
            with patch.object(self.holder, "_generate_envelope") as raw:
                decision = self.handle(request, context, apr, **kwargs)
                self.assertEqual((decision.status, decision.reason_code), ("blocked", reason))
                summary = self.agent.precompute_proofs([(request, context, apr)], now=TIMESTAMP, **kwargs)
                self.assertEqual(summary["cached"], 0)
                self.assertEqual(summary["skipped"][0]["reason"], reason)
                authenticated.assert_not_called()
                raw.assert_not_called()
        self.assertEqual(self.agent.pending_approvals(), ())

    def test_original_forged_id_and_opaque_relabel_relay_stop_before_generation(self):
        request = make_request()
        self.assert_no_generation(request, make_context(), None, BLOCK_UNAUTHENTICATED_REQUEST)
        context_b = make_context(OTHER_VERIFIER_ID)
        opaque = ProofContext("deployment:opaque", context_b.value, TIMESTAMP)
        self.assert_no_generation(request, opaque, None, BLOCK_CONTEXT_MISMATCH)
        # Even a genuine pinned signature and explicit override cannot bless
        # a non-recomputable context.
        apr = make_apr(request, opaque)
        apr["request"]["extensions"] = verification_context_extension(opaque)
        apr = sign_apr(apr, 0xA9701)
        self.assert_no_generation(request, opaque, apr, BLOCK_CONTEXT_MISMATCH, allow_unauthenticated=True)

    def test_attacker_key_for_trusted_id_and_unpinned_key_are_refused(self):
        request, context = make_request(), make_context()
        self.assert_no_generation(request, context, make_apr(request, context, key=31337), BLOCK_UNAUTHENTICATED_REQUEST)
        self.agent.set_compliance_policy(make_compliance_policy(verifier_signing_keys={}))
        self.assert_no_generation(request, context, make_apr(request, context), BLOCK_UNAUTHENTICATED_REQUEST)

    def test_unsigned_demand_or_nonce_substitution_is_refused(self):
        request, context = make_request(), make_context()
        for mutate in (
            lambda a: a["request"]["parameters"][KYC_PROOF_TYPE].update(requiredLevel=2),
            lambda a: a.update(verifierId=OTHER_VERIFIER_ID),
            lambda a: a.update(nonce="0x" + "0" * 63 + "1"),
        ):
            apr = make_apr(request, context)
            mutate(apr)
            self.assert_no_generation(request, context, apr, BLOCK_UNAUTHENTICATED_REQUEST)

    def test_known_profile_relay_and_hidden_context_metadata_are_refused(self):
        request, context = make_request(), make_context()
        self.assert_no_generation(request, make_context(session_id=999), make_apr(request, context), BLOCK_CONTEXT_MISMATCH)
        hidden = dataclasses.replace(context, purpose="hidden")
        self.assert_no_generation(request, hidden, make_apr(request, context), BLOCK_CONTEXT_MISMATCH)

    def test_expired_future_and_noncanonical_nonces_are_refused(self):
        for changes in ({"expiresAt": TIMESTAMP - 1, "issuedAt": TIMESTAMP - 10},
                        {"issuedAt": TIMESTAMP + 1}, {"nonce": "0x1"}):
            request, context = make_request(), make_context()
            apr = make_apr(request, context)
            apr.update(changes)
            if "nonce" in changes:
                request = dataclasses.replace(request, nonce=changes["nonce"])
            apr = sign_apr(apr, 0xA9701)
            self.assert_no_generation(request, context, apr, BLOCK_UNAUTHENTICATED_REQUEST)

    def test_honest_receipt_authenticates_demand_and_audit_names_pinned_key(self):
        request, context = make_request(), make_context()
        apr = make_apr(request, context)
        with patch.object(self.holder, "generate_authenticated_proof", wraps=self.holder.generate_authenticated_proof) as generate:
            decision = self.handle(request, context, apr)
            self.assertEqual(decision.status, "responded")
            generate.assert_called_once()
        self.assertTrue(verify_receipt_as_holder(decision.receipt)["valid"])
        self.assertEqual(decision.receipt["apr"], apr)
        self.assertNotIn("receipt", decision.to_wire())  # holder custody
        event = self.agent.audit_log.events[-1]
        self.assertEqual(event["verifier_key"], "0x" + signing_pin().hex())
        self.assertEqual(event["authentication"], "AUTHENTICATED")
        self.assertEqual(self.holder.override_log, [])

    def queue(self):
        self.agent.set_compliance_policy(make_compliance_policy(actions={KYC_PROOF_TYPE: ACTION_REQUIRE_PRINCIPAL_APPROVAL}))
        request, context = make_request(), make_context()
        apr = make_apr(request, context)
        decision = self.handle(request, context, apr)
        self.assertEqual(decision.status, "queued")
        return request, context, apr, decision.approval_id

    def test_approval_rechecks_pin_expiry_policy_and_consent_before_generation(self):
        for change, reason in (("pin", BLOCK_UNAUTHENTICATED_REQUEST), ("expiry", BLOCK_UNAUTHENTICATED_REQUEST),
                               ("policy", BLOCK_POLICY), ("ceiling", "PLANNING_REFUSED")):
            with self.subTest(change=change):
                request, context, apr, approval_id = self.queue()
                now = TIMESTAMP
                if change == "pin":
                    self.agent.set_compliance_policy(make_compliance_policy(verifier_signing_keys={}))
                elif change == "expiry":
                    now += 3601
                elif change == "policy":
                    self.agent.set_compliance_policy(make_compliance_policy(actions={KYC_PROOF_TYPE: ACTION_BLOCK}))
                else:
                    self.agent.set_compliance_policy(make_compliance_policy(disclosure_ceiling={}))
                with patch.object(self.holder, "generate_authenticated_proof") as generate:
                    decision = self.agent.approve(approval_id, now=now)
                    self.assertEqual((decision.status, decision.reason_code), ("blocked", reason))
                    generate.assert_not_called()

    def test_queued_request_and_exposed_approval_are_detached(self):
        request, context, apr, approval_id = self.queue()
        request.parameters[KYC_PROOF_TYPE]["requiredLevel"] = 9
        apr["request"]["parameters"][KYC_PROOF_TYPE]["requiredLevel"] = 10
        exposed = self.agent.pending_approvals()[0]
        exposed.apr.clear()
        exposed.request.parameters.clear()
        decision = self.agent.approve(approval_id, now=TIMESTAMP)
        self.assertEqual(decision.status, "responded")
        self.assertTrue(verify_receipt_as_holder(decision.receipt)["valid"])

    def test_cache_is_bound_to_exact_apr_and_release_rechecks_pin_and_expiry(self):
        for revoke in (False, True):
            request, context = make_request(), make_context()
            apr = make_apr(request, context)
            self.agent.set_compliance_policy(make_compliance_policy())
            self.assertEqual(self.agent.precompute_proofs([(request, context, apr)], now=TIMESTAMP)["cached"], 1)
            if revoke:
                self.agent.set_compliance_policy(make_compliance_policy(verifier_signing_keys={}))
                now = TIMESTAMP
            else:
                now = TIMESTAMP + 3601
            with patch.object(self.holder, "generate_authenticated_proof") as generate:
                decision = self.agent.handle_proof_request(request, context, apr=apr, now=now)
                self.assertEqual(decision.status, "blocked")
                generate.assert_not_called()

    def test_honest_cache_returns_receipt_and_other_nonce_cannot_use_it(self):
        request, context = make_request(), make_context()
        apr = make_apr(request, context)
        self.assertEqual(self.agent.precompute_proofs([(request, context, apr)], now=TIMESTAMP)["cached"], 1)
        other = make_request()
        with patch.object(self.holder, "generate_authenticated_proof", wraps=self.holder.generate_authenticated_proof) as generate:
            decision = self.handle(other, context, make_apr(other, context))
            self.assertEqual(decision.status, "responded")
            generate.assert_called_once()
        with patch.object(self.holder, "generate_authenticated_proof") as generate:
            decision = self.handle(request, context, apr)
            generate.assert_not_called()
        self.assertTrue(verify_receipt_as_holder(decision.receipt)["valid"])
        self.assertEqual(decision.receipt["apr"], apr)
        self.assertTrue(self.agent.audit_log.events[-1]["from_cache"])

    def test_explicit_unauthenticated_override_is_logged_and_receipted(self):
        request, context = make_request(), make_context()
        decision = self.handle(request, context, allow_unauthenticated=True)
        self.assertEqual(decision.status, "responded")
        receipt = verify_receipt(decision.receipt)
        self.assertFalse(receipt["aprValid"])
        self.assertTrue(receipt["holderValid"])
        self.assertTrue(receipt["contextBound"])
        self.assertEqual(self.holder.override_log[-1]["kind"], "UNAUTHENTICATED")
        event = self.agent.audit_log.events[-1]
        self.assertEqual(event["authentication"], "UNAUTHENTICATED")
        self.assertEqual(event["verifier_key"], "")

    def test_approval_rule_cannot_queue_an_impersonated_request(self):
        self.agent.set_compliance_policy(make_compliance_policy(
            actions={KYC_PROOF_TYPE: ACTION_REQUIRE_PRINCIPAL_APPROVAL}
        ))
        request, context = make_request(), make_context()
        self.assert_no_generation(request, context, make_apr(request, context, key=31337),
                                  BLOCK_UNAUTHENTICATED_REQUEST)

    def test_replacing_policy_inputs_does_not_mutate_trusted_pins(self):
        policy = make_compliance_policy()
        self.agent.set_compliance_policy(policy)
        policy.verifier_signing_keys.clear()
        request, context = make_request(), make_context()
        decision = self.handle(request, context, make_apr(request, context))
        self.assertEqual(decision.status, "responded")
        self.assertTrue(verify_receipt_as_holder(decision.receipt)["valid"])

    def test_override_does_not_allow_a_valid_unpinned_signer(self):
        request, context = make_request(), make_context()
        self.assert_no_generation(request, context, make_apr(request, context, key=31337),
                                  BLOCK_UNAUTHENTICATED_REQUEST, allow_unauthenticated=True)

    def test_backend_cannot_mutate_the_retained_signed_demand(self):
        request, context = make_request(), make_context()
        apr = make_apr(request, context)
        original = self.holder._generate_envelope

        def mutate_caller(*args, **kwargs):
            apr["request"]["parameters"][KYC_PROOF_TYPE]["requiredLevel"] = 9
            request.parameters.clear()
            return original(*args, **kwargs)

        with patch.object(self.holder, "_generate_envelope", side_effect=mutate_caller):
            decision = self.handle(request, context, apr)
        self.assertEqual(decision.status, "responded")
        self.assertTrue(verify_receipt_as_holder(decision.receipt)["valid"])
        self.assertEqual(decision.receipt["apr"]["request"]["parameters"][KYC_PROOF_TYPE]["requiredLevel"], 1)

    def test_signed_purpose_bound_custom_age_is_supported(self):
        request = make_request()
        context = ProofContext.purpose_bound(VERIFIER_ID, 555, "KYC", TIMESTAMP)
        apr = make_apr(request, context)
        apr["request"]["extensions"] = verification_context_extension(context, 60)
        apr = sign_apr(apr, 0xA9701)
        decision = self.handle(request, context, apr)
        self.assertEqual(decision.status, "responded")
        self.assertTrue(verify_receipt_as_holder(decision.receipt)["valid"])


if __name__ == "__main__":
    unittest.main()
