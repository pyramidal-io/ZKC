"""ZKC-Agent compliance API tests (spec §5.4).

Covers: the policy decision matrix (tri-state × verifier trust × overrides,
deny-by-default), auto-response within policy (end-to-end verified),
replay / wrong-verifier rejection, approval-required queueing + principal
notification + approve/deny, disclosure-ceiling enforcement, the
precomputed-proof warm path, counterparty verification, and audit-log
redaction.
"""

import copy
import dataclasses
import json
import secrets
import pathlib
import tempfile
import unittest
from unittest import mock

from _path import REPO_ROOT
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402

from holder_fixtures import (
    DRAFT_OPT_IN_REVIEW_STATUSES,
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_kyc_credential,
)
from predicate_fixtures import issue_source_credential
import zkc_agent.agent as agent_module
from zkc_agent import (
    ACTION_AUTO_APPROVE,
    ACTION_BLOCK,
    ACTION_REQUIRE_PRINCIPAL_APPROVAL,
    AgentCompliancePolicy,
    ApprovalNotFoundError,
    AuditLog,
    PolicyConfigurationError,
    ZKCAgentClient,
    BLOCK_CONTEXT_MISMATCH,
    BLOCK_GENERATION_FAILED,
    BLOCK_NO_POLICY,
    BLOCK_PLANNING_REFUSED,
    BLOCK_POLICY,
    BLOCK_PRINCIPAL_DENIED,
    BLOCK_REPLAYED_REQUEST,
    BLOCK_UNTRUSTED_VERIFIER,
    redact,
)
from zkc_crypto import (ProofContext, derive_credential_binding_key, field_to_hex, sign_apr, apr_signer_pubkey)
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    NegotiationRequest,
    PredicateRegistry,
    StubBackend,
)
from zkc_holder.predicates import single_leaf_inclusion_witness, single_leaf_set_root
from zkc_registry.store import _policy_from_document, validate_verifier_policy
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    TrustedIssuer,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
MASTER_SEED = 42
VERIFIER_ID = "did:zkc:verifier:exchange-a"
OTHER_VERIFIER_ID = "did:zkc:verifier:exchange-b"
KYC_MINIMUM = {"requiredLevel": 1, "requiredAttributes": [True, False, False, False, False]}


# Public deterministic test key; never use for a deployment.
AGENT_TEST_KEY = 0xA9701
TIMESTAMP = 1_700_000_000


def make_apr(request, context, *, key=AGENT_TEST_KEY):
    return sign_apr({
        "verifierId": request.verifier_id, "nonce": request.nonce,
        "issuedAt": TIMESTAMP - 1, "expiresAt": TIMESTAMP + 3600,
        "request": {"proofTypes": list(request.proof_types),
                    "parameters": copy.deepcopy(request.parameters), "context": context.to_metadata()},
    }, key)


def signing_pin():
    request = NegotiationRequest(VERIFIER_ID, (KYC_PROOF_TYPE,), {KYC_PROOF_TYPE: KYC_MINIMUM}, field_to_hex(1))
    return apr_signer_pubkey(make_apr(request, make_context()))


class SignedTestAgent(ZKCAgentClient):
    """Supply genuine signed requests to existing honest policy-flow tests."""

    def handle_proof_request(self, request, context, current_epochs=None, **kwargs):
        kwargs.setdefault("apr", make_apr(request, context))
        kwargs.setdefault("now", TIMESTAMP)
        return super().handle_proof_request(request, context, current_epochs, **kwargs)

    def approve(self, approval_id, **kwargs):
        kwargs.setdefault("now", TIMESTAMP)
        return super().approve(approval_id, **kwargs)

    def precompute_proofs(self, entries, **kwargs):
        kwargs.setdefault("now", TIMESTAMP)
        return super().precompute_proofs(
            [(request, context, make_apr(request, context)) for request, context in entries], **kwargs
        )


def make_policy_document(verifier_id=VERIFIER_ID, proof_requirements=None):
    document = {
        "version": "zkc:registry:verifier-policy:v1",
        "verifierId": verifier_id,
        "displayName": "Agent Test Verifier",
        "acceptedProofTypes": [KYC_PROOF_TYPE],
        "requiredReviewStatuses": ["reviewed"],
        "trustedIssuers": [
            {
                "issuerId": TEST_ISSUER_ID,
                "publicKeyX": "0x" + TEST_ISSUER_KEY_X.hex(),
                "publicKeyY": "0x" + TEST_ISSUER_KEY_Y.hex(),
                "proofTypes": [KYC_PROOF_TYPE, "zkc:proof:kyc:v2"],
            }
        ],
        "acceptsOutOfRegistryIssuers": True,
        "requiredContextProfile": "",
        "maxEpochLag": 10,
        "proofRequirements": (
            proof_requirements
            if proof_requirements is not None
            else {KYC_PROOF_TYPE: dict(KYC_MINIMUM)}
        ),
        "updatedAt": "2026-06-11T00:00:00Z",
    }
    validate_verifier_policy(document, "<test>")
    return _policy_from_document(document, "<test>")


def make_compliance_policy(**overrides):
    defaults = dict(
        disclosure_ceiling={
            KYC_PROOF_TYPE: {
                "requiredLevel": 2,
                "requiredAttributes": [True, True, True, False, True],
            }
        },
        trusted_verifiers=(VERIFIER_ID,),
        actions={KYC_PROOF_TYPE: ACTION_AUTO_APPROVE},
        verifier_overrides={},
        verifier_signing_keys={VERIFIER_ID: (signing_pin(),)},
    )
    defaults.update(overrides)
    return AgentCompliancePolicy(**defaults)


def make_context(verifier_id=VERIFIER_ID, session_id=555):
    return ProofContext.verifier_session(verifier_id, session_id, 1_700_000_000)


def make_request(verifier_id=VERIFIER_ID, parameters=None, proof_types=(KYC_PROOF_TYPE,)):
    return NegotiationRequest(
        verifier_id, tuple(proof_types),
        parameters if parameters is not None else {KYC_PROOF_TYPE: dict(KYC_MINIMUM)},
        field_to_hex(secrets.randbelow(1 << 248)),
    )


class AgentTestBase(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        # The agent answers with the anonymous kyc:v2 presentation, whose
        # registry entry is still draft: opt in explicitly (Safeguard 4).
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
        self.notifications = []
        self.agent = SignedTestAgent(
            self.holder,
            REGISTRY,
            policy_documents={VERIFIER_ID: make_policy_document()},
            compliance_policy=make_compliance_policy(),
            principal_notifier=lambda event, payload: self.notifications.append(
                (event, payload)
            ),
            counterparty_verifier=self.make_verifier(),
        )

    def make_verifier(self):
        policy = VerifierTrustPolicy(
            issuers=(
                TrustedIssuer(
                    issuer_id=TEST_ISSUER_ID,
                    public_key_x=TEST_ISSUER_KEY_X,
                    public_key_y=TEST_ISSUER_KEY_Y,
                    proof_types=(KYC_PROOF_TYPE, "zkc:proof:kyc:v2"),
                ),
            )
        )
        return ZKCVerifier(REPO_ROOT, policy, StubVerifyBackend())

    def verification_request(self, context):
        return VerificationRequest(
            proof_types=["zkc:proof:kyc:v2"],
            parameters={"zkc:proof:kyc:v2": dict(KYC_MINIMUM)},
            context=context,
            accumulator_states={
                TEST_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                    roots=self.provider.roots(TEST_ISSUER_ID),
                )
            },
        )


class PolicyMatrixTests(AgentTestBase):
    """Tri-state × verifier trust × per-verifier override, deny-by-default."""

    def decide(self, policy):
        self.agent.set_compliance_policy(policy)
        return self.agent.handle_proof_request(make_request(), make_context())

    def test_auto_approve_responds(self):
        decision = self.decide(make_compliance_policy())
        self.assertEqual(decision.status, "responded")
        self.assertIsNotNone(decision.envelope)

    def test_default_holder_blocks_the_draft_v2_presentation(self):
        # Safeguard 4: without the explicit draft opt-in the holder refuses
        # the draft kyc:v2 entry, so the agent blocks and logs no override.
        self.holder._accepted_review_statuses = ("reviewed", "self_attested")
        decision = self.decide(make_compliance_policy())
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_GENERATION_FAILED)
        self.assertIsNone(decision.envelope)
        self.assertEqual(self.holder.override_log, [])

    def test_require_approval_queues(self):
        decision = self.decide(
            make_compliance_policy(
                actions={KYC_PROOF_TYPE: ACTION_REQUIRE_PRINCIPAL_APPROVAL}
            )
        )
        self.assertEqual(decision.status, "queued")
        self.assertTrue(decision.approval_id)

    def test_block_action_blocks(self):
        decision = self.decide(make_compliance_policy(actions={KYC_PROOF_TYPE: ACTION_BLOCK}))
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_POLICY)

    def test_unruled_proof_type_blocked_by_default(self):
        decision = self.decide(make_compliance_policy(actions={}))
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_POLICY)

    def test_untrusted_verifier_blocked(self):
        self.agent.set_compliance_policy(make_compliance_policy())
        decision = self.agent.handle_proof_request(
            make_request(verifier_id=OTHER_VERIFIER_ID),
            make_context(verifier_id=OTHER_VERIFIER_ID),
        )
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_UNTRUSTED_VERIFIER)

    def test_verifier_override_tightens(self):
        decision = self.decide(
            make_compliance_policy(
                verifier_overrides={
                    VERIFIER_ID: {KYC_PROOF_TYPE: ACTION_REQUIRE_PRINCIPAL_APPROVAL}
                }
            )
        )
        self.assertEqual(decision.status, "queued")

    def test_verifier_override_blocks(self):
        decision = self.decide(
            make_compliance_policy(
                verifier_overrides={VERIFIER_ID: {KYC_PROOF_TYPE: ACTION_BLOCK}}
            )
        )
        self.assertEqual(decision.status, "blocked")

    def test_no_policy_blocks(self):
        agent = SignedTestAgent(
            self.holder, REGISTRY, policy_documents={VERIFIER_ID: make_policy_document()}
        )
        decision = agent.handle_proof_request(make_request(), make_context())
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_NO_POLICY)

    def test_policy_validation_fails_closed(self):
        with self.assertRaises(PolicyConfigurationError):
            AgentCompliancePolicy(actions={KYC_PROOF_TYPE: "yolo"})
        with self.assertRaises(PolicyConfigurationError):
            AgentCompliancePolicy(
                trusted_verifiers=(),
                verifier_overrides={VERIFIER_ID: {KYC_PROOF_TYPE: ACTION_BLOCK}},
            )


class AutoResponseTests(AgentTestBase):
    def test_auto_response_verifies_end_to_end(self):
        context = make_context()
        decision = self.agent.handle_proof_request(make_request(), context)
        self.assertEqual(decision.status, "responded")
        result = self.make_verifier().verify(
            decision.envelope, self.verification_request(context)
        )
        self.assertTrue(result.valid, result.to_dict())
        wire = decision.to_wire()
        self.assertEqual(wire["status"], "proof")
        self.assertIn("envelope", wire)

    def test_ceiling_blocks_request_beyond_consent(self):
        # The verifier's published minimum (level 2 here) exceeds the
        # principal's ceiling (level 1): the agent must refuse even though
        # the action says auto-approve.
        self.agent.register_verifier_policy(
            VERIFIER_ID,
            make_policy_document(
                proof_requirements={
                    KYC_PROOF_TYPE: {
                        "requiredLevel": 2,
                        "requiredAttributes": [True, False, False, False, False],
                    }
                }
            ),
        )
        self.agent.set_compliance_policy(
            make_compliance_policy(
                disclosure_ceiling={
                    KYC_PROOF_TYPE: {
                        "requiredLevel": 1,
                        "requiredAttributes": [True, False, False, False, False],
                    }
                }
            )
        )
        request = make_request(
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 2,
                    "requiredAttributes": [True, False, False, False, False],
                }
            }
        )
        decision = self.agent.handle_proof_request(request, make_context())
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_PLANNING_REFUSED)

    def test_typed_ceiling_refuses_non_kyc_request_beyond_consent(self):
        """Security review R3.6 PoC at the agent: the ceiling compared only
        KYC values, so accreditation required0 = 10^10 under a ceiling of
        100000 was planned and would have been answered."""
        proof_type = "zkc:proof:accreditation:v7"
        document = make_policy_document().raw | {
            "acceptedProofTypes": [proof_type],
            "trustedIssuers": [
                dict(make_policy_document().raw["trustedIssuers"][0], proofTypes=[proof_type])
            ],
        }
        document.pop("proofRequirements")
        validate_verifier_policy(document, "<test>")
        self.agent.register_verifier_policy(
            VERIFIER_ID, _policy_from_document(document, "<test>")
        )
        self.agent.set_compliance_policy(
            make_compliance_policy(
                disclosure_ceiling={
                    proof_type: {"required0": 100_000, "required1": 0, "flagRequired": False}
                },
                actions={proof_type: ACTION_REQUIRE_PRINCIPAL_APPROVAL},
            )
        )

        def request(required0):
            return make_request(
                parameters={
                    proof_type: {"required0": required0, "required1": 0, "flagRequired": False}
                },
                proof_types=(proof_type,),
            )

        decision = self.agent.handle_proof_request(request(10_000_000_000), make_context())
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_PLANNING_REFUSED)
        self.assertEqual(self.agent.pending_approvals(), ())
        # Within a u8 ceiling the request plans and waits for the principal;
        # one level more is refused.
        self.agent.set_compliance_policy(
            make_compliance_policy(
                disclosure_ceiling={
                    proof_type: {"required0": 200, "required1": 0, "flagRequired": False}
                },
                actions={proof_type: ACTION_REQUIRE_PRINCIPAL_APPROVAL},
            )
        )
        decision = self.agent.handle_proof_request(request(201), make_context())
        self.assertEqual(decision.reason_code, BLOCK_PLANNING_REFUSED)
        decision = self.agent.handle_proof_request(request(200), make_context())
        self.assertEqual(decision.status, "queued")
        (approval,) = self.agent.pending_approvals()
        summary = approval.summary()
        self.assertEqual(summary["plan"]["items"][0]["parameters"]["required0"], 200)
        self.assertEqual(summary["warnings"], [])

    def test_exact_member_set_proof_needs_opt_in_and_shows_warnings(self):
        """A source-of-funds proof along the verifier's path discloses the
        holder's exact code: refused without the principal's opt-in, and with
        it queued with the overbreadth warnings in the approval summary."""
        proof_type = "zkc:proof:source:v8"
        document = make_policy_document().raw | {
            "acceptedProofTypes": [proof_type],
            "trustedIssuers": [
                dict(make_policy_document().raw["trustedIssuers"][0], proofTypes=[proof_type])
            ],
        }
        document.pop("proofRequirements")
        validate_verifier_policy(document, "<test>")
        self.agent.register_verifier_policy(
            VERIFIER_ID, _policy_from_document(document, "<test>")
        )
        path_index, siblings = single_leaf_inclusion_witness()
        parameters = {
            "setRoot": single_leaf_set_root(7),
            "pathIndex": path_index,
            "siblings": siblings,
        }
        ceiling = {"setRoot": parameters["setRoot"]}
        self.holder.store_credential(issue_source_credential(
            master_seed=MASTER_SEED, credential_id=71, provider=self.provider,
        ))

        def handle(ceiling):
            self.agent.set_compliance_policy(
                make_compliance_policy(
                    disclosure_ceiling={proof_type: ceiling},
                    actions={proof_type: ACTION_REQUIRE_PRINCIPAL_APPROVAL},
                )
            )
            return self.agent.handle_proof_request(
                make_request(parameters={proof_type: dict(parameters)}, proof_types=(proof_type,)),
                make_context(),
            )

        self.assertEqual(handle(ceiling).reason_code, BLOCK_PLANNING_REFUSED)
        decision = handle(dict(ceiling, allowExactMemberDisclosure=True))
        self.assertEqual(decision.status, "queued")
        (approval,) = self.agent.pending_approvals()
        summary = approval.summary()
        self.assertEqual(
            sorted(warning["kind"] for warning in summary["warnings"]),
            ["narrow_set", "verifier_inclusion_path"],
        )
        notified = [payload for event, payload in self.notifications if event == "approval_required"]
        self.assertEqual(notified[-1]["warnings"], summary["warnings"])
        self.assertEqual(self.agent.approve(decision.approval_id).status, "responded")
        self.assertEqual([record["kind"] for record in self.holder.override_log], ["EXACT_MEMBER"])
        with self.assertRaises(PolicyConfigurationError):
            make_compliance_policy(
                disclosure_ceiling={proof_type: dict(ceiling, allowExactMemberDisclosure=1)}
            )

    def test_plan_warnings_reach_the_disclosure_notification_and_audit_log(self):
        warning = {
            "proofType": KYC_PROOF_TYPE,
            "element": "jurisdictionCanonicalSet",
            "kind": "narrow_set",
            "mode": "inclusion",
            "anonymitySetSize": 1,
            "threshold": 5,
        }

        class WarningPlanner(agent_module.ProofPlanner):
            def plan(self, request, consent_scope=None):
                return dataclasses.replace(
                    super().plan(request, consent_scope=consent_scope), warnings=(warning,)
                )

        with mock.patch.object(agent_module, "ProofPlanner", WarningPlanner):
            decision = self.agent.handle_proof_request(make_request(), make_context())
        self.assertEqual(decision.status, "responded")
        disclosed = [
            event for event in self.agent.audit_log.events if event["event"] == "proof_disclosed"
        ]
        self.assertEqual(disclosed[-1]["plan_warnings"], [warning])
        notified = [payload for event, payload in self.notifications if event == "proof_disclosed"]
        self.assertEqual(notified[-1]["warnings"], [warning])

    def test_blocked_wire_responses_are_constant_shape(self):
        """Wrong verifier, blocked type, replay, ceiling: identical wire
        rejections (modulo nonce) — the cause is never revealed."""
        wires = []
        # Untrusted verifier.
        decision = self.agent.handle_proof_request(
            make_request(verifier_id=OTHER_VERIFIER_ID),
            make_context(verifier_id=OTHER_VERIFIER_ID),
        )
        wires.append(decision.to_wire())
        # Blocked proof type.
        self.agent.set_compliance_policy(
            make_compliance_policy(actions={KYC_PROOF_TYPE: ACTION_BLOCK})
        )
        wires.append(self.agent.handle_proof_request(make_request(), make_context()).to_wire())
        # Replay.
        self.agent.set_compliance_policy(make_compliance_policy())
        request = make_request()
        self.agent.handle_proof_request(request, make_context())
        wires.append(self.agent.handle_proof_request(request, make_context()).to_wire())
        for wire in wires:
            wire.pop("nonce")
        self.assertEqual(wires[0], wires[1])
        self.assertEqual(wires[1], wires[2])


class ReplayAndContextTests(AgentTestBase):
    def test_replayed_nonce_rejected(self):
        request = make_request()
        first = self.agent.handle_proof_request(request, make_context())
        self.assertEqual(first.status, "responded")
        second = self.agent.handle_proof_request(request, make_context(session_id=556))
        self.assertEqual(second.status, "blocked")
        self.assertEqual(second.reason_code, BLOCK_REPLAYED_REQUEST)

    def test_wrong_verifier_context_rejected(self):
        # Context bound to verifier B presented with a request from verifier A.
        decision = self.agent.handle_proof_request(
            make_request(), make_context(verifier_id=OTHER_VERIFIER_ID)
        )
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_CONTEXT_MISMATCH)

    def test_non_reconstructing_context_rejected(self):
        context = make_context()
        tampered = ProofContext(
            profile=context.profile,
            value=context.value + 1,
            timestamp=context.timestamp,
            verifier_id=context.verifier_id,
            session_id=context.session_id,
        )
        decision = self.agent.handle_proof_request(make_request(), tampered)
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.reason_code, BLOCK_CONTEXT_MISMATCH)


class ApprovalFlowTests(AgentTestBase):
    def setUp(self):
        super().setUp()
        self.agent.set_compliance_policy(
            make_compliance_policy(
                actions={KYC_PROOF_TYPE: ACTION_REQUIRE_PRINCIPAL_APPROVAL}
            )
        )

    def test_approval_queue_and_notification(self):
        context = make_context()
        decision = self.agent.handle_proof_request(make_request(), context)
        self.assertEqual(decision.status, "queued")
        events = [event for event, _ in self.notifications]
        self.assertIn("approval_required", events)
        (approval,) = self.agent.pending_approvals()
        self.assertEqual(approval.approval_id, decision.approval_id)
        summary = approval.summary()
        self.assertEqual(summary["verifierId"], VERIFIER_ID)
        self.assertEqual(summary["proofTypes"], [KYC_PROOF_TYPE])

    def test_approve_releases_proof(self):
        context = make_context()
        decision = self.agent.handle_proof_request(make_request(), context)
        released = self.agent.approve(decision.approval_id)
        self.assertEqual(released.status, "responded")
        result = self.make_verifier().verify(
            released.envelope, self.verification_request(context)
        )
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(self.agent.pending_approvals(), ())
        with self.assertRaises(ApprovalNotFoundError):
            self.agent.approve(decision.approval_id)

    def test_deny_blocks(self):
        decision = self.agent.handle_proof_request(make_request(), make_context())
        denied = self.agent.deny(decision.approval_id)
        self.assertEqual(denied.status, "blocked")
        self.assertEqual(denied.reason_code, BLOCK_PRINCIPAL_DENIED)
        with self.assertRaises(ApprovalNotFoundError):
            self.agent.deny(decision.approval_id)


class PrecomputeTests(AgentTestBase):
    def test_precompute_then_serve_from_cache(self):
        context = make_context()
        request = make_request()
        summary = self.agent.precompute_proofs([(request, context)])
        self.assertEqual(summary["cached"], 1)
        self.assertEqual(summary["skipped"], [])
        decision = self.agent.handle_proof_request(request, context)
        self.assertEqual(decision.status, "responded")
        disclosed = [
            event for event in self.agent.audit_log.events if event["event"] == "proof_disclosed"
        ]
        self.assertTrue(disclosed[-1]["from_cache"])
        result = self.make_verifier().verify(
            decision.envelope, self.verification_request(context)
        )
        self.assertTrue(result.valid, result.to_dict())

    def test_precompute_never_bypasses_policy(self):
        self.agent.set_compliance_policy(
            make_compliance_policy(actions={KYC_PROOF_TYPE: ACTION_BLOCK})
        )
        summary = self.agent.precompute_proofs([(make_request(), make_context())])
        self.assertEqual(summary["cached"], 0)
        self.assertEqual(summary["skipped"][0]["reason"], BLOCK_POLICY)


class CounterpartyVerificationTests(AgentTestBase):
    def make_counterparty_envelope(self, context):
        provider = LocalAccumulatorProvider()
        counterparty_holder = HolderClient.from_seed(
            77,
            REGISTRY,
            StubBackend(),
            accumulator_provider=provider,
            accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        credential = issue_kyc_credential(
            master_seed=77, credential_id=9, provider=provider, expires_at=2_000_000_000
        )
        counterparty_holder.store_credential(credential)
        from zkc_holder import ProofRequest, TrustPolicy
        from zkc_holder.credential import TrustedIssuer as HolderTrustedIssuer

        trust_policy = TrustPolicy(
            issuers=(
                HolderTrustedIssuer(
                    issuer_id=TEST_ISSUER_ID,
                    public_key_x=TEST_ISSUER_KEY_X,
                    public_key_y=TEST_ISSUER_KEY_Y,
                    proof_types=(KYC_PROOF_TYPE, "zkc:proof:kyc:v2"),
                ),
            )
        )
        envelope = generate_unauthenticated_linkable(
            counterparty_holder, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters={KYC_PROOF_TYPE: dict(KYC_MINIMUM)},
                context=context,
                trust_policy=trust_policy,
            )
        )
        states = {
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=provider.current_epoch(TEST_ISSUER_ID),
                roots=provider.roots(TEST_ISSUER_ID),
            )
        }
        return envelope, states

    def test_valid_counterparty_accepted(self):
        context = make_context(session_id=999)
        envelope, states = self.make_counterparty_envelope(context)
        request = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={KYC_PROOF_TYPE: dict(KYC_MINIMUM)},
            context=context,
            accumulator_states=states,
        )
        result = self.agent.verify_counterparty(envelope, request)
        self.assertTrue(result.valid, result.to_dict())
        audited = [
            event
            for event in self.agent.audit_log.events
            if event["event"] == "counterparty_verified"
        ]
        self.assertTrue(audited and audited[-1]["valid"])

    def test_wrong_context_counterparty_rejected(self):
        context = make_context(session_id=999)
        envelope, states = self.make_counterparty_envelope(context)
        other_context = make_context(session_id=1000)
        request = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={KYC_PROOF_TYPE: dict(KYC_MINIMUM)},
            context=other_context,
            accumulator_states=states,
        )
        result = self.agent.verify_counterparty(envelope, request)
        self.assertFalse(result.valid)

    def test_unconfigured_counterparty_verifier_fails_closed(self):
        agent = SignedTestAgent(self.holder, REGISTRY)
        with self.assertRaises(PolicyConfigurationError):
            agent.verify_counterparty({}, None)


class AuditRedactionTests(AgentTestBase):
    def test_redact_strips_forbidden_keys_recursively(self):
        event = redact(
            {
                "proofs": [{"proof": "0xdeadbeef"}],
                "nested": {"claims": {"level": 3}, "ok": 1},
                "seed": 42,
                "fine": "value",
            }
        )
        self.assertEqual(event["proofs"], "[REDACTED]")
        self.assertEqual(event["nested"]["claims"], "[REDACTED]")
        self.assertEqual(event["seed"], "[REDACTED]")
        self.assertEqual(event["fine"], "value")

    def test_audit_log_refuses_unredacted_writes(self):
        log = AuditLog()
        entry = log.record("test_event", envelope={"proofs": ["x"]})
        self.assertEqual(entry["envelope"], "[REDACTED]")

    def test_full_flow_log_contains_no_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "audit.jsonl"
            notifications = []
            agent = SignedTestAgent(
                self.holder,
                REGISTRY,
                policy_documents={VERIFIER_ID: make_policy_document()},
                compliance_policy=make_compliance_policy(),
                principal_notifier=lambda event, payload: notifications.append(event),
                audit_log=AuditLog(path=path),
                counterparty_verifier=self.make_verifier(),
            )
            context = make_context()
            decision = agent.handle_proof_request(make_request(), context)
            self.assertEqual(decision.status, "responded")
            # Queue + deny one too.
            agent.set_compliance_policy(
                make_compliance_policy(
                    actions={KYC_PROOF_TYPE: ACTION_REQUIRE_PRINCIPAL_APPROVAL}
                )
            )
            queued = agent.handle_proof_request(make_request(), make_context(session_id=777))
            agent.deny(queued.approval_id)

            raw = path.read_text()
            # Every line is valid JSON.
            for line in raw.splitlines():
                json.loads(line)
            # No credential claims, signature, seed, proof payload, or
            # witness material anywhere in the log.
            self.assertNotIn(self.credential.signature.hex(), raw)
            self.assertNotIn("verifiedAttributes", raw)
            self.assertNotIn("zkc:stub", raw)  # stub proof payload marker
            binding_key = derive_credential_binding_key(MASTER_SEED)
            self.assertNotIn(field_to_hex(binding_key), raw)
            self.assertNotIn(field_to_hex(self.credential.holder_commitment), raw)
            forbidden_present = [
                key
                for key in ("\"proof\"", "\"claims\"", "\"witness\"", "\"seed\"")
                if key in raw
            ]
            for key in forbidden_present:
                # Only ever with a redacted value.
                for line in raw.splitlines():
                    entry = json.loads(line)
                    self._assert_only_redacted(entry, key.strip('"'))

    def _assert_only_redacted(self, node, key):
        if isinstance(node, dict):
            for entry_key, value in node.items():
                if entry_key == key:
                    self.assertEqual(value, "[REDACTED]")
                self._assert_only_redacted(value, key)
        elif isinstance(node, list):
            for item in node:
                self._assert_only_redacted(item, key)


if __name__ == "__main__":
    unittest.main()
