"""Metadata-leakage assertions (CI pin for docs/zkc_metadata_leakage_threat_model.md).

Pins the IMPLEMENTED mitigations so they cannot silently regress:

- M1: registry reads are local-copy only (no network at lookup time);
- M2: witness refresh via credential-anonymous epoch fetch — the wire
  request names no credential and is identical for every holder;
- M3: constant-shape refusals — wire rejections are indistinguishable
  between no-credential and policy-refusal causes, and planning never
  touches the credential store;
- M4: lifecycle refresh runs through the anonymous provider (refresh
  decoupled from proof time).
"""

import secrets
import socket
import unittest
from unittest.mock import patch

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from _path import REPO_ROOT

from zkc_crypto import ProofContext, field_to_hex, sign_apr
from test_agent_compliance import signing_pin
from zkc_agent import AgentCompliancePolicy, ZKCAgentClient
from zkc_holder import (
    REFUSAL_MESSAGE,
    HolderClient,
    LifecycleManager,
    NegotiationRequest,
    OpaquePredicateError,
    OverbroadRequestError,
    PredicateRegistry,
    ProofPlanner,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    TrustedIssuer,
)
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import IssuerSigningKey, SandboxIssuerAdapter
from zkc_registry import DiscoveryRegistry
from zkc_registry.store import _policy_from_document, validate_verifier_policy
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    EPOCH_DELTA_REQUEST,
    InMemoryVerifierCheckpointStore,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    VerifierAccumulatorCache,
)
from zkc_verifier import (
    StubVerifyBackend,
    TrustedIssuer as VerifierTrustedIssuer,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)

ISSUER_ID = "zkc:issuer:sandbox"
KYC_SCHEMA_ID = "zkc:cred:kyc:v1"
KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
TIMESTAMP = 1_770_000_000
VERIFIER_ID = "did:zkc:verifier:exchange-a"

SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(SIGNING_KEY.metadata_entry())
REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
KYC_MINIMUM = {"requiredLevel": 1, "requiredAttributes": [True, False, False, False, True]}
PARAMETERS = {KYC_PROOF_TYPE: dict(KYC_MINIMUM)}


def make_service():
    return RevocationAccumulatorService(
        "sandbox-active-credentials",
        "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
        SIGNING_KEY,
        clock=lambda: TIMESTAMP,
    )


def obtain_credential(adapter, client):
    from zkc_holder import Credential

    holder_commitment_hex = field_to_hex(client.get_binding_commitment())
    subject = adapter.verify_subject(
        {"schemaId": KYC_SCHEMA_ID, "fixtureId": "sandbox-alice-basic"}
    )
    challenge = adapter.request_binding_challenge(
        {
            "subjectRef": subject["subjectRef"],
            "holderCommitment": holder_commitment_hex,
            "schemaId": KYC_SCHEMA_ID,
        }
    )
    response = client.binding_challenge_response(
        adapter.issuer_id, KYC_SCHEMA_ID, challenge["nonce"], challenge["expiresAt"]
    )
    adapter.bind_holder_commitment(
        {
            "subjectRef": subject["subjectRef"],
            "holderCommitment": holder_commitment_hex,
            "schemaId": KYC_SCHEMA_ID,
            "nonce": challenge["nonce"],
            "challengeResponse": response,
        }
    )
    envelope = adapter.issue_credential(
        {"subjectRef": subject["subjectRef"], "schemaId": KYC_SCHEMA_ID}
    )
    credential = Credential.from_dict(envelope["credential"])
    client.store_credential(credential)
    return credential


class LocalRegistryReadTests(unittest.TestCase):
    """M1: registry lookups never touch the network."""

    def test_registry_loads_with_networking_disabled(self):
        original_socket = socket.socket

        def refuse(*args, **kwargs):  # pragma: no cover — must not be hit
            raise AssertionError("registry read attempted to open a network socket")

        socket.socket = refuse
        try:
            registry = PredicateRegistry.from_repo(REPO_ROOT)
            self.assertIsNotNone(registry.resolve(KYC_PROOF_TYPE))
            discovery = DiscoveryRegistry.from_repo(REPO_ROOT)
            self.assertTrue(discovery.issuers())
            self.assertTrue(
                discovery.find_accepting_verifiers(KYC_PROOF_TYPE)
                or discovery.verifier_policies()
            )
        finally:
            socket.socket = original_socket


class AnonymousWitnessRefreshTests(unittest.TestCase):
    """M2: the epoch-fetch protocol cannot distinguish which credential
    refreshed."""

    def build_holder(self, master_seed):
        service = make_service()
        adapter = SandboxIssuerAdapter(
            signing_key=SIGNING_KEY, accumulator=service, clock=lambda: TIMESTAMP
        )
        provider = PrivateWitnessProvider(
            {ISSUER_ID: service},
            issuer_keys={ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            announcement_sources={ISSUER_ID: service},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: TIMESTAMP,
            accumulator_ids={ISSUER_ID: "sandbox-active-credentials"},
        )
        client = HolderClient.from_seed(
            master_seed, REGISTRY, StubBackend(), accumulator_provider=provider
        )
        credential = obtain_credential(adapter, client)
        return service, adapter, provider, client, credential

    def test_request_names_no_credential_and_is_holder_invariant(self):
        service_a, _, provider_a, client_a, credential_a = self.build_holder(9001)
        service_b, _, provider_b, client_b, credential_b = self.build_holder(9002)
        self.assertNotEqual(credential_a.holder_commitment, credential_b.holder_commitment)
        client_a.update_witness(credential_a.credential_id)
        client_b.update_witness(credential_b.credential_id)
        request_a = provider_a.sent_requests[-1]
        request_b = provider_b.sent_requests[-1]
        # Identical wire shape for different holders/credentials.
        self.assertEqual(request_a, request_b)
        self.assertEqual(request_a["type"], EPOCH_DELTA_REQUEST)
        self.assertNotIn("credentialId", request_a)

    def test_anonymous_refresh_proves_end_to_end(self):
        service, adapter, _provider, client, _credential = self.build_holder(9001)
        context = ProofContext.verifier_session("verifier.example", 7, TIMESTAMP)
        trust_policy = TrustPolicy(
            issuers=(
                TrustedIssuer(
                    issuer_id=ISSUER_ID,
                    public_key_x=KEY_X,
                    public_key_y=KEY_Y,
                    proof_types=(KYC_PROOF_TYPE,),
                ),
            )
        )
        request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=PARAMETERS,
            context=context,
            trust_policy=trust_policy,
        )
        envelope = generate_unauthenticated_linkable(client, request)
        self.assertEqual(
            envelope["proofs"][0]["publicInputs"]["accumulator_epoch"], service.epoch
        )
        verifier = ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                issuers=(
                    VerifierTrustedIssuer(
                        issuer_id=ISSUER_ID,
                        public_key_x=KEY_X,
                        public_key_y=KEY_Y,
                        proof_types=(KYC_PROOF_TYPE,),
                    ),
                )
            ),
            StubVerifyBackend(),
        )
        cache = VerifierAccumulatorCache(
            {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            accumulator_ids={ISSUER_ID: service.accumulator_id},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: TIMESTAMP,
        )
        cache.refresh_from_issuer(ISSUER_ID, adapter)
        result = verifier.verify(
            envelope,
            VerificationRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=PARAMETERS,
                context=context,
                accumulator_states=cache.accumulator_states(),
            ),
        )
        self.assertTrue(result.valid, result.to_dict())

        prior_state = service.handle_request({
            "type": EPOCH_DELTA_REQUEST,
            "accumulatorId": service.accumulator_id,
        })
        service.register(10_001)
        with patch.object(service, "handle_request", return_value=prior_state):
            with self.assertRaisesRegex(StaleWitnessError, "independently published"):
                generate_unauthenticated_linkable(client, request)

    def test_full_sync_and_gap_backfill(self):
        service, _, provider, client, credential = self.build_holder(9001)
        client.update_witness(credential.credential_id)  # full sync first
        for filler in range(1, 4):  # churn several epochs (a gap to backfill)
            service.register(10_000 + filler)
        witness = client.update_witness(credential.credential_id)
        self.assertEqual(witness.accumulator_epoch, service.epoch)
        self.assertEqual(provider.sent_requests[0], provider.sent_requests[-1])
        self.assertNotIn("fromEpoch", provider.sent_requests[-1])

    def test_revocation_still_fails_closed(self):
        service, adapter, provider, client, credential = self.build_holder(9001)
        adapter.revoke_credential(credential.credential_id)
        with self.assertRaises(StaleWitnessError):
            client.update_witness(credential.credential_id)

    def test_lifecycle_tick_uses_anonymous_refresh(self):
        """M4: scheduled refresh through the anonymous provider."""
        service, _, provider, client, credential = self.build_holder(9001)
        for filler in range(1, 10):  # push the witness into the refresh margin
            service.register(20_000 + filler)
        manager = LifecycleManager(client, provider)
        report = manager.tick(TIMESTAMP)
        self.assertEqual(report.refreshed, [(credential.issuer_id, credential.credential_id)])
        self.assertNotIn("credentialId", provider.sent_requests[-1])


class ConstantShapeRefusalTests(unittest.TestCase):
    """M3: 'cannot satisfy' is indistinguishable between no-credential and
    policy-refusal at the wire level."""

    @staticmethod
    def make_policy_document(accepted=(KYC_PROOF_TYPE,)):
        document = {
            "version": "zkc:registry:verifier-policy:v1",
            "verifierId": VERIFIER_ID,
            "displayName": "Leakage Test Verifier",
            "acceptedProofTypes": list(accepted),
            "requiredReviewStatuses": ["reviewed"],
            "trustedIssuers": [
                {
                    "issuerId": ISSUER_ID,
                    "publicKeyX": "0x" + KEY_X.hex(),
                    "publicKeyY": "0x" + KEY_Y.hex(),
                    "proofTypes": [KYC_PROOF_TYPE],
                }
            ],
            "acceptsOutOfRegistryIssuers": True,
            "requiredContextProfile": "",
            "maxEpochLag": 10,
            "proofRequirements": {
                proof_type: dict(KYC_MINIMUM)
                for proof_type in accepted
                if proof_type == KYC_PROOF_TYPE
            },
            "updatedAt": "2026-06-11T00:00:00Z",
        }
        validate_verifier_policy(document, "<test>")
        return _policy_from_document(document, "<test>")

    def make_agent(self, with_credential: bool, actions=None):
        client = HolderClient.from_seed(9001, REGISTRY, StubBackend())
        if with_credential:
            adapter = SandboxIssuerAdapter(
                signing_key=SIGNING_KEY, accumulator=make_service(), clock=lambda: TIMESTAMP
            )
            obtain_credential(adapter, client)
        policy = AgentCompliancePolicy(
            disclosure_ceiling={KYC_PROOF_TYPE: dict(KYC_MINIMUM)},
            trusted_verifiers=(VERIFIER_ID,),
            verifier_signing_keys={VERIFIER_ID: (signing_pin(),)},
            actions=actions if actions is not None else {KYC_PROOF_TYPE: "auto_approve"},
        )
        return ZKCAgentClient(
            client,
            REGISTRY,
            policy_documents={VERIFIER_ID: self.make_policy_document()},
            compliance_policy=policy,
        )

    def answer(self, agent, request, context):
        request = NegotiationRequest(request.verifier_id, request.proof_types, request.parameters,
                                     field_to_hex(secrets.randbelow(1 << 248)))
        apr = sign_apr({"verifierId": request.verifier_id, "nonce": request.nonce,
                        "issuedAt": TIMESTAMP - 1, "expiresAt": TIMESTAMP + 60,
                        "request": {"proofTypes": list(request.proof_types),
                                    "parameters": request.parameters, "context": context.to_metadata()}}, 0xA9701)
        return agent.handle_proof_request(request, context, apr=apr, now=TIMESTAMP)

    def test_wire_rejections_are_cause_indistinguishable(self):
        context = ProofContext.verifier_session(VERIFIER_ID, 555, TIMESTAMP)
        wires = {}

        # Cause 1: the holder simply has NO matching credential.
        agent = self.make_agent(with_credential=False)
        request = NegotiationRequest.new(VERIFIER_ID, (KYC_PROOF_TYPE,), PARAMETERS)
        wires["no_credential"] = self.answer(agent, request, context).to_wire()

        # Cause 2: the holder HAS the credential but policy blocks the type.
        agent = self.make_agent(with_credential=True, actions={KYC_PROOF_TYPE: "block"})
        request = NegotiationRequest.new(VERIFIER_ID, (KYC_PROOF_TYPE,), PARAMETERS)
        wires["policy_block"] = self.answer(agent, request, context).to_wire()

        # Cause 3: overbroad request (asks beyond the published minimums).
        agent = self.make_agent(with_credential=True)
        request = NegotiationRequest.new(
            VERIFIER_ID,
            (KYC_PROOF_TYPE,),
            {KYC_PROOF_TYPE: {"requiredLevel": 3, "requiredAttributes": [True] * 5}},
        )
        wires["overbroad"] = self.answer(agent, request, context).to_wire()

        # Cause 4: untrusted verifier.
        agent = self.make_agent(with_credential=True)
        other = "did:zkc:verifier:stranger"
        request = NegotiationRequest.new(other, (KYC_PROOF_TYPE,), PARAMETERS)
        wires["untrusted_verifier"] = self.answer(
            agent, request, ProofContext.verifier_session(other, 555, TIMESTAMP)
        ).to_wire()

        # All rejections are byte-identical modulo the echoed nonce.
        for wire in wires.values():
            wire.pop("nonce")
        reference = wires.pop("no_credential")
        self.assertEqual(reference["status"], "rejected")
        self.assertEqual(reference["message"], REFUSAL_MESSAGE)
        for cause, wire in wires.items():
            self.assertEqual(wire, reference, f"cause {cause} is distinguishable")

    def test_planner_refusals_share_one_message_and_touch_no_store(self):
        # The planner is constructed WITHOUT any credential store — planning
        # and refusing are store-independent by construction.
        policy = self.make_policy_document(
            accepted=(KYC_PROOF_TYPE, "zkc:proof:secret-scoring:v1")
        )
        planner = ProofPlanner(REGISTRY, policy)
        messages = set()
        with self.assertRaises(OverbroadRequestError) as overbroad:
            planner.plan(
                NegotiationRequest.new(
                    VERIFIER_ID,
                    (KYC_PROOF_TYPE,),
                    {KYC_PROOF_TYPE: {"requiredLevel": 3, "requiredAttributes": [True] * 5}},
                )
            )
        messages.add(overbroad.exception.message)
        with self.assertRaises(OpaquePredicateError) as opaque:
            planner.plan(
                NegotiationRequest.new(VERIFIER_ID, ("zkc:proof:secret-scoring:v1",), {})
            )
        messages.add(opaque.exception.message)
        self.assertEqual(messages, {REFUSAL_MESSAGE})


if __name__ == "__main__":
    unittest.main()
