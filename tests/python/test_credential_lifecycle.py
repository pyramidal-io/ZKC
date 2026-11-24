"""Credential lifecycle + revocation freshness hardening tests.

Covers: atomic renewal (issuer re-issuance preserving the holder commitment,
old credential revoked both-or-neither in one epoch), the holder lifecycle
manager (staleness states, proactive refresh scheduling, tick()), chained
epoch announcements (gap detection + backfill, signed-fork detection), and
the failure-mode paths (missed refresh → stale rejection → recover via
refresh; revoked → renewal; epoch gap → structured error).
"""

import unittest

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from _path import REPO_ROOT

from zkc_crypto import ProofContext, field_to_hex
from zkc_holder import (
    Credential,
    CredentialHealth,
    HolderClient,
    LifecycleManager,
    PredicateRegistry,
    ProofRequest,
    RefreshPolicy,
    STATE_AGING,
    STATE_FRESH,
    STATE_STALE,
    STATE_UNUSABLE,
    StubBackend,
    TrustPolicy,
    TrustedIssuer,
    assess_credential,
)
from zkc_holder.accumulator import MAX_EPOCH_LAG
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import AdapterError, IssuerSigningKey, SandboxIssuerAdapter
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    AnnouncementChain,
    AnnouncementAuthenticationError,
    AnnouncementReplayError,
    InMemoryVerifierCheckpointStore,
    ChainLinkageError,
    EpochGapError,
    RevocationAccumulatorService,
    VerifierAccumulatorCache,
    WitnessUpdateProvider,
    announcement_hash,
    compute_announcement_digest,
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
MASTER_SEED = 9001
TIMESTAMP = 1_770_000_000

SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(SIGNING_KEY.metadata_entry())
REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
PARAMETERS = {
    KYC_PROOF_TYPE: {
        "requiredLevel": 1,
        "requiredAttributes": [True, False, False, False, True],
    }
}


def make_service(**kwargs) -> RevocationAccumulatorService:
    kwargs.setdefault("clock", lambda: TIMESTAMP)
    return RevocationAccumulatorService(
        "sandbox-active-credentials",
        "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
        SIGNING_KEY,
        **kwargs,
    )


class LifecycleStackTestBase(unittest.TestCase):
    """Issuer adapter + revocation service + holder + verifier stack."""

    def setUp(self):
        self.service = make_service()
        self.adapter = SandboxIssuerAdapter(
            signing_key=SIGNING_KEY, accumulator=self.service, clock=lambda: TIMESTAMP
        )
        self.provider = WitnessUpdateProvider(
            {ISSUER_ID: self.service},
            {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: TIMESTAMP,
            accumulator_ids={ISSUER_ID: "sandbox-active-credentials"},
        )
        self.client = HolderClient.from_seed(
            MASTER_SEED, REGISTRY, StubBackend(), accumulator_provider=self.provider
        )
        self.context = ProofContext.verifier_session("verifier.example", 7, TIMESTAMP)
        self.trust_policy = TrustPolicy(
            issuers=(
                TrustedIssuer(
                    issuer_id=ISSUER_ID,
                    public_key_x=KEY_X,
                    public_key_y=KEY_Y,
                    proof_types=(KYC_PROOF_TYPE,),
                ),
            )
        )
        self.verifier = ZKCVerifier(
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
        self.cache = VerifierAccumulatorCache(
            {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            accumulator_ids={ISSUER_ID: self.service.accumulator_id},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: TIMESTAMP,
        )

    def obtain_credential(self) -> Credential:
        holder_commitment_hex = field_to_hex(self.client.get_binding_commitment())
        subject = self.adapter.verify_subject(
            {"schemaId": KYC_SCHEMA_ID, "fixtureId": "sandbox-alice-basic"}
        )
        challenge = self.adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment_hex,
                "schemaId": KYC_SCHEMA_ID,
            }
        )
        response = self.client.binding_challenge_response(
            self.adapter.issuer_id, KYC_SCHEMA_ID, challenge["nonce"], challenge["expiresAt"]
        )
        self.adapter.bind_holder_commitment(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment_hex,
                "schemaId": KYC_SCHEMA_ID,
                "nonce": challenge["nonce"],
                "challengeResponse": response,
            }
        )
        envelope = self.adapter.issue_credential(
            {"subjectRef": subject["subjectRef"], "schemaId": KYC_SCHEMA_ID}
        )
        credential = Credential.from_dict(envelope["credential"])
        self.client.store_credential(credential)
        return credential

    def holder_request(self) -> ProofRequest:
        return ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=PARAMETERS,
            context=self.context,
            trust_policy=self.trust_policy,
        )

    def verification_request(self) -> VerificationRequest:
        self.cache.refresh_from_issuer(ISSUER_ID, self.adapter)
        return VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=PARAMETERS,
            context=self.context,
            accumulator_states=self.cache.accumulator_states(),
        )


class RenewalTests(LifecycleStackTestBase):
    def test_renewal_preserves_commitment_and_revokes_old_atomically(self):
        old = self.obtain_credential()
        epoch_before = self.service.epoch
        envelope = self.adapter.renew_credential(
            {"credentialId": field_to_hex(old.credential_id), "expiresAt": TIMESTAMP + 999_999}
        )
        renewed = Credential.from_dict(envelope["credential"])
        # Same holder commitment, fresh validity, fresh slot.
        self.assertEqual(renewed.holder_commitment, old.holder_commitment)
        self.assertEqual(renewed.expires_at, TIMESTAMP + 999_999)
        self.assertNotEqual(renewed.credential_id, old.credential_id)
        self.assertEqual(envelope["renewal"]["renewedFrom"], field_to_hex(old.credential_id))
        # ATOMIC: exactly one epoch transition for register+revoke.
        self.assertEqual(self.service.epoch, epoch_before + 1)
        self.assertTrue(self.service.is_active(renewed.credential_id))
        self.assertFalse(self.service.is_active(old.credential_id))
        # Old credential can no longer refresh witnesses; new one proves.
        with self.assertRaises(StaleWitnessError):
            self.client.update_witness(old.credential_id)
        self.client.remove_credential(old.credential_id)  # superseded by renewal
        self.client.store_credential(renewed)
        proof_envelope = generate_unauthenticated_linkable(self.client, self.holder_request())
        result = self.verifier.verify(proof_envelope, self.verification_request())
        self.assertTrue(result.valid, result.to_dict())

    def test_renewal_failures_leave_state_untouched(self):
        old = self.obtain_credential()
        epoch_before = self.service.epoch
        cases = [
            {"credentialId": field_to_hex(123456789)},  # unknown credential
            {"credentialId": field_to_hex(old.credential_id), "expiresAt": TIMESTAMP - 1},
            {},  # missing credentialId
        ]
        for payload in cases:
            with self.assertRaises(AdapterError, msg=payload):
                self.adapter.renew_credential(payload)
            # Both-or-neither: nothing moved.
            self.assertEqual(self.service.epoch, epoch_before)
            self.assertTrue(self.service.is_active(old.credential_id))

    def test_renewing_a_revoked_credential_is_refused(self):
        old = self.obtain_credential()
        self.adapter.revoke_credential(old.credential_id)
        epoch_before = self.service.epoch
        with self.assertRaises(AdapterError):
            self.adapter.renew_credential({"credentialId": field_to_hex(old.credential_id)})
        self.assertEqual(self.service.epoch, epoch_before)


class StalenessAssessmentTests(unittest.TestCase):
    """Pure lifecycle assessment: fresh/aging/stale/unusable thresholds."""

    def setUp(self):
        self.policy = RefreshPolicy(refresh_margin_epochs=3, expiry_margin_seconds=1000)
        from zkc_holder import AccumulatorWitness

        self.witness = AccumulatorWitness(
            path_index=0, siblings=[0] * 32, accumulator_root=1, accumulator_epoch=100
        )

    def credential(self, expires_at=0, witness="default"):
        return Credential(
            credential_type="zkc:kyc:v1",
            proof_type=KYC_PROOF_TYPE,
            issuer_id=ISSUER_ID,
            holder_commitment=1,
            credential_id=42,
            claims={"level": 1, "verifiedAttributes": [True] * 5},
            expires_at=expires_at,
            signature=b"\x00" * 64,
            witness=self.witness if witness == "default" else witness,
        )

    def test_fresh_within_margin(self):
        health = assess_credential(self.credential(), 100 + 6, TIMESTAMP, self.policy)
        self.assertEqual(health.state, STATE_FRESH)
        self.assertFalse(health.refresh_due)
        self.assertEqual(health.witness_lag, 6)

    def test_aging_inside_refresh_margin(self):
        health = assess_credential(self.credential(), 100 + 7, TIMESTAMP, self.policy)
        self.assertEqual(health.state, STATE_AGING)
        self.assertTrue(health.refresh_due)

    def test_stale_beyond_max_epoch_lag(self):
        health = assess_credential(
            self.credential(), 100 + MAX_EPOCH_LAG + 1, TIMESTAMP, self.policy
        )
        self.assertEqual(health.state, STATE_STALE)
        self.assertTrue(health.refresh_due)

    def test_expired_is_unusable_and_renewal_required(self):
        health = assess_credential(
            self.credential(expires_at=TIMESTAMP - 1), 100, TIMESTAMP, self.policy
        )
        self.assertEqual(health.state, STATE_UNUSABLE)
        self.assertTrue(health.renewal_required)

    def test_near_expiry_is_aging_with_renewal_flag(self):
        health = assess_credential(
            self.credential(expires_at=TIMESTAMP + 500), 100, TIMESTAMP, self.policy
        )
        self.assertEqual(health.state, STATE_AGING)
        self.assertTrue(health.renewal_required)
        self.assertEqual(health.expires_in, 500)

    def test_missing_witness_is_unusable(self):
        health = assess_credential(self.credential(witness=None), 100, TIMESTAMP, self.policy)
        self.assertEqual(health.state, STATE_UNUSABLE)

    def test_refresh_scheduling_is_pure(self):
        self.assertEqual(self.policy.refresh_due_lag, MAX_EPOCH_LAG - 3)
        self.assertEqual(self.policy.next_refresh_epoch(100), 100 + MAX_EPOCH_LAG - 3)
        with self.assertRaises(ValueError):
            RefreshPolicy(refresh_margin_epochs=MAX_EPOCH_LAG + 1)

    def test_health_serializes(self):
        health = assess_credential(self.credential(), 100, TIMESTAMP, self.policy)
        self.assertIsInstance(health, CredentialHealth)
        self.assertEqual(health.to_dict()["state"], STATE_FRESH)


class FailureModeTests(LifecycleStackTestBase):
    def test_missed_refresh_rejected_then_recovered_via_tick(self):
        credential = self.obtain_credential()
        # Other credentials churn the accumulator past MAX_EPOCH_LAG.
        for filler in range(1, MAX_EPOCH_LAG + 2):
            self.service.register(10_000 + filler)

        # A holder that MISSED its refreshes (no provider) fails closed.
        offline_client = HolderClient.from_seed(MASTER_SEED, REGISTRY, StubBackend())
        offline_client.store_credential(credential)
        with self.assertRaises(StaleWitnessError):
            generate_unauthenticated_linkable(
                offline_client, ProofRequest(
                    proof_types=[KYC_PROOF_TYPE],
                    parameters=PARAMETERS,
                    context=self.context,
                    trust_policy=self.trust_policy,
                    current_epochs={ISSUER_ID: self.service.epoch},
                )
            )

        # Recovery: a lifecycle tick refreshes the witness proactively…
        manager = LifecycleManager(self.client, self.provider)
        stale_health = manager.assess(TIMESTAMP)[0]
        self.assertEqual(stale_health.state, STATE_STALE)
        report = manager.tick(TIMESTAMP)
        self.assertEqual(report.refreshed, [(credential.issuer_id, credential.credential_id)])
        self.assertEqual(report.refresh_failed, [])
        # …after which the proof is generated and verifies.
        envelope = generate_unauthenticated_linkable(self.client, self.holder_request())
        result = self.verifier.verify(envelope, self.verification_request())
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(manager.assess(TIMESTAMP)[0].state, STATE_FRESH)

    def test_revoked_credential_surfaces_renewal_path(self):
        credential = self.obtain_credential()
        self.adapter.revoke_credential(credential.credential_id)
        # Churn until the (now-dead) witness is due for refresh: revocation
        # is DISCOVERED at the next scheduled refresh, fail closed.
        for filler in range(1, MAX_EPOCH_LAG):
            self.service.register(10_000 + filler)
        manager = LifecycleManager(self.client, self.provider)
        report = manager.tick(TIMESTAMP)
        # Refresh is refused (revoked) and renewal is surfaced, not skipped.
        self.assertEqual(report.refreshed, [])
        self.assertEqual(len(report.refresh_failed), 1)
        failed = report.refresh_failed[0]
        self.assertEqual(
            (failed["issuerId"], failed["credentialId"]),
            (credential.issuer_id, credential.credential_id),
        )
        # The serialized report never carries the credential id.
        self.assertEqual(set(report.to_dict()["refreshFailed"][0]), {"issuerId", "reason"})
        self.assertTrue(report.renewal_required)

        # Revocation cannot be bypassed with renewal or a fresh stage-1 handle.
        with self.assertRaises(AdapterError):
            self.adapter.renew_credential(
                {"credentialId": field_to_hex(credential.credential_id)}
            )
        with self.assertRaises(AdapterError):
            self.obtain_credential()
        with self.assertRaises(StaleWitnessError):
            generate_unauthenticated_linkable(self.client, self.holder_request())


class AnnouncementChainTests(unittest.TestCase):
    def test_chain_accepts_sequential_announcements(self):
        service = make_service()
        chain = AnnouncementChain(trusted_keys={SIGNING_KEY.key_id: KEY_PIN})
        chain.ingest(service.announcement_for_epoch(0))
        for credential_id in (1, 2, 3):
            service.register(credential_id)
            chain.ingest(service.current_announcement())
        self.assertEqual(chain.last_epoch, 3)

    def test_epoch_gap_is_a_structured_error_and_backfill_recovers(self):
        service = make_service()
        chain = AnnouncementChain(trusted_keys={SIGNING_KEY.key_id: KEY_PIN})
        chain.ingest(service.announcement_for_epoch(0))
        for credential_id in (1, 2, 3, 4):
            service.register(credential_id)
        with self.assertRaises(EpochGapError) as caught:
            chain.ingest(service.current_announcement())
        self.assertEqual(caught.exception.missing_epochs, [1, 2, 3])
        # Backfill the missing epochs from the service, then re-ingest.
        chain.backfill(
            service.announcement_for_epoch(epoch)
            for epoch in caught.exception.missing_epochs
        )
        chain.ingest(service.current_announcement())
        self.assertEqual(chain.last_epoch, 4)

    def test_signed_fork_is_detected(self):
        service = make_service()
        chain = AnnouncementChain(trusted_keys={SIGNING_KEY.key_id: KEY_PIN})
        chain.ingest(service.announcement_for_epoch(0))
        service.register(1)
        genuine = service.current_announcement()
        # An issuer-signed announcement for the same epoch that does NOT
        # extend the observed chain (different previous hash): a fork.

        forged = dict(genuine)
        forged["previousAnnouncementHash"] = "0x" + "22" * 32
        digest = compute_announcement_digest(forged)
        forged["signature"] = "0x" + SIGNING_KEY.sign_digest(digest).hex()
        with self.assertRaises(ChainLinkageError):
            chain.ingest(forged)
        # The genuine successor still ingests cleanly.
        chain.ingest(genuine)
        self.assertEqual(chain.last_epoch, 1)

    def test_replay_and_tamper_rejected(self):
        service = make_service()
        chain = AnnouncementChain(trusted_keys={SIGNING_KEY.key_id: KEY_PIN})
        chain.ingest(service.announcement_for_epoch(0))
        service.register(1)
        announcement = service.current_announcement()
        chain.ingest(announcement)
        with self.assertRaises(AnnouncementReplayError):
            chain.ingest(announcement)  # replay (epoch does not advance)
        service.register(2)
        tampered = dict(service.current_announcement())
        tampered["root"] = field_to_hex(1)
        with self.assertRaises(AnnouncementAuthenticationError):
            chain.ingest(tampered)  # signature no longer covers the content

    def test_announcement_hash_is_stable(self):
        service = make_service()
        announcement = service.current_announcement()
        self.assertEqual(announcement_hash(announcement), announcement_hash(dict(announcement)))


if __name__ == "__main__":
    unittest.main()
