"""Launch-profile verifier ingestion of authenticated revocation metadata."""

import copy
import tempfile
import unittest

import _path  # noqa: F401

from zkc_crypto import field_to_hex
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import IssuerSigningKey, SandboxIssuerAdapter
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    AnnouncementAuthenticationError,
    AnnouncementFreshnessError,
    AnnouncementMetadataError,
    AnnouncementReplayError,
    BackfillLimitError,
    ChainLinkageError,
    InMemoryVerifierCheckpointStore,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    SQLiteVerifierCheckpointStore,
    VerifierAccumulatorCache,
    VerifierCheckpointStoreError,
    compute_announcement_digest,
)


ISSUER_ID = "zkc:issuer:sandbox"
TIMESTAMP = 1_770_000_000
SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(SIGNING_KEY.metadata_entry())
ACCUMULATOR_ID = "sandbox-active-credentials"


def _service():
    return RevocationAccumulatorService(
        ACCUMULATOR_ID,
        "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
        SIGNING_KEY,
        clock=lambda: TIMESTAMP,
    )


def _adapter(service):
    return SandboxIssuerAdapter(
        signing_key=SIGNING_KEY,
        accumulator=service,
        clock=lambda: TIMESTAMP,
    )


def _cache(store=None, **kwargs):
    return VerifierAccumulatorCache(
        {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        checkpoint_store=store or InMemoryVerifierCheckpointStore(),
        clock=lambda: TIMESTAMP,
        max_announcement_age=3600,
        **kwargs,
    )


def _resign(metadata):
    announcement = metadata["revocation"]["currentAnnouncement"]
    announcement["signature"] = "0x" + SIGNING_KEY.sign_digest(
        compute_announcement_digest(announcement)
    ).hex()


class AuthenticatedMetadataIngestionTests(unittest.TestCase):
    def test_ingests_only_exact_v2_metadata_under_a_prepinned_key_id(self):
        service = _service()
        service.register(101)
        metadata = _adapter(service).issuer_metadata()
        cache = _cache()

        cache.ingest_metadata(ISSUER_ID, metadata)

        state = cache.state(ISSUER_ID)
        self.assertTrue(state.authenticated)
        self.assertEqual(state.accumulator_id, ACCUMULATOR_ID)
        self.assertEqual(state.current_epoch, 1)
        self.assertEqual(state.roots[1], service.root())
        self.assertEqual(state.max_epoch_lag, metadata["revocation"]["maxEpochLag"])

    def test_rejects_legacy_missing_mismatched_unknown_key_and_stale_metadata(self):
        service = _service()
        metadata = _adapter(service).issuer_metadata()

        legacy = copy.deepcopy(metadata)
        legacy["version"] = "zkc:issuer-metadata:v1"
        legacy["revocation"].pop("currentAnnouncement")
        with self.assertRaises(AnnouncementMetadataError):
            _cache().ingest_metadata(ISSUER_ID, legacy)

        mismatched = copy.deepcopy(metadata)
        mismatched["revocation"]["currentRoot"] = field_to_hex(1)
        with self.assertRaises(AnnouncementMetadataError):
            _cache().ingest_metadata(ISSUER_ID, mismatched)

        other_accumulator = RevocationAccumulatorService(
            "attacker-selected-accumulator",
            "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
            SIGNING_KEY,
            clock=lambda: TIMESTAMP,
        )
        with self.assertRaises(AnnouncementMetadataError):
            _cache().ingest_metadata(
                ISSUER_ID, _adapter(other_accumulator).issuer_metadata()
            )

        self_asserted = copy.deepcopy(metadata)
        self_asserted["revocation"]["currentAnnouncement"]["signingKeyId"] = "same-doc-key"
        self_asserted["signingKeys"][0]["keyId"] = "same-doc-key"
        _resign(self_asserted)
        with self.assertRaises(AnnouncementAuthenticationError):
            _cache().ingest_metadata(ISSUER_ID, self_asserted)

        stale = VerifierAccumulatorCache(
            {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: TIMESTAMP + 3601,
            max_announcement_age=3600,
        )
        with self.assertRaises(AnnouncementFreshnessError):
            stale.ingest_metadata(ISSUER_ID, metadata)

        clock = {"now": TIMESTAMP}
        expiring = VerifierAccumulatorCache(
            {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: clock["now"],
            max_announcement_age=3600,
        )
        expiring.ingest_metadata(ISSUER_ID, metadata)
        clock["now"] += 3601
        with self.assertRaises(AnnouncementFreshnessError):
            expiring.state(ISSUER_ID)

    def test_gap_backfill_is_bounded_ordered_and_atomic(self):
        service = _service()
        adapter = _adapter(service)
        allowed = _cache(max_backfill=2)
        allowed.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
        for credential_id in (101, 102, 103):
            service.register(credential_id)

        allowed.ingest_metadata(
            ISSUER_ID,
            adapter.issuer_metadata(),
            history_loader=lambda start, end: service.announcement_history(start, end),
        )
        self.assertEqual(allowed.state(ISSUER_ID).current_epoch, 3)

        limited_store = InMemoryVerifierCheckpointStore()
        limited = _cache(store=limited_store, max_backfill=1)
        fresh_service = _service()
        fresh_adapter = _adapter(fresh_service)
        limited.ingest_metadata(ISSUER_ID, fresh_adapter.issuer_metadata())
        for credential_id in (201, 202, 203):
            fresh_service.register(credential_id)
        with self.assertRaises(BackfillLimitError):
            limited.ingest_metadata(
                ISSUER_ID,
                fresh_adapter.issuer_metadata(),
                history_loader=lambda start, end: fresh_service.announcement_history(start, end),
            )
        self.assertEqual(
            limited_store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)["announcement"]["epoch"],
            0,
        )

    def test_rotation_succeeds_only_when_the_successor_key_is_prepinned(self):
        service = _service()
        old_metadata = _adapter(service).issuer_metadata()
        successor = IssuerSigningKey.from_seed(
            b"pre-pinned-successor", key_id="sandbox-2026-rotation"
        )
        trusted = VerifierAccumulatorCache(
            {
                ISSUER_ID: {
                    SIGNING_KEY.key_id: KEY_PIN,
                    successor.key_id: AnnouncementKeyPin.from_signing_key_entry(
                        successor.metadata_entry()
                    ),
                }
            },
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: TIMESTAMP,
        )
        trusted.ingest_metadata(ISSUER_ID, old_metadata)

        service.rotate_signing_key(successor)
        service.register(101)
        rotated_metadata = SandboxIssuerAdapter(
            signing_key=successor,
            accumulator=service,
            clock=lambda: TIMESTAMP,
        ).issuer_metadata()
        trusted.ingest_metadata(ISSUER_ID, rotated_metadata)
        self.assertEqual(trusted.state(ISSUER_ID).current_epoch, 1)

        untrusted = _cache()
        with self.assertRaises(AnnouncementAuthenticationError):
            untrusted.ingest_metadata(ISSUER_ID, rotated_metadata)

    def test_signed_fork_has_stable_error_and_retains_evidence(self):
        service = _service()
        service.register(101)
        metadata = _adapter(service).issuer_metadata()
        store = InMemoryVerifierCheckpointStore()
        cache = _cache(store=store)
        cache.ingest_metadata(ISSUER_ID, metadata)

        fork = copy.deepcopy(metadata)
        fork["revocation"]["currentRoot"] = field_to_hex(1)
        fork["revocation"]["currentAnnouncement"]["root"] = field_to_hex(1)
        _resign(fork)
        with self.assertRaises(ChainLinkageError) as ctx:
            cache.ingest_metadata(ISSUER_ID, fork)
        self.assertEqual(ctx.exception.code, "CHAIN_FORKED")
        evidence = store.evidence(ISSUER_ID, ACCUMULATOR_ID)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["candidate"], fork["revocation"]["currentAnnouncement"])
        self.assertEqual(evidence[0]["predecessor"], metadata["revocation"]["currentAnnouncement"])

    def test_checkpoint_write_failure_does_not_advance_the_accepted_view(self):
        class FailingStore(InMemoryVerifierCheckpointStore):
            fail = False

            def compare_and_swap_checkpoint(
                self, issuer_id, accumulator_id, expected_head, checkpoint
            ):
                if self.fail:
                    raise VerifierCheckpointStoreError("injected checkpoint failure")
                super().compare_and_swap_checkpoint(
                    issuer_id, accumulator_id, expected_head, checkpoint
                )

        service = _service()
        adapter = _adapter(service)
        store = FailingStore()
        cache = _cache(store=store)
        cache.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
        service.register(101)
        store.fail = True
        with self.assertRaises(VerifierCheckpointStoreError):
            cache.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
        self.assertEqual(cache.state(ISSUER_ID).current_epoch, 0)
        self.assertEqual(
            store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)["announcement"]["epoch"],
            0,
        )

    def test_persisted_checkpoint_rejects_replay_after_restart(self):
        service = _service()
        adapter = _adapter(service)
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/verifier-checkpoints.sqlite3"
            first_store = SQLiteVerifierCheckpointStore(path)
            first = _cache(store=first_store)
            first.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
            service.register(101)
            first.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
            first_store.close()

            second_store = SQLiteVerifierCheckpointStore(path)
            second = _cache(store=second_store)
            with self.assertRaises(AnnouncementReplayError) as ctx:
                second.ingest_metadata(
                    ISSUER_ID,
                    {
                        **adapter.issuer_metadata(),
                        "revocation": {
                            **adapter.issuer_metadata()["revocation"],
                            "currentRoot": service.announcement_for_epoch(0)["root"],
                            "currentEpoch": 0,
                            "currentAnnouncement": service.announcement_for_epoch(0),
                        },
                    },
                )
            self.assertEqual(ctx.exception.code, "ANNOUNCEMENT_REPLAY")
            second_store.close()

    def test_restart_revalidates_every_retained_historical_root(self):
        service = _service()
        adapter = _adapter(service)
        store = InMemoryVerifierCheckpointStore()
        first = _cache(store=store, max_epoch_lag=2)
        for credential_id in (101, 102, 103):
            service.register(credential_id)
            first.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())

        persisted = store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)
        persisted["announcements"]["2"]["root"] = field_to_hex(1)
        # The store refuses to rewrite retained history, so tamper at rest.
        store._checkpoints[(ISSUER_ID, ACCUMULATOR_ID)] = persisted
        recovered = _cache(store=store, max_epoch_lag=2)
        with self.assertRaises(VerifierCheckpointStoreError):
            recovered.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())


class PrivateWitnessCheckpointTests(unittest.TestCase):
    def _provider(self, service, store):
        return PrivateWitnessProvider(
            {ISSUER_ID: service},
            issuer_keys={ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            announcement_sources={ISSUER_ID: service},
            checkpoint_store=store,
            clock=lambda: TIMESTAMP,
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        )

    def test_same_epoch_signed_replacement_is_retained_as_fork_evidence(self):
        service = _service()
        service.register(101)
        store = InMemoryVerifierCheckpointStore()
        provider = self._provider(service, store)
        provider.witness(ISSUER_ID, 101)

        fork = copy.deepcopy(service.current_announcement())
        fork["announcedAt"] += 1
        fork["signature"] = "0x" + SIGNING_KEY.sign_digest(
            compute_announcement_digest(fork)
        ).hex()
        service._announcements[service.epoch] = fork
        with self.assertRaisesRegex(StaleWitnessError, "CHAIN_FORKED"):
            provider.witness(ISSUER_ID, 101)
        holder_scope = PrivateWitnessProvider.checkpoint_scope(ACCUMULATOR_ID)
        self.assertEqual(len(store.evidence(ISSUER_ID, holder_scope)), 1)

    def test_restart_rejects_an_older_signed_checkpoint(self):
        service = _service()
        service.register(101)
        store = InMemoryVerifierCheckpointStore()
        self._provider(service, store).witness(ISSUER_ID, 101)
        genesis = service.announcement_for_epoch(0)

        class ReplayingService:
            accumulator_id = ACCUMULATOR_ID
            epoch = 0

            def handle_request(self, _request):
                return {
                    "mode": "full",
                    "accumulatorId": ACCUMULATOR_ID,
                    "epoch": 0,
                    "root": genesis["root"],
                    "announcement": genesis,
                    "leaves": [],
                }

            def current_announcement(self):
                return genesis

            def announcement_for_epoch(self, _epoch):
                return genesis

        restarted = self._provider(ReplayingService(), store)
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_REPLAY"):
            restarted.witness(ISSUER_ID, 101)

    def test_provider_checkpoint_does_not_overwrite_shared_verifier_history(self):
        service = _service()
        adapter = _adapter(service)
        store = InMemoryVerifierCheckpointStore()
        cache = _cache(store=store, max_epoch_lag=2)
        cache.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
        service.register(101)
        cache.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
        verifier_checkpoint = store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)
        self.assertEqual(set(verifier_checkpoint["announcements"]), {"0", "1"})

        service.register(102)
        self._provider(service, store).witness(ISSUER_ID, 101)

        self.assertEqual(
            store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID),
            verifier_checkpoint,
        )
        holder_scope = PrivateWitnessProvider.checkpoint_scope(ACCUMULATOR_ID)
        self.assertEqual(
            store.load_checkpoint(ISSUER_ID, holder_scope)["announcement"]["epoch"],
            2,
        )

    def test_history_lookup_failures_are_closed_as_stale_witness_errors(self):
        service = _service()
        service.register(101)
        provider = self._provider(service, InMemoryVerifierCheckpointStore())
        provider.witness(ISSUER_ID, 101)
        service.register(102)
        service.register(103)

        def unavailable_history(_epoch):
            raise KeyError("history unavailable")

        service.announcement_for_epoch = unavailable_history
        with self.assertRaisesRegex(StaleWitnessError, "historical announcement backfill"):
            provider.witness(ISSUER_ID, 101)

    def test_checkpoint_store_failures_are_closed_as_stale_witness_errors(self):
        class FailingStore(InMemoryVerifierCheckpointStore):
            operation = None

            def load_checkpoint(self, issuer_id, accumulator_id):
                if self.operation == "load":
                    raise VerifierCheckpointStoreError("injected load failure")
                return super().load_checkpoint(issuer_id, accumulator_id)

            def compare_and_swap_checkpoint(
                self, issuer_id, accumulator_id, expected_head, checkpoint
            ):
                if self.operation == "save":
                    raise VerifierCheckpointStoreError("injected save failure")
                super().compare_and_swap_checkpoint(
                    issuer_id, accumulator_id, expected_head, checkpoint
                )

            def retain_evidence(self, issuer_id, accumulator_id, evidence):
                if self.operation == "evidence":
                    raise VerifierCheckpointStoreError("injected evidence failure")
                super().retain_evidence(issuer_id, accumulator_id, evidence)

        for operation in ("load", "save"):
            with self.subTest(operation=operation):
                service = _service()
                service.register(101)
                store = FailingStore()
                store.operation = operation
                with self.assertRaisesRegex(StaleWitnessError, "checkpoint store"):
                    self._provider(service, store).witness(ISSUER_ID, 101)

        service = _service()
        service.register(101)
        store = FailingStore()
        provider = self._provider(service, store)
        provider.witness(ISSUER_ID, 101)
        fork = copy.deepcopy(service.current_announcement())
        fork["announcedAt"] += 1
        fork["signature"] = "0x" + SIGNING_KEY.sign_digest(
            compute_announcement_digest(fork)
        ).hex()
        service._announcements[service.epoch] = fork
        store.operation = "evidence"
        with self.assertRaisesRegex(StaleWitnessError, "checkpoint store"):
            provider.witness(ISSUER_ID, 101)


if __name__ == "__main__":
    unittest.main()
