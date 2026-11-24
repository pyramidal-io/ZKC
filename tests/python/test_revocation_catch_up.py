"""Resumable, bounded revocation catch-up for verifiers and holders.

Regression for the 2026-10-04 review finding R7.6. Every successful mutation
advances the epoch, so more than ``max_backfill`` (32) mutations between two
polls is ordinary traffic. Before ``catch_up``, both the verifier cache and
the private witness provider refused such a gap outright, and historical
heads could not be ingested once they were older than the age limit. The
only recovery was to delete the checkpoint, a cold start that discards
replay and fork protection.

``catch_up`` closes the gap one bounded step per call: each call verifies at
most ``max_backfill`` announcements past the persisted checkpoint (signature,
epoch continuity, predecessor link), persists the step, and returns a
resumable ``CatchUpStatus``. Intermediate announcements need not be fresh;
the head keeps the age rule.
"""

import copy
import functools
import inspect
import math
import tempfile
import unittest
from unittest import mock

import _path  # noqa: F401

import zkc_revocation.chain as chain_module
from zkc_crypto import SparseMerkleAccumulator, field_to_hex
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import IssuerSigningKey, SandboxIssuerAdapter
from zkc_issuer.errors import AdapterError
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    ANNOUNCEMENT_VERSION,
    EPOCH_DELTA_REQUEST,
    EPOCH_DELTA_RESPONSE,
    GENESIS_ANNOUNCEMENT_HASH,
    AnnouncementAuthenticationError,
    AnnouncementFreshnessError,
    AnnouncementMetadataError,
    AnnouncementReplayError,
    BackfillLimitError,
    CatchUpStatus,
    ChainLinkageError,
    InMemoryVerifierCheckpointStore,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    SQLiteVerifierCheckpointStore,
    VerifierAccumulatorCache,
    announcement_hash,
    compute_announcement_digest,
)


ISSUER_ID = "zkc:issuer:sandbox"
ACCUMULATOR_ID = "sandbox-active-credentials"
ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(SIGNING_KEY.metadata_entry())
CREDENTIAL_ID = 7
MAX_EPOCH_LAG = 10

# The finding's acceptance case: a consumer 1000 epochs behind, with the
# default max_backfill of both consumers.
GAP = 1000
MAX_BACKFILL = 32
EXPECTED_CALLS = math.ceil(GAP / MAX_BACKFILL)
RESTART_AFTER_CALLS = 16

# Epochs 0..GAP-1 are a burst published one second apart. The head follows
# at HEAD_TIME. At HEAD_TIME every historical announcement, and so every
# intermediate checkpoint, is older than the 3600 s age limit.
GENESIS_TIME = 1_770_000_000
HEAD_TIME = GENESIS_TIME + 5_000
# Small-gap tests run while their whole prefix is still fresh.
EARLY_TIME = GENESIS_TIME + 100


def _sign(announcement: dict) -> dict:
    announcement = dict(announcement)
    announcement.pop("signature", None)
    announcement["signature"] = "0x" + SIGNING_KEY.sign_digest(
        compute_announcement_digest(announcement)
    ).hex()
    return announcement


@functools.lru_cache(maxsize=None)
def _chain() -> tuple:
    """One genuine signed chain, epochs 0..GAP, shared read-only by the tests.

    The leaf set stays ``[CREDENTIAL_ID]``, so a holder can rebuild the root
    of any epoch from the full leaf fetch.
    """
    root = field_to_hex(SparseMerkleAccumulator([CREDENTIAL_ID]).root())
    previous = GENESIS_ANNOUNCEMENT_HASH
    announcements = []
    for epoch in range(GAP + 1):
        announcement = _sign(
            {
                "version": ANNOUNCEMENT_VERSION,
                "accumulatorId": ACCUMULATOR_ID,
                "root": root,
                "epoch": epoch,
                "announcedAt": HEAD_TIME if epoch == GAP else GENESIS_TIME + epoch,
                "maxEpochLag": MAX_EPOCH_LAG,
                "signingKeyId": SIGNING_KEY.key_id,
                "previousAnnouncementHash": previous,
            }
        )
        previous = announcement_hash(announcement)
        announcements.append(announcement)
    return tuple(announcements)


def _forged(epoch: int) -> dict:
    """The genuine announcement with a changed root and its old signature."""
    forged = copy.deepcopy(_chain()[epoch])
    forged["root"] = field_to_hex(1)
    return forged


def _forked(epoch: int) -> dict:
    """A second issuer-signed announcement for ``epoch`` (equivocation).

    It links to the genuine predecessor, so the genuine successor does not
    link to it.
    """
    forked = copy.deepcopy(_chain()[epoch])
    forked["root"] = field_to_hex(1)
    return _sign(forked)


class _ChainIssuer:
    """Serves one signed chain as an issuer's current and historical endpoints.

    ``announcements`` may be edited to serve a forged or forked history.
    """

    accumulator_id = ACCUMULATOR_ID

    def __init__(self, head_epoch: int):
        self.announcements = list(_chain())
        self.head_epoch = head_epoch
        self.history_requests = []

    @property
    def epoch(self) -> int:
        return self.head_epoch

    def current_announcement(self) -> dict:
        return copy.deepcopy(self.announcements[self.head_epoch])

    def announcement_for_epoch(self, epoch: int) -> dict:
        if type(epoch) is not int or not 0 <= epoch <= self.head_epoch:
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "invalid announcement epoch")
        self.history_requests.append((epoch, epoch))
        return copy.deepcopy(self.announcements[epoch])

    def announcement_history(self, start: int, end: int) -> list:
        if not 0 <= start <= end <= self.head_epoch:
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "invalid history range")
        self.history_requests.append((start, end))
        return [copy.deepcopy(item) for item in self.announcements[start : end + 1]]

    def issuer_metadata(self) -> dict:
        head = self.current_announcement()
        return {
            "version": "zkc:issuer-metadata:v2",
            "issuerId": ISSUER_ID,
            "revocation": {
                "accumulatorId": ACCUMULATOR_ID,
                "type": "POSEIDON2_MERKLE_ACTIVE_SET",
                "currentRoot": head["root"],
                "currentEpoch": head["epoch"],
                "maxEpochLag": head["maxEpochLag"],
                "updateEndpoint": ENDPOINT,
                "currentAnnouncement": head,
            },
        }

    def handle_request(self, request: dict) -> dict:
        """Credential-anonymous epoch fetch; always the full leaf set."""
        if request.get("type") != EPOCH_DELTA_REQUEST or "credentialId" in request:
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "unexpected request")
        head = self.current_announcement()
        return {
            "type": EPOCH_DELTA_RESPONSE,
            "accumulatorId": ACCUMULATOR_ID,
            "epoch": head["epoch"],
            "root": head["root"],
            "announcement": head,
            "mode": "full",
            "leaves": [field_to_hex(CREDENTIAL_ID)],
        }


class _SignatureLog:
    """Record the epoch of every announcement signature the chain verifies."""

    def __init__(self):
        self.epochs = []
        verify = chain_module.verify_epoch_announcement

        def counting(announcement, *args, **kwargs):
            self.epochs.append(announcement.get("epoch"))
            return verify(announcement, *args, **kwargs)

        self._patch = mock.patch.object(chain_module, "verify_epoch_announcement", counting)

    def __enter__(self):
        self._patch.start()
        return self

    def __exit__(self, *exc_info):
        self._patch.stop()
        return False


def _cache(store, clock, **kwargs) -> VerifierAccumulatorCache:
    return VerifierAccumulatorCache(
        {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        checkpoint_store=store,
        clock=lambda: clock["now"],
        **kwargs,
    )


def _provider(service, store, clock, **kwargs) -> PrivateWitnessProvider:
    # The synthetic chain already holds its one leaf at epoch 0, as an
    # authorized migration checkpoint would; a native accumulator has none.
    kwargs.setdefault("migrated_leaf_slots", {ISSUER_ID: 1})
    return PrivateWitnessProvider(
        {ISSUER_ID: service},
        issuer_keys={ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
        announcement_sources={ISSUER_ID: service},
        checkpoint_store=store,
        clock=lambda: clock["now"],
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        **kwargs,
    )


HOLDER_SCOPE = PrivateWitnessProvider.checkpoint_scope(ACCUMULATOR_ID)


def _persisted_epoch(store, scope=ACCUMULATOR_ID):
    checkpoint = store.load_checkpoint(ISSUER_ID, scope)
    return None if checkpoint is None else checkpoint["announcement"]["epoch"]


def _anchored_verifier(store, head_epoch=0, clock_now=EARLY_TIME):
    """A verifier whose checkpoint is the genuine announcement at ``head_epoch``."""
    clock = {"now": clock_now}
    issuer = _ChainIssuer(head_epoch)
    cache = _cache(store, clock)
    cache.ingest_metadata(ISSUER_ID, issuer.issuer_metadata())
    return cache, issuer, clock


def _anchored_holder(store, head_epoch=0, clock_now=EARLY_TIME):
    """A holder whose checkpoint is the genuine announcement at ``head_epoch``."""
    clock = {"now": clock_now}
    issuer = _ChainIssuer(head_epoch)
    holder = _provider(issuer, store, clock)
    holder.witness(ISSUER_ID, CREDENTIAL_ID)
    return holder, issuer, clock


class _SQLiteTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = f"{directory.name}/checkpoints.sqlite3"

    def open_store(self):
        store = SQLiteVerifierCheckpointStore(self.path)
        self.addCleanup(store.close)
        return store


class CatchUpDefaultsTests(unittest.TestCase):
    def test_both_consumers_default_to_a_backfill_bound_of_32(self):
        for consumer in (VerifierAccumulatorCache, PrivateWitnessProvider):
            with self.subTest(consumer=consumer.__name__):
                default = inspect.signature(consumer).parameters["max_backfill"].default
                self.assertEqual(default, MAX_BACKFILL)
        self.assertEqual(EXPECTED_CALLS, 32)

    def test_status_reports_remaining_epochs_and_completion(self):
        partial = CatchUpStatus(ISSUER_ID, ACCUMULATOR_ID, 32, 1000, 32)
        self.assertEqual((partial.remaining, partial.complete), (968, False))
        done = CatchUpStatus(ISSUER_ID, ACCUMULATOR_ID, 1000, 1000, 8)
        self.assertEqual((done.remaining, done.complete), (0, True))


class ThousandEpochCatchUpTests(_SQLiteTestCase):
    """Acceptance: 1000 epochs behind, ceil(1000/32) calls, no state deleted."""

    def _assert_bounded_step(self, log, start, status):
        expected_epoch = min(start + MAX_BACKFILL, GAP)
        new = [epoch for epoch in log.epochs if epoch > start]
        rechecked = [epoch for epoch in log.epochs if epoch <= start]
        # Each new announcement's signature is verified exactly once, in
        # epoch order, and never more than max_backfill of them per call.
        self.assertEqual(new, list(range(start + 1, expected_epoch + 1)))
        self.assertLessEqual(len(new), MAX_BACKFILL)
        self.assertEqual(status.verified, len(new))
        self.assertEqual(status.checkpoint_epoch, expected_epoch)
        self.assertEqual(status.target_epoch, GAP)
        self.assertEqual(status.remaining, GAP - expected_epoch)
        self.assertEqual(status.complete, expected_epoch == GAP)
        return rechecked

    def test_verifier_reaches_the_head_in_ceil_gap_over_max_backfill_calls(self):
        store = self.open_store()
        cache, issuer, clock = _anchored_verifier(store, head_epoch=0, clock_now=GENESIS_TIME)
        issuer.head_epoch = GAP
        clock["now"] = HEAD_TIME

        # The all-or-nothing ingest still refuses the gap and changes nothing.
        with self.assertRaises(BackfillLimitError):
            cache.ingest_metadata(
                ISSUER_ID, issuer.issuer_metadata(), history_loader=issuer.announcement_history
            )
        self.assertEqual(_persisted_epoch(store), 0)

        calls = 0
        restarted = False
        status = None
        while status is None or not status.complete:
            start = _persisted_epoch(store)
            with _SignatureLog() as log:
                status = cache.catch_up(
                    ISSUER_ID, issuer.issuer_metadata(), issuer.announcement_history
                )
            calls += 1
            rechecked = self._assert_bounded_step(log, start, status)
            # The step is durable before the call returns.
            self.assertEqual(_persisted_epoch(store), status.checkpoint_epoch)
            if restarted:
                # A restarted cache re-validates the persisted window once.
                self.assertEqual(
                    sorted(set(rechecked)), list(range(start - MAX_EPOCH_LAG, start + 1))
                )
                restarted = False
            else:
                # Only the persisted head is re-checked as the chain anchor.
                self.assertEqual(rechecked, [start])
            if status.complete:
                break
            # An intermediate checkpoint is stale, so no root is served
            # until the catch-up reaches the fresh head.
            with self.assertRaises(AnnouncementFreshnessError):
                cache.state(ISSUER_ID)
            if calls == RESTART_AFTER_CALLS:
                store.close()
                store = self.open_store()
                cache = _cache(store, clock)
                restarted = True

        self.assertEqual(calls, EXPECTED_CALLS)
        state = cache.state(ISSUER_ID)
        self.assertEqual(state.current_epoch, GAP)
        # The checkpoint retains the whole lag window, but a superseded root
        # is served only while the announcement that superseded it is within
        # the age limit (specification 2.4.2). Epochs 991..999 were announced
        # more than 3600 s before HEAD_TIME, so only GAP - 1 (superseded at
        # HEAD_TIME) and the head remain servable.
        persisted = store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)["announcements"]
        self.assertEqual(sorted(map(int, persisted)), list(range(GAP - MAX_EPOCH_LAG, GAP + 1)))
        self.assertEqual(sorted(state.roots), [GAP - 1, GAP])
        self.assertEqual(store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])
        # History came in bounded, contiguous, non-overlapping ranges.
        self.assertTrue(
            all(end - start + 1 <= MAX_BACKFILL for start, end in issuer.history_requests)
        )
        fetched = [
            epoch for start, end in issuer.history_requests for epoch in range(start, end + 1)
        ]
        self.assertEqual(fetched, list(range(1, GAP)))
        # Polling the reached head again is a complete no-op.
        with _SignatureLog() as log:
            again = cache.catch_up(ISSUER_ID, issuer.issuer_metadata(), issuer.announcement_history)
        self.assertEqual((again.complete, again.verified, log.epochs), (True, 0, []))

    def test_holder_reaches_the_head_in_ceil_gap_over_max_backfill_calls(self):
        store = self.open_store()
        holder, issuer, clock = _anchored_holder(store, head_epoch=0, clock_now=GENESIS_TIME)
        issuer.head_epoch = GAP
        clock["now"] = HEAD_TIME

        # A witness refresh still refuses the gap and changes nothing.
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED"):
            holder.witness(ISSUER_ID, CREDENTIAL_ID)
        self.assertEqual(_persisted_epoch(store, HOLDER_SCOPE), 0)
        requests_before = len(holder.sent_requests)

        calls = 0
        restarted = False
        status = None
        while status is None or not status.complete:
            start = _persisted_epoch(store, HOLDER_SCOPE)
            with _SignatureLog() as log:
                status = holder.catch_up(ISSUER_ID)
            calls += 1
            rechecked = self._assert_bounded_step(log, start, status)
            self.assertEqual(_persisted_epoch(store, HOLDER_SCOPE), status.checkpoint_epoch)
            # The anchor is re-checked; a restarted provider also re-checks
            # the persisted head once when it loads it.
            self.assertEqual(rechecked, [start, start] if restarted else [start])
            restarted = False
            if not status.complete and calls == RESTART_AFTER_CALLS:
                store.close()
                store = self.open_store()
                holder = _provider(issuer, store, clock)
                requests_before = len(holder.sent_requests)
                restarted = True

        self.assertEqual(calls, EXPECTED_CALLS)
        # Catch-up fetched announcements only: no leaves, no credential.
        self.assertEqual(len(holder.sent_requests), requests_before)
        self.assertEqual(store.evidence(ISSUER_ID, HOLDER_SCOPE), [])
        self.assertEqual(
            [request for request in issuer.history_requests if request[0] != request[1]], []
        )
        fetched = [start for start, _ in issuer.history_requests]
        # The one-epoch history fetches cover the gap once, in order, beside
        # the head which comes from the current-announcement endpoint.
        self.assertEqual(fetched, list(range(1, GAP)))
        witness = holder.witness(ISSUER_ID, CREDENTIAL_ID)
        self.assertEqual(witness.accumulator_epoch, GAP)


class VerifierCatchUpFailClosedTests(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryVerifierCheckpointStore()
        self.cache, self.issuer, self.clock = _anchored_verifier(self.store)
        self.issuer.head_epoch = 70

    def catch_up(self, issuer=None):
        issuer = issuer or self.issuer
        return self.cache.catch_up(
            ISSUER_ID, issuer.issuer_metadata(), issuer.announcement_history
        )

    def test_forged_intermediate_fails_closed_and_the_catch_up_resumes(self):
        self.assertEqual(self.catch_up().checkpoint_epoch, 32)
        self.issuer.announcements[40] = _forged(40)
        with self.assertRaises(AnnouncementAuthenticationError) as ctx:
            self.catch_up()
        self.assertEqual(ctx.exception.code, "ANNOUNCEMENT_AUTHENTICATION_FAILED")
        self.assertEqual(_persisted_epoch(self.store), 32)
        self.assertEqual(self.store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])

        self.issuer.announcements[40] = copy.deepcopy(_chain()[40])
        self.assertEqual(self.catch_up().checkpoint_epoch, 64)
        self.assertTrue(self.catch_up().complete)

    def test_forked_intermediate_is_chain_forked_with_evidence(self):
        self.assertEqual(self.catch_up().checkpoint_epoch, 32)
        self.issuer.announcements[40] = _forked(40)
        with self.assertRaises(ChainLinkageError) as ctx:
            self.catch_up()
        self.assertEqual(ctx.exception.code, "CHAIN_FORKED")
        self.assertEqual(_persisted_epoch(self.store), 32)
        evidence = self.store.evidence(ISSUER_ID, ACCUMULATOR_ID)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["errorCode"], "CHAIN_FORKED")
        # The conflicting pair is the forked 40 this step accepted and the
        # genuine 41 that does not link to it, not the persisted checkpoint.
        self.assertEqual(evidence[0]["predecessor"], _forked(40))
        self.assertEqual(evidence[0]["candidate"], _chain()[41])

    def test_a_fork_persisted_at_a_step_boundary_fails_the_next_link(self):
        self.issuer.announcements[32] = _forked(32)
        self.assertEqual(self.catch_up().checkpoint_epoch, 32)
        with self.assertRaises(ChainLinkageError):
            self.catch_up()
        self.assertEqual(_persisted_epoch(self.store), 32)
        evidence = self.store.evidence(ISSUER_ID, ACCUMULATOR_ID)
        self.assertEqual(evidence[0]["predecessor"], _forked(32))
        self.assertEqual(evidence[0]["candidate"], _chain()[33])

    def test_missing_or_reordered_history_persists_nothing(self):
        loaders = {
            "short": lambda start, end: self.issuer.announcement_history(start, end)[:-1],
            "reordered": lambda start, end: self.issuer.announcement_history(start, end)[::-1],
            "not a list": lambda start, end: tuple(self.issuer.announcement_history(start, end)),
        }
        for name, loader in loaders.items():
            with self.subTest(loader=name):
                with self.assertRaises(AnnouncementMetadataError):
                    self.cache.catch_up(ISSUER_ID, self.issuer.issuer_metadata(), loader)
                self.assertEqual(_persisted_epoch(self.store), 0)

    def test_head_at_or_behind_the_checkpoint_is_classified_as_by_ingest(self):
        self.issuer.head_epoch = 20
        self.assertTrue(self.catch_up().complete)
        with _SignatureLog() as log:
            status = self.catch_up()
        self.assertEqual((status.complete, status.verified, log.epochs), (True, 0, []))

        older = _ChainIssuer(19)
        with self.assertRaises(AnnouncementReplayError) as ctx:
            self.catch_up(older)
        self.assertEqual(ctx.exception.code, "ANNOUNCEMENT_REPLAY")

        equivocating = _ChainIssuer(20)
        equivocating.announcements[20] = _forked(20)
        with self.assertRaises(ChainLinkageError):
            self.catch_up(equivocating)
        self.assertEqual(len(self.store.evidence(ISSUER_ID, ACCUMULATOR_ID)), 1)
        self.assertEqual(_persisted_epoch(self.store), 20)

    def test_stale_head_fails_before_any_history_is_fetched(self):
        self.clock["now"] = GENESIS_TIME + 70 + 3601
        with self.assertRaises(AnnouncementFreshnessError):
            self.catch_up()
        self.assertEqual(self.issuer.history_requests, [])
        self.assertEqual(_persisted_epoch(self.store), 0)

    def test_an_unauthenticated_far_head_cannot_widen_a_step(self):
        metadata = self.issuer.issuer_metadata()
        head = metadata["revocation"]["currentAnnouncement"]
        head["epoch"] = metadata["revocation"]["currentEpoch"] = (1 << 63) + 5
        with _SignatureLog() as log:
            status = self.cache.catch_up(ISSUER_ID, metadata, self.issuer.announcement_history)
        self.assertEqual(self.issuer.history_requests, [(1, 32)])
        self.assertEqual([epoch for epoch in log.epochs if epoch > 0], list(range(1, 33)))
        self.assertEqual(status.checkpoint_epoch, 32)
        # The forged head is checked when the catch-up reaches it; genuine
        # history ends first, and the issuer refuses to serve past it.
        self.issuer.head_epoch = 64
        self.catch_up()
        with self.assertRaises(AdapterError):
            self.cache.catch_up(ISSUER_ID, metadata, self.issuer.announcement_history)
        self.assertEqual(_persisted_epoch(self.store), 64)

    def test_a_disabled_backfill_bound_refuses_to_catch_up(self):
        store = InMemoryVerifierCheckpointStore()
        cache = _cache(store, self.clock, max_backfill=0)
        cache.ingest_metadata(ISSUER_ID, _ChainIssuer(0).issuer_metadata())
        with self.assertRaises(BackfillLimitError):
            cache.catch_up(
                ISSUER_ID, self.issuer.issuer_metadata(), self.issuer.announcement_history
            )
        self.assertEqual(_persisted_epoch(store), 0)

    def test_cold_start_anchors_on_the_fresh_head(self):
        store = InMemoryVerifierCheckpointStore()
        cache = _cache(store, self.clock)
        with _SignatureLog() as log:
            status = cache.catch_up(
                ISSUER_ID, self.issuer.issuer_metadata(), self.issuer.announcement_history
            )
        self.assertEqual(log.epochs, [70])
        self.assertEqual((status.checkpoint_epoch, status.verified, status.complete), (70, 1, True))
        self.assertEqual(self.issuer.history_requests, [])


class ConcurrentCatchUpTests(unittest.TestCase):
    """A worker whose write loses the race reports the shared head instead of
    verifying a second step in the same call."""

    def test_verifier_conflict_reports_the_other_workers_head(self):
        store = InMemoryVerifierCheckpointStore()
        worker_a, issuer, clock = _anchored_verifier(store)
        worker_b = _cache(store, clock)
        issuer.head_epoch = 70
        raced = []

        def racing_loader(start, end):
            if not raced:
                raced.append(
                    worker_a.catch_up(ISSUER_ID, issuer.issuer_metadata(), issuer.announcement_history)
                )
            return issuer.announcement_history(start, end)

        with _SignatureLog() as log:
            status = worker_b.catch_up(ISSUER_ID, issuer.issuer_metadata(), racing_loader)
        self.assertEqual(raced[0].checkpoint_epoch, 32)
        self.assertEqual((status.checkpoint_epoch, status.verified, status.complete), (32, 32, False))
        # Neither worker verified a second step within the call.
        self.assertEqual(max(log.epochs), 32)
        status = worker_b.catch_up(ISSUER_ID, issuer.issuer_metadata(), issuer.announcement_history)
        self.assertEqual(status.checkpoint_epoch, 64)

    def test_verifier_conflict_on_the_final_step_completes_on_the_same_head(self):
        store = InMemoryVerifierCheckpointStore()
        worker_a, issuer, clock = _anchored_verifier(store)
        worker_b = _cache(store, clock)
        issuer.head_epoch = 20

        def racing_loader(start, end):
            worker_a.catch_up(ISSUER_ID, issuer.issuer_metadata(), issuer.announcement_history)
            return issuer.announcement_history(start, end)

        status = worker_b.catch_up(ISSUER_ID, issuer.issuer_metadata(), racing_loader)
        self.assertEqual((status.checkpoint_epoch, status.complete), (20, True))

    def test_holder_conflict_reports_the_other_holders_head(self):
        store = InMemoryVerifierCheckpointStore()
        holder_a, issuer, clock = _anchored_holder(store)
        issuer.head_epoch = 70

        class RacingIssuer(_ChainIssuer):
            raced = None

            def announcement_for_epoch(self, epoch):
                if RacingIssuer.raced is None:
                    RacingIssuer.raced = holder_a.catch_up(ISSUER_ID)
                return issuer.announcement_for_epoch(epoch)

        racing = RacingIssuer(70)
        holder_b = _provider(racing, store, clock)
        status = holder_b.catch_up(ISSUER_ID)
        self.assertEqual(RacingIssuer.raced.checkpoint_epoch, 32)
        self.assertEqual((status.checkpoint_epoch, status.verified, status.complete), (32, 32, False))
        self.assertEqual(holder_b.catch_up(ISSUER_ID).checkpoint_epoch, 64)


class HolderCatchUpFailClosedTests(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryVerifierCheckpointStore()
        self.holder, self.issuer, self.clock = _anchored_holder(self.store)
        self.issuer.head_epoch = 70

    def test_forged_intermediate_fails_closed_and_the_catch_up_resumes(self):
        self.assertEqual(self.holder.catch_up(ISSUER_ID).checkpoint_epoch, 32)
        self.issuer.announcements[40] = _forged(40)
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_AUTHENTICATION_FAILED"):
            self.holder.catch_up(ISSUER_ID)
        self.assertEqual(_persisted_epoch(self.store, HOLDER_SCOPE), 32)
        self.assertEqual(self.store.evidence(ISSUER_ID, HOLDER_SCOPE), [])

        self.issuer.announcements[40] = copy.deepcopy(_chain()[40])
        self.assertEqual(self.holder.catch_up(ISSUER_ID).checkpoint_epoch, 64)
        self.assertTrue(self.holder.catch_up(ISSUER_ID).complete)
        self.assertEqual(self.holder.witness(ISSUER_ID, CREDENTIAL_ID).accumulator_epoch, 70)

    def test_forked_intermediate_is_chain_forked_with_evidence(self):
        self.assertEqual(self.holder.catch_up(ISSUER_ID).checkpoint_epoch, 32)
        self.issuer.announcements[40] = _forked(40)
        with self.assertRaisesRegex(StaleWitnessError, "CHAIN_FORKED"):
            self.holder.catch_up(ISSUER_ID)
        self.assertEqual(_persisted_epoch(self.store, HOLDER_SCOPE), 32)
        evidence = self.store.evidence(ISSUER_ID, HOLDER_SCOPE)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["predecessor"], _forked(40))
        self.assertEqual(evidence[0]["candidate"], _chain()[41])

    def test_misnumbered_or_unavailable_history_persists_nothing(self):
        def unavailable(_epoch):
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "history unavailable")

        cases = {
            "wrong epoch": lambda epoch: copy.deepcopy(_chain()[epoch + 1]),
            "unavailable": unavailable,
        }
        for name, fetch in cases.items():
            with self.subTest(case=name):
                with mock.patch.object(self.issuer, "announcement_for_epoch", fetch):
                    with self.assertRaisesRegex(StaleWitnessError, "historical announcement backfill"):
                        self.holder.catch_up(ISSUER_ID)
                self.assertEqual(_persisted_epoch(self.store, HOLDER_SCOPE), 0)

    def test_head_at_or_behind_the_checkpoint_is_classified_as_by_refresh(self):
        self.issuer.head_epoch = 20
        self.assertTrue(self.holder.catch_up(ISSUER_ID).complete)
        status = self.holder.catch_up(ISSUER_ID)
        self.assertEqual((status.complete, status.verified), (True, 0))

        self.issuer.head_epoch = 19
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_REPLAY"):
            self.holder.catch_up(ISSUER_ID)

        self.issuer.head_epoch = 20
        self.issuer.announcements[20] = _forked(20)
        with self.assertRaisesRegex(StaleWitnessError, "CHAIN_FORKED"):
            self.holder.catch_up(ISSUER_ID)
        self.assertEqual(len(self.store.evidence(ISSUER_ID, HOLDER_SCOPE)), 1)

    def test_stale_head_fails_before_any_history_is_fetched(self):
        self.clock["now"] = GENESIS_TIME + 70 + 3601
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_STALE"):
            self.holder.catch_up(ISSUER_ID)
        self.assertEqual(self.issuer.history_requests, [])

    def test_a_disabled_backfill_bound_refuses_to_catch_up(self):
        store = InMemoryVerifierCheckpointStore()
        issuer = _ChainIssuer(0)
        holder = _provider(issuer, store, self.clock, max_backfill=0)
        holder.witness(ISSUER_ID, CREDENTIAL_ID)
        issuer.head_epoch = 5
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED"):
            holder.catch_up(ISSUER_ID)
        self.assertEqual(_persisted_epoch(store, HOLDER_SCOPE), 0)


class IssuerServiceCatchUpTests(unittest.TestCase):
    """The reference issuer service serves everything catch-up needs.

    34 issuances between two polls is the review's reproduction: a gap of 33
    missing announcements, one more than the default bound.
    """

    BURST = 34

    @classmethod
    def setUpClass(cls):
        cls.timestamp = GENESIS_TIME
        cls.service = RevocationAccumulatorService(
            ACCUMULATOR_ID, ENDPOINT, SIGNING_KEY, clock=lambda: cls.timestamp
        )
        cls.adapter = SandboxIssuerAdapter(
            signing_key=SIGNING_KEY, accumulator=cls.service, clock=lambda: cls.timestamp
        )
        cls.service.register(CREDENTIAL_ID)
        cls.first_metadata = cls.adapter.issuer_metadata()
        cls.first_epoch = cls.service.epoch
        for credential_id in range(100, 100 + cls.BURST):
            cls.service.register(credential_id)

    def test_verifier_catches_up_with_the_service_history_endpoint(self):
        store = InMemoryVerifierCheckpointStore()
        cache = _cache(store, {"now": GENESIS_TIME})
        cache.ingest_metadata(ISSUER_ID, self.first_metadata)
        loader = self.service.announcement_history
        with self.assertRaises(BackfillLimitError):
            cache.ingest_metadata(ISSUER_ID, self.adapter.issuer_metadata(), history_loader=loader)

        statuses = []
        while not statuses or not statuses[-1].complete:
            statuses.append(cache.catch_up(ISSUER_ID, self.adapter.issuer_metadata(), loader))
        self.assertEqual([status.verified for status in statuses], [32, 2])
        self.assertEqual(cache.state(ISSUER_ID).current_epoch, self.service.epoch)
        self.assertEqual(cache.state(ISSUER_ID).roots[self.service.epoch], self.service.root())

    def test_holder_catches_up_with_the_service_announcement_endpoints(self):
        store = InMemoryVerifierCheckpointStore()
        service = self.service
        first = self.first_epoch

        class FirstView:
            """The service as it was before the burst."""

            accumulator_id = ACCUMULATOR_ID

            def current_announcement(self):
                return self.announcement_for_epoch(first)

            def announcement_for_epoch(self, epoch):
                if epoch > first:
                    raise ValueError("epoch is outside the initial view")
                return service.announcement_for_epoch(epoch)

            def handle_request(self, _request):
                announcement = self.current_announcement()
                return {
                    "mode": "full",
                    "accumulatorId": ACCUMULATOR_ID,
                    "epoch": first,
                    "root": announcement["root"],
                    "announcement": announcement,
                    "leaves": [field_to_hex(CREDENTIAL_ID)],
                }

        clock = {"now": GENESIS_TIME}
        _provider(FirstView(), store, clock).witness(ISSUER_ID, CREDENTIAL_ID)
        holder = _provider(service, store, clock)
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED"):
            holder.witness(ISSUER_ID, CREDENTIAL_ID)

        statuses = []
        while not statuses or not statuses[-1].complete:
            statuses.append(holder.catch_up(ISSUER_ID))
        self.assertEqual([status.verified for status in statuses], [32, 2])
        witness = holder.witness(ISSUER_ID, CREDENTIAL_ID)
        self.assertEqual(witness.accumulator_epoch, service.epoch)
        self.assertEqual(witness.accumulator_root, service.root())


if __name__ == "__main__":
    unittest.main()
