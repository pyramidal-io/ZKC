"""Monotonic revocation checkpoints shared by workers, threads, and processes.

A verifier worker with an older in-process view must never move the shared
durable checkpoint backwards: an older genuine metadata document is still
valid relative to that worker's own view, and an older checkpoint re-admits
roots that contain credentials revoked since. The store re-reads the
persisted head atomically with each write, ingest re-reads it first, and
one lock per (issuer, accumulator) serializes threads.
"""

import collections
import copy
import functools
import multiprocessing
import os
import queue
import random
import sys
import tempfile
import threading
import time
import unittest

import _path  # noqa: F401

from zkc_crypto import field_to_hex, hex_to_field
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import IssuerSigningKey, SandboxIssuerAdapter
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    EPOCH_DELTA_REQUEST,
    AnnouncementReplayError,
    InMemoryVerifierCheckpointStore,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    SQLiteVerifierCheckpointStore,
    VerifierAccumulatorCache,
    VerifierCheckpointConflictError,
    VerifierCheckpointStoreError,
    announcement_hash,
    compute_announcement_digest,
)


ISSUER_ID = "zkc:issuer:sandbox"
ACCUMULATOR_ID = "sandbox-active-credentials"
ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
TIMESTAMP = 1_770_000_000
SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(SIGNING_KEY.metadata_entry())
FINAL_EPOCH = 30
REVOKED_CREDENTIAL = 2
STRESS_EPOCH = 14


History = collections.namedtuple("History", "metadata announcements responses service")


@functools.lru_cache(maxsize=None)
def _history() -> History:
    """One genuine signed chain, epochs 0..30, shared read-only by the tests.

    Credential 2 is issued at epoch 2 and revoked at epoch 3, so the epoch-2
    root still contains a credential the issuer revoked later.
    """
    service = RevocationAccumulatorService(
        ACCUMULATOR_ID, ENDPOINT, SIGNING_KEY, clock=lambda: TIMESTAMP
    )
    template = SandboxIssuerAdapter(
        signing_key=SIGNING_KEY, accumulator=service, clock=lambda: TIMESTAMP
    ).issuer_metadata()
    metadata = []
    responses = {}

    def record():
        metadata.append({**copy.deepcopy(template), "revocation": service.metadata()})
        if service.epoch in (1, 2):
            responses[service.epoch] = service.handle_request(
                {"type": EPOCH_DELTA_REQUEST, "accumulatorId": ACCUMULATOR_ID}
            )

    record()
    service.register(1)
    record()
    service.register(REVOKED_CREDENTIAL)
    record()
    service.revoke(REVOKED_CREDENTIAL)
    record()
    for credential_id in range(100, 100 + FINAL_EPOCH - 3):
        service.register(credential_id)
        record()
    announcements = tuple(service.announcement_history(0, FINAL_EPOCH))
    return History(tuple(metadata), announcements, responses, service)


def _metadata(epoch: int) -> dict:
    return copy.deepcopy(_history().metadata[epoch])


def _announcement(epoch: int) -> dict:
    return copy.deepcopy(_history().announcements[epoch])


def _loader(announcements):
    def load(start, end):
        return [copy.deepcopy(announcements[epoch]) for epoch in range(start, end + 1)]

    return load


def _cache(store, **kwargs) -> VerifierAccumulatorCache:
    return VerifierAccumulatorCache(
        {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        checkpoint_store=store,
        clock=lambda: TIMESTAMP,
        **kwargs,
    )


def _persisted_epoch(store, scope=ACCUMULATOR_ID):
    checkpoint = store.load_checkpoint(ISSUER_ID, scope)
    return None if checkpoint is None else checkpoint["announcement"]["epoch"]


def _checkpoint(*window) -> dict:
    """A verifier checkpoint document whose head is the last announcement."""
    return {
        "version": "zkc:verifier-revocation-checkpoint:v1",
        "issuerId": ISSUER_ID,
        "accumulatorId": ACCUMULATOR_ID,
        "announcement": dict(window[-1]),
        "announcements": {str(item["epoch"]): dict(item) for item in window},
    }


def _signed_successor(previous: dict, root: int) -> dict:
    """An issuer-signed announcement that links to ``previous`` (a fork)."""
    announcement = {
        key: previous[key]
        for key in ("version", "accumulatorId", "announcedAt", "maxEpochLag", "signingKeyId")
    }
    announcement.update(
        root=field_to_hex(root),
        epoch=previous["epoch"] + 1,
        previousAnnouncementHash=announcement_hash(previous),
    )
    announcement["signature"] = "0x" + SIGNING_KEY.sign_digest(
        compute_announcement_digest(announcement)
    ).hex()
    return announcement


class _StaleReadStore(SQLiteVerifierCheckpointStore):
    """Serves a captured older checkpoint for the next ``stale_reads`` reads.

    This models a race: another worker commits a newer head after this
    worker's re-read and before its write.
    """

    def __init__(self, path):
        super().__init__(path)
        self.stale_document = None
        self.stale_reads = 0

    def load_checkpoint(self, issuer_id, accumulator_id):
        if self.stale_reads:
            self.stale_reads -= 1
            return copy.deepcopy(self.stale_document)
        return super().load_checkpoint(issuer_id, accumulator_id)


class _SQLiteFileTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = os.path.join(directory.name, "checkpoints.sqlite3")

    def open_store(self, store_type=SQLiteVerifierCheckpointStore, **kwargs):
        store = store_type(self.path, **kwargs)
        self.addCleanup(store.close)
        return store


class _CheckpointStoreContract:
    """Monotonic write contract shared by every bundled checkpoint store."""

    def make_store(self):
        raise NotImplementedError

    def assert_conflict(self, store, write, *args):
        before = store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)
        with self.assertRaises(VerifierCheckpointConflictError):
            write(ISSUER_ID, ACCUMULATOR_ID, *args)
        self.assertEqual(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID), before)

    def assert_malformed(self, store, document):
        before = store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)
        with self.assertRaises(VerifierCheckpointStoreError) as ctx:
            store.save_checkpoint(ISSUER_ID, ACCUMULATOR_ID, document)
        self.assertNotIsInstance(ctx.exception, VerifierCheckpointConflictError)
        self.assertEqual(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID), before)

    def test_first_checkpoint_and_an_identical_rewrite_are_accepted(self):
        store = self.make_store()
        document = _checkpoint(_announcement(0), _announcement(1), _announcement(2))
        store.save_checkpoint(ISSUER_ID, ACCUMULATOR_ID, document)
        store.save_checkpoint(ISSUER_ID, ACCUMULATOR_ID, document)
        self.assertEqual(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID), document)

    def test_older_head_is_rejected(self):
        store = self.make_store()
        store.save_checkpoint(
            ISSUER_ID, ACCUMULATOR_ID, _checkpoint(_announcement(4), _announcement(5))
        )
        older = _checkpoint(_announcement(2), _announcement(3))
        self.assert_conflict(store, store.save_checkpoint, older)
        self.assert_conflict(store, store.compare_and_swap_checkpoint, _announcement(5), older)
        self.assertEqual(_persisted_epoch(store), 5)

    def test_same_epoch_fork_is_rejected(self):
        store = self.make_store()
        store.save_checkpoint(
            ISSUER_ID, ACCUMULATOR_ID, _checkpoint(_announcement(4), _announcement(5))
        )
        fork = _signed_successor(_announcement(4), 9_999)
        self.assert_conflict(store, store.save_checkpoint, _checkpoint(_announcement(4), fork))
        self.assert_conflict(store, store.save_checkpoint, _checkpoint(fork))

    def test_successor_that_does_not_link_to_the_head_is_rejected(self):
        store = self.make_store()
        store.save_checkpoint(ISSUER_ID, ACCUMULATOR_ID, _checkpoint(_announcement(5)))
        forked_head = _signed_successor(_signed_successor(_announcement(4), 9_999), 10_000)
        self.assertEqual(forked_head["epoch"], 6)
        self.assert_conflict(store, store.save_checkpoint, _checkpoint(forked_head))
        # A matching expected head does not excuse a provable fork.
        self.assert_conflict(
            store, store.compare_and_swap_checkpoint, _announcement(5), _checkpoint(forked_head)
        )

    def test_rewritten_retained_history_is_rejected(self):
        store = self.make_store()
        store.save_checkpoint(
            ISSUER_ID,
            ACCUMULATOR_ID,
            _checkpoint(_announcement(3), _announcement(4), _announcement(5)),
        )
        fork_4 = _signed_successor(_announcement(3), 9_999)
        fork_5 = _signed_successor(fork_4, 10_000)
        fork_6 = _signed_successor(fork_5, 10_001)
        self.assert_conflict(store, store.save_checkpoint, _checkpoint(fork_4, fork_5, fork_6))
        self.assertEqual(
            store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)["announcement"], _announcement(5)
        )

    def test_extension_through_a_retained_or_linked_head_is_accepted(self):
        store = self.make_store()
        store.save_checkpoint(
            ISSUER_ID, ACCUMULATOR_ID, _checkpoint(_announcement(4), _announcement(5))
        )
        store.save_checkpoint(
            ISSUER_ID,
            ACCUMULATOR_ID,
            _checkpoint(_announcement(5), _announcement(6), _announcement(7)),
        )
        store.save_checkpoint(ISSUER_ID, ACCUMULATOR_ID, _checkpoint(_announcement(8)))
        self.assertEqual(_persisted_epoch(store), 8)

    def test_gap_past_the_window_needs_the_validated_expected_head(self):
        store = self.make_store()
        store.save_checkpoint(ISSUER_ID, ACCUMULATOR_ID, _checkpoint(_announcement(5)))
        successor = _checkpoint(_announcement(8))
        self.assert_conflict(store, store.save_checkpoint, successor)
        self.assert_conflict(store, store.compare_and_swap_checkpoint, _announcement(4), successor)
        store.compare_and_swap_checkpoint(ISSUER_ID, ACCUMULATOR_ID, _announcement(5), successor)
        self.assertEqual(_persisted_epoch(store), 8)

    def test_compare_and_swap_requires_the_persisted_head_it_names(self):
        store = self.make_store()
        genesis = _checkpoint(_announcement(0))
        self.assert_conflict(store, store.compare_and_swap_checkpoint, _announcement(0), genesis)
        self.assertIsNone(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID))
        store.compare_and_swap_checkpoint(ISSUER_ID, ACCUMULATOR_ID, None, genesis)
        successor = _checkpoint(_announcement(0), _announcement(1))
        self.assert_conflict(store, store.compare_and_swap_checkpoint, None, successor)
        store.compare_and_swap_checkpoint(ISSUER_ID, ACCUMULATOR_ID, _announcement(0), successor)
        self.assertEqual(_persisted_epoch(store), 1)

    def test_malformed_checkpoints_fail_closed_without_a_conflict(self):
        store = self.make_store()
        store.save_checkpoint(ISSUER_ID, ACCUMULATOR_ID, _checkpoint(_announcement(4)))
        gapped = _checkpoint(_announcement(5), _announcement(7))
        stale_head = _checkpoint(_announcement(5), _announcement(6))
        stale_head["announcement"] = _announcement(5)
        padded = _checkpoint(_announcement(5))
        padded["announcements"] = {"05": _announcement(5)}
        unlinked_6 = _announcement(6)
        unlinked_6["previousAnnouncementHash"] = announcement_hash(_announcement(3))
        unlinked = _checkpoint(_announcement(5), unlinked_6)
        for name, document in (
            ("not a document", ["not", "a", "document"]),
            ("no window", {"announcement": _announcement(5)}),
            ("gapped window", gapped),
            ("head is not the newest", stale_head),
            ("non-canonical epoch key", padded),
            ("window is not hash-linked", unlinked),
        ):
            with self.subTest(name):
                self.assert_malformed(store, document)
        self.assertEqual(_persisted_epoch(store), 4)


class InMemoryCheckpointStoreContractTests(_CheckpointStoreContract, unittest.TestCase):
    def make_store(self):
        return InMemoryVerifierCheckpointStore()


class SQLiteCheckpointStoreContractTests(_CheckpointStoreContract, _SQLiteFileTestCase):
    def make_store(self):
        return self.open_store()


class StaleVerifierWorkerTests(_SQLiteFileTestCase):
    """Two verifier workers share one SQLite checkpoint file."""

    def _advanced_workers(self, store_b):
        history = _history()
        worker_a = _cache(self.open_store())
        worker_b = _cache(store_b)
        worker_a.ingest_metadata(ISSUER_ID, _metadata(1))
        # Worker B loads and serves the shared epoch-1 checkpoint.
        self.assertEqual(worker_b.state(ISSUER_ID, ACCUMULATOR_ID).current_epoch, 1)
        worker_a.ingest_metadata(
            ISSUER_ID, _metadata(FINAL_EPOCH), history_loader=_loader(history.announcements)
        )
        return worker_b

    def test_stale_worker_cannot_roll_back_the_shared_checkpoint(self):
        worker_b = self._advanced_workers(self.open_store())
        # A stale cache or mirror hands worker B the genuine epoch-2 document.
        # It still extends worker B's own epoch-1 view.
        with self.assertRaises(AnnouncementReplayError) as ctx:
            worker_b.ingest_metadata(ISSUER_ID, _metadata(2))
        self.assertEqual(ctx.exception.code, "ANNOUNCEMENT_REPLAY")
        self.assertEqual(_persisted_epoch(self.open_store()), FINAL_EPOCH)
        self.assertEqual(worker_b.state(ISSUER_ID).current_epoch, FINAL_EPOCH)

        restarted = _cache(self.open_store()).state(ISSUER_ID, ACCUMULATOR_ID)
        self.assertEqual(restarted.current_epoch, FINAL_EPOCH)
        revoked_root = hex_to_field(_metadata(2)["revocation"]["currentRoot"])
        self.assertNotIn(revoked_root, restarted.roots.values())
        self.assertEqual(min(restarted.roots), FINAL_EPOCH - 10)

    def test_store_rejects_the_stale_write_when_the_reload_races(self):
        store_b = self.open_store(_StaleReadStore)
        worker_b = self._advanced_workers(store_b)
        store_b.stale_document = _checkpoint(_announcement(1))
        store_b.stale_reads = 1
        with self.assertRaises(AnnouncementReplayError):
            worker_b.ingest_metadata(ISSUER_ID, _metadata(2))
        self.assertEqual(store_b.stale_reads, 0)
        self.assertEqual(_persisted_epoch(self.open_store()), FINAL_EPOCH)

        # The store keeps refusing a writer that never sees the newer head.
        store_c = self.open_store(_StaleReadStore)
        worker_c = _cache(store_c)
        store_c.stale_document = _checkpoint(_announcement(1))
        store_c.stale_reads = 99
        with self.assertRaises(VerifierCheckpointConflictError):
            worker_c.ingest_metadata(ISSUER_ID, _metadata(2))
        self.assertEqual(_persisted_epoch(self.open_store()), FINAL_EPOCH)

        # A store that returns a head older than the view a worker accepted
        # lost history; serving or advancing from it fails closed.
        store_b.stale_reads = 1
        with self.assertRaisesRegex(VerifierCheckpointStoreError, "accepted view"):
            worker_b.state(ISSUER_ID)

    def test_one_lock_serializes_ingest_for_an_issuer_accumulator(self):
        store = InMemoryVerifierCheckpointStore()
        cache = _cache(store)
        cache.ingest_metadata(ISSUER_ID, _metadata(1))
        entered, release = threading.Event(), threading.Event()
        history = _history()
        outcome = {}

        def paused_loader(start, end):
            entered.set()
            release.wait(30)
            return _loader(history.announcements)(start, end)

        def ingest(name, epoch, loader):
            try:
                cache.ingest_metadata(ISSUER_ID, _metadata(epoch), history_loader=loader)
                outcome[name] = "ingested"
            except AnnouncementReplayError:
                outcome[name] = "replay"

        newer = threading.Thread(target=ingest, args=("newer", 5, paused_loader))
        older = threading.Thread(target=ingest, args=("older", 3, _loader(history.announcements)))
        newer.start()
        self.assertTrue(entered.wait(30))
        older.start()
        older.join(0.3)
        # The older ingest waits for the lock instead of validating against
        # the epoch-1 view the paused ingest started from.
        self.assertTrue(older.is_alive())
        release.set()
        newer.join(30)
        older.join(30)
        self.assertEqual(outcome, {"newer": "ingested", "older": "replay"})
        self.assertEqual(_persisted_epoch(store), 5)


class _CapturedResponseService:
    """Serves a captured epoch-delta response, as a lagging mirror would."""

    accumulator_id = ACCUMULATOR_ID

    def __init__(self, response, announcements):
        self.response = response
        self._announcements = announcements

    @property
    def epoch(self):
        return self.response["epoch"]

    def handle_request(self, _request):
        return copy.deepcopy(self.response)

    def current_announcement(self):
        return self.announcement_for_epoch(self.epoch)

    def announcement_for_epoch(self, epoch):
        return copy.deepcopy(self._announcements[epoch])


class StaleHolderTests(_SQLiteFileTestCase):
    """Two holder providers share one SQLite checkpoint file."""

    def _provider(self, service, store):
        return PrivateWitnessProvider(
            {ISSUER_ID: service},
            issuer_keys={ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            announcement_sources={ISSUER_ID: service},
            checkpoint_store=store,
            clock=lambda: TIMESTAMP,
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        )

    def _holder_epoch(self):
        scope = PrivateWitnessProvider.checkpoint_scope(ACCUMULATOR_ID)
        return _persisted_epoch(self.open_store(), scope)

    def _advanced_providers(self, holder_b_store):
        history = _history()
        mirror = _CapturedResponseService(history.responses[1], history.announcements)
        holder_b = self._provider(mirror, holder_b_store)
        self.assertEqual(holder_b.witness(ISSUER_ID, 1).accumulator_epoch, 1)
        holder_a = self._provider(history.service, self.open_store())
        self.assertEqual(holder_a.witness(ISSUER_ID, 1).accumulator_epoch, FINAL_EPOCH)
        self.assertEqual(self._holder_epoch(), FINAL_EPOCH)
        # Holder B's mirror now serves the genuine, still-fresh epoch-2 state.
        mirror.response = history.responses[2]
        return holder_b

    def test_stale_holder_cannot_roll_back_the_shared_holder_checkpoint(self):
        holder_b = self._advanced_providers(self.open_store())
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_REPLAY"):
            holder_b.witness(ISSUER_ID, REVOKED_CREDENTIAL)
        self.assertEqual(self._holder_epoch(), FINAL_EPOCH)

    def test_holder_store_rejects_a_writer_that_never_sees_the_newer_head(self):
        store_b = self.open_store(_StaleReadStore)
        holder_b = self._advanced_providers(store_b)
        store_b.stale_document = {
            "version": "zkc:holder-revocation-checkpoint:v1",
            "issuerId": ISSUER_ID,
            "accumulatorId": ACCUMULATOR_ID,
            "announcement": _announcement(1),
            "announcements": {"1": _announcement(1)},
        }
        store_b.stale_reads = 99
        with self.assertRaisesRegex(StaleWitnessError, "checkpoint store"):
            holder_b.witness(ISSUER_ID, REVOKED_CREDENTIAL)
        self.assertEqual(self._holder_epoch(), FINAL_EPOCH)


# --- concurrent stress ------------------------------------------------------------

# Each worker stops once the shared head reaches STRESS_EPOCH, or after this
# many ingest attempts.
STRESS_ATTEMPTS = 40


def _race(cache, store, seed, metadata, announcements, start) -> dict:
    """Race another worker to advance the shared checkpoint to STRESS_EPOCH.

    Each attempt reads the shared head and ingests the document one or two
    epochs ahead (two needs a bounded backfill). Both workers often validate
    against the same head, so their writes collide. Sometimes a worker that
    fell behind ingests a document that a lagging cache or mirror would
    serve: newer than its own last ingest but older than the shared head.
    The worker records every persisted and served epoch it observes.
    """
    rng = random.Random(seed)
    loader = _loader(announcements)
    outcomes = collections.Counter()
    persisted, served, unexpected = [], [], []
    last_ingested = 0
    start()
    for _ in range(STRESS_ATTEMPTS):
        head = _persisted_epoch(store)
        persisted.append(head)
        if head >= STRESS_EPOCH:
            break
        if last_ingested + 1 < head and rng.random() < 0.4:
            epoch = rng.randrange(last_ingested + 1, head)
        else:
            epoch = min(STRESS_EPOCH, head + rng.choice((1, 1, 2)))
        try:
            cache.ingest_metadata(
                ISSUER_ID, copy.deepcopy(metadata[epoch]), history_loader=loader
            )
            outcomes["ingested"] += 1
            last_ingested = epoch
        except AnnouncementReplayError:
            outcomes["replay"] += 1
        except VerifierCheckpointConflictError:
            outcomes["conflict"] += 1
        except Exception as exc:  # noqa: BLE001 - reported to the asserting thread
            unexpected.append(f"epoch {epoch}: {exc!r}")
        persisted.append(_persisted_epoch(store))
        served.append(cache.state(ISSUER_ID).current_epoch)
        # Uneven pauses let a worker that fell behind lead again.
        time.sleep(rng.choice((0.0, 0.02, 0.05)))
    return {
        "outcomes": dict(outcomes),
        "persisted": persisted,
        "served": served,
        "unexpected": unexpected,
    }


def _process_worker(path, seed, metadata, announcements, barrier, results):
    store = SQLiteVerifierCheckpointStore(path)
    try:
        report = _race(
            _cache(store, max_epoch_lag=1),
            store,
            seed,
            metadata,
            announcements,
            lambda: barrier.wait(60),
        )
    except Exception as exc:  # noqa: BLE001 - reported to the parent process
        report = {"outcomes": {}, "persisted": [], "served": [], "unexpected": [repr(exc)]}
    finally:
        store.close()
    results.put(report)


class ConcurrentCheckpointStressTests(_SQLiteFileTestCase):
    """Two threads or two processes race to advance one shared checkpoint.

    Each worker records the persisted and served epoch around every ingest,
    and the test thread polls the file through its own connection. No
    observer may ever see the epoch decrease.
    """

    SEEDS = (7, 11)

    def setUp(self):
        super().setUp()
        history = _history()
        self.metadata = history.metadata[: STRESS_EPOCH + 1]
        self.announcements = history.announcements[: STRESS_EPOCH + 1]
        seed_store = SQLiteVerifierCheckpointStore(self.path)
        _cache(seed_store).ingest_metadata(ISSUER_ID, _metadata(0))
        seed_store.close()
        self.observer = self.open_store()

    def poll(self, polled):
        polled.append(_persisted_epoch(self.observer))

    def assert_monotonic(self, reports, polled):
        for report in reports:
            self.assertEqual(report["unexpected"], [])
            self.assertEqual(report["persisted"], sorted(report["persisted"]))
            self.assertEqual(report["served"], sorted(report["served"]))
        self.assertEqual(polled, sorted(polled))
        self.assertGreater(sum(report["outcomes"].get("ingested", 0) for report in reports), 0)
        self.assertEqual(_persisted_epoch(self.observer), STRESS_EPOCH)
        restarted = _cache(self.open_store(), max_epoch_lag=1)
        self.assertEqual(restarted.state(ISSUER_ID, ACCUMULATOR_ID).current_epoch, STRESS_EPOCH)

    def run_threads(self, worker_for):
        """Race two threads; ``worker_for()`` returns (cache, store, owned)."""
        barrier = threading.Barrier(3)
        reports, errors, polled = {}, [], []

        def run(seed):
            try:
                cache, store, owned = worker_for()
                try:
                    reports[seed] = _race(
                        cache,
                        store,
                        seed,
                        self.metadata,
                        self.announcements,
                        lambda: barrier.wait(30),
                    )
                finally:
                    if owned:
                        store.close()
            except Exception as exc:  # noqa: BLE001 - asserted below
                errors.append(repr(exc))
                barrier.abort()

        interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-4)
        try:
            threads = [threading.Thread(target=run, args=(seed,)) for seed in self.SEEDS]
            for thread in threads:
                thread.start()
            barrier.wait(30)
            while any(thread.is_alive() for thread in threads):
                self.poll(polled)
                time.sleep(0.002)
            for thread in threads:
                thread.join(30)
        finally:
            sys.setswitchinterval(interval)
        self.assertEqual(errors, [])
        self.assert_monotonic(list(reports.values()), polled)

    def test_two_threads_sharing_one_cache_never_regress_the_checkpoint(self):
        store = self.open_store(check_same_thread=False)
        cache = _cache(store, max_epoch_lag=1)
        self.run_threads(lambda: (cache, store, False))

    def test_two_threads_with_their_own_connections_never_regress_the_checkpoint(self):
        def worker():
            store = SQLiteVerifierCheckpointStore(self.path)
            return _cache(store, max_epoch_lag=1), store, True

        self.run_threads(worker)

    def test_two_processes_never_regress_the_checkpoint(self):
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(3)
        results = context.Queue()
        processes = [
            context.Process(
                target=_process_worker,
                args=(self.path, seed, self.metadata, self.announcements, barrier, results),
            )
            for seed in self.SEEDS
        ]
        for process in processes:
            process.start()
        self.addCleanup(lambda: [process.kill() for process in processes if process.is_alive()])
        barrier.wait(60)
        reports, polled = [], []
        deadline = time.monotonic() + 120
        while len(reports) < len(processes):
            self.assertLess(time.monotonic(), deadline, "stress workers did not finish")
            self.poll(polled)
            try:
                reports.append(results.get(timeout=0.005))
            except queue.Empty:
                failed = [p.exitcode for p in processes if p.exitcode not in (None, 0)]
                self.assertEqual(failed, [])
        for process in processes:
            process.join(30)
            self.assertEqual(process.exitcode, 0)
        self.assert_monotonic(reports, polled)


if __name__ == "__main__":
    unittest.main()
