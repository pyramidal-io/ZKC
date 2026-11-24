"""Fork-evidence classification and cold-start anchor authorization.

Regression for the 2026-10-04 review finding R7.11 (PoCs lane6/poc6 and
lane6/poc13):

(a) An announcement for another accumulator was raised as ``CHAIN_FORKED``
    and retained as equivocation evidence, and the retained pair was the
    persisted checkpoint plus the failing item. One issuer key may sign
    several accumulators, so a relay that substituted the issuer's genuine
    announcement of a second accumulator into a backfill planted false
    attribution against an honest issuer. A scope mismatch is now
    ``ACCUMULATOR_ID_MISMATCH`` and is never evidence; only an actual
    (predecessor, candidate) conflict under one accumulator and one signing
    key is retained, also mid-backfill and mid-catch-up.
(b) A cold-starting verifier or holder accepted any first announcement as
    its anchor, including a zero-predecessor "migration checkpoint" at an
    epoch above 0, and nothing could express the local authorization that
    specification section 2.4.1 requires. That anchor is now refused with
    ``MIGRATION_CHECKPOINT_UNAUTHORIZED`` unless ``authorized_migrations``
    names ``(issuer_id, accumulator_id, epoch)``.
(c) The holder took its accumulator id from the service object. It now
    needs an explicit holder-local pin and rejects any other accumulator.
"""

import copy
import unittest

import _path  # noqa: F401

from zkc_crypto import SparseMerkleAccumulator, field_to_hex
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import IssuerSigningKey
from zkc_issuer.errors import AdapterError
from zkc_revocation import (
    ANNOUNCEMENT_VERSION,
    EPOCH_DELTA_REQUEST,
    EPOCH_DELTA_RESPONSE,
    GENESIS_ANNOUNCEMENT_HASH,
    AccumulatorIdMismatchError,
    AnnouncementChain,
    AnnouncementKeyPin,
    ChainLinkageError,
    AnnouncementFreshnessError,
    InMemoryVerifierCheckpointStore,
    LivenessHeadMismatchError,
    MigrationCheckpointUnauthorizedError,
    PrivateWitnessProvider,
    VerifierAccumulatorCache,
    WitnessUpdateProvider,
    announcement_hash,
    compute_announcement_digest,
    compute_liveness_digest,
)
from zkc_revocation.service import LIVENESS_VERSION
from zkc_revocation.chain import EQUIVOCATION_EVIDENCE_VERSION, validate_authorized_migrations


ISSUER_ID = "zkc:issuer:sandbox"
ACCUMULATOR_ID = "sandbox-active-credentials"
OTHER_ACCUMULATOR_ID = "sandbox-sanctions-credentials"
ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
CREDENTIAL_ID = 7
MAX_EPOCH_LAG = 10
T0 = 1_770_000_000
NOW = T0 + 100
MIGRATION_EPOCH = 5000

KEY = IssuerSigningKey.test_issuer()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(KEY.metadata_entry())
SECOND_KEY = IssuerSigningKey.from_seed(b"zkc-fork-evidence-second-key", key_id="second-key")
SECOND_PIN = AnnouncementKeyPin.from_signing_key_entry(SECOND_KEY.metadata_entry())
ROOT = field_to_hex(SparseMerkleAccumulator([CREDENTIAL_ID]).root())

HOLDER_SCOPE = PrivateWitnessProvider.checkpoint_scope(ACCUMULATOR_ID)


def _sign(announcement: dict, key=KEY) -> dict:
    announcement = dict(announcement)
    announcement.pop("signature", None)
    announcement["signingKeyId"] = key.key_id
    announcement["signature"] = "0x" + key.sign_digest(
        compute_announcement_digest(announcement)
    ).hex()
    return announcement


def _announcement(accumulator_id, epoch, previous, *, root=ROOT, key=KEY, announced_at=None):
    return _sign(
        {
            "version": ANNOUNCEMENT_VERSION,
            "accumulatorId": accumulator_id,
            "root": root,
            "epoch": epoch,
            "announcedAt": T0 + epoch if announced_at is None else announced_at,
            "maxEpochLag": MAX_EPOCH_LAG,
            "signingKeyId": key.key_id,
            "previousAnnouncementHash": previous,
        },
        key,
    )


def _chain(accumulator_id=ACCUMULATOR_ID, length=12) -> list:
    """A genuine signed chain, epochs 0..length-1, under KEY."""
    announcements = []
    previous = GENESIS_ANNOUNCEMENT_HASH
    for epoch in range(length):
        announcement = _announcement(accumulator_id, epoch, previous)
        previous = announcement_hash(announcement)
        announcements.append(announcement)
    return announcements


HONEST = _chain()
# The same issuer key signs a second accumulator. Its announcements are
# genuine; only the accumulator differs.
OTHER = _chain(OTHER_ACCUMULATOR_ID)


def _forked(epoch: int) -> dict:
    """A second issuer-signed announcement for ``epoch`` that links to the
    genuine predecessor, so the genuine successor does not link to it."""
    return _announcement(
        ACCUMULATOR_ID, epoch, HONEST[epoch]["previousAnnouncementHash"], root=field_to_hex(1)
    )


def _migration_checkpoint(epoch=MIGRATION_EPOCH) -> dict:
    """PoC lane6/poc13: a zero-predecessor v3 checkpoint at epoch > 0."""
    return _announcement(ACCUMULATOR_ID, epoch, GENESIS_ANNOUNCEMENT_HASH, announced_at=T0)


def _metadata(head: dict) -> dict:
    return {
        "version": "zkc:issuer-metadata:v2",
        "issuerId": ISSUER_ID,
        "revocation": {
            "accumulatorId": head["accumulatorId"],
            "type": "POSEIDON2_MERKLE_ACTIVE_SET",
            "currentRoot": head["root"],
            "currentEpoch": head["epoch"],
            "maxEpochLag": head["maxEpochLag"],
            "updateEndpoint": ENDPOINT,
            "currentAnnouncement": copy.deepcopy(head),
        },
    }


class _Source:
    """An issuer's current and historical announcement endpoints.

    ``history`` maps epoch -> announcement and may be edited to serve a
    substituted or forked history. It also answers the holder's
    credential-anonymous full leaf fetch.
    """

    def __init__(self, head: dict, history=HONEST, accumulator_id=ACCUMULATOR_ID):
        self.accumulator_id = accumulator_id
        self.head = copy.deepcopy(head)
        self.history = {item["epoch"]: copy.deepcopy(item) for item in history}
        self.liveness = None

    def current_liveness(self) -> dict:
        if self.liveness is None:
            raise RuntimeError("no liveness statement published")
        return copy.deepcopy(self.liveness)

    @property
    def epoch(self) -> int:
        return self.head["epoch"]

    def current_announcement(self) -> dict:
        return copy.deepcopy(self.head)

    def announcement_for_epoch(self, epoch: int) -> dict:
        if epoch == self.head["epoch"]:
            return copy.deepcopy(self.head)
        if epoch not in self.history:
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "invalid announcement epoch")
        return copy.deepcopy(self.history[epoch])

    def announcement_history(self, start: int, end: int) -> list:
        return [self.announcement_for_epoch(epoch) for epoch in range(start, end + 1)]

    def issuer_metadata(self) -> dict:
        return _metadata(self.head)

    def handle_request(self, request: dict) -> dict:
        if request.get("type") != EPOCH_DELTA_REQUEST:
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "unexpected request")
        head = self.current_announcement()
        return {
            "type": EPOCH_DELTA_RESPONSE,
            "accumulatorId": head["accumulatorId"],
            "epoch": head["epoch"],
            "root": head["root"],
            "announcement": head,
            "mode": "full",
            "leaves": [field_to_hex(CREDENTIAL_ID)],
        }


def _cache(store, keys=None, **kwargs) -> VerifierAccumulatorCache:
    kwargs.setdefault("clock", lambda: NOW)
    return VerifierAccumulatorCache(
        {ISSUER_ID: keys or {KEY.key_id: KEY_PIN}},
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        checkpoint_store=store,
        **kwargs,
    )


def _holder(source, store, **kwargs) -> PrivateWitnessProvider:
    kwargs.setdefault("accumulator_ids", {ISSUER_ID: ACCUMULATOR_ID})
    kwargs.setdefault("clock", lambda: NOW)
    return PrivateWitnessProvider(
        {ISSUER_ID: source},
        issuer_keys={ISSUER_ID: {KEY.key_id: KEY_PIN}},
        announcement_sources={ISSUER_ID: source},
        checkpoint_store=store,
        **kwargs,
    )


def _liveness(head: dict, issued_at: int) -> dict:
    """A genuine ``zkc:epoch-liveness:v1`` statement naming ``head``."""
    statement = {
        "version": LIVENESS_VERSION,
        "accumulatorId": head["accumulatorId"],
        "epoch": head["epoch"],
        "headHash": announcement_hash(head),
        "issuedAt": issued_at,
        "signingKeyId": KEY.key_id,
    }
    statement["signature"] = "0x" + KEY.sign_digest(compute_liveness_digest(statement)).hex()
    return statement


def _persisted_epoch(store, scope=ACCUMULATOR_ID):
    checkpoint = store.load_checkpoint(ISSUER_ID, scope)
    return None if checkpoint is None else checkpoint["announcement"]["epoch"]


def _substituted_loader(source, epoch=3):
    """PoC lane6/poc6: a keyless relay swaps in the other accumulator's
    genuine announcement for ``epoch``."""

    def loader(start, end):
        history = source.announcement_history(start, end)
        history[epoch - start] = copy.deepcopy(OTHER[epoch])
        return history

    return loader


class ChainScopeTests(unittest.TestCase):
    def test_unpinned_chain_scopes_to_the_anchor_accumulator(self):
        chain = AnnouncementChain(trusted_keys={KEY.key_id: KEY_PIN}, checkpoint=HONEST[2])
        with self.assertRaises(AccumulatorIdMismatchError) as ctx:
            chain.ingest(OTHER[3])
        self.assertEqual(ctx.exception.code, "ACCUMULATOR_ID_MISMATCH")
        self.assertNotIsInstance(ctx.exception, ChainLinkageError)
        self.assertEqual(chain.last_epoch, 2)
        chain.ingest(HONEST[3])

    def test_pinned_chain_refuses_another_accumulator_even_as_its_checkpoint(self):
        with self.assertRaises(AccumulatorIdMismatchError):
            AnnouncementChain(
                trusted_keys={KEY.key_id: KEY_PIN},
                checkpoint=OTHER[2],
                accumulator_id=ACCUMULATOR_ID,
            )

    def test_linkage_error_names_the_actual_predecessor(self):
        chain = AnnouncementChain(
            trusted_keys={KEY.key_id: KEY_PIN},
            checkpoint=HONEST[1],
            accumulator_id=ACCUMULATOR_ID,
        )
        chain.ingest(HONEST[2])
        chain.ingest(_forked(3))
        with self.assertRaises(ChainLinkageError) as ctx:
            chain.ingest(HONEST[4])
        self.assertEqual(ctx.exception.predecessor, _forked(3))
        self.assertEqual(ctx.exception.candidate, HONEST[4])
        self.assertEqual(ctx.exception.evidence_pair, (_forked(3), HONEST[4]))

    def test_cross_key_conflict_is_a_fork_but_not_evidence(self):
        keys = {KEY.key_id: KEY_PIN, SECOND_KEY.key_id: SECOND_PIN}
        chain = AnnouncementChain(trusted_keys=keys, checkpoint=HONEST[2])
        cross_key = _announcement(ACCUMULATOR_ID, 3, GENESIS_ANNOUNCEMENT_HASH, key=SECOND_KEY)
        with self.assertRaises(ChainLinkageError) as ctx:
            chain.ingest(cross_key)
        self.assertEqual(ctx.exception.code, "CHAIN_FORKED")
        self.assertIsNone(ctx.exception.evidence_pair)


class VerifierEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryVerifierCheckpointStore()
        self.cache = _cache(self.store)
        self.cache.ingest_metadata(ISSUER_ID, _metadata(HONEST[1]))
        self.source = _Source(HONEST[4])

    def test_cross_accumulator_substitution_in_backfill_is_not_evidence(self):
        with self.assertRaises(AccumulatorIdMismatchError) as ctx:
            self.cache.ingest_metadata(
                ISSUER_ID, self.source.issuer_metadata(), _substituted_loader(self.source)
            )
        self.assertEqual(ctx.exception.code, "ACCUMULATOR_ID_MISMATCH")
        self.assertEqual(self.store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])
        self.assertEqual(self.store.evidence(ISSUER_ID, OTHER_ACCUMULATOR_ID), [])
        self.assertEqual(_persisted_epoch(self.store), 1)
        # The honest history still advances the checkpoint.
        self.cache.ingest_metadata(
            ISSUER_ID, self.source.issuer_metadata(), self.source.announcement_history
        )
        self.assertEqual(_persisted_epoch(self.store), 4)

    def test_cross_accumulator_substitution_in_catch_up_is_not_evidence(self):
        cache = _cache(self.store, max_backfill=2)
        with self.assertRaises(AccumulatorIdMismatchError):
            cache.catch_up(
                ISSUER_ID, self.source.issuer_metadata(), _substituted_loader(self.source)
            )
        self.assertEqual(self.store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])
        self.assertEqual(_persisted_epoch(self.store), 1)

    def test_mid_backfill_fork_retains_the_actual_conflicting_pair(self):
        self.source.history[3] = _forked(3)
        with self.assertRaises(ChainLinkageError) as ctx:
            self.cache.ingest_metadata(
                ISSUER_ID, self.source.issuer_metadata(), self.source.announcement_history
            )
        self.assertEqual(ctx.exception.code, "CHAIN_FORKED")
        evidence = self.store.evidence(ISSUER_ID, ACCUMULATOR_ID)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["version"], EQUIVOCATION_EVIDENCE_VERSION)
        self.assertEqual(evidence[0]["errorCode"], "CHAIN_FORKED")
        # The forked 3 that the backfill accepted and the head that does not
        # link to it; the persisted checkpoint (epoch 1) is not part of it.
        self.assertEqual(evidence[0]["predecessor"], _forked(3))
        self.assertEqual(evidence[0]["candidate"], HONEST[4])
        self.assertNotIn("checkpoint", evidence[0])
        self.assertEqual(_persisted_epoch(self.store), 1)

    def test_mid_catch_up_fork_retains_the_actual_conflicting_pair(self):
        cache = _cache(self.store, max_backfill=3)
        source = _Source(HONEST[8])
        source.history[5] = _forked(5)
        self.assertEqual(
            cache.catch_up(ISSUER_ID, source.issuer_metadata(), source.announcement_history)
            .checkpoint_epoch,
            4,
        )
        with self.assertRaises(ChainLinkageError):
            cache.catch_up(ISSUER_ID, source.issuer_metadata(), source.announcement_history)
        evidence = self.store.evidence(ISSUER_ID, ACCUMULATOR_ID)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["predecessor"], _forked(5))
        self.assertEqual(evidence[0]["candidate"], HONEST[6])
        self.assertEqual(_persisted_epoch(self.store), 4)

    def test_cross_key_successor_fails_closed_without_evidence(self):
        keys = {KEY.key_id: KEY_PIN, SECOND_KEY.key_id: SECOND_PIN}
        store = InMemoryVerifierCheckpointStore()
        cache = _cache(store, keys=keys)
        cache.ingest_metadata(ISSUER_ID, _metadata(HONEST[1]))
        cross_key = _announcement(ACCUMULATOR_ID, 2, GENESIS_ANNOUNCEMENT_HASH, key=SECOND_KEY)
        with self.assertRaises(ChainLinkageError) as ctx:
            cache.ingest_metadata(ISSUER_ID, _metadata(cross_key))
        self.assertEqual(ctx.exception.code, "CHAIN_FORKED")
        self.assertEqual(store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])
        self.assertEqual(_persisted_epoch(store), 1)


class HolderEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryVerifierCheckpointStore()
        self.source = _Source(HONEST[1])
        self.holder = _holder(self.source, self.store)
        self.assertEqual(self.holder.current_epoch(ISSUER_ID), 1)
        self.source.head = copy.deepcopy(HONEST[4])

    def test_cross_accumulator_substitution_in_backfill_is_not_evidence(self):
        self.source.history[3] = copy.deepcopy(OTHER[3])
        with self.assertRaisesRegex(StaleWitnessError, "ACCUMULATOR_ID_MISMATCH"):
            self.holder.current_epoch(ISSUER_ID)
        self.assertEqual(self.store.evidence(ISSUER_ID, HOLDER_SCOPE), [])
        self.assertEqual(_persisted_epoch(self.store, HOLDER_SCOPE), 1)

    def test_cross_accumulator_substitution_in_catch_up_is_not_evidence(self):
        holder = _holder(self.source, self.store, max_backfill=3)
        self.source.head = copy.deepcopy(HONEST[8])
        self.source.history[3] = copy.deepcopy(OTHER[3])
        # The catch-up step fetches history by epoch and checks only the
        # epoch itself; the chain's accumulator pin refuses the substitute.
        with self.assertRaisesRegex(StaleWitnessError, "ACCUMULATOR_ID_MISMATCH"):
            holder.catch_up(ISSUER_ID)
        self.assertEqual(self.store.evidence(ISSUER_ID, HOLDER_SCOPE), [])
        self.assertEqual(_persisted_epoch(self.store, HOLDER_SCOPE), 1)

    def test_mid_backfill_fork_retains_the_actual_conflicting_pair(self):
        self.source.history[3] = _forked(3)
        with self.assertRaisesRegex(StaleWitnessError, "CHAIN_FORKED"):
            self.holder.current_epoch(ISSUER_ID)
        evidence = self.store.evidence(ISSUER_ID, HOLDER_SCOPE)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["version"], EQUIVOCATION_EVIDENCE_VERSION)
        self.assertEqual(evidence[0]["predecessor"], _forked(3))
        self.assertEqual(evidence[0]["candidate"], HONEST[4])
        self.assertEqual(_persisted_epoch(self.store, HOLDER_SCOPE), 1)

    def test_mid_catch_up_fork_retains_the_actual_conflicting_pair(self):
        holder = _holder(self.source, self.store, max_backfill=3)
        self.source.head = copy.deepcopy(HONEST[8])
        self.source.history[3] = _forked(3)
        with self.assertRaisesRegex(StaleWitnessError, "CHAIN_FORKED"):
            holder.catch_up(ISSUER_ID)
        evidence = self.store.evidence(ISSUER_ID, HOLDER_SCOPE)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["predecessor"], _forked(3))
        self.assertEqual(evidence[0]["candidate"], HONEST[4])
        self.assertEqual(_persisted_epoch(self.store, HOLDER_SCOPE), 1)


class HolderAccumulatorPinTests(unittest.TestCase):
    def test_a_bare_service_needs_an_explicit_pin(self):
        source = _Source(HONEST[1])
        with self.assertRaisesRegex(ValueError, "pinned revocation accumulator id"):
            _holder(source, InMemoryVerifierCheckpointStore(), accumulator_ids=None)
        with self.assertRaisesRegex(ValueError, "pinned revocation accumulator id"):
            WitnessUpdateProvider(
                {ISSUER_ID: source},
                {ISSUER_ID: {KEY.key_id: KEY_PIN}},
                checkpoint_store=InMemoryVerifierCheckpointStore(),
            )

    def test_a_target_pin_must_agree_with_accumulator_ids(self):
        with self.assertRaisesRegex(ValueError, "contradicts"):
            WitnessUpdateProvider(
                {ISSUER_ID: (_Source(HONEST[1]), OTHER_ACCUMULATOR_ID)},
                {ISSUER_ID: {KEY.key_id: KEY_PIN}},
                checkpoint_store=InMemoryVerifierCheckpointStore(),
                accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
            )
        with self.assertRaises(ValueError):
            WitnessUpdateProvider(
                {ISSUER_ID: _Source(HONEST[1])},
                {ISSUER_ID: {KEY.key_id: KEY_PIN}},
                checkpoint_store=InMemoryVerifierCheckpointStore(),
                accumulator_ids={"zkc:issuer:unknown": ACCUMULATOR_ID},
            )

    def test_a_service_that_changed_namespace_is_rejected(self):
        # The issuer restarted under another accumulator namespace. The pin,
        # not the service object, decides the scope, so nothing starts a
        # fresh checkpoint scope.
        store = InMemoryVerifierCheckpointStore()
        holder = _holder(_Source(OTHER[1], OTHER, OTHER_ACCUMULATOR_ID), store)
        for refresh in (
            lambda: holder.current_epoch(ISSUER_ID),
            lambda: holder.catch_up(ISSUER_ID),
            lambda: holder.witness(ISSUER_ID, CREDENTIAL_ID),
        ):
            with self.assertRaisesRegex(StaleWitnessError, "ACCUMULATOR_ID_MISMATCH"):
                refresh()
        for scope in (HOLDER_SCOPE, PrivateWitnessProvider.checkpoint_scope(OTHER_ACCUMULATOR_ID)):
            self.assertIsNone(store.load_checkpoint(ISSUER_ID, scope))
            self.assertEqual(store.evidence(ISSUER_ID, scope), [])

    def test_a_published_head_of_another_accumulator_is_rejected(self):
        # The service object keeps the pinned id, but the publication source
        # serves the issuer's genuine head of the other accumulator.
        source = _Source(OTHER[1], OTHER)
        store = InMemoryVerifierCheckpointStore()
        holder = _holder(source, store)
        with self.assertRaisesRegex(StaleWitnessError, "ACCUMULATOR_ID_MISMATCH"):
            holder.current_epoch(ISSUER_ID)
        self.assertIsNone(store.load_checkpoint(ISSUER_ID, HOLDER_SCOPE))


class ColdStartMigrationTests(unittest.TestCase):
    POLICY = {(ISSUER_ID, ACCUMULATOR_ID, MIGRATION_EPOCH)}

    def test_verifier_refuses_an_unauthorized_migration_checkpoint(self):
        for name, policy in (
            ("no policy", ()),
            ("other epoch", {(ISSUER_ID, ACCUMULATOR_ID, MIGRATION_EPOCH - 1)}),
        ):
            with self.subTest(policy=name):
                store = InMemoryVerifierCheckpointStore()
                cache = _cache(store, authorized_migrations=policy)
                with self.assertRaises(MigrationCheckpointUnauthorizedError) as ctx:
                    cache.ingest_metadata(ISSUER_ID, _metadata(_migration_checkpoint()))
                self.assertEqual(ctx.exception.code, "MIGRATION_CHECKPOINT_UNAUTHORIZED")
                with self.assertRaises(MigrationCheckpointUnauthorizedError):
                    cache.catch_up(
                        ISSUER_ID, _metadata(_migration_checkpoint()), lambda *_: []
                    )
                self.assertIsNone(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID))
                with self.assertRaises(KeyError):
                    cache.state(ISSUER_ID)

    def test_verifier_accepts_an_authorized_migration_checkpoint(self):
        store = InMemoryVerifierCheckpointStore()
        cache = _cache(store, authorized_migrations=self.POLICY)
        cache.ingest_metadata(ISSUER_ID, _metadata(_migration_checkpoint()))
        self.assertEqual(cache.state(ISSUER_ID).current_epoch, MIGRATION_EPOCH)
        # Once a checkpoint is retained, another zero-predecessor
        # announcement is a fork, whatever the policy says.
        reset = _announcement(
            ACCUMULATOR_ID, MIGRATION_EPOCH + 1, GENESIS_ANNOUNCEMENT_HASH, announced_at=T0
        )
        with self.assertRaises(ChainLinkageError):
            cache.ingest_metadata(ISSUER_ID, _metadata(reset))

    def test_verifier_cold_start_at_genesis_or_a_linked_head_stays_trust_on_first_use(self):
        for head in (HONEST[0], HONEST[7]):
            with self.subTest(epoch=head["epoch"]):
                cache = _cache(InMemoryVerifierCheckpointStore())
                cache.ingest_metadata(ISSUER_ID, _metadata(head))
                self.assertEqual(cache.state(ISSUER_ID).current_epoch, head["epoch"])

    def test_holder_refuses_an_unauthorized_migration_checkpoint(self):
        source = _Source(_migration_checkpoint())
        store = InMemoryVerifierCheckpointStore()
        holder = _holder(source, store)
        for refresh in (
            lambda: holder.witness(ISSUER_ID, CREDENTIAL_ID),
            lambda: holder.catch_up(ISSUER_ID),
            lambda: holder.current_epoch(ISSUER_ID),
        ):
            with self.assertRaisesRegex(StaleWitnessError, "MIGRATION_CHECKPOINT_UNAUTHORIZED"):
                refresh()
        self.assertIsNone(store.load_checkpoint(ISSUER_ID, HOLDER_SCOPE))

    def test_holder_accepts_an_authorized_migration_checkpoint(self):
        source = _Source(_migration_checkpoint())
        store = InMemoryVerifierCheckpointStore()
        holder = _holder(source, store, authorized_migrations=self.POLICY)
        witness = holder.witness(ISSUER_ID, CREDENTIAL_ID)
        self.assertEqual(witness.accumulator_epoch, MIGRATION_EPOCH)
        self.assertEqual(_persisted_epoch(store, HOLDER_SCOPE), MIGRATION_EPOCH)

    def test_policy_entries_are_validated(self):
        self.assertEqual(validate_authorized_migrations(None), frozenset())
        for bad in (
            "zkc:issuer:sandbox",
            {ISSUER_ID: MIGRATION_EPOCH},
            [[ISSUER_ID, ACCUMULATOR_ID, MIGRATION_EPOCH]],
            [(ISSUER_ID, ACCUMULATOR_ID, 0)],
            [(ISSUER_ID, ACCUMULATOR_ID, True)],
            [(ISSUER_ID, "", MIGRATION_EPOCH)],
            [(ISSUER_ID, ACCUMULATOR_ID, 1 << 64)],
        ):
            with self.subTest(policy=bad), self.assertRaises(ValueError):
                validate_authorized_migrations(bad)
        for unpinned in (
            {("zkc:issuer:unknown", ACCUMULATOR_ID, MIGRATION_EPOCH)},
            {(ISSUER_ID, OTHER_ACCUMULATOR_ID, MIGRATION_EPOCH)},
        ):
            with self.subTest(unpinned=unpinned):
                with self.assertRaisesRegex(ValueError, "not pinned"):
                    _cache(InMemoryVerifierCheckpointStore(), authorized_migrations=unpinned)
                with self.assertRaisesRegex(ValueError, "not pinned"):
                    _holder(
                        _Source(HONEST[1]),
                        InMemoryVerifierCheckpointStore(),
                        authorized_migrations=unpinned,
                    )


class LivenessScopeTests(unittest.TestCase):
    """A signed liveness statement (PR 94) stays inside the pinned scope and
    never stands in for migration authorization."""

    LATE = T0 + 5_000  # every announcement here is past the 3600 s age limit

    def test_verifier_never_accepts_liveness_for_another_accumulator(self):
        store = InMemoryVerifierCheckpointStore()
        _cache(store).ingest_metadata(ISSUER_ID, _metadata(HONEST[1]))
        document = _metadata(HONEST[2])
        document["revocation"]["currentLiveness"] = _liveness(OTHER[2], NOW)
        with self.assertRaises(LivenessHeadMismatchError) as ctx:
            _cache(store).ingest_metadata(ISSUER_ID, document)
        self.assertEqual(ctx.exception.code, "LIVENESS_HEAD_MISMATCH")
        self.assertEqual(_persisted_epoch(store), 1)
        self.assertEqual(store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])
        self.assertEqual(store.evidence(ISSUER_ID, OTHER_ACCUMULATOR_ID), [])

        # It cannot refresh a stale head of the pinned accumulator either.
        late = _cache(InMemoryVerifierCheckpointStore(), clock=lambda: self.LATE)
        document["revocation"]["currentLiveness"] = _liveness(OTHER[2], self.LATE)
        with self.assertRaises(AnnouncementFreshnessError):
            late.ingest_metadata(ISSUER_ID, document)

    def test_verifier_liveness_does_not_authorize_a_migration_checkpoint(self):
        document = _metadata(_migration_checkpoint())
        document["revocation"]["currentLiveness"] = _liveness(
            _migration_checkpoint(), self.LATE
        )
        store = InMemoryVerifierCheckpointStore()
        with self.assertRaises(MigrationCheckpointUnauthorizedError):
            _cache(store, clock=lambda: self.LATE).ingest_metadata(ISSUER_ID, document)
        self.assertIsNone(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID))
        authorized = _cache(
            store,
            clock=lambda: self.LATE,
            authorized_migrations={(ISSUER_ID, ACCUMULATOR_ID, MIGRATION_EPOCH)},
        )
        authorized.ingest_metadata(ISSUER_ID, document)
        self.assertEqual(authorized.state(ISSUER_ID).current_epoch, MIGRATION_EPOCH)

    def test_holder_ignores_liveness_for_another_accumulator(self):
        source = _Source(HONEST[1])
        source.liveness = _liveness(OTHER[1], self.LATE)
        store = InMemoryVerifierCheckpointStore()
        holder = _holder(source, store, clock=lambda: self.LATE)
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_STALE"):
            holder.current_epoch(ISSUER_ID)
        self.assertIsNone(store.load_checkpoint(ISSUER_ID, HOLDER_SCOPE))
        self.assertEqual(store.evidence(ISSUER_ID, HOLDER_SCOPE), [])

    def test_holder_liveness_does_not_authorize_a_migration_checkpoint(self):
        source = _Source(_migration_checkpoint())
        source.liveness = _liveness(_migration_checkpoint(), self.LATE)
        store = InMemoryVerifierCheckpointStore()
        holder = _holder(source, store, clock=lambda: self.LATE)
        with self.assertRaisesRegex(StaleWitnessError, "MIGRATION_CHECKPOINT_UNAUTHORIZED"):
            holder.current_epoch(ISSUER_ID)
        self.assertIsNone(store.load_checkpoint(ISSUER_ID, HOLDER_SCOPE))
        authorized = _holder(
            source,
            store,
            clock=lambda: self.LATE,
            authorized_migrations={(ISSUER_ID, ACCUMULATOR_ID, MIGRATION_EPOCH)},
        )
        self.assertEqual(authorized.current_epoch(ISSUER_ID), MIGRATION_EPOCH)


if __name__ == "__main__":
    unittest.main()
