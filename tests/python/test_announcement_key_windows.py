"""Announcement signing-key validity windows on issuer, verifier and holder.

Regression tests for review finding R7.5 (2026-10-04, PoC lane6/poc7):

(1) the issuer service signed announcements with a key outside its validity
    window, and issuance or revocation under that key still advanced the
    accumulator;
(2) verifier and holder pins were ``keyId -> (x, y)`` with no window, so an
    announcement signed years after ``notAfter`` was accepted;
(3) the only window check (metadata assembly) surfaced as HTTP 400 on the
    metadata GET, an issuer outage reported as a client error.
"""

import copy
import dataclasses
import datetime
import json
import tempfile
import unittest
import urllib.error
import urllib.request

import _path  # noqa: F401

from zkc_crypto import derive_holder_commitment_from_seed, field_to_hex, hex_to_field
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import (
    AdapterError,
    IssuerSigningKey,
    SandboxIssuerAdapter,
    compute_binding_response,
)
from zkc_issuer.ledger import InMemoryIssuanceLedgerStore
from zkc_revocation import (
    AnnouncementChain,
    AnnouncementKeyPin,
    AnnouncementKeyWindowError,
    DurableRevocationAccumulatorService,
    InMemoryVerifierCheckpointStore,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    SQLiteAccumulatorStateStore,
    VerifierAccumulatorCache,
    VerifierCheckpointStoreError,
    WitnessUpdateProvider,
)
from zkc_revocation.store import AccumulatorStoreError
from zkc_transport import (
    HTTPWitnessUpdateProvider,
    IssuerServer,
    RevocationServer,
    RevocationServiceClient,
)

ISSUER_ID = "zkc:issuer:sandbox"
ACCUMULATOR_ID = "sandbox-active-credentials"
ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
SCHEMA = "zkc:cred:kyc:v1"
WINDOW_CODE = "ANNOUNCEMENT_KEY_OUTSIDE_VALIDITY"

T0 = 1_770_000_000  # 2026-02-02T02:40:00Z
T_LATE = T0 + 5_000  # after the narrow verifier pins below close

# Issuer-side keys. Their own windows cover T0 and T_LATE, which models a
# rotated-out key that the verifier no longer trusts but someone still holds.
OLD_KEY = IssuerSigningKey.test_issuer(not_after="2027-01-01T00:00:00Z")  # pinned: tests assert this window
NEW_KEY = IssuerSigningKey.from_seed(b"zkc-key-window-successor", key_id="window-successor")

# A short-lived issuer key for the issuer-side tests: 2026-02-01 .. 2026-03-01.
SHORT_KEY = IssuerSigningKey.from_seed(
    b"zkc-key-window-short",
    key_id="short-lived-2026-02",
    not_before="2026-02-01T00:00:00Z",
    not_after="2026-03-01T00:00:00Z",
)
SHORT_EXPIRES = 1_772_323_200  # 2026-03-01T00:00:00Z, first instant outside
SUCCESSOR_KEY = IssuerSigningKey.from_seed(
    b"zkc-key-window-short-successor",
    key_id="short-lived-successor",
    not_before="2026-02-15T00:00:00Z",
    not_after="2026-06-01T00:00:00Z",
)


def pin(key, not_before=T0 - 86_400, not_after=T0 + 1_000, retire_after_epoch=None):
    x, y = key.public_key_coordinates()
    return AnnouncementKeyPin(x, y, not_before, not_after, retire_after_epoch)


def entry_pin(key, **kwargs):
    return AnnouncementKeyPin.from_signing_key_entry(key.metadata_entry(), **kwargs)


def metadata(announcement: dict) -> dict:
    """Minimal authenticated metadata v2 around one signed announcement."""
    return {
        "version": "zkc:issuer-metadata:v2",
        "issuerId": ISSUER_ID,
        "revocation": {
            "accumulatorId": announcement["accumulatorId"],
            "currentRoot": announcement["root"],
            "currentEpoch": announcement["epoch"],
            "maxEpochLag": announcement["maxEpochLag"],
            "currentAnnouncement": copy.deepcopy(announcement),
        },
    }


def clocked_service(key=OLD_KEY, start=T0):
    clock = {"now": start}
    service = RevocationAccumulatorService(
        ACCUMULATOR_ID, ENDPOINT, key, clock=lambda: clock["now"]
    )
    return service, clock


def cache(store, pins, clock, **kwargs):
    return VerifierAccumulatorCache(
        {ISSUER_ID: pins},
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        checkpoint_store=store,
        clock=lambda: clock["now"],
        **kwargs,
    )


def provider(service, store, pins, clock, **kwargs):
    return PrivateWitnessProvider(
        {ISSUER_ID: service},
        issuer_keys={ISSUER_ID: pins},
        announcement_sources={ISSUER_ID: service},
        checkpoint_store=store,
        clock=lambda: clock["now"],
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        **kwargs,
    )


def history_loader(service):
    return lambda start, end: service.announcement_history(start, end)


def service_state(service) -> dict:
    """Every piece of issuer state an epoch transition can touch."""
    return {
        "epoch": service.epoch,
        "root": service.root(),
        "leaves": service._accumulator.leaves(),
        "credentials": service.credential_ids(),
        "revoked": frozenset(service._revoked),
        "snapshots": copy.deepcopy(service._snapshots),
        "announcements": copy.deepcopy(service._announcements),
        "lastHash": service._last_announcement_hash,
        "signers": service.signing_key_history(),
        "signingKey": service._signing_key.key_id,
        "current": service.current_announcement(),
    }


class PinTypeTests(unittest.TestCase):
    """Pins carry a mandatory window; a bare (x, y) pin fails closed."""

    def test_bare_coordinate_pins_are_refused_everywhere(self):
        x, y = OLD_KEY.public_key_coordinates()
        service, clock = clocked_service()
        for label, build in (
            ("chain map", lambda: AnnouncementChain(trusted_keys={OLD_KEY.key_id: (x, y)})),
            ("chain positional", lambda: AnnouncementChain(x, y)),
            ("chain without keys", lambda: AnnouncementChain()),
            ("verifier", lambda: cache(
                InMemoryVerifierCheckpointStore(), {OLD_KEY.key_id: (x, y)}, clock
            )),
            ("holder", lambda: provider(
                service, InMemoryVerifierCheckpointStore(), {OLD_KEY.key_id: (x, y)}, clock
            )),
            ("per-credential holder", lambda: WitnessUpdateProvider(
                {ISSUER_ID: service}, {ISSUER_ID: {OLD_KEY.key_id: (x, y)}},
                checkpoint_store=InMemoryVerifierCheckpointStore(),
                accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
            )),
            ("HTTP per-credential holder", lambda: HTTPWitnessUpdateProvider(
                {ISSUER_ID: ("http://127.0.0.1:9", ACCUMULATOR_ID)},
                {ISSUER_ID: {OLD_KEY.key_id: (x, y)}},
                checkpoint_store=InMemoryVerifierCheckpointStore(),
            )),
            ("empty", lambda: cache(InMemoryVerifierCheckpointStore(), {}, clock)),
        ):
            with self.subTest(label), self.assertRaises(ValueError):
                build()

    def test_pin_fields_are_validated(self):
        x, y = OLD_KEY.public_key_coordinates()
        for kwargs in (
            {"not_before": T0, "not_after": T0},
            {"not_before": T0 + 1, "not_after": T0},
            {"not_before": -1, "not_after": T0},
            {"not_before": True, "not_after": T0},
            {"not_before": T0, "not_after": 1 << 64},
            {"not_before": T0, "not_after": T0 + 1, "retire_after_epoch": -1},
            {"not_before": T0, "not_after": T0 + 1, "retire_after_epoch": "3"},
        ):
            with self.subTest(kwargs), self.assertRaises(ValueError):
                AnnouncementKeyPin(x, y, **kwargs)
        with self.assertRaises(ValueError):
            AnnouncementKeyPin(x[:31], y, T0, T0 + 1)

    def test_entry_pin_requires_an_explicit_utc_offset(self):
        entry = OLD_KEY.metadata_entry()
        pinned = AnnouncementKeyPin.from_signing_key_entry(entry, retire_after_epoch=7)
        self.assertEqual(pinned.not_before, 1_767_225_600)
        self.assertEqual(pinned.not_after, 1_798_761_600)
        self.assertEqual(pinned.retire_after_epoch, 7)
        for field, value in (
            ("notAfter", "2027-01-01T00:00:00"),
            ("notAfter", ""),
            ("notBefore", None),
            ("publicKey", entry["publicKey"].upper()),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                AnnouncementKeyPin.from_signing_key_entry({**entry, field: value})


class VerifierWindowTests(unittest.TestCase):
    def test_poc_late_announcement_is_rejected_and_checkpoint_unchanged(self):
        """PoC part 2: an expired pinned key's late announcement is refused."""
        service, clock = clocked_service()
        store = InMemoryVerifierCheckpointStore()
        verifier = cache(store, {OLD_KEY.key_id: pin(OLD_KEY)}, clock)
        verifier.ingest_metadata(ISSUER_ID, metadata(service.current_announcement()))
        before = copy.deepcopy(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID))

        clock["now"] = T_LATE
        service.register(5)
        with self.assertRaises(AnnouncementKeyWindowError) as ctx:
            verifier.ingest_metadata(ISSUER_ID, metadata(service.current_announcement()))
        self.assertEqual(ctx.exception.code, WINDOW_CODE)
        self.assertEqual(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID), before)
        self.assertEqual(store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])

    def test_window_is_half_open_for_a_cold_start(self):
        service, clock = clocked_service()
        genesis = service.current_announcement()
        for label, pinned, accepted in (
            ("notAfter equals announcedAt", pin(OLD_KEY, T0 - 10, T0), False),
            ("notBefore after announcedAt", pin(OLD_KEY, T0 + 1, T0 + 10), False),
            ("notBefore equals announcedAt", pin(OLD_KEY, T0, T0 + 1), True),
        ):
            with self.subTest(label):
                store = InMemoryVerifierCheckpointStore()
                verifier = cache(store, {OLD_KEY.key_id: pinned}, clock)
                if accepted:
                    verifier.ingest_metadata(ISSUER_ID, metadata(genesis))
                    self.assertEqual(verifier.state(ISSUER_ID).current_epoch, 0)
                else:
                    with self.assertRaises(AnnouncementKeyWindowError):
                        verifier.ingest_metadata(ISSUER_ID, metadata(genesis))
                    self.assertIsNone(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID))

    def _late_history_then_rotation(self):
        """Genesis in window; epochs 1-3 by OLD after its pin closed; epoch 4
        by a pinned successor, in its window and fresh."""
        service, clock = clocked_service()
        genesis = service.current_announcement()
        clock["now"] = T_LATE
        for credential_id in (101, 202, 303):
            service.register(credential_id)
        service.rotate_signing_key(NEW_KEY)
        service.register(404)
        return service, clock, genesis

    def test_catch_up_rejects_historical_announcements_outside_the_window(self):
        service, clock, genesis = self._late_history_then_rotation()
        pins = {
            OLD_KEY.key_id: pin(OLD_KEY),
            NEW_KEY.key_id: pin(NEW_KEY, T0, T0 + 1_000_000),
        }
        head = metadata(service.current_announcement())
        store = InMemoryVerifierCheckpointStore()
        clock["now"] = T0
        verifier = cache(store, pins, clock, max_backfill=2)
        verifier.ingest_metadata(ISSUER_ID, metadata(genesis))
        before = copy.deepcopy(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID))
        clock["now"] = T_LATE

        with self.assertRaises(AnnouncementKeyWindowError):
            verifier.catch_up(ISSUER_ID, head, history_loader(service))
        self.assertEqual(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID), before)

        bounded = cache(store, pins, clock)
        with self.assertRaises(AnnouncementKeyWindowError):
            bounded.ingest_metadata(ISSUER_ID, head, history_loader(service))
        self.assertEqual(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID), before)

        # Control: pins whose windows cover the history reach the head.
        wide = {
            OLD_KEY.key_id: pin(OLD_KEY, T0 - 86_400, T_LATE + 1),
            NEW_KEY.key_id: pins[NEW_KEY.key_id],
        }
        wide_clock = {"now": T0}
        caught_up = cache(InMemoryVerifierCheckpointStore(), wide, wide_clock, max_backfill=2)
        caught_up.ingest_metadata(ISSUER_ID, metadata(genesis))
        wide_clock["now"] = T_LATE
        statuses = []
        while not statuses or not statuses[-1].complete:
            statuses.append(caught_up.catch_up(ISSUER_ID, head, history_loader(service)))
        self.assertEqual(caught_up.state(ISSUER_ID).current_epoch, 4)

    def test_retire_after_epoch_bounds_the_epochs_a_key_signs(self):
        service, clock = clocked_service()
        announcements = [service.current_announcement()]
        for credential_id in (101, 202):
            service.register(credential_id)
            announcements.append(service.current_announcement())

        store = InMemoryVerifierCheckpointStore()
        verifier = cache(store, {OLD_KEY.key_id: pin(OLD_KEY, retire_after_epoch=1)}, clock)
        verifier.ingest_metadata(ISSUER_ID, metadata(announcements[0]))
        verifier.ingest_metadata(ISSUER_ID, metadata(announcements[1]))
        with self.assertRaises(AnnouncementKeyWindowError) as ctx:
            verifier.ingest_metadata(ISSUER_ID, metadata(announcements[2]))
        self.assertIn("retireAfterEpoch 1", str(ctx.exception))
        self.assertEqual(verifier.state(ISSUER_ID).current_epoch, 1)

    def test_rotation_to_a_pinned_successor_passes_retirement(self):
        service, clock = clocked_service()
        service.register(101)
        service.rotate_signing_key(NEW_KEY)
        service.register(202)
        pins = {
            OLD_KEY.key_id: pin(OLD_KEY, retire_after_epoch=1),
            NEW_KEY.key_id: pin(NEW_KEY, T0, T0 + 1_000_000),
        }
        verifier = cache(InMemoryVerifierCheckpointStore(), pins, clock)
        verifier.ingest_metadata(ISSUER_ID, metadata(service.announcement_for_epoch(0)))
        verifier.ingest_metadata(
            ISSUER_ID, metadata(service.current_announcement()), history_loader(service)
        )
        self.assertEqual(verifier.state(ISSUER_ID).current_epoch, 2)

    def test_persisted_checkpoint_is_rechecked_under_narrowed_pins(self):
        service, clock = clocked_service()
        clock["now"] = T_LATE
        service.register(101)
        store = InMemoryVerifierCheckpointStore()
        wide = cache(store, {OLD_KEY.key_id: pin(OLD_KEY, T0 - 10, T_LATE + 1)}, clock)
        wide.ingest_metadata(ISSUER_ID, metadata(service.current_announcement()))

        # The operator learns the key was compromised after T0 + 1000.
        narrowed = cache(store, {OLD_KEY.key_id: pin(OLD_KEY)}, clock)
        with self.assertRaises(VerifierCheckpointStoreError):
            narrowed.state(ISSUER_ID, ACCUMULATOR_ID)
        with self.assertRaises(VerifierCheckpointStoreError):
            narrowed.ingest_metadata(ISSUER_ID, metadata(service.current_announcement()))


class HolderWindowTests(unittest.TestCase):
    def test_witness_refresh_rejects_a_late_head(self):
        service, clock = clocked_service()
        service.register(101)
        store = InMemoryVerifierCheckpointStore()
        holder = provider(service, store, {OLD_KEY.key_id: pin(OLD_KEY)}, clock)
        holder.witness(ISSUER_ID, 101)
        scope = PrivateWitnessProvider.checkpoint_scope(ACCUMULATOR_ID)
        before = copy.deepcopy(store.load_checkpoint(ISSUER_ID, scope))
        self.assertEqual(before["announcement"]["epoch"], 1)

        clock["now"] = T_LATE
        service.register(202)
        with self.assertRaisesRegex(StaleWitnessError, WINDOW_CODE):
            holder.witness(ISSUER_ID, 101)
        self.assertEqual(store.load_checkpoint(ISSUER_ID, scope), before)

        cold_store = InMemoryVerifierCheckpointStore()
        cold = provider(service, cold_store, {OLD_KEY.key_id: pin(OLD_KEY)}, clock)
        with self.assertRaisesRegex(StaleWitnessError, WINDOW_CODE):
            cold.witness(ISSUER_ID, 101)
        self.assertIsNone(cold_store.load_checkpoint(ISSUER_ID, scope))

    def test_catch_up_rejects_historical_announcements_outside_the_window(self):
        service, clock = clocked_service()
        service.register(101)
        store = InMemoryVerifierCheckpointStore()
        pins = {
            OLD_KEY.key_id: pin(OLD_KEY),
            NEW_KEY.key_id: pin(NEW_KEY, T0, T0 + 1_000_000),
        }
        holder = provider(service, store, pins, clock, max_backfill=2)
        holder.witness(ISSUER_ID, 101)
        scope = PrivateWitnessProvider.checkpoint_scope(ACCUMULATOR_ID)
        before = copy.deepcopy(store.load_checkpoint(ISSUER_ID, scope))

        clock["now"] = T_LATE
        for credential_id in (202, 303, 404):
            service.register(credential_id)
        service.rotate_signing_key(NEW_KEY)
        service.register(505)
        with self.assertRaisesRegex(StaleWitnessError, WINDOW_CODE):
            holder.catch_up(ISSUER_ID)
        self.assertEqual(store.load_checkpoint(ISSUER_ID, scope), before)

        # Control: the same history under pins that cover it completes.
        wide = dict(pins, **{OLD_KEY.key_id: pin(OLD_KEY, T0 - 86_400, T_LATE + 1)})
        ok_store = InMemoryVerifierCheckpointStore()
        ok_store.compare_and_swap_checkpoint(ISSUER_ID, scope, None, before)
        caught_up = provider(service, ok_store, wide, clock, max_backfill=2)
        statuses = []
        while not statuses or not statuses[-1].complete:
            statuses.append(caught_up.catch_up(ISSUER_ID))
        self.assertEqual(statuses[-1].checkpoint_epoch, 5)
        caught_up.witness(ISSUER_ID, 101)

    def test_retire_after_epoch_applies_to_the_holder(self):
        service, clock = clocked_service()
        service.register(101)
        store = InMemoryVerifierCheckpointStore()
        holder = provider(
            service, store, {OLD_KEY.key_id: pin(OLD_KEY, retire_after_epoch=1)}, clock
        )
        holder.witness(ISSUER_ID, 101)
        service.register(202)
        with self.assertRaisesRegex(StaleWitnessError, "retireAfterEpoch 1"):
            holder.witness(ISSUER_ID, 101)


class HolderProviderKindTests(unittest.TestCase):
    """Every holder provider, in process and over HTTP, enforces the pin."""

    KINDS = ("private-local", "private-http", "per-credential-local", "per-credential-http")

    def make(self, kind, service, base_url, store, pins, clock, **policy):
        policy = dict(
            policy,
            checkpoint_store=store,
            clock=lambda: clock["now"],
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        )
        keys = {ISSUER_ID: pins}
        # The in-process service stands in for the independent publication
        # mirror that a private provider reads signed heads from.
        mirror = {ISSUER_ID: service}
        if kind == "private-local":
            return PrivateWitnessProvider(
                {ISSUER_ID: service}, keys, announcement_sources=mirror, **policy
            )
        if kind == "private-http":
            client = RevocationServiceClient(base_url)
            return PrivateWitnessProvider(
                {ISSUER_ID: (client, ACCUMULATOR_ID)}, keys, announcement_sources=mirror, **policy
            )
        if kind == "per-credential-local":
            return WitnessUpdateProvider({ISSUER_ID: service}, keys, **policy)
        return HTTPWitnessUpdateProvider({ISSUER_ID: (base_url, ACCUMULATOR_ID)}, keys, **policy)

    def run_kinds(self, scenario):
        for kind in self.KINDS:
            with self.subTest(kind):
                service, clock = clocked_service()
                service.register(101)
                with RevocationServer(service) as server:
                    scenario(kind, service, clock, server.base_url)

    def test_late_head_is_rejected_and_checkpoint_unchanged(self):
        def scenario(kind, service, clock, base_url):
            store = InMemoryVerifierCheckpointStore()
            holder = self.make(kind, service, base_url, store, {OLD_KEY.key_id: pin(OLD_KEY)}, clock)
            holder.witness(ISSUER_ID, 101)
            scope = type(holder).checkpoint_scope(ACCUMULATOR_ID)
            before = copy.deepcopy(store.load_checkpoint(ISSUER_ID, scope))
            self.assertEqual(before["announcement"]["epoch"], 1)
            clock["now"] = T_LATE
            service.register(202)
            with self.assertRaisesRegex(StaleWitnessError, WINDOW_CODE):
                holder.witness(ISSUER_ID, 101)
            self.assertEqual(store.load_checkpoint(ISSUER_ID, scope), before)

        self.run_kinds(scenario)

    def test_backfilled_history_outside_the_window_is_rejected(self):
        def scenario(kind, service, clock, base_url):
            store = InMemoryVerifierCheckpointStore()
            pins = {
                OLD_KEY.key_id: pin(OLD_KEY),
                NEW_KEY.key_id: pin(NEW_KEY, T0, T0 + 1_000_000),
            }
            holder = self.make(kind, service, base_url, store, pins, clock)
            holder.witness(ISSUER_ID, 101)
            scope = type(holder).checkpoint_scope(ACCUMULATOR_ID)
            before = copy.deepcopy(store.load_checkpoint(ISSUER_ID, scope))
            # Epochs 2-3 by the old key after its pin closed; epoch 4 by the
            # pinned successor, fresh and inside its own window.
            clock["now"] = T_LATE
            service.register(202)
            service.register(303)
            service.rotate_signing_key(NEW_KEY)
            service.register(404)
            with self.assertRaisesRegex(StaleWitnessError, WINDOW_CODE):
                holder.witness(ISSUER_ID, 101)
            self.assertEqual(store.load_checkpoint(ISSUER_ID, scope), before)

        self.run_kinds(scenario)

    def test_retire_after_epoch_and_valid_rotation(self):
        def scenario(kind, service, clock, base_url):
            retired = self.make(
                kind, service, base_url, InMemoryVerifierCheckpointStore(),
                {OLD_KEY.key_id: pin(OLD_KEY, retire_after_epoch=0)}, clock,
            )
            with self.assertRaisesRegex(StaleWitnessError, "retireAfterEpoch 0"):
                retired.witness(ISSUER_ID, 101)

            pins = {
                OLD_KEY.key_id: pin(OLD_KEY, retire_after_epoch=1),
                NEW_KEY.key_id: pin(NEW_KEY, T0, T0 + 1_000_000),
            }
            holder = self.make(kind, service, base_url, InMemoryVerifierCheckpointStore(), pins, clock)
            holder.witness(ISSUER_ID, 101)
            service.rotate_signing_key(NEW_KEY)
            service.register(202)
            witness = holder.witness(ISSUER_ID, 101)
            self.assertEqual(witness.accumulator_epoch, 2)

        self.run_kinds(scenario)


class IssuerSigningWindowTests(unittest.TestCase):
    """Issue/revoke/renew under a key outside its window change nothing."""

    def test_poc_service_refuses_to_sign_genesis_with_an_expired_key(self):
        late = int(datetime.datetime(2029, 6, 1, tzinfo=datetime.timezone.utc).timestamp())
        self.assertFalse(OLD_KEY.is_valid_at(late))
        with self.assertRaises(AdapterError) as ctx:
            RevocationAccumulatorService(ACCUMULATOR_ID, ENDPOINT, OLD_KEY, clock=lambda: late)
        self.assertEqual(ctx.exception.code, "EXPIRED_ISSUER_KEY")
        with self.assertRaises(AdapterError):
            RevocationAccumulatorService(
                ACCUMULATOR_ID, ENDPOINT, SHORT_KEY, clock=lambda: T0 - 86_400 * 3
            )
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteAccumulatorStateStore(f"{directory}/issuer.sqlite3", ACCUMULATOR_ID)
            try:
                with self.assertRaises(AdapterError):
                    DurableRevocationAccumulatorService.open(
                        ACCUMULATOR_ID, ENDPOINT, OLD_KEY, store, clock=lambda: late
                    )
                self.assertIsNone(store.load_log())
            finally:
                store.close()

    def test_signer_without_a_validity_window_is_refused(self):
        class NoWindow:
            key_id = OLD_KEY.key_id
            sign_digest = staticmethod(OLD_KEY.sign_digest)
            public_key_coordinates = staticmethod(OLD_KEY.public_key_coordinates)

        with self.assertRaisesRegex(ValueError, "validity window"):
            RevocationAccumulatorService(ACCUMULATOR_ID, ENDPOINT, NoWindow(), clock=lambda: T0)

    def assert_mutations_change_nothing(self, service, read_store=lambda: None):
        before, stored = service_state(service), read_store()
        for name, call in (
            ("register", lambda: service.register(909)),
            ("revoke", lambda: service.revoke(101)),
            ("replace", lambda: service.replace(101, 808)),
        ):
            with self.subTest(name):
                with self.assertRaises(AdapterError) as ctx:
                    call()
                self.assertEqual(ctx.exception.code, "EXPIRED_ISSUER_KEY")
                self.assertEqual(service_state(service), before)
                self.assertEqual(read_store(), stored)
        with self.assertRaises(AdapterError):
            service.ensure_can_sign()

    def test_in_memory_mutations_with_an_expired_key_change_nothing(self):
        service, clock = clocked_service(SHORT_KEY)
        service.register(101)
        clock["now"] = SHORT_EXPIRES
        self.assert_mutations_change_nothing(service)
        clock["now"] = SHORT_EXPIRES - 1
        service.revoke(101)
        self.assertEqual(service.epoch, 2)

    def test_durable_mutations_with_an_expired_key_change_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/issuer.sqlite3"
            clock = {"now": T0}
            store = SQLiteAccumulatorStateStore(path, ACCUMULATOR_ID)
            service = DurableRevocationAccumulatorService.open(
                ACCUMULATOR_ID, ENDPOINT, SHORT_KEY, store, clock=lambda: clock["now"]
            )
            service.register(101)
            clock["now"] = SHORT_EXPIRES

            def read_store():
                return store.load_log(), store._conn.total_changes

            self.assert_mutations_change_nothing(service, read_store)
            store.close()

            # Recovery still opens with the expired active key (reads work),
            # but it cannot sign; opening with a valid successor rotates.
            store = SQLiteAccumulatorStateStore(path, ACCUMULATOR_ID)
            reopened = DurableRevocationAccumulatorService.open(
                ACCUMULATOR_ID, ENDPOINT, SHORT_KEY, store, clock=lambda: clock["now"]
            )
            self.assertEqual(reopened.epoch, 1)
            with self.assertRaises(AdapterError):
                reopened.revoke(101)
            store.close()

            store = SQLiteAccumulatorStateStore(path, ACCUMULATOR_ID)
            rotated = DurableRevocationAccumulatorService.open(
                ACCUMULATOR_ID, ENDPOINT, SUCCESSOR_KEY, store,
                clock=lambda: clock["now"], allow_rotation=True,
            )
            rotated.revoke(101)
            self.assertEqual(rotated.epoch, 2)
            self.assertEqual(rotated.current_announcement()["signingKeyId"], SUCCESSOR_KEY.key_id)
            store.close()

    def test_rotation_to_a_valid_successor_resumes_signing(self):
        service, clock = clocked_service(SHORT_KEY)
        service.register(101)
        clock["now"] = SHORT_EXPIRES + 60
        with self.assertRaises(AdapterError):
            service.revoke(101)
        record = service.rotate_signing_key(SUCCESSOR_KEY)
        self.assertEqual(record["fromEpoch"], 2)
        service.revoke(101)
        self.assertEqual(service.epoch, 2)

        chain = AnnouncementChain(
            trusted_keys={
                SHORT_KEY.key_id: entry_pin(SHORT_KEY, retire_after_epoch=1),
                SUCCESSOR_KEY.key_id: entry_pin(SUCCESSOR_KEY),
            }
        )
        chain.backfill(service.announcement_history())
        self.assertEqual(chain.last_epoch, 2)

    def test_rotation_refuses_a_successor_outside_its_window(self):
        expired_successor = IssuerSigningKey.from_seed(
            b"zkc-key-window-expired-successor",
            key_id="expired-successor",
            not_before="2026-01-01T00:00:00Z",
            not_after="2026-02-01T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteAccumulatorStateStore(f"{directory}/issuer.sqlite3", ACCUMULATOR_ID)
            service = DurableRevocationAccumulatorService.open(
                ACCUMULATOR_ID, ENDPOINT, SHORT_KEY, store, clock=lambda: T0
            )
            before = (store.load_log(), service.signing_key_history())
            with self.assertRaises(AdapterError) as ctx:
                service.rotate_signing_key(expired_successor)
            self.assertEqual(ctx.exception.code, "EXPIRED_ISSUER_KEY")
            self.assertEqual((store.load_log(), service.signing_key_history()), before)
            service.register(101)
            self.assertEqual(service.current_announcement()["signingKeyId"], SHORT_KEY.key_id)
            store.close()
            store = SQLiteAccumulatorStateStore(f"{directory}/issuer.sqlite3", ACCUMULATOR_ID)
            with self.assertRaises(AccumulatorStoreError):
                DurableRevocationAccumulatorService.open(
                    ACCUMULATOR_ID, ENDPOINT, expired_successor, store,
                    clock=lambda: T0, allow_rotation=True,
                )
            store.close()


def bound_subject(adapter, fixture_id):
    subject = adapter.verify_subject({"schemaId": SCHEMA, "fixtureId": fixture_id})
    commitment = derive_holder_commitment_from_seed(7)
    payload = {
        "subjectRef": subject["subjectRef"],
        "schemaId": SCHEMA,
        "holderCommitment": field_to_hex(commitment),
    }
    challenge = adapter.request_binding_challenge(payload)
    response = compute_binding_response(
        commitment, adapter.issuer_id, SCHEMA,
        hex_to_field(challenge["nonce"]), challenge["expiresAt"],
    )
    adapter.bind_holder_commitment(
        {**payload, "nonce": challenge["nonce"], "challengeResponse": field_to_hex(response)}
    )
    return {"subjectRef": subject["subjectRef"], "schemaId": SCHEMA}


class AdapterSigningWindowTests(unittest.TestCase):
    """The adapter refuses before its ledger write-ahead, not after it."""

    def test_issue_revoke_renew_with_an_expired_announcement_key_change_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = {"now": T0}
            store = SQLiteAccumulatorStateStore(f"{directory}/issuer.sqlite3", ACCUMULATOR_ID)
            service = DurableRevocationAccumulatorService.open(
                ACCUMULATOR_ID, ENDPOINT, SHORT_KEY, store, clock=lambda: clock["now"]
            )
            ledger = InMemoryIssuanceLedgerStore()
            # The credential key (2026 calendar year) stays valid throughout;
            # only the announcement key expires.
            adapter = SandboxIssuerAdapter(
                signing_key=OLD_KEY, accumulator=service, clock=lambda: clock["now"],
                issuance_ledger=ledger,
            )
            issued = adapter.issue_credential(bound_subject(adapter, "sandbox-alice-basic"))
            credential_id = hex_to_field(issued["credential"]["credentialId"])

            clock["now"] = SHORT_EXPIRES - 60
            pending = bound_subject(adapter, "sandbox-bob-enhanced")
            clock["now"] = SHORT_EXPIRES
            before = (
                json.dumps(ledger.load_state(), sort_keys=True),
                store.load_log(),
                store._conn.total_changes,
                service_state(service),
            )
            for name, call in (
                ("issue", lambda: adapter.issue_credential(pending)),
                ("revoke", lambda: adapter.revoke_credential(credential_id)),
                ("renew", lambda: adapter.renew_credential(
                    {"credentialId": field_to_hex(credential_id)}
                )),
            ):
                with self.subTest(name):
                    with self.assertRaises(AdapterError) as ctx:
                        call()
                    self.assertEqual(ctx.exception.code, "EXPIRED_ISSUER_KEY")
                    after = (
                        json.dumps(ledger.load_state(), sort_keys=True),
                        store.load_log(),
                        store._conn.total_changes,
                        service_state(service),
                    )
                    self.assertEqual(after, before)
            store.close()


def http_get(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, json.loads(exc.read())


class MetadataEndpointFaultTests(unittest.TestCase):
    """PoC part 3: issuer-state faults on the metadata GET are 5xx."""

    def test_unpublishable_announcement_key_is_a_server_fault(self):
        service, _ = clocked_service()
        # The adapter publishes a window that excludes the signed announcedAt.
        published = dataclasses.replace(OLD_KEY, not_before="2026-03-01T00:00:00Z")
        adapter = SandboxIssuerAdapter(
            signing_key=published, accumulator=service, clock=lambda: T0
        )
        with IssuerServer(adapter, threaded=False) as server, self.assertLogs(
            "zkc.transport", "WARNING"
        ):
            status, body = http_get(server.base_url + "/.well-known/zkc-issuer.json")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": {"message": "issuer metadata is unavailable"}})

    def test_unpublished_rotated_key_is_a_server_fault(self):
        service, _ = clocked_service()
        adapter = SandboxIssuerAdapter(signing_key=OLD_KEY, accumulator=service, clock=lambda: T0)
        service.rotate_signing_key(NEW_KEY)
        service.register(101)
        with IssuerServer(adapter, threaded=False) as server, self.assertLogs(
            "zkc.transport", "WARNING"
        ):
            status, _body = http_get(server.base_url + "/.well-known/zkc-issuer.json")
        self.assertEqual(status, 503)

    def test_adapter_error_keeps_its_code_with_a_5xx_status(self):
        service, _ = clocked_service()
        adapter = SandboxIssuerAdapter(signing_key=OLD_KEY, accumulator=service, clock=lambda: T0)

        def unavailable():
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "store is not durable yet")

        adapter.issuer_metadata = unavailable
        with IssuerServer(adapter, threaded=False) as server:
            status, body = http_get(server.base_url + "/.well-known/zkc-issuer.json")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "REVOCATION_METADATA_UNAVAILABLE")
        self.assertNotIn("durable", body["error"]["message"])

    def test_healthy_metadata_and_client_errors_keep_their_status(self):
        service, _ = clocked_service()
        adapter = SandboxIssuerAdapter(signing_key=OLD_KEY, accumulator=service, clock=lambda: T0)
        with IssuerServer(adapter, threaded=False) as server:
            status, body = http_get(server.base_url + "/.well-known/zkc-issuer.json")
            request = urllib.request.Request(
                server.base_url + "/v1/issuer/verify-subject", data=b"{", method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                urllib.request.urlopen(request, timeout=30)
                client_status = 200
            except urllib.error.HTTPError as exc:
                with exc:
                    client_status = exc.code
        self.assertEqual(status, 200)
        self.assertEqual(body["revocation"]["currentAnnouncement"]["signingKeyId"], OLD_KEY.key_id)
        self.assertEqual(client_status, 400)


if __name__ == "__main__":
    unittest.main()
