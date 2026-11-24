"""Quiet-issuer liveness and time-bounded revocation latency (review R7.7).

Regression for the security review 2026-10-04 finding R7.7 (PoC
``lane6/poc3_backfill_quiet.py``, part B). Before the fix:

- v3 advances the epoch only on a mutation, so an honest issuer quiet for
  more than ``max_announcement_age`` (3600 s) could not publish fresh data:
  ``state()`` raised ``ANNOUNCEMENT_STALE`` and the holder refused to refresh
  an active credential;
- re-polling unchanged metadata raised ``ANNOUNCEMENT_REPLAY``;
- ``accumulator_states()`` failed for every issuer when one was stale;
- lag counted only in epochs, so a revoked credential stayed provable for
  ``maxEpochLag`` further mutations with no time bound.

The fix adds the signed ``zkc:epoch-liveness:v1`` statement and a time bound
on every served root (specification 2.4.2).
"""

import copy
import importlib.util
import inspect
import unittest
from unittest import mock

import _path  # noqa: F401
from _path import REPO_ROOT

from zkc_crypto import SparseMerkleAccumulator, field_to_hex
from zkc_crypto.ecdsa_secp256k1 import N
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import (
    AdapterError,
    IssuerSigningKey,
    SandboxIssuerAdapter,
    build_issuer_metadata,
    get_schema,
)
from zkc_revocation import (
    DEFAULT_LIVENESS_INTERVAL,
    LIVENESS_VERSION,
    AnnouncementAuthenticationError,
    AnnouncementChain,
    AnnouncementFreshnessError,
    AnnouncementKeyPin,
    AnnouncementKeyWindowError,
    ChainLinkageError,
    DurableRevocationAccumulatorService,
    InMemoryAccumulatorStateStore,
    InMemoryVerifierCheckpointStore,
    LivenessHeadMismatchError,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    VerifierAccumulatorCache,
    VerifierCheckpointStoreError,
    WitnessUpdateProvider,
    announcement_hash,
    compute_announcement_digest,
    compute_liveness_digest,
    liveness_names_head,
    liveness_transcript,
    verify_epoch_liveness,
    verify_liveness_statement,
)
from zkc_transport import HTTPWitnessUpdateProvider, RevocationServer, RevocationServiceClient

T0 = 1_770_000_000
ISSUER_ID = "zkc:issuer:sandbox"
ACCUMULATOR_ID = "sandbox-active-credentials"
BUSY_ISSUER_ID = "zkc:issuer:busy"
BUSY_ACCUMULATOR_ID = "busy-active-credentials"
ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
KEY = IssuerSigningKey.test_issuer()
PIN = AnnouncementKeyPin.from_signing_key_entry(KEY.metadata_entry())
BUSY_KEY = IssuerSigningKey.from_seed(b"zkc-liveness-busy-issuer", key_id="busy-2026")
BUSY_PIN = AnnouncementKeyPin.from_signing_key_entry(BUSY_KEY.metadata_entry())
OTHER_KEY = IssuerSigningKey.from_seed(b"zkc-liveness-other-key", key_id="other-2026")
OTHER_PIN = AnnouncementKeyPin.from_signing_key_entry(OTHER_KEY.metadata_entry())
SHORT_KEY = IssuerSigningKey.from_seed(
    b"zkc-liveness-short-key",
    key_id="short-2026",
    not_before="2026-01-01T00:00:00Z",
    not_after="2026-02-02T03:40:00Z",  # T0 + 3600
)
SHORT_PIN = AnnouncementKeyPin.from_signing_key_entry(SHORT_KEY.metadata_entry())
# Reference defaults of VerifierAccumulatorCache and the holder providers.
MAX_AGE = 3600
MAX_SKEW = 300
WORST_CASE_REVOCATION_LATENCY = MAX_AGE + MAX_SKEW


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


def _service(clock, key=KEY, accumulator_id=ACCUMULATOR_ID, **kwargs):
    return RevocationAccumulatorService(accumulator_id, ENDPOINT, key, clock=clock, **kwargs)


def _metadata(service, issuer_id=ISSUER_ID):
    """Authenticated metadata v2 exactly as the service publishes it."""
    return {
        "version": "zkc:issuer-metadata:v2",
        "issuerId": issuer_id,
        "revocation": service.metadata(),
    }


def _without_liveness(metadata):
    stripped = copy.deepcopy(metadata)
    stripped["revocation"].pop("currentLiveness")
    return stripped


def _with_liveness(metadata, liveness):
    replaced = copy.deepcopy(metadata)
    replaced["revocation"]["currentLiveness"] = liveness
    return replaced


def _signed_liveness(statement, key=KEY):
    statement = {name: value for name, value in statement.items() if name != "signature"}
    statement["signature"] = "0x" + key.sign_digest(compute_liveness_digest(statement)).hex()
    return statement


def _signed_announcement(announcement, key=KEY):
    announcement = {name: value for name, value in announcement.items() if name != "signature"}
    announcement["signature"] = "0x" + key.sign_digest(
        compute_announcement_digest(announcement)
    ).hex()
    return announcement


def _cache(clock, store=None, keys=None, **policy):
    return VerifierAccumulatorCache(
        {ISSUER_ID: keys or {KEY.key_id: PIN}},
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        checkpoint_store=store or InMemoryVerifierCheckpointStore(),
        clock=clock,
        **policy,
    )


def _root(*leaves):
    return SparseMerkleAccumulator(list(leaves)).root()


def _private_provider(services, keys, *, sources, **policy):
    """PrivateWitnessProvider with or without independent publication sources.

    PR 91 (merged to main after this branch's base) adds the mandatory
    ``announcement_sources`` argument; the tests run on either API.
    """
    if "announcement_sources" in inspect.signature(PrivateWitnessProvider.__init__).parameters:
        policy["announcement_sources"] = sources
    policy.setdefault("accumulator_ids", {ISSUER_ID: ACCUMULATOR_ID})
    return PrivateWitnessProvider(services, keys, **policy)


class _Relay:
    """A service front that rewrites update responses; it has no liveness API."""

    def __init__(self, service, rewrite):
        self.accumulator_id = service.accumulator_id
        self._service = service
        self._rewrite = rewrite

    def handle_request(self, request):
        return self._rewrite(copy.deepcopy(self._service.handle_request(request)))

    def current_announcement(self):
        return self._service.current_announcement()

    def announcement_for_epoch(self, epoch):
        return self._service.announcement_for_epoch(epoch)


class LivenessStatementTests(unittest.TestCase):
    """The issuer signs liveness without touching the chain."""

    def test_liveness_names_the_head_and_never_changes_chain_state(self):
        clock = Clock()
        store = InMemoryAccumulatorStateStore()
        service = DurableRevocationAccumulatorService.open(
            ACCUMULATOR_ID, ENDPOINT, KEY, store, clock=clock
        )
        service.register(7)
        head = service.current_announcement()
        before = (
            service.epoch,
            service.announcement_history(),
            dict(service._snapshots),
            store.load_log(),
        )
        statements = []
        for step in range(5):
            clock.now = T0 + step * DEFAULT_LIVENESS_INTERVAL
            statements.append(service.current_liveness())
        statements.append(service.sign_liveness())
        for statement in statements:
            self.assertEqual(statement["version"], LIVENESS_VERSION)
            self.assertEqual(statement["accumulatorId"], ACCUMULATOR_ID)
            self.assertEqual(statement["epoch"], head["epoch"])
            self.assertEqual(statement["headHash"], announcement_hash(head))
            self.assertTrue(verify_epoch_liveness(statement, *KEY.public_key_coordinates()))
        self.assertEqual(
            [statement["issuedAt"] for statement in statements[:5]],
            [T0 + step * DEFAULT_LIVENESS_INTERVAL for step in range(5)],
        )
        after = (
            service.epoch,
            service.announcement_history(),
            dict(service._snapshots),
            store.load_log(),
        )
        self.assertEqual(after, before)
        self.assertEqual(service.metadata()["currentAnnouncement"], head)
        # A liveness statement is not an announcement and cannot enter a chain.
        chain = AnnouncementChain(trusted_keys={KEY.key_id: PIN}, checkpoint=head)
        with self.assertRaises(AnnouncementAuthenticationError):
            chain.ingest(statements[-1])
        self.assertEqual(chain.last_announcement, head)
        # Nor can an announcement signature pass as a liveness signature.
        self.assertFalse(verify_epoch_liveness(head, *KEY.public_key_coordinates()))

    def test_liveness_uses_canonical_encodings_and_the_transcript_bound(self):
        clock = Clock()
        service = _service(clock)
        service.register(7)
        head = service.current_announcement()
        statement = service.current_liveness()
        x, y = KEY.public_key_coordinates()
        head_hash = statement["headHash"]
        aliases = {
            "upper-case headHash": {"headHash": "0x" + head_hash[2:].upper()},
            "headHash with whitespace": {"headHash": "0x " + head_hash[3:]},
            "headHash without 0x": {"headHash": "00" + head_hash[2:]},
            "short headHash": {"headHash": head_hash[:-2]},
            "upper-case signature": {"signature": "0x" + statement["signature"][2:].upper()},
            "boolean epoch": {"epoch": True},
            "float issuedAt": {"issuedAt": float(statement["issuedAt"])},
        }
        for name, change in aliases.items():
            with self.subTest(name):
                self.assertFalse(verify_epoch_liveness({**statement, **change}, x, y))
                with self.assertRaises(AnnouncementAuthenticationError):
                    verify_liveness_statement({**statement, **change}, {KEY.key_id: PIN})
        # Binding is JSON-type-strict as well.
        self.assertTrue(liveness_names_head(statement, head))
        self.assertFalse(liveness_names_head({**statement, "epoch": True}, head))
        self.assertFalse(liveness_names_head(statement, {**head, "epoch": 1.0}))
        # 95 fixed transcript bytes: identifiers may hold 65440 bytes together.
        within = {**statement, "accumulatorId": "a" * 65_000, "signingKeyId": "k" * 440}
        self.assertEqual(len(liveness_transcript(within)), 0xFFFF)
        with self.assertRaisesRegex(ValueError, "65535"):
            liveness_transcript({**within, "signingKeyId": "k" * 441})
        self.assertFalse(
            verify_epoch_liveness({**within, "signingKeyId": "k" * 441}, x, y)
        )

    def test_current_liveness_resigns_on_its_cadence_and_after_a_new_head(self):
        clock = Clock()
        service = _service(clock, liveness_interval=600)
        first = service.current_liveness()
        clock.now = T0 + 599
        self.assertEqual(service.current_liveness(), first)
        clock.now = T0 + 600
        second = service.current_liveness()
        self.assertEqual(second["issuedAt"], T0 + 600)
        clock.now = T0 + 601
        service.register(7)
        third = service.current_liveness()
        self.assertEqual((third["epoch"], third["issuedAt"]), (1, T0 + 601))
        self.assertEqual(third["headHash"], announcement_hash(service.current_announcement()))
        for bad in (0, -1, "900", 1.5, True, None):
            with self.subTest(interval=bad), self.assertRaises(ValueError):
                _service(clock, liveness_interval=bad)

    def test_publication_carries_liveness_additively(self):
        clock = Clock()
        service = _service(clock)
        service.register(7)
        metadata = SandboxIssuerAdapter(
            signing_key=KEY, accumulator=service, clock=clock
        ).issuer_metadata()
        revocation = metadata["revocation"]
        self.assertEqual(metadata["version"], "zkc:issuer-metadata:v2")
        self.assertEqual(revocation["currentLiveness"], service.current_liveness())
        request = {"type": "zkc:epoch-delta-request:v1", "accumulatorId": ACCUMULATOR_ID}
        self.assertEqual(service.handle_request(request)["liveness"], service.current_liveness())
        witness = service.handle_request(
            {
                "type": "zkc:witness-update-request:v1",
                "accumulatorId": ACCUMULATOR_ID,
                "credentialId": field_to_hex(7),
            }
        )
        self.assertEqual(witness["liveness"], service.current_liveness())

    def test_an_expired_key_signs_no_liveness_and_publication_omits_it(self):
        clock = Clock()
        service = _service(clock, key=SHORT_KEY)
        service.register(7)
        clock.now = T0 + 3600  # SHORT_KEY notAfter
        with self.assertRaises(AdapterError) as ctx:
            service.current_liveness()
        self.assertEqual(ctx.exception.code, "EXPIRED_ISSUER_KEY")
        self.assertNotIn("currentLiveness", service.metadata())
        request = {"type": "zkc:epoch-delta-request:v1", "accumulatorId": ACCUMULATOR_ID}
        self.assertNotIn("liveness", service.handle_request(request))
        # Rotation to a valid successor restores liveness for the same head;
        # the successor signs before it signs any announcement.
        service.rotate_signing_key(OTHER_KEY)
        liveness = service.current_liveness()
        self.assertEqual(liveness["signingKeyId"], OTHER_KEY.key_id)
        self.assertEqual(liveness["headHash"], announcement_hash(service.current_announcement()))


def _load_metadata_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_issuer_metadata",
        REPO_ROOT / "tests" / "issuer_adapter" / "validate_issuer_metadata.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Publication:
    """An accumulator whose metadata carries a chosen liveness statement."""

    def __init__(self, service, liveness):
        self._service = service
        self._liveness = liveness

    def metadata(self):
        block = self._service.metadata()
        block["currentLiveness"] = self._liveness
        return block


class MetadataPublicationTests(unittest.TestCase):
    """Issuer metadata v2 carries liveness additively and checks it."""

    def setUp(self):
        self.clock = Clock(T0 + 600)
        self.service = _service(self.clock)
        self.service.register(7)
        self.validator = _load_metadata_validator()

    def build(self, accumulator):
        return build_issuer_metadata(
            ISSUER_ID, "Sandbox", [KEY], [get_schema("zkc:cred:kyc:v1")], accumulator,
            "https://issuer.sandbox.zkc.dev",
        )

    def test_published_liveness_passes_the_independent_validator(self):
        metadata = self.build(self.service)
        self.assertIn("currentLiveness", metadata["revocation"])
        self.validator.validate_metadata(metadata, require_authenticated=True)
        # An old consumer that ignores the additive field still validates
        # the document without it.
        self.validator.validate_metadata(_without_liveness(metadata), require_authenticated=True)

    def test_builder_and_validator_refuse_a_liveness_they_cannot_authenticate(self):
        liveness = self.service.current_liveness()
        genesis = self.service.announcement_for_epoch(0)
        cases = {
            "other head": _signed_liveness(
                {**liveness, "epoch": 0, "headHash": announcement_hash(genesis)}
            ),
            "unpublished key": _signed_liveness(
                {**liveness, "signingKeyId": OTHER_KEY.key_id}, OTHER_KEY
            ),
            "bad signature": {**liveness, "issuedAt": liveness["issuedAt"] + 1},
        }
        for name, statement in cases.items():
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    self.build(_Publication(self.service, statement))
                tampered = _with_liveness(self.build(self.service), statement)
                with self.assertRaises((AssertionError, KeyError)):
                    self.validator.validate_metadata(tampered)
        legacy = {
            **_without_liveness(self.build(self.service)),
            "version": "zkc:issuer-metadata:v1",
        }
        legacy["revocation"].pop("currentAnnouncement")
        self.validator.validate_metadata(legacy)
        legacy["revocation"]["currentLiveness"] = liveness
        with self.assertRaises(AssertionError):
            self.validator.validate_metadata(legacy)


class QuietIssuerVerifierTests(unittest.TestCase):
    """PoC part B against VerifierAccumulatorCache."""

    def setUp(self):
        self.clock = Clock()
        self.service = _service(self.clock)
        self.adapter = SandboxIssuerAdapter(
            signing_key=KEY, accumulator=self.service, clock=self.clock
        )
        self.service.register(7)
        self.store = InMemoryVerifierCheckpointStore()
        self.cache = _cache(self.clock, self.store)
        self.cache.ingest_metadata(ISSUER_ID, self.adapter.issuer_metadata())
        self.checkpoint = self.store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)

    def assert_chain_unchanged(self):
        self.assertEqual(self.store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID), self.checkpoint)
        self.assertEqual(self.store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])
        self.assertEqual(self.service.epoch, 1)

    def test_poc_quiet_issuer_stays_verifiable_through_liveness(self):
        self.clock.now = T0 + 3601  # one quiet hour; the issuer is honest and online
        with self.assertRaises(AnnouncementFreshnessError):
            self.cache.state(ISSUER_ID)
        # Metadata without liveness is exactly the pre-fix situation.
        with self.assertRaises(AnnouncementFreshnessError):
            self.cache.ingest_metadata(ISSUER_ID, _without_liveness(self.adapter.issuer_metadata()))
        with mock.patch.object(
            self.store, "compare_and_swap_checkpoint", wraps=self.store.compare_and_swap_checkpoint
        ) as writes:
            # Re-polling the unchanged head with a fresh liveness statement.
            for poll in range(12):
                self.clock.now = T0 + 3601 + poll * 2000
                self.cache.ingest_metadata(ISSUER_ID, self.adapter.issuer_metadata())
                state = self.cache.state(ISSUER_ID)
                self.assertEqual(state.current_epoch, 1)
                self.assertEqual(state.roots, {1: _root(7)})
        writes.assert_not_called()
        self.assert_chain_unchanged()
        self.assertEqual(self.cache.accumulator_states()[ISSUER_ID].current_epoch, 1)

    def test_repolling_identical_metadata_is_a_silent_noop(self):
        metadata = self.adapter.issuer_metadata()
        with mock.patch.object(
            self.store, "compare_and_swap_checkpoint", wraps=self.store.compare_and_swap_checkpoint
        ) as writes:
            for _ in range(3):
                self.cache.ingest_metadata(ISSUER_ID, copy.deepcopy(metadata))
                self.cache.ingest_metadata(ISSUER_ID, _without_liveness(metadata))
        writes.assert_not_called()
        self.assert_chain_unchanged()
        # A restarted worker sharing the store treats it the same way.
        restarted = _cache(self.clock, self.store)
        restarted.ingest_metadata(ISSUER_ID, copy.deepcopy(metadata))
        self.assertEqual(restarted.state(ISSUER_ID).current_epoch, 1)
        self.assert_chain_unchanged()

    def test_catch_up_reaches_a_quiet_head_through_liveness(self):
        bounded = _cache(self.clock, max_backfill=2)
        bounded.ingest_metadata(ISSUER_ID, self.adapter.issuer_metadata())
        for credential_id in range(100, 105):
            self.service.register(credential_id)
        self.clock.now = T0 + 3601
        metadata = self.adapter.issuer_metadata()
        with self.assertRaises(AnnouncementFreshnessError):
            bounded.catch_up(ISSUER_ID, _without_liveness(metadata), self.service.announcement_history)
        statuses = []
        while not statuses or not statuses[-1].complete:
            statuses.append(
                bounded.catch_up(ISSUER_ID, metadata, self.service.announcement_history)
            )
        self.assertEqual([status.checkpoint_epoch for status in statuses], [3, 5, 6])
        self.assertEqual(bounded.state(ISSUER_ID).current_epoch, 6)

    def test_liveness_that_does_not_verify_or_name_the_head_is_rejected(self):
        # The head is still fresh on its own here, so a statement that names
        # another head reaches the binding check after the chain accepted
        # the head (a stale head fails first with ANNOUNCEMENT_STALE).
        self.clock.now = T0 + 3000
        live = self.adapter.issuer_metadata()
        statement = live["revocation"]["currentLiveness"]
        genesis = self.service.announcement_for_epoch(0)
        signature = bytes.fromhex(statement["signature"][2:])
        high_s = signature[:32] + (N - int.from_bytes(signature[32:], "big")).to_bytes(32, "big")
        flipped = bytearray(signature)
        flipped[-1] ^= 1
        cases = {
            "headHash of the previous head": (
                _signed_liveness({**statement, "epoch": 0, "headHash": announcement_hash(genesis)}),
                LivenessHeadMismatchError,
            ),
            "conflicting headHash at the head epoch": (
                _signed_liveness({**statement, "headHash": "0x" + "ab" * 32}),
                LivenessHeadMismatchError,
            ),
            "accumulatorId": (
                _signed_liveness({**statement, "accumulatorId": "attacker-accumulator"}),
                LivenessHeadMismatchError,
            ),
            "epoch": (_signed_liveness({**statement, "epoch": 2}), LivenessHeadMismatchError),
            "unpinned key": (
                _signed_liveness({**statement, "signingKeyId": OTHER_KEY.key_id}, OTHER_KEY),
                AnnouncementAuthenticationError,
            ),
            "key id of the pinned key, other signer": (
                _signed_liveness(statement, OTHER_KEY),
                AnnouncementAuthenticationError,
            ),
            "tampered signature": (
                {**statement, "signature": "0x" + flipped.hex()},
                AnnouncementAuthenticationError,
            ),
            "high-s twin": (
                {**statement, "signature": "0x" + high_s.hex()},
                AnnouncementAuthenticationError,
            ),
            "tampered issuedAt": (
                {**statement, "issuedAt": statement["issuedAt"] + 1},
                AnnouncementAuthenticationError,
            ),
            "extra field": ({**statement, "note": "x"}, AnnouncementAuthenticationError),
            "wrong version": (
                {**statement, "version": "zkc:epoch-liveness:v2"},
                AnnouncementAuthenticationError,
            ),
            "not an object": ("liveness", AnnouncementAuthenticationError),
            "future issuedAt": (
                _signed_liveness({**statement, "issuedAt": self.clock.now + MAX_SKEW + 1}),
                AnnouncementFreshnessError,
            ),
        }
        for name, (liveness, error) in cases.items():
            with self.subTest(name):
                with self.assertRaises(error) as ctx:
                    self.cache.ingest_metadata(ISSUER_ID, _with_liveness(live, liveness))
                self.assertEqual(ctx.exception.code, error.code)
                self.assert_chain_unchanged()
        # No rejected statement was kept: past the head's own age limit the
        # cache still has only the T0 statement.
        self.clock.now = T0 + 3601
        with self.assertRaises(AnnouncementFreshnessError):
            self.cache.state(ISSUER_ID)
        self.clock.now = T0 + 3000
        self.cache.ingest_metadata(ISSUER_ID, live)
        self.clock.now = T0 + 3601
        self.assertEqual(self.cache.state(ISSUER_ID).current_epoch, 1)

    def test_liveness_outside_its_key_window_or_retirement_is_rejected(self):
        self.clock.now = T0 + 3601
        live = self.adapter.issuer_metadata()
        statement = live["revocation"]["currentLiveness"]
        narrow = AnnouncementKeyPin(PIN.x, PIN.y, PIN.not_before, statement["issuedAt"])
        retired_successor = AnnouncementKeyPin(
            OTHER_PIN.x, OTHER_PIN.y, OTHER_PIN.not_before, OTHER_PIN.not_after,
            retire_after_epoch=0,
        )
        cases = {
            "issuedAt at notAfter": ({KEY.key_id: narrow}, statement),
            "epoch after retireAfterEpoch": (
                {KEY.key_id: PIN, OTHER_KEY.key_id: retired_successor},
                _signed_liveness({**statement, "signingKeyId": OTHER_KEY.key_id}, OTHER_KEY),
            ),
        }
        for name, (keys, liveness) in cases.items():
            with self.subTest(name):
                store = InMemoryVerifierCheckpointStore()
                cache = _cache(self.clock, store, keys=keys)
                self.clock.now = T0
                cache.ingest_metadata(ISSUER_ID, _without_liveness(live))
                persisted = store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)
                self.clock.now = T0 + 3601
                with self.assertRaises(AnnouncementKeyWindowError) as ctx:
                    cache.ingest_metadata(ISSUER_ID, _with_liveness(live, liveness))
                self.assertEqual(ctx.exception.code, "ANNOUNCEMENT_KEY_OUTSIDE_VALIDITY")
                self.assertEqual(store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID), persisted)
                with self.assertRaises(AnnouncementFreshnessError):
                    cache.state(ISSUER_ID)

    def test_rotated_successor_signs_liveness_only_for_consumers_that_pinned_it(self):
        self.service.rotate_signing_key(OTHER_KEY)
        self.clock.now = T0 + 3601
        metadata = _metadata(self.service)
        self.assertEqual(
            metadata["revocation"]["currentLiveness"]["signingKeyId"], OTHER_KEY.key_id
        )
        with self.assertRaises(AnnouncementAuthenticationError):
            self.cache.ingest_metadata(ISSUER_ID, metadata)
        self.assert_chain_unchanged()
        pinned = _cache(self.clock, self.store, keys={KEY.key_id: PIN, OTHER_KEY.key_id: OTHER_PIN})
        pinned.ingest_metadata(ISSUER_ID, metadata)
        self.assertEqual(pinned.state(ISSUER_ID).current_epoch, 1)
        self.assert_chain_unchanged()

    def test_a_forked_head_is_classified_before_a_liveness_mismatch(self):
        honest = self.adapter.issuer_metadata()
        self.service.register(8)
        self.cache.ingest_metadata(ISSUER_ID, self.adapter.issuer_metadata())
        checkpoint = self.store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)
        head = self.service.current_announcement()
        fork = _signed_announcement({**head, "root": field_to_hex(_root(7, 9))})
        forked = copy.deepcopy(self.adapter.issuer_metadata())
        forked["revocation"].update(currentAnnouncement=fork, currentRoot=fork["root"])
        with self.assertRaises(ChainLinkageError) as ctx:
            self.cache.ingest_metadata(ISSUER_ID, forked)
        self.assertEqual(ctx.exception.code, "CHAIN_FORKED")
        evidence = self.store.evidence(ISSUER_ID, ACCUMULATOR_ID)
        self.assertEqual([record["candidate"] for record in evidence], [fork])
        # A liveness statement for the other head is never evidence itself.
        stale_liveness = honest["revocation"]["currentLiveness"]
        with self.assertRaises(LivenessHeadMismatchError):
            self.cache.ingest_metadata(
                ISSUER_ID, _with_liveness(self.adapter.issuer_metadata(), stale_liveness)
            )
        self.assertEqual(len(self.store.evidence(ISSUER_ID, ACCUMULATOR_ID)), 1)
        self.assertEqual(self.store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID), checkpoint)


class _FailingStore(InMemoryVerifierCheckpointStore):
    def __init__(self, failing_issuer):
        super().__init__()
        self.failing_issuer = failing_issuer
        self.fail = False

    def load_checkpoint(self, issuer_id, accumulator_id):
        if self.fail and issuer_id == self.failing_issuer:
            raise VerifierCheckpointStoreError("injected read failure")
        return super().load_checkpoint(issuer_id, accumulator_id)


class PerIssuerStatesTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.quiet = _service(self.clock)
        self.quiet.register(7)
        self.busy = _service(self.clock, key=BUSY_KEY, accumulator_id=BUSY_ACCUMULATOR_ID)
        self.store = _FailingStore(BUSY_ISSUER_ID)
        self.cache = VerifierAccumulatorCache(
            {ISSUER_ID: {KEY.key_id: PIN}, BUSY_ISSUER_ID: {BUSY_KEY.key_id: BUSY_PIN}},
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID, BUSY_ISSUER_ID: BUSY_ACCUMULATOR_ID},
            checkpoint_store=self.store,
            clock=self.clock,
        )
        self.cache.ingest_metadata(ISSUER_ID, _metadata(self.quiet))
        self.cache.ingest_metadata(BUSY_ISSUER_ID, _metadata(self.busy, BUSY_ISSUER_ID))

    def test_poc_one_stale_issuer_does_not_block_another(self):
        self.clock.now = T0 + 3601
        self.busy.register(99)
        self.cache.ingest_metadata(BUSY_ISSUER_ID, _metadata(self.busy, BUSY_ISSUER_ID))
        results = self.cache.accumulator_state_results()
        self.assertIsInstance(results[ISSUER_ID], AnnouncementFreshnessError)
        self.assertEqual(results[BUSY_ISSUER_ID].current_epoch, 1)
        states = self.cache.accumulator_states()
        self.assertEqual(list(states), [BUSY_ISSUER_ID])
        self.assertTrue(states[BUSY_ISSUER_ID].authenticated)
        # The quiet issuer comes back with its next liveness statement.
        self.cache.ingest_metadata(ISSUER_ID, _metadata(self.quiet))
        self.assertEqual(sorted(self.cache.accumulator_states()), [BUSY_ISSUER_ID, ISSUER_ID])

    def test_an_unreadable_checkpoint_is_reported_for_its_issuer_only(self):
        self.store.fail = True
        results = self.cache.accumulator_state_results()
        self.assertIsInstance(results[BUSY_ISSUER_ID], VerifierCheckpointStoreError)
        self.assertEqual(list(self.cache.accumulator_states()), [ISSUER_ID])


class RevocationLatencyTests(unittest.TestCase):
    """A revoked credential stops verifying within MAX_AGE + MAX_SKEW seconds."""

    def setUp(self):
        self.verifier_clock = Clock()
        self.issuer_clock = Clock()
        self.service = _service(self.issuer_clock)
        self.cache = _cache(self.verifier_clock)
        self.cache.ingest_metadata(ISSUER_ID, _metadata(self.service))
        for credential_id in (7, 8):
            self.service.register(credential_id)
            self.cache.ingest_metadata(ISSUER_ID, _metadata(self.service))

    def poll(self, at):
        self.verifier_clock.now = at
        self.issuer_clock.now = at + self.issuer_ahead
        self.cache.ingest_metadata(ISSUER_ID, _metadata(self.service))

    def revoke_at(self, at):
        self.verifier_clock.now = at
        self.issuer_clock.now = at + self.issuer_ahead
        self.service.revoke(7)
        self.cache.ingest_metadata(ISSUER_ID, _metadata(self.service))

    def roots_containing_seven(self):
        state = self.cache.state(ISSUER_ID)
        self.assertEqual(state.current_epoch, 3)
        self.assertIn(3, state.roots)
        return {epoch for epoch, root in state.roots.items() if root in (_root(7), _root(7, 8))}

    def test_poc_superseded_roots_expire_in_time_with_one_later_epoch(self):
        self.issuer_ahead = 0
        t_revoked = T0 + 60
        self.revoke_at(t_revoked)
        # Epoch 1 was superseded at T0 (epoch 2), epoch 2 at t_revoked.
        superseded = {1: T0, 2: t_revoked}
        offsets = [0, 1800, MAX_AGE, MAX_AGE + 1, *range(5400, 3 * 86_400, 1800)]
        for offset in offsets:
            # The issuer stays quiet but online; liveness keeps its head fresh.
            self.poll(t_revoked + offset)
            with self.subTest(seconds_after_revocation=offset):
                self.assertEqual(
                    self.roots_containing_seven(),
                    {
                        epoch
                        for epoch, at in superseded.items()
                        if t_revoked + offset - at <= MAX_AGE
                    },
                )
        # Only one epoch followed the revocation, and maxEpochLag is 10: the
        # epoch-lag rule alone would keep epochs 1 and 2 servable forever.
        self.assertEqual((self.service.epoch, self.service.max_epoch_lag), (3, 10))

    def test_worst_case_latency_is_max_age_plus_clock_skew(self):
        # The honest issuer's clock runs MAX_SKEW ahead of the verifier's.
        self.issuer_ahead = MAX_SKEW
        t_revoked = T0 + 60
        self.revoke_at(t_revoked)
        self.poll(t_revoked + WORST_CASE_REVOCATION_LATENCY)
        self.assertEqual(self.roots_containing_seven(), {2})
        self.poll(t_revoked + WORST_CASE_REVOCATION_LATENCY + 1)
        self.assertEqual(self.roots_containing_seven(), set())
        self.assertEqual(WORST_CASE_REVOCATION_LATENCY, 3900)

    def test_withheld_revocation_cannot_keep_the_revoked_view_fresh(self):
        self.issuer_ahead = 0
        t_revoked = T0 + 600
        self.verifier_clock.now = self.issuer_clock.now = t_revoked - 1
        self.service.sign_liveness()
        captured = _metadata(self.service)  # the last view a relay keeps serving
        self.assertEqual(captured["revocation"]["currentLiveness"]["issuedAt"], t_revoked - 1)
        self.issuer_clock.now = t_revoked
        self.service.revoke(7)
        # The issuer only ever attests its current head.
        self.assertEqual(self.service.current_liveness()["epoch"], 3)
        for at in (t_revoked, t_revoked + 1800, t_revoked - 1 + MAX_AGE):
            self.verifier_clock.now = at
            self.cache.ingest_metadata(ISSUER_ID, copy.deepcopy(captured))
            self.assertEqual(self.cache.state(ISSUER_ID).current_epoch, 2)
        self.verifier_clock.now = t_revoked + MAX_AGE
        with self.assertRaises(AnnouncementFreshnessError):
            self.cache.state(ISSUER_ID)
        self.assertEqual(self.cache.accumulator_states(), {})


class QuietIssuerHolderTests(unittest.TestCase):
    """PoC part B for every holder witness provider."""

    def holders(self, service, clock, store_for):
        yield "private", _private_provider(
            {ISSUER_ID: service}, {ISSUER_ID: {KEY.key_id: PIN}},
            sources={ISSUER_ID: service}, checkpoint_store=store_for("private"), clock=clock,
        )
        yield "per-credential", WitnessUpdateProvider(
            {ISSUER_ID: service}, {ISSUER_ID: {KEY.key_id: PIN}},
            checkpoint_store=store_for("per-credential"), clock=clock,
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        )

    def test_poc_holder_refreshes_an_active_credential_of_a_quiet_issuer(self):
        clock = Clock()
        service = _service(clock)
        service.register(7)
        stores = {}

        def store_for(name):
            return stores.setdefault(name, InMemoryVerifierCheckpointStore())

        holders = dict(self.holders(service, clock, store_for))
        for holder in holders.values():
            holder.witness(ISSUER_ID, 7)
        clock.now = T0 + 3601
        for name, holder in holders.items():
            with self.subTest(name):
                scope = holder.checkpoint_scope(ACCUMULATOR_ID)
                before = stores[name].load_checkpoint(ISSUER_ID, scope)
                witness = holder.witness(ISSUER_ID, 7)
                self.assertEqual((witness.accumulator_epoch, witness.accumulator_root), (1, _root(7)))
                self.assertEqual(holder.current_epoch(ISSUER_ID), 1)
                self.assertEqual(stores[name].load_checkpoint(ISSUER_ID, scope), before)
                self.assertEqual(stores[name].evidence(ISSUER_ID, scope), [])

    def test_holder_without_liveness_keeps_failing_closed(self):
        clock = Clock()
        service = _service(clock)
        service.register(7)

        def strip(response):
            response.pop("liveness", None)
            return response

        relay = _Relay(service, strip)
        holder = WitnessUpdateProvider(
            {ISSUER_ID: relay}, {ISSUER_ID: {KEY.key_id: PIN}},
            checkpoint_store=InMemoryVerifierCheckpointStore(), clock=clock,
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        )
        holder.witness(ISSUER_ID, 7)
        clock.now = T0 + 3601
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_STALE"):
            holder.witness(ISSUER_ID, 7)
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_STALE"):
            holder.current_epoch(ISSUER_ID)

    def test_holder_rejects_liveness_that_does_not_verify_or_name_the_head(self):
        clock = Clock()
        service = _service(clock)
        service.register(7)
        genesis_hash = announcement_hash(service.announcement_for_epoch(0))
        cases = {
            "other head": (
                lambda statement: _signed_liveness(
                    {**statement, "epoch": 0, "headHash": genesis_hash}
                ),
                "LIVENESS_HEAD_MISMATCH",
            ),
            "unpinned signer": (
                lambda statement: _signed_liveness(
                    {**statement, "signingKeyId": OTHER_KEY.key_id}, OTHER_KEY
                ),
                "ANNOUNCEMENT_AUTHENTICATION_FAILED",
            ),
            "forged signature": (
                lambda statement: {**statement, "issuedAt": statement["issuedAt"] + 7},
                "ANNOUNCEMENT_AUTHENTICATION_FAILED",
            ),
        }
        for name, (forge, code) in cases.items():
            with self.subTest(name):
                clock.now = T0

                def rewrite(response, forge=forge):
                    response["liveness"] = forge(response["liveness"])
                    return response

                store = InMemoryVerifierCheckpointStore()
                honest = WitnessUpdateProvider(
                    {ISSUER_ID: service}, {ISSUER_ID: {KEY.key_id: PIN}},
                    checkpoint_store=store, clock=clock,
                    accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
                )
                honest.witness(ISSUER_ID, 7)
                scope = honest.checkpoint_scope(ACCUMULATOR_ID)
                before = store.load_checkpoint(ISSUER_ID, scope)
                # The head is still fresh on its own, so a statement naming
                # another head reaches the binding check.
                clock.now = T0 + 3000
                holder = WitnessUpdateProvider(
                    {ISSUER_ID: _Relay(service, rewrite)}, {ISSUER_ID: {KEY.key_id: PIN}},
                    checkpoint_store=store, clock=clock,
                    accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
                )
                with self.assertRaisesRegex(StaleWitnessError, code):
                    holder.witness(ISSUER_ID, 7)
                self.assertEqual(store.load_checkpoint(ISSUER_ID, scope), before)
                self.assertEqual(store.evidence(ISSUER_ID, scope), [])
                # Nothing rejected was kept to extend freshness later.
                clock.now = T0 + 3601
                with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_STALE"):
                    holder.current_epoch(ISSUER_ID)

    def test_private_holder_catches_up_to_a_quiet_head(self):
        clock = Clock()
        service = _service(clock)
        service.register(7)
        holder = _private_provider(
            {ISSUER_ID: service}, {ISSUER_ID: {KEY.key_id: PIN}},
            sources={ISSUER_ID: service}, checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=clock, max_backfill=2,
        )
        holder.witness(ISSUER_ID, 7)
        for credential_id in range(100, 105):
            service.register(credential_id)
        clock.now = T0 + 3601
        with self.assertRaisesRegex(StaleWitnessError, "BACKFILL_LIMIT"):
            holder.witness(ISSUER_ID, 7)
        statuses = []
        while not statuses or not statuses[-1].complete:
            statuses.append(holder.catch_up(ISSUER_ID))
        self.assertEqual(statuses[-1].checkpoint_epoch, 6)
        self.assertEqual(holder.witness(ISSUER_ID, 7).accumulator_epoch, 6)

    def test_http_holders_refresh_a_quiet_issuer(self):
        clock = Clock()
        service = _service(clock)
        service.register(7)
        with RevocationServer(service) as leaves, RevocationServer(service) as publication:
            client = RevocationServiceClient(leaves.base_url)
            holders = {
                "http per-credential": HTTPWitnessUpdateProvider(
                    {ISSUER_ID: (leaves.base_url, ACCUMULATOR_ID)}, {ISSUER_ID: {KEY.key_id: PIN}},
                    checkpoint_store=InMemoryVerifierCheckpointStore(), clock=clock,
                ),
                "http private": _private_provider(
                    {ISSUER_ID: (client, ACCUMULATOR_ID)}, {ISSUER_ID: {KEY.key_id: PIN}},
                    sources={ISSUER_ID: RevocationServiceClient(publication.base_url)},
                    checkpoint_store=InMemoryVerifierCheckpointStore(), clock=clock,
                ),
            }
            for holder in holders.values():
                holder.witness(ISSUER_ID, 7)
            clock.now = T0 + 3601
            for name, holder in holders.items():
                with self.subTest(name):
                    self.assertEqual(holder.witness(ISSUER_ID, 7).accumulator_epoch, 1)
                    # The statement from the update response also serves the
                    # head fetched over GET, which carries no liveness.
                    self.assertEqual(holder.current_epoch(ISSUER_ID), 1)


if __name__ == "__main__":
    unittest.main()
