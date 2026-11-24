"""Durable issuer storage: append-only epochs, delta window and key rotation.

Regression tests for review finding R7.13 (2026-10-04):

(a) every mutation rewrote one JSON document holding a leaf snapshot for
    every epoch, so bytes per write grew quadratically with issuances
    (0.08/0.27/0.97 MB after 40/80/160 issuances);
(b) recovery verified the whole history under the single supplied key, so
    the issuer could not reopen after an announcement-key rotation.
"""

import copy
import hashlib
import inspect
import json
import sqlite3
import tempfile
import unittest

import _path  # noqa: F401

from zkc_crypto import FIELD_MODULUS, field_to_hex
from zkc_issuer import IssuerSigningKey
from zkc_issuer.accumulator import MAX_EPOCH_LAG
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    AnnouncementChain,
    DurableRevocationAccumulatorService,
    InMemoryAccumulatorStateStore,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    SQLiteAccumulatorStateStore,
    VerifierAccumulatorCache,
    announcement_hash,
)
from zkc_revocation.service import DELTA_SNAPSHOT_WINDOW
from zkc_revocation.store import AccumulatorStoreError

ACCUMULATOR_ID = "sandbox-active-credentials"
ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
TIMESTAMP = 1_770_000_000
OLD_KEY = IssuerSigningKey.test_issuer()
NEW_KEY = IssuerSigningKey.from_seed(b"pre-pinned-successor", key_id="sandbox-2026-rotation")
THIRD_KEY = IssuerSigningKey.from_seed(b"second-successor", key_id="sandbox-2026-rotation-2")
TRUSTED_KEYS = {
    key.key_id: AnnouncementKeyPin.from_signing_key_entry(key.metadata_entry())
    for key in (OLD_KEY, NEW_KEY, THIRD_KEY)
}


def realistic_id(number: int) -> int:
    """A 254-bit credential id, as the review PoC used."""
    return int.from_bytes(hashlib.sha256(str(number).encode()).digest(), "big") % FIELD_MODULUS


def open_service(store, key=OLD_KEY, **kwargs):
    return DurableRevocationAccumulatorService.open(
        ACCUMULATOR_ID, ENDPOINT, key, store, clock=lambda: TIMESTAMP, **kwargs
    )


def verify_full_chain(test, service, expected_key_ids):
    history = service.announcement_history()
    chain = AnnouncementChain(trusted_keys=TRUSTED_KEYS)
    chain.backfill(history)
    test.assertEqual(chain.last_epoch, service.epoch)
    test.assertEqual(history[0]["previousAnnouncementHash"], "0x" + "00" * 32)
    test.assertEqual([item["signingKeyId"] for item in history], expected_key_ids)


def store_from_log(log) -> InMemoryAccumulatorStateStore:
    store = InMemoryAccumulatorStateStore()
    store._header = json.dumps(log["header"])
    store._signers = [json.dumps(record) for record in log["signers"]]
    store._epochs = [json.dumps(record) for record in log["epochs"]]
    return store


class AppendOnlyGrowthTests(unittest.TestCase):
    """PoC lane6/poc11: bytes per write must not depend on history length."""

    ISSUANCES = 160
    CHECKPOINTS = (40, 80, 160)

    @classmethod
    def setUpClass(cls):
        cls._dir = tempfile.TemporaryDirectory()
        cls.path = f"{cls._dir.name}/issuer.sqlite3"
        cls.store = SQLiteAccumulatorStateStore(cls.path, ACCUMULATOR_ID)
        cls.service = open_service(cls.store)
        connection = cls.store._conn
        cls.rows_changed = []
        cls.row_bytes = {}
        cls.rows_at_first_checkpoint = None
        for number in range(1, cls.ISSUANCES + 1):
            before = connection.total_changes
            cls.service.register(realistic_id(number))
            cls.rows_changed.append(connection.total_changes - before)
            (cls.row_bytes[number],) = connection.execute(
                "SELECT length(CAST(document AS BLOB)) FROM accumulator_epochs "
                "WHERE accumulator_id = ? AND epoch = ?",
                (ACCUMULATOR_ID, number),
            ).fetchone()
            if number == cls.CHECKPOINTS[0]:
                cls.rows_at_first_checkpoint = cls._rows(upto=number)

    @classmethod
    def _rows(cls, upto):
        return cls.store._conn.execute(
            "SELECT epoch, document FROM accumulator_epochs "
            "WHERE accumulator_id = ? AND epoch <= ? ORDER BY epoch",
            (ACCUMULATOR_ID, upto),
        ).fetchall()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        cls._dir.cleanup()

    def test_each_mutation_inserts_exactly_one_row(self):
        self.assertEqual(self.rows_changed, [1] * self.ISSUANCES)

    def test_bytes_per_write_stay_constant_as_issuances_grow(self):
        sizes = [self.row_bytes[number] for number in self.CHECKPOINTS]
        # One operation plus one signed announcement: under 1 KiB, and the
        # only variation is the decimal width of the epoch number.
        self.assertLess(max(sizes), 1024, sizes)
        self.assertLessEqual(max(sizes) - min(sizes), 8, sizes)
        every = list(self.row_bytes.values())
        self.assertLessEqual(max(every) - min(every), 8)

    def test_earlier_rows_are_never_rewritten(self):
        first = self.CHECKPOINTS[0]
        rows = self._rows(upto=first)
        self.assertEqual(
            [tuple(row) for row in rows],
            [tuple(row) for row in self.rows_at_first_checkpoint],
        )

    def test_store_rejects_updates_and_deletes_of_log_rows(self):
        connection = self.store._conn
        for statement in (
            "UPDATE accumulator_epochs SET document = '{}' WHERE epoch = 1",
            "DELETE FROM accumulator_epochs WHERE epoch = 1",
            "UPDATE accumulator_signers SET document = '{}'",
            "DELETE FROM accumulator_signers",
            "UPDATE accumulator_log_header SET document = '{}'",
            "DELETE FROM accumulator_log_header",
        ):
            with self.subTest(statement=statement):
                with self.assertRaisesRegex(sqlite3.DatabaseError, "append-only"):
                    with connection:
                        connection.execute(statement)

    def test_snapshots_are_pruned_to_the_delta_window(self):
        head = self.service.epoch
        self.assertEqual(
            sorted(self.service._snapshots),
            list(range(head - DELTA_SNAPSHOT_WINDOW, head + 1)),
        )

    def test_delta_served_inside_the_window_and_full_refresh_outside(self):
        head = self.service.epoch
        oldest = head - DELTA_SNAPSHOT_WINDOW
        anonymous = {"type": "zkc:epoch-delta-request:v1", "accumulatorId": ACCUMULATOR_ID}
        inside = self.service.handle_request({**anonymous, "fromEpoch": oldest})
        self.assertEqual(inside["mode"], "delta")
        self.assertEqual(len(inside["changedLeaves"]), DELTA_SNAPSHOT_WINDOW)
        outside = self.service.handle_request({**anonymous, "fromEpoch": oldest - 1})
        self.assertEqual(outside["mode"], "full")
        self.assertEqual(len(outside["leaves"]), head)
        named = {
            "type": "zkc:witness-update-request:v1",
            "accumulatorId": ACCUMULATOR_ID,
            "credentialId": field_to_hex(realistic_id(1)),
        }
        self.assertEqual(self.service.handle_request({**named, "fromEpoch": oldest})["mode"], "delta")
        self.assertEqual(self.service.handle_request({**named, "fromEpoch": oldest - 1})["mode"], "full")

    def test_restart_replays_the_log_to_the_same_state_and_window(self):
        with SQLiteAccumulatorStateStore(self.path, ACCUMULATOR_ID) as reopened:
            recovered = open_service(reopened)
            self.assertEqual(recovered._serialize_state(), self.service._serialize_state())


class DeltaWindowPolicyTests(unittest.TestCase):
    def test_window_covers_default_backfill_and_epoch_lag(self):
        for consumer in (VerifierAccumulatorCache, PrivateWitnessProvider):
            with self.subTest(consumer=consumer.__name__):
                default = inspect.signature(consumer).parameters["max_backfill"].default
                # The client's checkpoint epoch plus the announcements it may backfill.
                self.assertEqual(DELTA_SNAPSHOT_WINDOW, default + 1)
        self.assertGreaterEqual(DELTA_SNAPSHOT_WINDOW, MAX_EPOCH_LAG)

    def test_revoke_and_replace_rows_stay_small(self):
        store = InMemoryAccumulatorStateStore()
        service = open_service(store)
        for number in range(1, 6):
            service.register(realistic_id(number))
        service.revoke(realistic_id(1))
        service.replace(realistic_id(2), realistic_id(6))
        sizes = [len(text.encode()) for text in store._epochs]
        self.assertLess(max(sizes), 1024, sizes)


class SigningKeyRotationTests(unittest.TestCase):
    """PoC lane6/poc8: the issuer must reopen after an announcement-key rotation."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = f"{self._dir.name}/issuer.sqlite3"

    def tearDown(self):
        self._dir.cleanup()

    def reopen(self, key, **kwargs):
        store = SQLiteAccumulatorStateStore(self.path, ACCUMULATOR_ID)
        try:
            return open_service(store, key, **kwargs), store
        except BaseException:
            store.close()
            raise

    def test_rotation_then_restart_with_successor_continues_the_chain(self):
        service, store = self.reopen(OLD_KEY)
        service.register(1)
        service.register(2)
        record = service.rotate_signing_key(NEW_KEY)
        self.assertEqual(record["fromEpoch"], 3)
        service.register(3)
        store.close()

        recovered, store = self.reopen(NEW_KEY)
        recovered.register(4)
        verify_full_chain(self, recovered, [OLD_KEY.key_id] * 3 + [NEW_KEY.key_id] * 2)
        self.assertEqual(
            [(item["keyId"], item["fromEpoch"]) for item in recovered.signing_key_history()],
            [(OLD_KEY.key_id, 0), (NEW_KEY.key_id, 3)],
        )
        store.close()

        # The retired key no longer opens the issuer; the successor still does.
        with self.assertRaisesRegex(AccumulatorStoreError, "does not match the active"):
            self.reopen(OLD_KEY)
        with self.assertRaisesRegex(AccumulatorStoreError, "does not match the active"):
            self.reopen(OLD_KEY, allow_rotation=True)
        recovered, store = self.reopen(NEW_KEY)
        self.assertEqual(recovered.epoch, 4)
        store.close()

    def test_restart_between_rotation_and_next_epoch(self):
        service, store = self.reopen(OLD_KEY)
        service.register(1)
        service.rotate_signing_key(NEW_KEY)
        head = service.current_announcement()
        store.close()

        recovered, store = self.reopen(NEW_KEY)
        # Nothing was re-signed: the head is still the old key's announcement.
        self.assertEqual(recovered.current_announcement(), head)
        recovered.register(2)
        current = recovered.current_announcement()
        self.assertEqual(current["signingKeyId"], NEW_KEY.key_id)
        self.assertEqual(current["previousAnnouncementHash"], announcement_hash(head))
        verify_full_chain(self, recovered, [OLD_KEY.key_id] * 2 + [NEW_KEY.key_id])
        store.close()

    def test_unrecorded_successor_fails_closed_unless_rotation_is_explicit(self):
        service, store = self.reopen(OLD_KEY)
        service.register(1)
        service.register(2)
        store.close()

        with self.assertRaisesRegex(AccumulatorStoreError, "not the active announcement signer"):
            self.reopen(NEW_KEY)
        with SQLiteAccumulatorStateStore(self.path, ACCUMULATOR_ID) as untouched:
            self.assertEqual(len(untouched.load_log()["signers"]), 1)

        rotated, store = self.reopen(NEW_KEY, allow_rotation=True)
        self.assertEqual(
            [(item["keyId"], item["fromEpoch"]) for item in rotated.signing_key_history()],
            [(OLD_KEY.key_id, 0), (NEW_KEY.key_id, 3)],
        )
        rotated.register(3)
        store.close()

        recovered, store = self.reopen(NEW_KEY)
        verify_full_chain(self, recovered, [OLD_KEY.key_id] * 3 + [NEW_KEY.key_id])
        store.close()

    def test_successive_rotations_reopen_with_the_latest_key(self):
        service, store = self.reopen(OLD_KEY)
        service.register(1)
        service.rotate_signing_key(NEW_KEY)
        service.register(2)
        store.close()
        service, store = self.reopen(NEW_KEY)
        service.rotate_signing_key(THIRD_KEY)
        service.register(3)
        store.close()

        recovered, store = self.reopen(THIRD_KEY)
        recovered.revoke(1)
        verify_full_chain(
            self,
            recovered,
            [OLD_KEY.key_id] * 2 + [NEW_KEY.key_id] + [THIRD_KEY.key_id] * 2,
        )
        store.close()
        for retired in (OLD_KEY, NEW_KEY):
            with self.subTest(retired=retired.key_id):
                with self.assertRaisesRegex(AccumulatorStoreError, "does not match the active"):
                    self.reopen(retired)

    def test_rotation_refuses_reused_key_ids_and_public_keys(self):
        service = open_service(InMemoryAccumulatorStateStore())
        same_id_other_key = IssuerSigningKey.from_seed(b"impostor", key_id=OLD_KEY.key_id)
        same_key_other_id = IssuerSigningKey.test_issuer(key_id="renamed-test-issuer")
        for successor in (OLD_KEY, same_id_other_key, same_key_other_id):
            with self.subTest(successor=successor.key_id):
                with self.assertRaisesRegex(ValueError, "already recorded"):
                    service.rotate_signing_key(successor)
        service.rotate_signing_key(NEW_KEY)
        with self.assertRaisesRegex(ValueError, "already recorded"):
            service.rotate_signing_key(OLD_KEY)
        self.assertEqual(len(service.signing_key_history()), 2)

    def test_failed_signer_write_keeps_the_active_key(self):
        class FailingSignerStore(InMemoryAccumulatorStateStore):
            def append_signer(self, record):
                raise AccumulatorStoreError("injected signer write failure")

        store = FailingSignerStore()
        service = open_service(store)
        service.register(1)
        with self.assertRaises(AccumulatorStoreError):
            service.rotate_signing_key(NEW_KEY)
        self.assertEqual(len(service.signing_key_history()), 1)
        service.register(2)
        self.assertEqual(service.current_announcement()["signingKeyId"], OLD_KEY.key_id)
        self.assertEqual(open_service(store).epoch, 2)

    def test_in_memory_service_records_rotation_and_refuses_unrecorded_keys(self):
        service = RevocationAccumulatorService(
            ACCUMULATOR_ID, ENDPOINT, OLD_KEY, clock=lambda: TIMESTAMP
        )
        service.rotate_signing_key(NEW_KEY)
        service.register(1)
        self.assertEqual(service.current_announcement()["signingKeyId"], NEW_KEY.key_id)
        # Swapping the key behind the service's back cannot sign an epoch.
        service._signing_key = THIRD_KEY
        with self.assertRaisesRegex(RuntimeError, "active recorded announcement signer"):
            service.register(2)
        self.assertEqual(service.epoch, 1)


class TamperedHistoryTests(unittest.TestCase):
    """Recovery authenticates every row, including the signer records."""

    @classmethod
    def setUpClass(cls):
        store = InMemoryAccumulatorStateStore()
        service = open_service(store)
        service.register(1001)  # epoch 1, OLD_KEY
        service.register(1002)  # epoch 2, OLD_KEY
        service.rotate_signing_key(NEW_KEY)
        service.revoke(1001)  # epoch 3, NEW_KEY
        service.replace(1002, 1003)  # epoch 4, NEW_KEY
        cls.log = store.load_log()
        cls.expected = service._serialize_state()

    def assert_rejected(self, mutate, message, key=NEW_KEY):
        log = copy.deepcopy(self.log)
        mutate(log)
        with self.assertRaisesRegex(AccumulatorStoreError, message):
            open_service(store_from_log(log), key)

    def test_untampered_history_recovers(self):
        recovered = open_service(store_from_log(copy.deepcopy(self.log)), NEW_KEY)
        self.assertEqual(recovered._serialize_state(), self.expected)

    def test_tampered_signer_records_fail_closed(self):
        third_public_key = "0x" + "".join(
            part.hex() for part in THIRD_KEY.public_key_coordinates()
        )
        cases = {
            "successor public key replaced": (
                lambda log: log["signers"][1].update(publicKey=third_public_key),
                "epoch 3 announcement signature is invalid",
            ),
            "genesis public key replaced": (
                lambda log: log["signers"][0].update(publicKey=third_public_key),
                "epoch 0 announcement signature is invalid",
            ),
            "successor starts later": (
                lambda log: log["signers"][1].update(fromEpoch=4),
                "epoch 3 is not signed by its recorded signer",
            ),
            "successor starts earlier": (
                lambda log: log["signers"][1].update(fromEpoch=2),
                "epoch 2 is not signed by its recorded signer",
            ),
            "successor removed": (
                lambda log: log["signers"].pop(),
                "epoch 3 is not signed by its recorded signer",
            ),
            "successor key id renamed": (
                lambda log: log["signers"][1].update(keyId="sandbox-forged"),
                "epoch 3 is not signed by its recorded signer",
            ),
            "genesis signer starts late": (
                lambda log: log["signers"][0].update(fromEpoch=1),
                "does not sign from genesis",
            ),
            "duplicate signer": (
                lambda log: log["signers"].append(dict(log["signers"][1], fromEpoch=5)),
                "recorded twice",
            ),
            "extra signer field": (
                lambda log: log["signers"][1].update(privateKey="00"),
                "signer record shape",
            ),
            "non-canonical public key": (
                lambda log: log["signers"][1].update(
                    publicKey=log["signers"][1]["publicKey"].upper().replace("0X", "0x")
                ),
                "lowercase hex",
            ),
        }
        for name, (mutate, message) in cases.items():
            with self.subTest(case=name):
                self.assert_rejected(mutate, message)

    def test_tampered_epoch_records_fail_closed(self):
        def swap_revoked_credential(log):
            # Register and later revoke a different id: the final leaves are
            # identical, so only the per-epoch signed roots expose the swap.
            log["epochs"][1]["operation"]["credentialId"] = format(1004, "x")
            log["epochs"][3]["operation"]["credentialId"] = format(1004, "x")

        cases = {
            "announcement root": (
                lambda log: log["epochs"][3]["announcement"].update(root=field_to_hex(42)),
                "epoch 3 announcement signature is invalid",
            ),
            "operation credential": (
                lambda log: log["epochs"][1]["operation"].update(credentialId=format(1004, "x")),
                "epoch 1 root does not match",
            ),
            "revoked credential swapped consistently": (
                swap_revoked_credential,
                "epoch 1 root does not match",
            ),
            "revocation of an unknown credential": (
                lambda log: log["epochs"][3]["operation"].update(credentialId=format(1005, "x")),
                "operation cannot be replayed",
            ),
            "operation type": (
                lambda log: log["epochs"][4]["operation"].update(type="register"),
                "operation shape",
            ),
            "non-canonical credential hex": (
                lambda log: log["epochs"][1]["operation"].update(credentialId="03e9"),
                "not canonical",
            ),
            "missing epoch": (
                lambda log: log["epochs"].pop(2),
                "not contiguous",
            ),
            "reordered announcements": (
                lambda log: log["epochs"][3].update(announcement=log["epochs"][4]["announcement"]),
                "epoch 3 announcement does not describe",
            ),
            "genesis operation": (
                lambda log: log["epochs"][0].update(operation={"type": "register"}),
                "epoch 0 is not genesis",
            ),
            "header lag": (
                lambda log: log["header"].update(maxEpochLag=3),
                "does not describe",
            ),
        }
        for name, (mutate, message) in cases.items():
            with self.subTest(case=name):
                self.assert_rejected(mutate, message)

    def test_header_identity_mismatches_fail_closed(self):
        self.assert_rejected(
            lambda log: log["header"].update(version="zkc:revocation-accumulator-state:v9"),
            "unsupported accumulator state version",
        )
        self.assert_rejected(
            lambda log: log["header"].update(accumulatorId="other-accumulator"),
            "accumulator id in store does not match",
        )

    def test_tampered_sqlite_signer_row_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/issuer.sqlite3"
            with SQLiteAccumulatorStateStore(path, ACCUMULATOR_ID) as store:
                service = open_service(store)
                service.register(1001)
                service.rotate_signing_key(NEW_KEY)
                service.register(1002)
            third_public_key = "0x" + "".join(
                part.hex() for part in THIRD_KEY.public_key_coordinates()
            )
            connection = sqlite3.connect(path)
            with connection:
                connection.execute("DROP TRIGGER accumulator_signers_no_update")
                (document,) = connection.execute(
                    "SELECT document FROM accumulator_signers WHERE sequence = 1"
                ).fetchone()
                record = json.loads(document)
                record["publicKey"] = third_public_key
                connection.execute(
                    "UPDATE accumulator_signers SET document = ? WHERE sequence = 1",
                    (json.dumps(record),),
                )
            connection.close()
            with SQLiteAccumulatorStateStore(path, ACCUMULATOR_ID) as store:
                with self.assertRaisesRegex(AccumulatorStoreError, "signature is invalid"):
                    open_service(store, NEW_KEY)


def legacy_v2_document(service: RevocationAccumulatorService) -> dict:
    """The v2 document the previous format wrote (its ``_serialize_state``)."""

    def hexes(values):
        return [format(int(value), "x") for value in values]

    return {
        "version": "zkc:revocation-accumulator-state:v2",
        "accumulatorId": service.accumulator_id,
        "updateEndpoint": service.update_endpoint,
        "maxEpochLag": service.max_epoch_lag,
        "epoch": service.epoch,
        "leaves": hexes(service._accumulator.leaves()),
        "indexByCredential": {
            format(int(cid), "x"): int(index)
            for cid, index in service._index_by_credential.items()
        },
        "revoked": hexes(sorted(service._revoked)),
        "snapshots": {str(epoch): hexes(leaves) for epoch, leaves in service._snapshots.items()},
        "announcements": {
            str(epoch): announcement for epoch, announcement in service._announcements.items()
        },
        "lastAnnouncementHash": service._last_announcement_hash,
    }


class LegacyStateMigrationTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = f"{self._dir.name}/issuer.sqlite3"
        service = RevocationAccumulatorService(
            ACCUMULATOR_ID, ENDPOINT, OLD_KEY, clock=lambda: TIMESTAMP
        )
        service.register(1001)
        service.register(1002)
        service.revoke(1001)
        service.replace(1002, 1003)
        service.register(1004)
        self.live = service
        self.document = legacy_v2_document(service)

    def tearDown(self):
        self._dir.cleanup()

    def write_legacy(self, document):
        connection = sqlite3.connect(self.path)
        with connection:
            connection.execute(
                "CREATE TABLE accumulator_state ("
                " accumulator_id TEXT PRIMARY KEY, document TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO accumulator_state(accumulator_id, document) VALUES(?, ?)",
                (ACCUMULATOR_ID, json.dumps(document, sort_keys=True)),
            )
        connection.close()

    def legacy_rows(self):
        connection = sqlite3.connect(self.path)
        try:
            return connection.execute("SELECT COUNT(*) FROM accumulator_state").fetchone()[0]
        finally:
            connection.close()

    def test_verified_legacy_state_migrates_to_the_log(self):
        self.write_legacy(self.document)
        with SQLiteAccumulatorStateStore(self.path, ACCUMULATOR_ID) as store:
            migrated = open_service(store)
            self.assertEqual(migrated.root(), self.live.root())
            self.assertEqual(migrated.announcement_history(), self.live.announcement_history())
            self.assertIsNone(store.load_legacy_state())
            self.assertEqual(len(store.load_log()["epochs"]), self.live.epoch + 1)
            migrated.register(1005)
        self.assertEqual(self.legacy_rows(), 0)
        with SQLiteAccumulatorStateStore(self.path, ACCUMULATOR_ID) as store:
            recovered = open_service(store)
            self.assertEqual(recovered.epoch, self.live.epoch + 1)
            verify_full_chain(self, recovered, [OLD_KEY.key_id] * (recovered.epoch + 1))

    def test_inconsistent_legacy_state_is_refused_and_left_untouched(self):
        tampered_snapshot = copy.deepcopy(self.document)
        tampered_snapshot["snapshots"]["2"][0] = format(1009, "x")
        tampered_index = copy.deepcopy(self.document)
        tampered_index["indexByCredential"][format(1003, "x")] = 0
        tampered_root = copy.deepcopy(self.document)
        tampered_root["announcements"]["3"]["root"] = field_to_hex(42)
        missing_epoch = copy.deepcopy(self.document)
        del missing_epoch["snapshots"]["4"]
        cases = {
            "snapshot": (tampered_snapshot, OLD_KEY, "cannot be migrated"),
            "credential index": (tampered_index, OLD_KEY, "credential index differs"),
            "announcement": (tampered_root, OLD_KEY, "signature is invalid"),
            "missing snapshot": (missing_epoch, OLD_KEY, "do not cover every epoch"),
            "different key": (self.document, NEW_KEY, "not signed by its recorded signer"),
        }
        for name, (document, key, message) in cases.items():
            with self.subTest(case=name):
                self._dir.cleanup()
                self._dir = tempfile.TemporaryDirectory()
                self.path = f"{self._dir.name}/issuer.sqlite3"
                self.write_legacy(document)
                with SQLiteAccumulatorStateStore(self.path, ACCUMULATOR_ID) as store:
                    with self.assertRaisesRegex(AccumulatorStoreError, message):
                        open_service(store, key)
                    self.assertIsNone(store.load_log())
                    self.assertEqual(store.load_legacy_state(), document)


if __name__ == "__main__":
    unittest.main()
