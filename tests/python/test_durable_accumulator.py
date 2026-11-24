"""Durable revocation accumulator state: persistence, recovery, and continuity.

Asserts the recovery contract for DurableRevocationAccumulatorService: reopen
the same store after a simulated restart and the service comes back at the same
epoch and root, with the issuer-SIGNED announcement chain intact, still able to
serve witness updates (including deltas spanning the restart). Also checks the
durable service behind a SandboxIssuerAdapter, so issuance persists.
"""

import json
import tempfile
import unittest

import _path  # noqa: F401

from zkc_crypto import field_to_hex, hex_to_field
from zkc_issuer import IssuerSigningKey, SandboxIssuerAdapter
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    AnnouncementChain,
    DurableRevocationAccumulatorService,
    InMemoryAccumulatorStateStore,
    InMemoryVerifierCheckpointStore,
    SQLiteAccumulatorStateStore,
    WitnessUpdateProvider,
    verify_epoch_announcement,
)
from zkc_revocation.store import AccumulatorStoreError

ACCUMULATOR_ID = "durable-active-credentials"
UPDATE_ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
TIMESTAMP = 1_770_000_000

SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(SIGNING_KEY.metadata_entry())


class FailingAccumulatorStateStore(InMemoryAccumulatorStateStore):
    def __init__(self):
        super().__init__()
        self.fail_writes = False

    def append_epoch(self, record: dict) -> None:
        if self.fail_writes:
            raise AccumulatorStoreError("injected durable write failure")
        super().append_epoch(record)


class DurableAccumulatorRecoveryTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self._path = f"{self._dir.name}/accumulator.db"

    def tearDown(self):
        self._dir.cleanup()

    def _open(self, store):
        return DurableRevocationAccumulatorService.open(
            ACCUMULATOR_ID, UPDATE_ENDPOINT, SIGNING_KEY, store, clock=lambda: TIMESTAMP
        )

    def test_fresh_open_persists_genesis(self):
        store = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        service = self._open(store)
        self.assertEqual(service.epoch, 0)
        # Genesis state is on disk immediately.
        self.assertTrue(store.exists())
        store.close()

    def test_recovers_epoch_root_and_announcement(self):
        store = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        service = self._open(store)
        service.register(1001)
        service.register(1002)
        epoch_before = service.epoch
        root_before = service.root()
        announcement_before = service.current_announcement()
        store.close()

        # Simulated restart: reopen the same DB in a fresh store + service.
        store2 = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        recovered = self._open(store2)
        self.assertEqual(recovered.epoch, epoch_before)
        self.assertEqual(recovered.root(), root_before)
        self.assertEqual(recovered.current_announcement(), announcement_before)
        # The restored announcement still verifies under the issuer key.
        self.assertTrue(verify_epoch_announcement(recovered.current_announcement(), KEY_X, KEY_Y))
        store2.close()

    def test_witness_identical_across_restart(self):
        store = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        service = self._open(store)
        service.register(1001)
        service.register(1002)
        witness_before = service.witness(1001)
        store.close()

        store2 = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        recovered = self._open(store2)
        self.assertEqual(recovered.witness(1001), witness_before)
        store2.close()

    def test_announcement_chain_continues_after_restart(self):
        store = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        service = self._open(store)
        service.register(1001)
        service.register(1002)
        store.close()

        store2 = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        recovered = self._open(store2)
        recovered.register(1003)  # new epoch links to the restored chain head
        chain = AnnouncementChain(trusted_keys={SIGNING_KEY.key_id: KEY_PIN})
        chain.backfill([recovered.announcement_for_epoch(e) for e in range(recovered.epoch + 1)])
        # No EpochGapError / ChainLinkageError: the chain is unbroken.
        self.assertEqual(chain.last_epoch, recovered.epoch)

    def test_ordered_announcement_history_survives_restart(self):
        store = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        service = self._open(store)
        service.register(1001)
        service.register(1002)
        service.register(1003)
        expected = service.announcement_history(from_epoch=1)
        store.close()

        store2 = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        recovered = self._open(store2)
        self.assertEqual(recovered.announcement_history(from_epoch=1), expected)
        self.assertEqual([item["epoch"] for item in expected], [1, 2, 3])
        store2.close()

    def test_failed_mutations_leave_the_last_durable_epoch_unchanged(self):
        for operation in ("register", "revoke", "replace"):
            with self.subTest(operation=operation):
                store = FailingAccumulatorStateStore()
                service = self._open(store)
                service.register(1001)
                service.register(1002)
                before = service._serialize_state()
                stored = store.load_log()
                metadata = service.metadata()
                witness = service.witness(1001)
                mutate = {
                    "register": lambda: service.register(1003),
                    "revoke": lambda: service.revoke(1001),
                    "replace": lambda: service.replace(1001, 1003),
                }[operation]
                store.fail_writes = True
                with self.assertRaises(AccumulatorStoreError):
                    mutate()
                self.assertEqual(service._serialize_state(), before)
                self.assertEqual(store.load_log(), stored)
                self.assertEqual(service.metadata(), metadata)
                self.assertEqual(service.witness(1001), witness)
                self.assertTrue(service.is_active(1001))
                self.assertFalse(service.is_known(1003))
                self.assertEqual(self._open(store)._serialize_state(), before)
                # Retrying the same operation succeeds once, with no epoch gap.
                store.fail_writes = False
                mutate()
                self.assertEqual(service.epoch, before["epoch"] + 1)
                recovered = self._open(store)
                self.assertEqual(recovered._serialize_state(), service._serialize_state())

    def test_sqlite_transaction_failure_preserves_live_and_stored_state(self):
        with SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID) as store:
            service = self._open(store)
            service.register(1001)
            before = service._serialize_state()
            stored = store.load_log()
            store._conn.execute(
                "CREATE TRIGGER reject_save BEFORE INSERT ON accumulator_epochs "
                "BEGIN SELECT RAISE(ABORT, 'injected transaction failure'); END"
            )
            with self.assertRaises(AccumulatorStoreError):
                service.replace(1001, 1002)
            self.assertEqual(service._serialize_state(), before)
            self.assertEqual(store.load_log(), stored)
            self.assertEqual(self._open(store)._serialize_state(), before)
            store._conn.execute("DROP TRIGGER reject_save")
            service.replace(1001, 1002)
            self.assertEqual(service.epoch, 2)

    def test_delta_witness_update_spans_restart(self):
        # A holder that synced at epoch N before the restart can still get a
        # delta from N afterwards (the per-epoch snapshots are persisted).
        store = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        service = self._open(store)
        service.register(1001)
        from_epoch = service.epoch
        store.close()

        store2 = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        recovered = self._open(store2)
        recovered.register(1002)  # changes the tree post-restart
        request = {
            "type": "zkc:witness-update-request:v1",
            "accumulatorId": ACCUMULATOR_ID,
            "credentialId": field_to_hex(1001),
            "fromEpoch": from_epoch,
        }
        response = recovered.handle_request(request)
        self.assertEqual(response["mode"], "delta")
        self.assertEqual(response["witnessDelta"]["fromEpoch"], from_epoch)
        store2.close()

    def test_revocation_state_recovers(self):
        store = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        service = self._open(store)
        service.register(1001)
        service.register(1002)
        service.revoke(1001)
        store.close()

        store2 = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        recovered = self._open(store2)
        self.assertFalse(recovered.is_active(1001))
        self.assertTrue(recovered.is_active(1002))
        # The revoked credential's witness is refused after recovery.
        from zkc_issuer.errors import AdapterError

        with self.assertRaises(AdapterError):
            recovered.witness(1001)
        store2.close()

    def test_recovery_rejects_mismatched_accumulator_id(self):
        store = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        self._open(store)
        store.close()
        # A store row written for ACCUMULATOR_ID cannot recover a different id.
        store2 = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        with self.assertRaises(AccumulatorStoreError):
            DurableRevocationAccumulatorService.open(
                "some-other-id", UPDATE_ENDPOINT, SIGNING_KEY, store2, clock=lambda: TIMESTAMP
            )
        store2.close()

    def test_recovery_rejects_corrupt_announcement_history(self):
        store = InMemoryAccumulatorStateStore()
        service = self._open(store)
        service.register(1001)
        record = json.loads(store._epochs[1])
        record["announcement"]["root"] = field_to_hex(42)
        store._epochs[1] = json.dumps(record)
        with self.assertRaisesRegex(AccumulatorStoreError, "accumulator history is invalid"):
            self._open(store)

    def test_recovery_rejects_a_different_signing_key(self):
        store = InMemoryAccumulatorStateStore()
        service = self._open(store)
        service.register(1001)
        wrong_key = IssuerSigningKey.generate("replacement-not-authorized")
        with self.assertRaisesRegex(AccumulatorStoreError, "not the active announcement signer"):
            DurableRevocationAccumulatorService.open(
                ACCUMULATOR_ID,
                UPDATE_ENDPOINT,
                wrong_key,
                store,
                clock=lambda: TIMESTAMP,
            )

    def test_in_memory_store_round_trips(self):
        store = InMemoryAccumulatorStateStore()
        service = self._open(store)
        service.register(1001)
        root_before = service.root()
        # A new service reading the SAME in-memory store recovers the state.
        recovered = self._open(store)
        self.assertEqual(recovered.root(), root_before)
        self.assertEqual(recovered.epoch, service.epoch)


class DurableAccumulatorBehindIssuerTests(unittest.TestCase):
    """The durable service plugged into the issuer adapter persists issuance."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self._path = f"{self._dir.name}/issuer-accumulator.db"

    def tearDown(self):
        self._dir.cleanup()

    def test_issuance_persists_through_durable_accumulator(self):
        from zkc_crypto import derive_holder_commitment_from_seed
        from zkc_issuer import compute_binding_response

        store = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        accumulator = DurableRevocationAccumulatorService.open(
            ACCUMULATOR_ID, UPDATE_ENDPOINT, SIGNING_KEY, store, clock=lambda: TIMESTAMP
        )
        adapter = SandboxIssuerAdapter(
            signing_key=SIGNING_KEY, accumulator=accumulator, clock=lambda: TIMESTAMP
        )
        schema_id = "zkc:cred:kyc:v1"
        master_seed = 7
        holder_commitment = derive_holder_commitment_from_seed(master_seed)
        holder_commitment_hex = field_to_hex(holder_commitment)

        subject = adapter.verify_subject(
            {"schemaId": schema_id, "fixtureId": "sandbox-alice-basic"}
        )
        challenge = adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment_hex,
                "schemaId": schema_id,
            }
        )
        response = compute_binding_response(
            holder_commitment,
            adapter.issuer_id,
            schema_id,
            hex_to_field(challenge["nonce"]),
            challenge["expiresAt"],
        )
        adapter.bind_holder_commitment(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment_hex,
                "schemaId": schema_id,
                "nonce": challenge["nonce"],
                "challengeResponse": field_to_hex(response),
            }
        )
        envelope = adapter.issue_credential(
            {"subjectRef": subject["subjectRef"], "schemaId": schema_id}
        )
        credential_id = hex_to_field(envelope["credential"]["credentialId"])
        root_after_issuance = accumulator.root()
        store.close()

        # Restart the issuer's accumulator from the store: the issued
        # credential is still active and its witness recovers.
        store2 = SQLiteAccumulatorStateStore(self._path, ACCUMULATOR_ID)
        recovered = DurableRevocationAccumulatorService.open(
            ACCUMULATOR_ID, UPDATE_ENDPOINT, SIGNING_KEY, store2, clock=lambda: TIMESTAMP
        )
        self.assertEqual(recovered.root(), root_after_issuance)
        self.assertTrue(recovered.is_active(credential_id))
        # Witness fetched after recovery still verifies against the root.
        provider = WitnessUpdateProvider(
            {"did:zkc:test-issuer": recovered},
            {"did:zkc:test-issuer": {SIGNING_KEY.key_id: KEY_PIN}},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: TIMESTAMP,
            accumulator_ids={"did:zkc:test-issuer": ACCUMULATOR_ID},
        )
        witness = provider.witness("did:zkc:test-issuer", credential_id)
        self.assertEqual(field_to_hex(witness.accumulator_root), field_to_hex(recovered.root()))
        store2.close()


if __name__ == "__main__":
    unittest.main()
