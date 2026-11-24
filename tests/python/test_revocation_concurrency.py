"""Concurrent epoch publication through the real issuer/revocation transports.

Real Poseidon roots and issuer signatures are used throughout. Barriers start
mixed mutation/read bursts together; signing yields to expose interleavings.
"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import tempfile
import threading
import time
import unittest

import _path  # noqa: F401

from zkc_crypto import (
    SparseMerkleAccumulator,
    compute_merkle_root,
    derive_holder_commitment_from_seed,
    field_to_hex,
    hex_to_field,
)
from zkc_issuer import AdapterError, IssuerSigningKey, SandboxIssuerAdapter, compute_binding_response
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    AnnouncementChain,
    DurableRevocationAccumulatorService,
    InMemoryAccumulatorStateStore,
    RevocationAccumulatorService,
    SQLiteAccumulatorStateStore,
    apply_witness_delta,
    compute_announcement_digest,
    compute_liveness_digest,
)
from zkc_revocation.store import AccumulatorStoreError
from zkc_transport import (
    IssuerAdminClient,
    IssuerAdminServer,
    IssuerServer,
    IssuerServiceClient,
    OperatorKey,
    RevocationServer,
    RevocationServiceClient,
)

TIMESTAMP = 1_770_000_000
ACCUMULATOR_ID = "sandbox-active-credentials"
ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
SCHEMA = "zkc:cred:kyc:v1"
KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(KEY.metadata_entry())
OPERATOR = OperatorKey.from_seed(b"zkc-test-operator-concurrency", "operator-1")


class RecordingKey:
    key_id = KEY.key_id

    def __init__(self):
        self.digests = []
        self.fail = False

    def sign_digest(self, digest):
        time.sleep(0.001)
        if self.fail:
            raise ValueError("injected signing failure")
        self.digests.append(digest)
        return KEY.sign_digest(digest)

    def is_valid_at(self, timestamp):
        return KEY.is_valid_at(timestamp)

    def public_key_coordinates(self):
        return KEY_X, KEY_Y


def service_with(key, store=None):
    if store is None:
        return RevocationAccumulatorService(
            ACCUMULATOR_ID, ENDPOINT, key, clock=lambda: TIMESTAMP
        )
    return DurableRevocationAccumulatorService.open(
        ACCUMULATOR_ID, ENDPOINT, key, store, clock=lambda: TIMESTAMP
    )


def prepare_issue(adapter):
    """A real bound issuer session; the returned opaque handle is used verbatim."""
    subject = adapter.verify_subject({"schemaId": SCHEMA, "fixtureId": "sandbox-alice-basic"})
    commitment = derive_holder_commitment_from_seed(7)
    payload = {
        "subjectRef": subject["subjectRef"], "schemaId": SCHEMA,
        "holderCommitment": field_to_hex(commitment),
    }
    challenge = adapter.request_binding_challenge(payload)
    response = compute_binding_response(
        commitment, adapter.issuer_id, SCHEMA,
        hex_to_field(challenge["nonce"]), challenge["expiresAt"],
    )
    adapter.bind_holder_commitment({
        **payload, "nonce": challenge["nonce"], "challengeResponse": field_to_hex(response),
    })
    return {"subjectRef": subject["subjectRef"], "schemaId": SCHEMA}


class EpochConcurrencyTests(unittest.TestCase):
    def assert_response_snapshot(self, response, credential_id=None, old_witness=None):
        announcement = response["announcement"]
        self.assertEqual(response["epoch"], announcement["epoch"])
        self.assertEqual(response["root"], announcement["root"])
        if credential_id is None:
            self.assertEqual(
                field_to_hex(SparseMerkleAccumulator(
                    [hex_to_field(leaf) for leaf in response["leaves"]]
                ).root()), response["root"],
            )
        else:
            witness = (apply_witness_delta(old_witness, response)
                       if response["mode"] == "delta" else response["witness"])
            self.assertEqual(witness["accumulatorEpoch"], response["epoch"])
            self.assertEqual(witness["accumulatorRoot"], response["root"])
            self.assertEqual(field_to_hex(compute_merkle_root(
                credential_id, witness["pathIndex"],
                [hex_to_field(sibling) for sibling in witness["siblings"]],
            )), response["root"])

    def test_100_threaded_issue_revoke_bursts_preserve_signed_state_and_recovery(self):
        # Fresh small trees per trial bound runtime and isolate failures. Half
        # use SQLite's DEFAULT options, opened on the test thread and written
        # on HTTP workers; the rest exercise the in-memory service directly.
        with tempfile.TemporaryDirectory() as directory, ThreadPoolExecutor(max_workers=5) as pool:
            for trial in range(100):
                with self.subTest(trial=trial):
                    key = RecordingKey()
                    store = (SQLiteAccumulatorStateStore(
                        f"{directory}/{trial}.db", ACCUMULATOR_ID
                    ) if trial % 2 else None)
                    try:
                        service = service_with(key, store)
                        # Liveness statements are the only other signatures
                        # the service makes; record each one it signs.
                        liveness_digests = []
                        sign_liveness = service.sign_liveness

                        def recording_sign_liveness(sign=sign_liveness, digests=liveness_digests):
                            statement = sign()
                            digests.append(compute_liveness_digest(statement))
                            return statement

                        service.sign_liveness = recording_sign_liveness
                        # Own the issuer ledger at genesis before seeding the
                        # unrelated accumulator traffic used by this stress test.
                        adapter = SandboxIssuerAdapter(
                            signing_key=KEY, accumulator=service, clock=lambda: TIMESTAMP
                        )
                        revoked_ids = (1001, 1002)
                        survivor = 1003
                        for credential_id in (*revoked_ids, survivor):
                            service.register(credential_id)
                        stale = {cid: service.witness(cid) for cid in revoked_ids}
                        old_witness = service.witness(survivor)
                        issue_payload = prepare_issue(adapter)
                        # Both servers retain their default threaded=True.
                        with IssuerServer(adapter) as issuer, RevocationServer(service) as revocation, \
                                IssuerAdminServer(
                                    adapter, {OPERATOR.key_id: OPERATOR.public_key_hex()},
                                    clock=lambda: TIMESTAMP,
                                ) as admin:
                            issuer_client = IssuerServiceClient(issuer.base_url, timeout=30)
                            admin_client = IssuerAdminClient(
                                admin.base_url, OPERATOR, adapter.issuer_id,
                                timeout=30, clock=lambda: TIMESTAMP,
                            )
                            revocation_client = RevocationServiceClient(revocation.base_url, timeout=30)
                            barrier = threading.Barrier(5)

                            def together(operation, *args):
                                barrier.wait(timeout=30)
                                return operation(*args)

                            jobs = [
                                pool.submit(together, issuer_client.issue_credential, issue_payload),
                                *(pool.submit(together, admin_client.revoke_credential, cid)
                                  for cid in revoked_ids),
                                pool.submit(together, revocation_client.epoch_delta, ACCUMULATOR_ID),
                                pool.submit(together, revocation_client.witness_update,
                                            ACCUMULATOR_ID, survivor, old_witness["accumulatorEpoch"]),
                            ]
                            issued, first_revoke, second_revoke, delta, witness = [
                                job.result(timeout=60) for job in jobs
                            ]
                            # Successful SDK results require actual HTTP 200s.
                            for acknowledgement in (first_revoke, second_revoke):
                                self.assertIn("currentAnnouncement", acknowledgement)
                            self.assert_response_snapshot(delta)
                            self.assert_response_snapshot(witness, survivor, old_witness)
                            head = revocation_client.current_announcement()
                            self.assertEqual(head["epoch"], 6)
                            self.assertEqual(head["root"], field_to_hex(service.root()))
                            issued_id = hex_to_field(issued["credential"]["credentialId"])
                            self.assertEqual(head["root"], field_to_hex(
                                SparseMerkleAccumulator([0, 0, survivor, issued_id]).root()
                            ))
                            for cid in revoked_ids:
                                self.assertFalse(service.is_active(cid))
                                with self.assertRaises(AdapterError):
                                    service.witness(cid)
                                # A revoked holder's formerly valid membership
                                # path cannot authenticate at the signed head.
                                old = stale[cid]
                                self.assertNotEqual(field_to_hex(compute_merkle_root(
                                    cid, old["pathIndex"],
                                    [hex_to_field(sibling) for sibling in old["siblings"]],
                                )), head["root"])
                            issued_id = hex_to_field(issued["credential"]["credentialId"])
                            self.assertTrue(service.is_active(issued_id))
                            self.assert_response_snapshot(
                                revocation_client.witness_update(ACCUMULATOR_ID, issued_id), issued_id
                            )
                        history = service.announcement_history()
                        self.assertEqual([item["epoch"] for item in history], list(range(7)))
                        # Every signing call is accounted for: no overwritten,
                        # orphaned or second announcement for any epoch, and
                        # no signature other than an announcement or a
                        # recorded liveness statement.
                        self.assertEqual(Counter(key.digests), Counter(
                            compute_announcement_digest(item) for item in history
                        ) + Counter(liveness_digests))
                        chain = AnnouncementChain(trusted_keys={KEY.key_id: KEY_PIN})
                        chain.backfill(history)
                        self.assertEqual(chain.last_epoch, service.epoch)
                        for epoch, announcement in enumerate(history):
                            self.assertEqual(service.announcement_for_epoch(epoch), announcement)
                            self.assertEqual(announcement["root"], field_to_hex(
                                SparseMerkleAccumulator(service._snapshots[epoch]).root()
                            ))
                        if store is not None:
                            before = service._serialize_state()
                            store.close()
                            store = SQLiteAccumulatorStateStore(f"{directory}/{trial}.db", ACCUMULATOR_ID)
                            recovered = service_with(key, store)
                            self.assertEqual(recovered._serialize_state(), before)
                            # Recovery initializes the same lock and can mutate.
                            recovered.replace(issued_id, 1004)
                            chain.ingest(recovered.current_announcement())
                            self.assertFalse(recovered.is_active(issued_id))
                    finally:
                        if store is not None:
                            store.close()

    def test_competing_mutations_of_one_credential_commit_exactly_once(self):
        for operation in ("register", "revoke", "replace"):
            with self.subTest(operation=operation):
                key = RecordingKey()
                service = service_with(key, InMemoryAccumulatorStateStore())
                if operation != "register":
                    service.register(1001)
                before_epoch = service.epoch
                before_signatures = len(key.digests)
                barrier = threading.Barrier(2)

                def mutate():
                    barrier.wait(timeout=10)
                    try:
                        if operation == "register":
                            service.register(1001)
                        elif operation == "revoke":
                            service.revoke(1001)
                        else:
                            service.replace(1001, 1002)
                        return "committed"
                    except (AdapterError, ValueError):
                        return "refused"

                with ThreadPoolExecutor(max_workers=2) as pool:
                    jobs = [pool.submit(mutate) for _ in range(2)]
                    self.assertCountEqual([job.result(timeout=10) for job in jobs],
                                          ["committed", "refused"])
                self.assertEqual(service.epoch, before_epoch + 1)
                self.assertEqual(len(key.digests), before_signatures + 1)
                self.assertEqual(service.current_announcement()["root"], field_to_hex(service.root()))
                AnnouncementChain(trusted_keys={KEY.key_id: KEY_PIN}).backfill(service.announcement_history())

    def test_signing_failure_discards_candidate_and_retry_has_no_gap(self):
        key = RecordingKey()
        service = service_with(key)
        service.register(1001)
        before = service.metadata()
        key.fail = True
        with self.assertRaisesRegex(ValueError, "signing failure"):
            service.replace(1001, 1002)
        self.assertEqual(service.metadata(), before)
        self.assertTrue(service.is_active(1001))
        self.assertFalse(service.is_known(1002))
        key.fail = False
        service.replace(1001, 1002)
        self.assertEqual(service.epoch, 2)
        AnnouncementChain(trusted_keys={KEY.key_id: KEY_PIN}).backfill(service.announcement_history())

    def test_readers_wait_for_persist_and_observe_only_committed_state(self):
        entered = threading.Event()
        release = threading.Event()
        reader_started = threading.Event()

        class PausingStore(InMemoryAccumulatorStateStore):
            pause = False

            def append_epoch(self, record):
                if self.pause:
                    entered.set()
                    if not release.wait(timeout=10):
                        raise AccumulatorStoreError("test persist timeout")
                super().append_epoch(record)

        store = PausingStore()
        service = service_with(KEY, store)
        service.register(1001)
        before = service._serialize_state()
        store.pause = True
        with ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(service.revoke, 1001)
            try:
                self.assertTrue(entered.wait(timeout=10))
                # White-box checks during the pause prove the live state is
                # unchanged even before the failed/successful save returns.
                self.assertEqual(service._serialize_state(), before)

                def read():
                    reader_started.set()
                    return service.handle_epoch_delta_request({
                        "type": "zkc:epoch-delta-request:v1", "accumulatorId": ACCUMULATOR_ID,
                    })

                reader = pool.submit(read)
                self.assertTrue(reader_started.wait(timeout=10))
                self.assertFalse(reader.done())
            finally:
                release.set()
            writer.result(timeout=10)
            response = reader.result(timeout=10)
        self.assertEqual(response["epoch"], 2)
        self.assert_response_snapshot(response)
        self.assertEqual(response["leaves"], [field_to_hex(0)])


if __name__ == "__main__":
    unittest.main()
