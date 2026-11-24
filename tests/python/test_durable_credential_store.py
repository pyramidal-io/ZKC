"""Durable SQLite credential store: persistence, recovery, and round trips.

Exercises SQLiteCredentialStore against the same CredentialStore interface the
holder client uses, and asserts the recovery property: reopen the same DB file
in a fresh store instance and every stored credential is intact.
"""

import tempfile
import unittest

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402

from holder_fixtures import issue_kyc_credential
from zkc_holder import SQLiteCredentialStore
from zkc_holder.errors import StorageError


def _credential(credential_id: int, level: int = 2):
    return issue_kyc_credential(master_seed=99, credential_id=credential_id, level=level)


class SQLiteCredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self._path = f"{self._dir.name}/credentials.db"

    def tearDown(self):
        self._dir.cleanup()

    def test_put_get_list_delete(self):
        store = SQLiteCredentialStore(self._path)
        cred = _credential(1)
        store.put(cred)
        fetched = store.get(1)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.credential_id, 1)
        self.assertEqual(fetched.to_dict(), cred.to_dict())
        self.assertEqual(len(store.list()), 1)
        store.delete(1)
        self.assertIsNone(store.get(1))
        self.assertEqual(store.list(), [])
        store.close()

    def test_get_missing_returns_none(self):
        store = SQLiteCredentialStore(self._path)
        self.assertIsNone(store.get(404))
        store.close()

    def test_put_is_upsert(self):
        store = SQLiteCredentialStore(self._path)
        store.put(_credential(1, level=2))
        store.put(_credential(1, level=5))  # same id, new claims
        self.assertEqual(len(store.list()), 1)
        self.assertEqual(store.get(1).claims["level"], 5)
        store.close()

    def test_recovery_reopen_keeps_state(self):
        # Write through one store instance, then reopen the same file fresh.
        store = SQLiteCredentialStore(self._path)
        store.put(_credential(1))
        store.put(_credential(2))
        store.put(_credential(3))
        store.delete(2)
        store.close()

        recovered = SQLiteCredentialStore(self._path)
        ids = sorted(c.credential_id for c in recovered.list())
        self.assertEqual(ids, [1, 3])
        self.assertIsNotNone(recovered.get(1))
        self.assertIsNone(recovered.get(2))
        recovered.close()

    def test_recovery_preserves_full_credential_fidelity(self):
        store = SQLiteCredentialStore(self._path)
        original = _credential(7, level=3)
        store.put(original)
        store.close()

        recovered = SQLiteCredentialStore(self._path)
        restored = recovered.get(7)
        # Round-trips through Credential.to_dict()/from_dict() losslessly.
        self.assertEqual(restored.to_dict(), original.to_dict())
        self.assertEqual(restored.signature, original.signature)
        recovered.close()

    def test_context_manager_closes(self):
        with SQLiteCredentialStore(self._path) as store:
            store.put(_credential(1))
        # File persists after the context manager exits.
        with SQLiteCredentialStore(self._path) as reopened:
            self.assertEqual(len(reopened.list()), 1)

    def test_corrupt_document_is_storage_error(self):
        store = SQLiteCredentialStore(self._path)
        store.put(_credential(1))
        # Corrupt the stored JSON directly.
        store._conn.execute(
            "UPDATE credentials SET document = ? WHERE credential_id = ?",
            ("{not valid json", store._key(1)),
        )
        store._conn.commit()
        with self.assertRaises(StorageError):
            store.get(1)
        store.close()

    def test_drop_in_for_holder_client(self):
        # The store is usable as the holder client's credential store.
        from zkc_crypto import ProofContext, validate_compliance_proof_v1
        from zkc_holder import (
            HolderClient,
            LocalAccumulatorProvider,
            PredicateRegistry,
            ProofRequest,
            StubBackend,
            TrustPolicy,
        )
        from holder_fixtures import KYC_PROOF_TYPE, trusted_test_issuer
        from _path import REPO_ROOT

        provider = LocalAccumulatorProvider()
        store = SQLiteCredentialStore(self._path)
        client = HolderClient.from_seed(
            99,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            store=store,
            accumulator_provider=provider,
        )
        client.store_credential(
            issue_kyc_credential(master_seed=99, credential_id=42, provider=provider)
        )
        # Reopen the store: the holder client recovers the credential.
        store2 = SQLiteCredentialStore(self._path)
        client2 = HolderClient.from_seed(
            99,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            store=store2,
            accumulator_provider=provider,
        )
        self.assertEqual(len(client2.list_credentials()), 1)
        envelope = generate_unauthenticated_linkable(
            client2, ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters={
                    KYC_PROOF_TYPE: {
                        "requiredLevel": 1,
                        "requiredAttributes": [True, False, True, False, False],
                    }
                },
                context=ProofContext.verifier_session("verifier.example", 555, 1_700_000),
                trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
            )
        )
        validate_compliance_proof_v1(envelope)
        store.close()
        store2.close()


if __name__ == "__main__":
    unittest.main()
