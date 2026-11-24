"""Credential stores: issuer-qualified keys, framed MAC, and safe file writes.

Regression tests for security review 2026-10-04 R3.9:

* A second issuer that reuses a credential id no longer evicts the first
  issuer's credential. Every store keys by ``(issuer_id, credential_id)``; a
  lookup by credential id alone refuses (``AMBIGUOUS_CREDENTIAL``) rather than
  guess, and every holder path that knows the credential names its issuer.
* ``EncryptedFileCredentialStore`` v2 authenticates a length-framed header.
  A wrapper whose nonce/ciphertext boundary is shifted fails the MAC, and a
  nonce of any length other than 16 bytes fails authentication even with a
  MAC computed for it.
* Store files are written through an exclusive 0600 temporary file and an
  atomic rename. A planted ``<name>.tmp`` symlink is never followed and a
  symlink at the store path is refused.
* Existing v1 stores (encrypted file and SQLite) migrate without data loss and
  fail closed on any inconsistency.
"""

import hashlib
import hmac
import json
import os
import pathlib
import secrets
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock

import _path  # noqa: F401  (sys.path side effect)
from _path import REPO_ROOT
from holder_fixtures import (
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    generate_unauthenticated_linkable,
    issue_kyc_credential,
    trusted_test_issuer,
)
from test_rebind_auth_verifier import (
    CREDENTIAL_ID as REBIND_CREDENTIAL_ID,
    ISSUER_ID as REBIND_ISSUER_ID,
    KEY_X,
    KEY_Y,
    MASTER_SEED as REBIND_MASTER_SEED,
    SESSION_ID,
    TIMESTAMP,
    RebindAuthVerifierBase,
)
from zkc_crypto import ProofContext, field_to_hex, sign_apr, validate_compliance_proof_v1
from zkc_crypto.presentation import LINKABLE_PROFILE
from zkc_holder import (
    AmbiguousCredentialError,
    EncryptedFileCredentialStore,
    HolderClient,
    InMemoryCredentialStore,
    LifecycleManager,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    RebindSecret,
    SQLiteCredentialStore,
    StorageError,
    StubBackend,
    TrustPolicy,
    TrustedIssuer,
)
from zkc_holder import store as store_module
from zkc_holder.predicates import REBIND_AUTH_PROOF_TYPE
from zkc_holder.accumulator import MAX_EPOCH_LAG
from zkc_verifier import VerificationRequest

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
MASTER_SEED = 42
OTHER_ISSUER_ID = "did:zkc:issuer:other"
PASSPHRASE = b"correct horse"
POSIX_MODES = os.name == "posix" and hasattr(os, "fchmod")
APR_PRIVATE_KEY = 0xA9701


def _bank(credential_id=7, level=2, provider=None):
    return issue_kyc_credential(
        master_seed=MASTER_SEED, credential_id=credential_id, level=level, provider=provider
    )


def _other(credential_id=7, level=1, provider=None):
    return issue_kyc_credential(
        master_seed=MASTER_SEED,
        credential_id=credential_id,
        level=level,
        issuer_id=OTHER_ISSUER_ID,
        provider=provider,
    )


# --- (a) issuer-qualified keys, identical across every store -----------------


class _StoreKeyingContract:
    """Run against each bundled CredentialStore (subclasses set make_store)."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def make_store(self):
        raise NotImplementedError

    def test_same_id_from_another_issuer_is_stored_alongside(self):
        store = self.make_store()
        store.put(_bank())
        store.put(_other())
        stored = {(c.issuer_id, c.credential_id) for c in store.list()}
        self.assertEqual(stored, {(TEST_ISSUER_ID, 7), (OTHER_ISSUER_ID, 7)})
        self.assertEqual(store.get(7, issuer_id=TEST_ISSUER_ID).claims["level"], 2)
        self.assertEqual(store.get(7, issuer_id=OTHER_ISSUER_ID).claims["level"], 1)

    def test_id_only_lookup_refuses_to_guess(self):
        store = self.make_store()
        store.put(_bank())
        store.put(_other())
        with self.assertRaises(AmbiguousCredentialError) as ctx:
            store.get(7)
        self.assertEqual(ctx.exception.code, "AMBIGUOUS_CREDENTIAL")
        with self.assertRaises(AmbiguousCredentialError):
            store.delete(7)
        self.assertEqual(len(store.list()), 2)  # nothing was dropped

    def test_issuer_qualified_delete_keeps_the_other_issuer(self):
        store = self.make_store()
        store.put(_bank())
        store.put(_other())
        store.delete(7, issuer_id=OTHER_ISSUER_ID)
        remaining = store.get(7)  # unambiguous again
        self.assertEqual(remaining.issuer_id, TEST_ISSUER_ID)
        self.assertIsNone(store.get(7, issuer_id=OTHER_ISSUER_ID))
        store.delete(7, issuer_id=OTHER_ISSUER_ID)  # absent: no-op
        self.assertEqual(len(store.list()), 1)

    def test_same_issuer_and_id_replaces(self):
        store = self.make_store()
        store.put(_bank(level=2))
        store.put(_bank(level=5))
        self.assertEqual(len(store.list()), 1)
        self.assertEqual(store.get(7).claims["level"], 5)

    def test_credential_id_zero_is_an_ordinary_key(self):
        store = self.make_store()
        store.put(_bank(credential_id=0))
        self.assertEqual(store.get(0).credential_id, 0)
        self.assertEqual(store.get(0, issuer_id=TEST_ISSUER_ID).credential_id, 0)
        store.delete(0)
        self.assertIsNone(store.get(0))

    def test_unknown_issuer_or_id_is_absent(self):
        store = self.make_store()
        store.put(_bank())
        self.assertIsNone(store.get(8))
        self.assertIsNone(store.get(7, issuer_id="did:zkc:issuer:unknown"))


class InMemoryKeyingTests(_StoreKeyingContract, unittest.TestCase):
    def make_store(self):
        return InMemoryCredentialStore()


class EncryptedFileKeyingTests(_StoreKeyingContract, unittest.TestCase):
    def make_store(self):
        return EncryptedFileCredentialStore(self.directory / "creds.json", PASSPHRASE)

    def test_coexisting_credentials_survive_reopen(self):
        path = self.directory / "creds.json"
        EncryptedFileCredentialStore(path, PASSPHRASE).put(_bank())
        EncryptedFileCredentialStore(path, PASSPHRASE).put(_other())
        reopened = EncryptedFileCredentialStore(path, PASSPHRASE)
        self.assertEqual(len(reopened.list()), 2)


class SQLiteKeyingTests(_StoreKeyingContract, unittest.TestCase):
    def make_store(self):
        store = SQLiteCredentialStore(self.directory / "creds.db")
        self.addCleanup(store.close)
        return store

    def test_coexisting_credentials_survive_reopen(self):
        path = self.directory / "creds.db"
        with SQLiteCredentialStore(path) as store:
            store.put(_bank())
            store.put(_other())
        with SQLiteCredentialStore(path) as reopened:
            self.assertEqual(len(reopened.list()), 2)


class HolderClientKeyingTests(unittest.TestCase):
    """The review PoC through the holder client, plus every id lookup site."""

    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.client = HolderClient.from_seed(
            MASTER_SEED, REGISTRY, StubBackend(), accumulator_provider=self.provider
        )
        self.client.store_credential(_bank(provider=self.provider))
        self.client.store_credential(_other(provider=self.provider))

    def test_other_issuer_does_not_evict_the_first(self):
        stored = {(c.issuer_id, c.credential_id) for c in self.client.list_credentials()}
        self.assertEqual(stored, {(TEST_ISSUER_ID, 7), (OTHER_ISSUER_ID, 7)})

    def test_update_witness_and_remove_need_the_issuer_when_ids_collide(self):
        with self.assertRaises(AmbiguousCredentialError):
            self.client.update_witness(7)
        with self.assertRaises(AmbiguousCredentialError):
            self.client.remove_credential(7)
        witness = self.client.update_witness(7, issuer_id=OTHER_ISSUER_ID)
        self.assertIsNotNone(witness)
        self.client.remove_credential(7, issuer_id=OTHER_ISSUER_ID)
        self.assertEqual(
            [c.issuer_id for c in self.client.list_credentials()], [TEST_ISSUER_ID]
        )

    def test_proof_generation_refreshes_the_selected_issuers_credential(self):
        request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 2,
                    "requiredAttributes": [True, False, True, False, False],
                }
            },
            context=ProofContext.verifier_session("verifier.example", 555, 1_700_000),
            trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
        )
        envelope = generate_unauthenticated_linkable(self.client, request)
        validate_compliance_proof_v1(envelope)

    def test_lifecycle_tick_refreshes_each_colliding_credential(self):
        for issuer_id in (TEST_ISSUER_ID, OTHER_ISSUER_ID):
            self.client.update_witness(7, issuer_id=issuer_id)
            for filler in range(1, MAX_EPOCH_LAG + 2):  # churn past the lag bound
                self.provider.register(issuer_id, 10_000 + filler)
        manager = LifecycleManager(self.client, self.provider)
        self.assertEqual({h.state for h in manager.assess(1_000)}, {"stale"})
        report = manager.tick(now=1_000)
        self.assertEqual(report.refresh_failed, [])
        self.assertEqual(sorted(report.refreshed), [(OTHER_ISSUER_ID, 7), (TEST_ISSUER_ID, 7)])
        self.assertEqual({h.state for h in manager.assess(1_000)}, {"fresh"})


class RebindCredentialIdCollisionTests(RebindAuthVerifierBase):
    """Authenticated rebind names only a credentialId: never guess between issuers."""

    def holder(self, *credentials):
        holder = HolderClient.from_seed(REBIND_MASTER_SEED, REGISTRY, StubBackend())
        for credential in credentials:
            holder.store_credential(credential)
        return holder

    def trust_policy(self, *issuer_ids):
        return TrustPolicy(
            issuers=tuple(
                TrustedIssuer(
                    issuer_id=issuer_id,
                    public_key_x=KEY_X,
                    public_key_y=KEY_Y,
                    proof_types=(REBIND_AUTH_PROOF_TYPE,),
                )
                for issuer_id in issuer_ids
            )
        )

    def apr(self, parameters):
        return sign_apr(
            {
                "request": {
                    "proofTypes": [REBIND_AUTH_PROOF_TYPE],
                    "parameters": {REBIND_AUTH_PROOF_TYPE: dict(parameters)},
                    "context": {
                        "profile": self.context.profile,
                        "verifierId": "verifier.example",
                        "sessionId": field_to_hex(SESSION_ID),
                        "timestamp": TIMESTAMP,
                    },
                    "trustPolicy": {"issuers": []},
                    "presentation": {"profile": LINKABLE_PROFILE},
                },
                "verifierId": "verifier.example",
                "nonce": field_to_hex(0xABC124),
                "issuedAt": TIMESTAMP,
                "expiresAt": TIMESTAMP + 3600,
            },
            APR_PRIVATE_KEY,
        )

    def request(self, parameters, *issuer_ids):
        return ProofRequest(
            proof_types=[REBIND_AUTH_PROOF_TYPE],
            parameters={REBIND_AUTH_PROOF_TYPE: dict(parameters)},
            context=self.context,
            trust_policy=self.trust_policy(*issuer_ids),
            presentation_profile=LINKABLE_PROFILE,
            rebind_secret=RebindSecret(self.new_cbk),
        )

    def colliding(self):
        return self._credential(issuer_id=OTHER_ISSUER_ID)

    def test_untrusted_colliding_issuer_does_not_block_or_replace_rebind(self):
        parameters = {"credentialId": REBIND_CREDENTIAL_ID}
        holder = self.holder(self.credential, self.colliding())
        self.assertEqual(len(holder.list_credentials()), 2)
        apr = self.apr(parameters)
        result = holder.generate_authenticated_proof(
            apr, self.request(parameters, REBIND_ISSUER_ID), now=TIMESTAMP
        )
        verification = self.verifier().verify_authenticated(
            apr,
            result["envelope"],
            VerificationRequest(
                proof_types=[REBIND_AUTH_PROOF_TYPE],
                parameters={REBIND_AUTH_PROOF_TYPE: dict(parameters)},
                context=self.context,
                max_proof_age=3600,
                accumulator_states={REBIND_ISSUER_ID: self.authenticated_state},
            ),
            now=TIMESTAMP,
        )
        self.assertTrue(verification.valid, verification.to_dict())

    def test_two_trusted_issuers_with_the_same_id_are_refused(self):
        parameters = {"credentialId": REBIND_CREDENTIAL_ID}
        holder = self.holder(self.credential, self.colliding())
        with self.assertRaises(AmbiguousCredentialError):
            holder.generate_authenticated_proof(
                self.apr(parameters),
                self.request(parameters, REBIND_ISSUER_ID, OTHER_ISSUER_ID),
                now=TIMESTAMP,
            )


# --- (c) framed MAC, fixed nonce length, and format migration ----------------


def _legacy_v1_wrapper(passphrase: bytes, payload: dict, nonce_bytes: int = 16) -> dict:
    """The pre-R3.9 construction: MAC over nonce || ciphertext, no framing."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(nonce_bytes)
    material = hashlib.pbkdf2_hmac("sha256", passphrase, salt, 600_000, dklen=64)
    enc_key, mac_key = material[:32], material[32:]
    plaintext = json.dumps(payload, sort_keys=True).encode()
    ciphertext = bytes(
        a ^ b for a, b in zip(plaintext, store_module._keystream(enc_key, nonce, len(plaintext)))
    )
    return {
        "format": "zkc-credential-store:v1",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "mac": hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).hexdigest(),
    }


class EncryptedFileFormatTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self._dir.name)
        self.path = self.directory / "creds.json"
        self.store = EncryptedFileCredentialStore(self.path, PASSPHRASE)
        self.store.put(_bank())
        self.wrapper = json.loads(self.path.read_text())

    def tearDown(self):
        self._dir.cleanup()

    def write(self, wrapper):
        self.path.write_text(json.dumps(wrapper))

    def assert_authentication_fails(self):
        with self.assertRaises(StorageError) as ctx:
            EncryptedFileCredentialStore(self.path, PASSPHRASE).list()
        self.assertIn("authentication failed", str(ctx.exception))

    def test_written_format_is_v2_with_explicit_kdf(self):
        self.assertEqual(
            set(self.wrapper),
            {"format", "kdf", "iterations", "salt", "nonce", "ciphertext", "mac"},
        )
        self.assertEqual(self.wrapper["format"], "zkc-credential-store:v2")
        self.assertEqual(self.wrapper["kdf"], "pbkdf2-hmac-sha256")
        self.assertEqual(self.wrapper["iterations"], 600_000)
        self.assertEqual(len(bytes.fromhex(self.wrapper["salt"])), 16)
        self.assertEqual(len(bytes.fromhex(self.wrapper["nonce"])), 16)

    def test_boundary_shifted_wrapper_fails_the_mac(self):
        # The review PoC: move one byte from the ciphertext into the nonce.
        # The unframed v1 MAC input was unchanged by this.
        nonce, ciphertext = self.wrapper["nonce"], self.wrapper["ciphertext"]
        self.write(dict(self.wrapper, nonce=nonce + ciphertext[:2], ciphertext=ciphertext[2:]))
        self.assert_authentication_fails()
        self.write(dict(self.wrapper, nonce=nonce[:-2], ciphertext=nonce[-2:] + ciphertext))
        self.assert_authentication_fails()

    def test_nonce_of_any_other_length_fails_even_with_a_matching_mac(self):
        salt = bytes.fromhex(self.wrapper["salt"])
        ciphertext = bytes.fromhex(self.wrapper["ciphertext"])
        _, mac_key = self.store._derive_v2_keys(salt)
        for length in (0, 15, 17, 32):
            with self.subTest(nonce_length=length):
                nonce = secrets.token_bytes(length)
                # A tag computed over the framed header for this nonce: only
                # the length rule can reject it.
                tag = hmac.new(
                    mac_key, store_module._v2_mac_input(salt, nonce, ciphertext), hashlib.sha256
                ).hexdigest()
                self.write(dict(self.wrapper, nonce=nonce.hex(), mac=tag))
                self.assert_authentication_fails()

    def test_header_fields_are_authenticated_or_pinned(self):
        cases = {
            "iterations": dict(self.wrapper, iterations=1),
            "kdf": dict(self.wrapper, kdf="scrypt"),
            "extra field": dict(self.wrapper, comment="x"),
            "salt length": dict(self.wrapper, salt=self.wrapper["salt"][:-2]),
            "uppercase hex": dict(self.wrapper, nonce=self.wrapper["nonce"].upper()),
        }
        for name, wrapper in cases.items():
            with self.subTest(case=name):
                self.write(wrapper)
                with self.assertRaises(StorageError):
                    EncryptedFileCredentialStore(self.path, PASSPHRASE).list()

    def test_v2_mac_input_recut_as_a_v1_wrapper_fails_authentication(self):
        # Without per-format keys, the v2 tag also verified the unframed v1
        # input nonce || ciphertext cut from the v2 MAC input, and the store
        # failed only at JSON decoding. It must fail the MAC itself.
        salt = bytes.fromhex(self.wrapper["salt"])
        mac_input = store_module._v2_mac_input(
            salt,
            bytes.fromhex(self.wrapper["nonce"]),
            bytes.fromhex(self.wrapper["ciphertext"]),
        )
        self.write({
            "format": "zkc-credential-store:v1",
            "salt": self.wrapper["salt"],
            "nonce": mac_input[:16].hex(),
            "ciphertext": mac_input[16:].hex(),
            "mac": self.wrapper["mac"],
        })
        self.assert_authentication_fails()

    def test_v2_keys_are_label_separated_from_the_v1_split(self):
        salt = bytes.fromhex(self.wrapper["salt"])
        v2_enc, v2_mac = self.store._derive_v2_keys(salt)
        v1_enc, v1_mac = self.store._derive_v1_keys(salt)
        self.assertEqual(len({v2_enc, v2_mac, v1_enc, v1_mac}), 4)
        master = hashlib.pbkdf2_hmac("sha256", PASSPHRASE, salt, 600_000, dklen=32)
        self.assertEqual(
            v2_enc, hmac.new(master, b"zkc/credential-store/v2/enc", hashlib.sha256).digest()
        )
        self.assertEqual(
            v2_mac, hmac.new(master, b"zkc/credential-store/v2/mac", hashlib.sha256).digest()
        )

    def test_v2_wrapper_relabelled_as_v1_fails_authentication(self):
        downgraded = {
            key: value for key, value in self.wrapper.items() if key not in ("kdf", "iterations")
        }
        downgraded["format"] = "zkc-credential-store:v1"
        self.write(downgraded)
        self.assert_authentication_fails()

    def test_v1_store_is_migrated_to_v2_without_loss(self):
        bank, zero = _bank(), _bank(credential_id=0, level=3)
        payload = {f"{c.credential_id:#066x}": c.to_dict() for c in (bank, zero)}
        self.write(_legacy_v1_wrapper(PASSPHRASE, payload))
        store = EncryptedFileCredentialStore(self.path, PASSPHRASE)
        self.assertEqual(store.get(7).to_dict(), bank.to_dict())
        self.assertEqual(store.get(0).to_dict(), zero.to_dict())
        migrated = json.loads(self.path.read_text())
        self.assertEqual(migrated["format"], "zkc-credential-store:v2")
        # The migrated store keys by issuer: another issuer's id 7 coexists.
        store.put(_other())
        self.assertEqual(len(EncryptedFileCredentialStore(self.path, PASSPHRASE).list()), 3)

    def test_v1_store_with_a_mismatched_key_fails_closed_unchanged(self):
        bank = _bank()
        payload = {f"{8:#066x}": bank.to_dict()}  # key names a different id
        self.write(_legacy_v1_wrapper(PASSPHRASE, payload))
        before = self.path.read_bytes()
        with self.assertRaises(StorageError):
            EncryptedFileCredentialStore(self.path, PASSPHRASE).list()
        self.assertEqual(self.path.read_bytes(), before)

    def test_v1_store_with_a_wrong_nonce_length_fails_authentication(self):
        payload = {f"{7:#066x}": _bank().to_dict()}
        for length in (0, 15, 17, 32):
            with self.subTest(nonce_length=length):
                self.write(_legacy_v1_wrapper(PASSPHRASE, payload, nonce_bytes=length))
                self.assert_authentication_fails()

    def test_duplicate_issuer_and_id_in_a_v2_payload_fails_closed(self):
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
        enc_key, mac_key = self.store._derive_v2_keys(salt)
        plaintext = json.dumps([_bank().to_dict(), _bank(level=4).to_dict()]).encode()
        ciphertext = bytes(
            a ^ b for a, b in zip(plaintext, store_module._keystream(enc_key, nonce, len(plaintext)))
        )
        tag = hmac.new(
            mac_key, store_module._v2_mac_input(salt, nonce, ciphertext), hashlib.sha256
        ).hexdigest()
        self.write(dict(
            self.wrapper, salt=salt.hex(), nonce=nonce.hex(), ciphertext=ciphertext.hex(), mac=tag
        ))
        with self.assertRaises(StorageError):
            EncryptedFileCredentialStore(self.path, PASSPHRASE).list()


# --- (d) safe writes and private file modes ---------------------------------


@unittest.skipUnless(hasattr(os, "symlink"), "platform has no symbolic links")
class SafeWriteTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self._dir.name)
        self.path = self.directory / "creds.json"
        self.victim = self.directory / "victim.txt"
        self.victim.write_text("precious")

    def tearDown(self):
        self._dir.cleanup()

    def test_planted_tmp_symlink_is_not_followed(self):
        # The review PoC: the old writer opened the predictable creds.tmp.
        planted = self.directory / "creds.tmp"
        planted.symlink_to(self.victim)
        EncryptedFileCredentialStore(self.path, PASSPHRASE).put(_bank())
        self.assertEqual(self.victim.read_text(), "precious")
        self.assertTrue(planted.is_symlink())
        self.assertEqual(os.readlink(planted), str(self.victim))
        self.assertFalse(self.path.is_symlink())
        self.assertTrue(stat.S_ISREG(os.lstat(self.path).st_mode))
        self.assertEqual(len(EncryptedFileCredentialStore(self.path, PASSPHRASE).list()), 1)

    def test_symlink_at_the_store_path_is_refused(self):
        self.path.symlink_to(self.victim)
        store = EncryptedFileCredentialStore(self.path, PASSPHRASE)
        with self.assertRaises(StorageError):
            store.put(_bank())
        with self.assertRaises(StorageError):
            store.list()
        self.assertEqual(self.victim.read_text(), "precious")
        self.assertTrue(self.path.is_symlink())

    def test_symlink_at_the_sqlite_path_is_refused(self):
        database = self.directory / "creds.db"
        database.symlink_to(self.victim)
        with self.assertRaises(StorageError):
            SQLiteCredentialStore(database)
        self.assertEqual(self.victim.read_text(), "precious")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no FIFOs")
    def test_fifo_swapped_in_after_the_check_is_refused_without_blocking(self):
        os.mkfifo(self.path)
        # Simulate the swap after lstat: only O_NONBLOCK + fstat stand between
        # the store and a blocking open of a non-regular file.
        with mock.patch.object(store_module, "_refuse_symlink", lambda path: None):
            with self.assertRaises(StorageError) as ctx:
                EncryptedFileCredentialStore(self.path, PASSPHRASE).list()
        self.assertIn("not a regular file", str(ctx.exception))

    def test_directory_sync_failure_says_the_file_was_replaced(self):
        store = EncryptedFileCredentialStore(self.path, PASSPHRASE)
        with mock.patch.object(
            store_module, "_fsync_directory", side_effect=OSError("sync failed")
        ):
            with self.assertRaises(StorageError) as ctx:
                store.put(_bank())
        self.assertIn("was replaced", str(ctx.exception))
        self.assertEqual(len(store.list()), 1)

    @unittest.skipUnless(
        POSIX_MODES and hasattr(os, "geteuid") and os.geteuid() != 0,
        "needs POSIX permissions enforced for a non-root user",
    )
    def test_v1_store_in_a_read_only_directory_says_migration_is_needed(self):
        payload = {f"{7:#066x}": _bank().to_dict()}
        self.path.write_text(json.dumps(_legacy_v1_wrapper(PASSPHRASE, payload)))
        before = self.path.read_bytes()
        os.chmod(self.directory, 0o555)
        try:
            with self.assertRaises(StorageError) as ctx:
                EncryptedFileCredentialStore(self.path, PASSPHRASE).list()
        finally:
            os.chmod(self.directory, 0o755)
        self.assertIn("requires migration to v2", str(ctx.exception))
        self.assertIn("directory is not writable", str(ctx.exception))
        self.assertEqual(self.path.read_bytes(), before)

    def test_sqlite_path_swapped_during_open_is_refused(self):
        database = self.directory / "creds.db"
        with mock.patch.object(
            store_module, "_prepare_private_database", return_value=(-1, -1)
        ):
            with self.assertRaises(StorageError) as ctx:
                SQLiteCredentialStore(database)
        self.assertIn("changed while it was being opened", str(ctx.exception))

    @unittest.skipUnless(POSIX_MODES, "platform has no POSIX file modes")
    def test_existing_sqlite_files_are_made_private(self):
        database = self.directory / "creds.db"
        holder = sqlite3.connect(database)  # keeps the -wal file alive
        self.addCleanup(holder.close)
        holder.execute("PRAGMA journal_mode=WAL")
        holder.execute("CREATE TABLE scratch (x)")
        holder.execute("INSERT INTO scratch VALUES (1)")
        holder.commit()
        wal = pathlib.Path(str(database) + "-wal")
        self.assertTrue(wal.exists())
        os.chmod(database, 0o644)
        os.chmod(wal, 0o644)
        with SQLiteCredentialStore(database) as store:
            store.put(_bank())
        self.assertEqual(stat.S_IMODE(os.stat(database).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(wal).st_mode), 0o600)

    @unittest.skipUnless(POSIX_MODES, "platform has no POSIX file modes")
    def test_file_prefixed_sqlite_path_is_an_ordinary_private_path(self):
        previous = os.getcwd()
        os.chdir(self.directory)
        self.addCleanup(os.chdir, previous)
        with SQLiteCredentialStore("file:x.db") as store:
            store.put(_bank())
        literal = self.directory / "file:x.db"
        self.assertTrue(literal.exists())
        self.assertEqual(stat.S_IMODE(os.stat(literal).st_mode), 0o600)

    def test_no_temporary_file_is_left_behind(self):
        store = EncryptedFileCredentialStore(self.path, PASSPHRASE)
        store.put(_bank())
        store.put(_other())
        store.delete(7, issuer_id=OTHER_ISSUER_ID)
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()),
                         ["creds.json", "victim.txt"])

    @unittest.skipUnless(POSIX_MODES, "platform has no POSIX file modes")
    def test_store_files_are_private(self):
        previous = os.umask(0o022)
        try:
            store = EncryptedFileCredentialStore(self.path, PASSPHRASE)
            store.put(_bank())
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
            os.chmod(self.path, 0o644)  # a rewrite replaces it with a private file
            store.put(_other())
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
            database = self.directory / "creds.db"
            with SQLiteCredentialStore(database) as sqlite_store:
                sqlite_store.put(_bank())
                self.assertEqual(stat.S_IMODE(os.stat(database).st_mode), 0o600)
        finally:
            os.umask(previous)


# --- SQLite schema migration --------------------------------------------------


class SQLiteMigrationTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self._dir.name) / "creds.db"

    def tearDown(self):
        self._dir.cleanup()

    def make_v1(self, rows, version="1"):
        """The pre-R3.9 schema: credentials keyed by credential id alone."""
        conn = sqlite3.connect(self.path)
        conn.execute(
            "CREATE TABLE credentials (credential_id TEXT PRIMARY KEY, document TEXT NOT NULL)"
        )
        conn.execute("CREATE TABLE store_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT INTO store_meta(key, value) VALUES('version', ?)", (version,))
        for key, document in rows:
            conn.execute("INSERT INTO credentials VALUES(?, ?)", (key, document))
        conn.commit()
        conn.close()

    def snapshot(self):
        conn = sqlite3.connect(self.path)
        try:
            return (
                [r[1] for r in conn.execute("PRAGMA table_info(credentials)")],
                sorted(conn.execute("SELECT * FROM credentials").fetchall()),
                conn.execute("SELECT value FROM store_meta WHERE key='version'").fetchone()[0],
            )
        finally:
            conn.close()

    @staticmethod
    def row(credential, key=None):
        key = f"{credential.credential_id:#066x}" if key is None else key
        return key, json.dumps(credential.to_dict(), sort_keys=True)

    def test_v1_database_is_migrated_without_loss(self):
        bank, zero = _bank(), _bank(credential_id=0, level=3)
        self.make_v1([self.row(bank), self.row(zero)])
        with SQLiteCredentialStore(self.path) as store:
            self.assertEqual(store.get(7).to_dict(), bank.to_dict())
            self.assertEqual(store.get(0).to_dict(), zero.to_dict())
            store.put(_other())
            self.assertEqual(len(store.list()), 3)
        columns, rows, version = self.snapshot()
        self.assertEqual(columns, ["issuer_id", "credential_id", "document"])
        self.assertEqual(version, "2")
        self.assertEqual(len(rows), 3)
        with SQLiteCredentialStore(self.path) as reopened:  # idempotent
            self.assertEqual(len(reopened.list()), 3)

    def test_v1_row_that_does_not_match_its_key_fails_closed_unchanged(self):
        self.make_v1([self.row(_bank(), key=f"{8:#066x}")])
        before = self.snapshot()
        with self.assertRaises(StorageError):
            SQLiteCredentialStore(self.path)
        self.assertEqual(self.snapshot(), before)

    def test_corrupt_v1_row_fails_closed_unchanged(self):
        self.make_v1([(f"{7:#066x}", "{not json")])
        before = self.snapshot()
        with self.assertRaises(StorageError):
            SQLiteCredentialStore(self.path)
        self.assertEqual(self.snapshot(), before)

    def test_unknown_schema_version_fails_closed(self):
        self.make_v1([self.row(_bank())], version="3")
        with self.assertRaises(StorageError):
            SQLiteCredentialStore(self.path)


if __name__ == "__main__":
    unittest.main()
