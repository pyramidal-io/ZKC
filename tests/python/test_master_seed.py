"""Canonical AFP-KDC v1.0.1 master-seed handling across ZKC consumers."""

import json
import secrets
import unittest
from unittest import mock

from _path import REPO_ROOT

from zkc_crypto import (
    FIELD_MODULUS,
    MASTER_SEED_PROFILE,
    derive_credential_binding_key,
    derive_holder_commitment_from_seed,
    generate_master_seed,
    master_seed_to_bytes,
    master_seed_to_field,
    master_seed_to_hex,
)
from zkc_crypto.delegation import derive_delegation_signing_key
from zkc_holder import HolderClient, PredicateRegistry, StubBackend
from zkc_crypto.holder_keys import (
    derive_fresh_receipt_key,
    derive_linkable_receipt_key,
    derive_scoped_receipt_key,
)
from zkc_holder.audit_export import derive_authorization_key

AUDITOR_KEY_ID = "did:zkc:auditor:seed-test#key-1"


VECTORS = json.loads(
    (REPO_ROOT / "tests" / "vectors" / "kdc_master_seed_v1.json").read_text()
)


class MasterSeedEncodingTests(unittest.TestCase):
    def test_profile_and_boundary_vectors(self):
        self.assertEqual(MASTER_SEED_PROFILE, VECTORS["profile"])
        self.assertEqual(FIELD_MODULUS, int(VECTORS["fieldModulus"], 16))

        by_name = {case["name"]: case for case in VECTORS["cases"]}
        for case in VECTORS["cases"]:
            seed_hex = case["seed"]
            seed_bytes = bytes.fromhex(seed_hex[2:])
            seed_int = int(seed_hex, 16)
            expected_field = int(case["kdcInput"], 16)

            with self.subTest(case=case["name"]):
                self.assertEqual(master_seed_to_bytes(seed_bytes), seed_bytes)
                self.assertEqual(master_seed_to_bytes(seed_int), seed_bytes)
                self.assertEqual(master_seed_to_bytes(seed_hex), seed_bytes)
                self.assertEqual(master_seed_to_hex(seed_bytes), seed_hex)
                self.assertEqual(master_seed_to_field(seed_bytes), expected_field)
                self.assertEqual(
                    derive_credential_binding_key(seed_bytes),
                    int(case["credentialBindingKey"], 16),
                )
                self.assertEqual(
                    derive_holder_commitment_from_seed(seed_bytes),
                    int(case["holderCommitment"], 16),
                )

        # AFP-KDC v1.0.1 deliberately maps 32-byte seeds modulo r. The profile
        # and vectors make these aliases explicit instead of silently relying
        # on host-language integer coercion.
        for case in VECTORS["cases"]:
            alias_of = case.get("kdcAliasOf")
            if alias_of:
                self.assertEqual(case["kdcInput"], by_name[alias_of]["kdcInput"])

    def test_noncanonical_host_encodings_fail_closed(self):
        invalid = (
            True,
            False,
            -1,
            1 << 256,
            1.0,
            None,
            b"\x00" * 31,
            b"\x00" * 33,
            bytearray(32),
            "0x0",
            "0X" + "00" * 32,
            "0x" + "AA" * 32,
            "00" * 32,
        )
        for seed in invalid:
            with self.subTest(seed=repr(seed)), self.assertRaises((TypeError, ValueError)):
                master_seed_to_bytes(seed)

    def test_generation_preserves_all_256_bits(self):
        entropy = bytes.fromhex(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"
        )
        with mock.patch.object(secrets, "token_bytes", return_value=entropy) as token_bytes:
            self.assertEqual(generate_master_seed(), entropy)
        token_bytes.assert_called_once_with(32)

    def test_byte_domain_consumers_do_not_collapse_kdc_aliases(self):
        zero = 0
        modulus = FIELD_MODULUS
        self.assertEqual(master_seed_to_field(zero), master_seed_to_field(modulus))
        self.assertEqual(
            derive_credential_binding_key(zero), derive_credential_binding_key(modulus)
        )
        self.assertNotEqual(
            derive_authorization_key(zero, AUDITOR_KEY_ID),
            derive_authorization_key(modulus, AUDITOR_KEY_ID),
        )
        self.assertNotEqual(
            derive_linkable_receipt_key(zero, 1), derive_linkable_receipt_key(modulus, 1)
        )
        self.assertNotEqual(
            derive_delegation_signing_key(zero), derive_delegation_signing_key(modulus)
        )

    def test_every_host_consumer_uses_the_same_canonical_seed_bytes(self):
        seed_int = FIELD_MODULUS
        seed_bytes = master_seed_to_bytes(seed_int)
        seed_hex = master_seed_to_hex(seed_int)
        registry = PredicateRegistry.from_repo(REPO_ROOT)

        clients = [
            HolderClient.from_seed(seed, registry, StubBackend())
            for seed in (seed_int, seed_bytes, seed_hex)
        ]
        self.assertTrue(all(client._master_seed == seed_bytes for client in clients))
        self.assertEqual(len({client.get_binding_commitment() for client in clients}), 1)
        self.assertEqual(
            len({client.receipt_public_key(verifier_identity=1)["x"] for client in clients}), 1
        )
        self.assertEqual(
            len(
                {
                    derive_authorization_key(seed, AUDITOR_KEY_ID)
                    for seed in (seed_int, seed_bytes, seed_hex)
                }
            ),
            1,
        )
        self.assertEqual(
            len(
                {
                    derive_delegation_signing_key(seed)
                    for seed in (seed_int, seed_bytes, seed_hex)
                }
            ),
            1,
        )

        for invalid in (-1, 1 << 256, True, b"\x00" * 31, "0x1"):
            with self.subTest(invalid=repr(invalid)):
                for consumer in (
                    derive_credential_binding_key,
                    lambda seed: derive_authorization_key(seed, AUDITOR_KEY_ID),
                    lambda seed: derive_linkable_receipt_key(seed, 1),
                    lambda seed: derive_scoped_receipt_key(seed, 1),
                    lambda seed: derive_fresh_receipt_key(seed, 1),
                    derive_delegation_signing_key,
                ):
                    with self.assertRaises((TypeError, ValueError)):
                        consumer(invalid)
                with self.assertRaises((TypeError, ValueError)):
                    HolderClient.from_seed(invalid, registry, StubBackend())


if __name__ == "__main__":
    unittest.main()
