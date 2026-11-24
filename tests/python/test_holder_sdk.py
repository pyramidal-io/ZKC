"""Holder SDK unit + integration tests (stub backend; no toolchain needed)."""

import hashlib
import json
import logging
import pathlib
import tempfile
import unittest

from _path import REPO_ROOT
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402

from holder_fixtures import (
    KYC_PROOF_TYPE,
    TEST_ISSUER_ID,
    issue_kyc_credential,
    trusted_test_issuer,
)
from zkc_crypto import ProofContext, field_to_hex, validate_compliance_proof_v1
from zkc_crypto.poseidon2 import poseidon2
from zkc_holder import (
    BackendUnavailableError,
    ConsentRequiredError,
    ConstraintViolationError,
    ContextError,
    EncryptedFileCredentialStore,
    HolderClient,
    LocalAccumulatorProvider,
    NoMatchingCredentialError,
    OpaquePredicateError,
    PredicateRegistry,
    ProofRequest,
    StaleCredentialError,
    StaleWitnessError,
    StorageError,
    StubBackend,
    TrustPolicy,
    UnknownIssuerError,
)
from zkc_holder.aggregation import aggregate_commitments, aggregated_claim_binding

MASTER_SEED = 42
REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)


def make_request(**overrides):
    defaults = dict(
        proof_types=[KYC_PROOF_TYPE],
        parameters={
            KYC_PROOF_TYPE: {
                "requiredLevel": 1,
                "requiredAttributes": [True, False, True, False, False],
            }
        },
        context=ProofContext.verifier_session("verifier.example", 555, 1_700_000),
        trust_policy=TrustPolicy(issuers=(trusted_test_issuer(),)),
        max_proof_age=3600,
    )
    defaults.update(overrides)
    return ProofRequest(**defaults)


def make_client(provider=None, store=None):
    return HolderClient.from_seed(
        MASTER_SEED,
        REGISTRY,
        StubBackend(),
        store=store,
        accumulator_provider=provider,
    )


class RegistryTests(unittest.TestCase):
    def test_registry_resolves_reviewed_predicates(self):
        entry = REGISTRY.resolve(KYC_PROOF_TYPE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.circuit, "zkc_kyc")
        self.assertTrue((REPO_ROOT / entry.source_path).is_file())

    def test_registry_covers_all_published_encoders(self):
        encoder_dir = REPO_ROOT / "schemas" / "public-inputs"
        published = set()
        for path in encoder_dir.glob("*.json"):
            published.update(json.loads(path.read_text())["proofTypes"])
        self.assertEqual(set(REGISTRY.proof_types()), published)

    def test_unknown_predicate_is_opaque(self):
        self.assertIsNone(REGISTRY.resolve("zkc:proof:secret-scoring:v1"))


class StoreTests(unittest.TestCase):
    def test_encrypted_store_roundtrip(self):
        credential = issue_kyc_credential(master_seed=MASTER_SEED, credential_id=42)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "store.json"
            store = EncryptedFileCredentialStore(path, b"correct horse")
            store.put(credential)
            loaded = EncryptedFileCredentialStore(path, b"correct horse").get(42)
            self.assertEqual(loaded.to_dict(), credential.to_dict())
            # Ciphertext at rest: plaintext markers must not appear on disk.
            raw = path.read_text()
            self.assertNotIn("holderCommitment", raw)
            self.assertNotIn(field_to_hex(credential.holder_commitment), raw)

    def test_wrong_passphrase_fails_closed(self):
        credential = issue_kyc_credential(master_seed=MASTER_SEED, credential_id=42)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "store.json"
            EncryptedFileCredentialStore(path, b"right").put(credential)
            with self.assertRaises(StorageError):
                EncryptedFileCredentialStore(path, b"wrong").list()

    def test_tampered_store_fails_closed(self):
        credential = issue_kyc_credential(master_seed=MASTER_SEED, credential_id=42)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "store.json"
            store = EncryptedFileCredentialStore(path, b"pass")
            store.put(credential)
            wrapper = json.loads(path.read_text())
            ciphertext = bytearray.fromhex(wrapper["ciphertext"])
            ciphertext[0] ^= 1
            wrapper["ciphertext"] = ciphertext.hex()
            path.write_text(json.dumps(wrapper))
            with self.assertRaises(StorageError):
                store.list()


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.client = make_client(self.provider)

    def test_no_credentials_fails(self):
        with self.assertRaises(NoMatchingCredentialError):
            self.client.select_credential(make_request(), KYC_PROOF_TYPE)

    def test_unknown_issuer_fails(self):
        credential = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=42, provider=self.provider,
            issuer_id="did:zkc:unknown-issuer",
        )
        self.client.store_credential(credential)
        with self.assertRaises(UnknownIssuerError):
            self.client.select_credential(make_request(), KYC_PROOF_TYPE)

    def test_expired_credential_fails(self):
        credential = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=42, provider=self.provider,
            expires_at=100,  # before the request timestamp
        )
        self.client.store_credential(credential)
        with self.assertRaises(StaleCredentialError):
            self.client.select_credential(make_request(), KYC_PROOF_TYPE)

    def test_insufficient_level_fails(self):
        credential = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=42, provider=self.provider, level=1
        )
        self.client.store_credential(credential)
        request = make_request(
            parameters={KYC_PROOF_TYPE: {"requiredLevel": 3,
                                         "requiredAttributes": [False] * 5}}
        )
        with self.assertRaises(NoMatchingCredentialError):
            self.client.select_credential(request, KYC_PROOF_TYPE)

    def test_minimal_disclosure_prefers_lowest_satisfying_level(self):
        low = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=1, provider=self.provider, level=2
        )
        high = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=2, provider=self.provider, level=3
        )
        self.client.store_credential(low)
        self.client.store_credential(high)
        selected = self.client.select_credential(make_request(), KYC_PROOF_TYPE)
        self.assertEqual(selected.credential_id, 1)

    def test_wrong_holder_credential_rejected_at_store(self):
        foreign = issue_kyc_credential(master_seed=99, credential_id=7)
        with self.assertRaises(Exception):
            self.client.store_credential(foreign)


class ProofGenerationTests(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.client = make_client(self.provider)
        self.credential = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=42, provider=self.provider
        )
        self.client.store_credential(self.credential)

    def test_issuer_to_holder_envelope_roundtrip(self):
        envelope = generate_unauthenticated_linkable(self.client, make_request())
        validate_compliance_proof_v1(envelope)
        self.assertEqual(envelope["proofs"][0]["proofType"], KYC_PROOF_TYPE)
        self.assertTrue(envelope["proofs"][0]["proof"].startswith("zkc:stub:v1:"))
        public_inputs = envelope["proofs"][0]["publicInputs"]
        self.assertEqual(
            public_inputs["holder_commitment"],
            field_to_hex(self.client.get_binding_commitment()),
        )
        self.assertEqual(
            public_inputs["proof_context"],
            envelope["metadata"]["context"]["value"],
        )

    def test_no_secrets_in_envelope(self):
        envelope = generate_unauthenticated_linkable(self.client, make_request())
        serialized = json.dumps(envelope)
        from zkc_crypto import derive_credential_binding_key
        self.assertNotIn(field_to_hex(MASTER_SEED), serialized)
        self.assertNotIn(
            field_to_hex(derive_credential_binding_key(MASTER_SEED)), serialized
        )
        self.assertNotIn(self.credential.signature.hex(), serialized)

    def test_witness_refresh_after_revocation_fails_closed(self):
        self.provider.revoke(TEST_ISSUER_ID, 42)
        with self.assertRaises(StaleWitnessError):
            generate_unauthenticated_linkable(self.client, make_request())

    def test_stale_epoch_without_refresh_fails(self):
        # A client with NO provider must fail closed on a stale stored witness.
        witness = self.provider.witness(TEST_ISSUER_ID, 42)
        witness.accumulator_epoch = 0
        credential = issue_kyc_credential(master_seed=MASTER_SEED, credential_id=42)
        credential.witness = witness
        offline_client = make_client(provider=None)
        offline_client.store_credential(credential)
        request = make_request(current_epochs={TEST_ISSUER_ID: 50})
        with self.assertRaises(StaleWitnessError):
            generate_unauthenticated_linkable(offline_client, request)

    def test_wrong_context_fails(self):
        context = ProofContext.verifier_session("verifier.example", 555, 1_700_000)
        tampered = ProofContext(
            profile=context.profile,
            value=(context.value + 1),
            timestamp=context.timestamp,
            verifier_id=context.verifier_id,
            session_id=context.session_id,
        )
        with self.assertRaises(ContextError):
            generate_unauthenticated_linkable(self.client, make_request(context=tampered))

    def test_opaque_predicate_refused_by_default(self):
        request = make_request(proof_types=["zkc:proof:opaque-scoring:v1"], parameters={})
        with self.assertRaises(OpaquePredicateError):
            generate_unauthenticated_linkable(self.client, request)

    def test_opaque_predicate_optin_is_explicit_and_logged(self):
        request = make_request(proof_types=["zkc:proof:opaque-scoring:v1"], parameters={})
        with self.assertLogs("zkc.holder", level=logging.WARNING) as logs:
            with self.assertRaises(BackendUnavailableError):
                generate_unauthenticated_linkable(self.client, request, allow_opaque=True)
        self.assertTrue(any("OPAQUE PREDICATE OPT-IN" in line for line in logs.output))

    def test_composite_disclosure_requires_per_predicate_consent(self):
        request = make_request(proof_types=[KYC_PROOF_TYPE, "zkc:proof:jurisdiction:v1"])
        with self.assertRaises(ConsentRequiredError):
            generate_unauthenticated_linkable(self.client, request)

    def test_stub_backend_refuses_false_statement(self):
        # Credential level 1 cannot satisfy requiredLevel 3 — selection blocks
        # this first, so drive the backend directly with a forged witness.
        from zkc_holder.backend import StubBackend, build_kyc_witness
        from zkc_crypto import derive_credential_binding_key

        witness = self.provider.witness(TEST_ISSUER_ID, 42)
        full_witness = build_kyc_witness(
            credential_binding_key=derive_credential_binding_key(MASTER_SEED),
            credential=self.credential,
            issuer=trusted_test_issuer(),
            witness=witness,
            required_level=1,
            required_attributes=[False] * 5,
            proof_context=777,
            timestamp=12345,
            current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
        )
        full_witness["credential_level"] = 3  # claim a level the issuer never signed
        with self.assertRaises(ConstraintViolationError):
            StubBackend().prove("zkc_kyc", full_witness)

    def test_aggregation_entry_point(self):
        envelope = generate_unauthenticated_linkable(self.client, make_request(), aggregate=True)
        validate_compliance_proof_v1(envelope)
        aggregation = envelope["aggregation"]
        self.assertEqual(len(aggregation["inputProofCommitments"]), 1)
        # Recompute the chain from the envelope contents.
        from zkc_crypto import hex_to_field, string_to_field
        from zkc_holder.aggregation import commitment_for_envelope_proof

        entry = REGISTRY.resolve(KYC_PROOF_TYPE)
        self.assertTrue(entry.vk_hash, "registry entry must pin the circuit vkHash")
        commitment = commitment_for_envelope_proof(
            envelope["proofs"][0], bytes.fromhex(entry.vk_hash.removeprefix("0x"))
        )
        self.assertEqual(field_to_hex(commitment), aggregation["inputProofCommitments"][0])
        context_value = hex_to_field(envelope["metadata"]["context"]["value"])
        expected = aggregate_commitments(
            context_value,
            self.client.get_binding_commitment(),
            [commitment],
            [string_to_field(KYC_PROOF_TYPE)],
            [True],
        )
        self.assertEqual(field_to_hex(expected), aggregation["aggregationCommitment"])
        self.assertEqual(
            field_to_hex(aggregated_claim_binding(expected, context_value)),
            aggregation["aggregatedClaimBinding"],
        )
        self.assertEqual(
            aggregated_claim_binding(expected, context_value),
            poseidon2(expected, context_value),
        )

    def test_aggregation_vk_commitment_binds_manifest_vk_hash(self):
        """The simulated-recursion input is the manifest-pinned vk hash.

        The commitment binds the verification key actually verified against —
        a different VK (a different circuit build) changes every downstream
        aggregation commitment, so a swapped artifact cannot inherit an
        aggregation computed for the pinned one.
        """
        import json as _json

        from zkc_holder.aggregation import commitment_for_envelope_proof

        envelope = generate_unauthenticated_linkable(self.client, make_request())
        proof_entry = envelope["proofs"][0]
        entry = REGISTRY.resolve(KYC_PROOF_TYPE)

        manifest = _json.loads((REPO_ROOT / "artifacts" / "manifest.json").read_text())
        manifest_vk_hash = next(
            circuit["vkHash"] for circuit in manifest["circuits"] if circuit["name"] == entry.circuit
        )
        self.assertEqual(entry.vk_hash, manifest_vk_hash)

        pinned = bytes.fromhex(entry.vk_hash.removeprefix("0x"))
        different_vk = hashlib.sha256(pinned).digest()  # any other 32-byte vk identity
        self.assertNotEqual(
            commitment_for_envelope_proof(proof_entry, pinned),
            commitment_for_envelope_proof(proof_entry, different_vk),
        )

    def test_aggregation_fails_closed_without_vk_pin(self):
        """No manifest-pinned vk hash -> aggregation refuses to build."""
        import dataclasses

        from zkc_holder.errors import HolderError

        unpinned = PredicateRegistry(
            [
                dataclasses.replace(entry, vk_hash="")
                for entry in REGISTRY.resolve_all(KYC_PROOF_TYPE)
            ]
        )
        client = HolderClient.from_seed(
            MASTER_SEED,
            unpinned,
            StubBackend(),
            accumulator_provider=self.provider,
        )
        client.store_credential(self.credential)
        with self.assertRaises(HolderError) as caught:
            generate_unauthenticated_linkable(client, make_request(), aggregate=True)
        self.assertIn("manifest-pinned verification key hash", str(caught.exception))

    def test_aggregation_requires_consent_flags(self):
        with self.assertRaises(ConsentRequiredError):
            aggregate_commitments(777, 1, [5], [6], [False])


if __name__ == "__main__":
    unittest.main()
