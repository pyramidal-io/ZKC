"""KAT and behavior tests for the zkc_crypto package.

Every hash construction is pinned against the repository's golden vectors
(tests/vectors/zkc_core_vectors.json) and the Noir circuit fixtures, so the
Python and Noir implementations cannot drift silently.
"""

import json
import unittest

from _path import REPO_ROOT

from zkc_crypto import (
    DOMAIN_ZKC_BINDING,
    DOMAIN_ZKC_CLAIM,
    DOMAIN_ZKC_CREDENTIAL,
    EnvelopeError,
    ProofContext,
    compute_claim_binding_2,
    compute_claim_binding_4,
    compute_kyc_credential_digest,
    compute_merkle_root,
    compute_profile_digest,
    compute_profile_digest_v2,
    derive_credential_binding_key,
    derive_holder_commitment,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
    field_to_hex,
    hex_to_field,
    poseidon2,
    poseidon3,
    poseidon4,
    validate_compliance_proof_v1,
    SparseMerkleAccumulator,
)
from zkc_crypto._poseidon2_constants import (
    PERMUTATION_TEST_INPUT,
    PERMUTATION_TEST_OUTPUT,
)
from zkc_crypto.poseidon2 import permutation
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes, sign, verify

VECTORS = json.loads((REPO_ROOT / "tests" / "vectors" / "zkc_core_vectors.json").read_text())


class Poseidon2Tests(unittest.TestCase):
    def test_barretenberg_permutation_vector(self):
        self.assertEqual(permutation(PERMUTATION_TEST_INPUT), PERMUTATION_TEST_OUTPUT)

    def test_sponge_kats_match_golden_vectors(self):
        kats = VECTORS["poseidon2_kats"]
        self.assertEqual(field_to_hex(poseidon2(1, 2)), kats["poseidon2_1_2"])
        self.assertEqual(field_to_hex(poseidon3(1, 2, 3)), kats["poseidon3_1_2_3"])
        self.assertEqual(field_to_hex(poseidon4(1, 2, 3, 4)), kats["poseidon4_1_2_3_4"])


class KdcTests(unittest.TestCase):
    def test_domains_match_golden_vectors(self):
        domains = VECTORS["domains"]
        self.assertEqual(field_to_hex(DOMAIN_ZKC_CREDENTIAL), domains["zkc_credential"])
        self.assertEqual(field_to_hex(DOMAIN_ZKC_BINDING), domains["zkc_binding"])
        self.assertEqual(field_to_hex(DOMAIN_ZKC_CLAIM), domains["zkc_claim"])

    def test_kdc_a6_seed_42(self):
        kat = VECTORS["kdc_a6_seed_42"]
        seed = hex_to_field(kat["master_seed"])
        cbk = derive_credential_binding_key(seed)
        self.assertEqual(field_to_hex(cbk), kat["credential_binding_key"])
        self.assertEqual(
            field_to_hex(derive_holder_commitment(cbk)), kat["holder_commitment"]
        )
        self.assertEqual(
            field_to_hex(derive_holder_commitment_from_seed(seed)), kat["holder_commitment"]
        )

    def test_claim_binding_kat(self):
        self.assertEqual(
            field_to_hex(compute_claim_binding_2(1, 31, 777, 12345)),
            VECTORS["claim_binding_examples"]["compute_claim_binding_2_1_31_777_12345"],
        )
        self.assertEqual(
            field_to_hex(compute_claim_binding_4(1, 2, 0, False, 777, 12345)),
            VECTORS["claim_binding_examples"][
                "compute_claim_binding_4_1_2_0_false_777_12345"
            ],
        )
        self.assertEqual(
            field_to_hex(compute_claim_binding_4(1, 2, 0, True, 777, 12345)),
            VECTORS["claim_binding_examples"][
                "compute_claim_binding_4_1_2_0_true_777_12345"
            ],
        )

    def test_claim_binding_4_rejects_boolean_aliases(self):
        for value in (0, 1, "true", None, []):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    compute_claim_binding_4(1, 2, 0, value, 777, 12345)


class DigestTests(unittest.TestCase):
    # Pinned in noir/zkc_remaining_predicates kat_profile_digests.
    HOLDER = 0x24DD41C93A298E537C6AC62487057A09229C1AB00B2BAEC40B45A325712840BF

    def test_profile_digest_kats(self):
        """The legacy v1--v4 digest remains pinned for historical proofs."""
        cases = [
            (1, 3, 1, 0x2DC81A5616770B2CEEF674B5CC7B14B0A74F3441FD04AFCBBFDF4113EAE72FD7),
            (1, 3, 0, 0x2605527F864B40B25CD08F360F6C142BA4450E5067E966F4404E5053202C88CB),
            (2, 7, 0, 0x06BD842D08C7C2C3E713F312308EFC5D8B0BC2C818684916D9A8AE12D35A17BE),
            (3, 840, 2026, 0x212FAADCDE940E4E4BEB145A438EDDF2AA9B18B79A2A5BC0BD3EF9F4A6ED6DFE),
            (4, 150, 0, 0x21A39DA221C61B87C10E0DE193553BF59D4A51D7E69749802D69714F07A37295),
        ]
        for predicate_type, claim_0, claim_1, expected in cases:
            self.assertEqual(
                compute_profile_digest(self.HOLDER, 42, predicate_type, claim_0, claim_1, 2000000),
                expected,
            )

    def test_profile_digest_v2_authenticates_every_profile_field(self):
        fields = {
            "holder_commitment": self.HOLDER,
            "credential_id": 42,
            "predicate_type": 3,
            "claim_0": 840,
            "claim_1": 2026,
            "valid_from": 1_700_000_000,
            "valid_until": 2_000_000_000,
        }
        baseline = compute_profile_digest_v2(**fields)
        self.assertEqual(
            baseline,
            poseidon4(
                poseidon4(
                    fields["holder_commitment"],
                    fields["credential_id"],
                    fields["predicate_type"],
                    fields["valid_from"],
                ),
                fields["claim_0"],
                fields["claim_1"],
                fields["valid_until"],
            ),
        )
        for name, value in fields.items():
            with self.subTest(field=name):
                changed = {**fields, name: value + 1}
                self.assertNotEqual(compute_profile_digest_v2(**changed), baseline)

    def test_kyc_digest_matches_circuit_fixture_signature(self):
        # The valid KYC fixture in noir/zkc_kyc/src/main.nr carries an ECDSA
        # signature over the digest computed inside the circuit. Verifying
        # that signature against our Python digest proves both agree.
        key_x = bytes(
            [137, 81, 38, 98, 181, 144, 46, 180, 102, 61, 191, 66, 140, 98, 244, 92, 229, 44,
             211, 23, 36, 201, 121, 32, 86, 185, 98, 216, 108, 62, 37, 26]
        )
        key_y = bytes(
            [34, 85, 29, 119, 46, 134, 16, 31, 56, 87, 20, 235, 116, 171, 39, 5, 122, 99, 146,
             254, 158, 5, 185, 45, 152, 119, 236, 243, 137, 31, 179, 114]
        )
        signature = bytes(
            [217, 126, 200, 195, 113, 255, 24, 125, 65, 74, 79, 242, 197, 254, 34, 101, 153, 106,
             13, 117, 226, 63, 169, 8, 26, 239, 207, 147, 179, 21, 39, 31, 51, 153, 200, 96, 223,
             140, 4, 75, 129, 37, 99, 82, 104, 97, 17, 55, 123, 118, 194, 183, 39, 140, 191, 114,
             252, 149, 254, 147, 236, 154, 162, 208]
        )
        digest = compute_kyc_credential_digest(
            self.HOLDER, 42, 2, [True, True, True, False, True], 2000000
        )
        self.assertTrue(verify(key_x, key_y, signature, digest_to_message_bytes(digest)))
        # And a tampered digest must not verify.
        wrong = compute_kyc_credential_digest(
            self.HOLDER, 42, 3, [True, True, True, False, True], 2000000
        )
        self.assertFalse(verify(key_x, key_y, signature, digest_to_message_bytes(wrong)))


class MerkleTests(unittest.TestCase):
    def test_root_matches_circuit_fixture_semantics(self):
        # Fixtures use compute_merkle_root(credential_id, 0, [0; 32]).
        root = compute_merkle_root(42, 0, [0] * 32)
        current = 42
        for _ in range(32):
            current = poseidon2(current, 0)
        self.assertEqual(root, current)

    def test_path_index_bit_order(self):
        # index 1 means the leaf is the RIGHT child at level 0.
        siblings = [7] + [0] * 31
        root = compute_merkle_root(42, 1, siblings)
        current = poseidon2(7, 42)
        for _ in range(31):
            current = poseidon2(current, 0)
        self.assertEqual(root, current)

    def test_sparse_accumulator_witnesses_verify(self):
        accumulator = SparseMerkleAccumulator()
        for leaf in (101, 202, 303):
            accumulator.add(leaf)
        root = accumulator.root()
        for leaf in (101, 202, 303):
            index, siblings = accumulator.witness(accumulator.index_of(leaf))
            self.assertEqual(compute_merkle_root(leaf, index, siblings), root)

    def test_sparse_accumulator_revocation_changes_root(self):
        accumulator = SparseMerkleAccumulator()
        accumulator.add(101)
        index, siblings = accumulator.witness(accumulator.index_of(101))
        old_root = accumulator.root()
        accumulator.remove(0)
        self.assertNotEqual(accumulator.root(), old_root)
        self.assertNotEqual(compute_merkle_root(101, index, siblings), accumulator.root())


class EcdsaTests(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        private_key = 0xDEADBEEF % N
        key_x, key_y = public_key_bytes(private_key)
        digest = b"\x11" * 32
        signature = sign(digest, private_key)
        self.assertTrue(verify(key_x, key_y, signature, digest))
        self.assertFalse(verify(key_x, key_y, signature, b"\x22" * 32))
        tampered = bytes([signature[0] ^ 1]) + signature[1:]
        self.assertFalse(verify(key_x, key_y, tampered, digest))

    def test_verify_fails_closed_on_malformed_inputs(self):
        private_key = 7
        key_x, key_y = public_key_bytes(private_key)
        digest = b"\x11" * 32
        signature = sign(digest, private_key)
        self.assertFalse(verify(key_x, key_y, signature[:-1], digest))
        self.assertFalse(verify(key_x[:-1], key_y, signature, digest))
        self.assertFalse(verify(b"\x00" * 32, b"\x00" * 32, signature, digest))


class ContextTests(unittest.TestCase):
    def test_verifier_session_context_reconstructs(self):
        context = ProofContext.verifier_session("verifier.example", 555, 1700000000)
        self.assertTrue(context.reconstructs())
        metadata = context.to_metadata()
        self.assertEqual(ProofContext.from_metadata(metadata), context)

    def test_tampered_context_does_not_reconstruct(self):
        context = ProofContext.verifier_session("verifier.example", 555, 1700000000)
        tampered = ProofContext(
            profile=context.profile,
            value=(context.value + 1),
            timestamp=context.timestamp,
            verifier_id=context.verifier_id,
            session_id=context.session_id,
        )
        self.assertFalse(tampered.reconstructs())

    def test_context_requires_positive_timestamp(self):
        with self.assertRaises(ValueError):
            ProofContext.verifier_session("verifier.example", 555, 0)


class PublicInputEncoderTests(unittest.TestCase):
    def _kyc_inputs(self):
        return {
            "holder_commitment": field_to_hex(1),
            "claim_binding": field_to_hex(2),
            "proof_context": field_to_hex(3),
            "accumulator_root": field_to_hex(4),
            "accumulator_epoch": 100,
            "timestamp": 12345,
            "current_epoch": 105,
            "issuer_public_key_x": "0x" + "11" * 32,
            "issuer_public_key_y": "0x" + "22" * 32,
        }

    def _encoder(self):
        from zkc_crypto import PublicInputEncoder

        return PublicInputEncoder.load(
            REPO_ROOT / "schemas" / "public-inputs" / "zkc_kyc.json"
        )

    def test_kyc_encoding_shape(self):
        encoder = self._encoder()
        elements = encoder.field_elements(self._kyc_inputs())
        self.assertEqual(len(elements), 71)
        self.assertEqual(elements[0], 1)
        self.assertEqual(elements[4], 100)
        self.assertEqual(elements[7], 0x11)  # first issuer key byte
        encoded = encoder.encode_bytes(self._kyc_inputs())
        self.assertEqual(len(encoded), 71 * 32)

    def test_encoding_fails_closed(self):
        encoder = self._encoder()
        missing = self._kyc_inputs()
        del missing["timestamp"]
        with self.assertRaises(ValueError):
            encoder.field_elements(missing)
        wrong_bytes = self._kyc_inputs()
        wrong_bytes["issuer_public_key_x"] = "0x1111"
        with self.assertRaises(ValueError):
            encoder.field_elements(wrong_bytes)
        out_of_range = self._kyc_inputs()
        out_of_range["timestamp"] = 1 << 64
        with self.assertRaises(ValueError):
            encoder.field_elements(out_of_range)

    def test_unsigned_integer_encoding_rejects_coercible_aliases(self):
        encoder = self._encoder()
        for alias in ("12345", 12345.9, True):
            with self.subTest(alias=alias):
                inputs = self._kyc_inputs()
                inputs["timestamp"] = alias
                with self.assertRaisesRegex(ValueError, "must be an integer"):
                    encoder.field_elements(inputs)


class EnvelopeValidatorTests(unittest.TestCase):
    def _valid_envelope(self):
        return {
            "version": "zkc:proof:v1",
            "metadata": {
                "generatedAt": "2026-06-10T00:00:00Z",
                "expiresAt": "2026-06-10T01:00:00Z",
                "context": {
                    "profile": "zkc:context:verifier-session:v1",
                    "value": "0x" + "11" * 32,
                    "timestamp": 1700000000,
                },
            },
            "proofs": [
                {
                    "proofType": "zkc:proof:kyc:v1",
                    "proof": "0xabcd",
                    "publicInputs": {},
                    "principalConsent": True,
                }
            ],
            "holderBinding": {"commitment": "0x" + "22" * 32},
        }

    def test_valid_envelope_passes(self):
        validate_compliance_proof_v1(self._valid_envelope())

    def test_validator_covers_schema_required_fields(self):
        # Cross-check against the actual schema document so the stdlib
        # validator cannot silently drift from the published schema.
        schema = json.loads(
            (REPO_ROOT / "schemas" / "compliance-proof-v1.schema.json").read_text()
        )
        for required in schema["required"]:
            envelope = self._valid_envelope()
            del envelope[required]
            with self.assertRaises(EnvelopeError, msg=f"missing {required} must fail"):
                validate_compliance_proof_v1(envelope)
        for required in schema["properties"]["proofs"]["items"]["required"]:
            envelope = self._valid_envelope()
            del envelope["proofs"][0][required]
            with self.assertRaises(EnvelopeError, msg=f"missing proofs[].{required} must fail"):
                validate_compliance_proof_v1(envelope)

    def test_rejects_wrong_version_and_bad_hex(self):
        envelope = self._valid_envelope()
        envelope["version"] = "zkc:proof:v2"
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v1(envelope)
        envelope = self._valid_envelope()
        envelope["holderBinding"]["commitment"] = "0x1234"
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v1(envelope)

    def test_rejects_empty_and_oversized_proofs(self):
        envelope = self._valid_envelope()
        envelope["proofs"] = []
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v1(envelope)
        envelope = self._valid_envelope()
        envelope["proofs"] = envelope["proofs"] * 9
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v1(envelope)

    def test_aggregation_block_validation(self):
        envelope = self._valid_envelope()
        envelope["aggregation"] = {
            "proof": "zkc:stub:v1:00",
            "inputProofCommitments": ["0x" + "33" * 32],
            "aggregationCommitment": "0x" + "44" * 32,
            "aggregatedClaimBinding": "0x" + "55" * 32,
        }
        validate_compliance_proof_v1(envelope)
        del envelope["aggregation"]["aggregationCommitment"]
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v1(envelope)


if __name__ == "__main__":
    unittest.main()
