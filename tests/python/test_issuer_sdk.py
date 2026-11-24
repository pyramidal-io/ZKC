"""Unit tests for the zkc_issuer reference issuer SDK and sandbox adapter."""

import importlib.util
import json
import pathlib
import tempfile
import tracemalloc
import unittest
from collections.abc import Mapping
from types import MappingProxyType

import _path  # noqa: F401
from _path import REPO_ROOT

from zkc_crypto import (
    RUNTIME_ATTESTATION_ROOT_CLASS_CODES,
    RUNTIME_ATTESTATION_SCHEMA_ID,
    compute_jurisdiction_credential_digest,
    compute_jurisdiction_leaf,
    compute_merkle_root,
    compute_runtime_attestation_claim_commitment,
    compute_runtime_attestation_credential_digest,
    derive_credential_binding_key,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
    field_to_hex,
    hex_to_field,
    poseidon2,
    poseidon3,
)
from zkc_crypto.ecdsa_secp256k1 import verify as ecdsa_verify
from zkc_holder import Credential
from zkc_issuer import (
    ADAPTER_ERROR_CODES,
    FORBIDDEN_FIELDS,
    HUMAN_PRIVACY_PROFILE,
    KNOWN_PRIVACY_PROFILES,
    MACHINE_PRIVACY_PROFILE,
    SANDBOX_FIXTURES,
    SUPPORTED_SCHEMAS,
    AdapterError,
    BindingChallenge,
    IssuerAccumulator,
    IssuerSigningKey,
    RUNTIME_ATTESTATION_SCHEMA_ID as ISSUER_RUNTIME_ATTESTATION_SCHEMA_ID,
    SandboxIssuerAdapter,
    compute_binding_response,
    get_schema,
    holder_binding_response,
    reference_external_adapter,
    reject_forbidden,
)

MASTER_SEED = 7
HOLDER_COMMITMENT = derive_holder_commitment_from_seed(MASTER_SEED)
HOLDER_COMMITMENT_HEX = field_to_hex(HOLDER_COMMITMENT)


def _load_metadata_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_issuer_metadata",
        REPO_ROOT / "tests" / "issuer_adapter" / "validate_issuer_metadata.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scan_for_forbidden(value, hits):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_FIELDS:
                hits.append(key)
            _scan_for_forbidden(child, hits)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _scan_for_forbidden(child, hits)


def _bound_adapter(schema_id: str, fixture_id: str, **adapter_kwargs):
    """Run verify_subject + challenge + bind; return (adapter, subject_ref)."""
    # Default clock inside the sandbox key validity window (2026).
    adapter_kwargs.setdefault("clock", lambda: 1_770_000_000)
    adapter = SandboxIssuerAdapter(**adapter_kwargs)
    subject = adapter.verify_subject({"schemaId": schema_id, "fixtureId": fixture_id})
    challenge = adapter.request_binding_challenge(
        {
            "subjectRef": subject["subjectRef"],
            "holderCommitment": HOLDER_COMMITMENT_HEX,
            "schemaId": schema_id,
        }
    )
    response = compute_binding_response(
        HOLDER_COMMITMENT,
        adapter.issuer_id,
        schema_id,
        hex_to_field(challenge["nonce"]),
        challenge["expiresAt"],
    )
    adapter.bind_holder_commitment(
        {
            "subjectRef": subject["subjectRef"],
            "holderCommitment": HOLDER_COMMITMENT_HEX,
            "schemaId": schema_id,
            "nonce": challenge["nonce"],
            "challengeResponse": field_to_hex(response),
        }
    )
    return adapter, subject["subjectRef"]


class IssuerSigningKeyTests(unittest.TestCase):
    def test_test_issuer_key_matches_tool_derivation(self):
        # Pins the well-known TEST-ONLY key (tools/zkc_test_issuer.py pubkey):
        # drift in the seed derivation in either direction fails here.
        key = IssuerSigningKey.test_issuer()
        self.assertEqual(
            key.public_key_hex(),
            "0x1310fe42b7df28bae91d18e87f7a2f0c505fd5e20056d95a4b6a85b8d949e459"
            "502c40fd1bc33d2dbe3367b5cf3f48cd9b6aca0353cb9d34b31637146bdd1a86",
        )
        self.assertEqual(key.metadata_entry()["keyId"], "sandbox-2026-01")
        # And matches the shared holder-fixture derivation.
        from holder_fixtures import TEST_ISSUER_KEY_X, TEST_ISSUER_KEY_Y

        self.assertEqual(key.public_key_coordinates(), (TEST_ISSUER_KEY_X, TEST_ISSUER_KEY_Y))

    def test_generate_produces_distinct_signing_keys(self):
        first = IssuerSigningKey.generate("k1")
        second = IssuerSigningKey.generate("k2")
        self.assertNotEqual(first.private_key, second.private_key)
        digest = 12345
        message = digest_to_message_bytes(digest)
        x, y = first.public_key_coordinates()
        self.assertTrue(ecdsa_verify(x, y, first.sign_digest(digest), message))
        # The other key's signature must not verify under this public key.
        self.assertFalse(ecdsa_verify(x, y, second.sign_digest(digest), message))

    def test_repr_and_str_redact_the_private_scalar(self):
        key = IssuerSigningKey.test_issuer()
        secret_hex = f"{key.private_key:064x}"
        for rendering in (repr(key), str(key)):
            self.assertNotIn(secret_hex, rendering)
            self.assertNotIn(str(key.private_key), rendering)

    def test_private_dict_round_trip(self):
        key = IssuerSigningKey.generate("round-trip")
        loaded = IssuerSigningKey.from_private_dict(key.to_private_dict())
        self.assertEqual(loaded, key)

    def test_validity_window(self):
        key = IssuerSigningKey.test_issuer()
        self.assertTrue(key.is_valid_at(1_770_000_000))  # 2026-02
        self.assertFalse(key.is_valid_at(1_500_000_000))  # 2017
        self.assertFalse(key.is_valid_at(1_900_000_000))  # 2030

    def test_rejects_invalid_construction(self):
        with self.assertRaises(ValueError):
            IssuerSigningKey(key_id="bad", private_key=0)
        with self.assertRaises(ValueError):
            IssuerSigningKey(key_id="bad", private_key=5, scheme="BLS")
        with self.assertRaises(ValueError):
            IssuerSigningKey(
                key_id="bad",
                private_key=5,
                not_before="2027-01-01T00:00:00Z",
                not_after="2026-01-01T00:00:00Z",
            )


class JurisdictionDigestTests(unittest.TestCase):
    def test_mirrors_noir_construction(self):
        leaf = compute_jurisdiction_leaf(840, 2)
        self.assertEqual(leaf, poseidon2(840, 2))
        digest = compute_jurisdiction_credential_digest(11, 22, 840, 2, 1, 100, 200)
        header = poseidon3(11, 22, leaf)
        method = poseidon3(1, 100, 200)
        self.assertEqual(digest, poseidon2(header, method))

    def test_range_checks(self):
        with self.assertRaises(ValueError):
            compute_jurisdiction_leaf(1 << 16, 0)
        with self.assertRaises(ValueError):
            compute_jurisdiction_leaf(0, 256)
        with self.assertRaises(ValueError):
            compute_jurisdiction_credential_digest(1, 2, 3, 4, 256, 0, 0)


RUNTIME_SCHEMA_ID = RUNTIME_ATTESTATION_SCHEMA_ID
RUNTIME_CLAIMS = {
    "attestedManifestDigest": "sha256:" + "11" * 32,
    "rootClass": "root:build-provenance",
    "rootAuthorityIdentifier": "sigstore:rekor:public-good:v1",
    "rootMaterialDigest": "sha256:" + "22" * 32,
    "attestationEvidenceDigest": "sha256:" + "33" * 32,
    "verificationPolicyDigest": "sha256:" + "44" * 32,
    "validFrom": 1_700_000_000,
    "validUntil": 1_700_003_600,
}


def _compute_runtime_digest(claims: dict) -> int:
    return compute_runtime_attestation_credential_digest(
        123,
        456,
        claims["attestedManifestDigest"],
        claims["rootClass"],
        claims["rootAuthorityIdentifier"],
        claims["rootMaterialDigest"],
        claims["attestationEvidenceDigest"],
        claims["verificationPolicyDigest"],
        claims["validFrom"],
        claims["validUntil"],
    )


class RuntimeAttestationDigestTests(unittest.TestCase):
    def test_known_answer_claim_commitment_and_digest(self):
        claim_commitment = compute_runtime_attestation_claim_commitment(
            RUNTIME_CLAIMS["attestedManifestDigest"],
            RUNTIME_CLAIMS["rootClass"],
            RUNTIME_CLAIMS["rootAuthorityIdentifier"],
            RUNTIME_CLAIMS["rootMaterialDigest"],
            RUNTIME_CLAIMS["attestationEvidenceDigest"],
            RUNTIME_CLAIMS["verificationPolicyDigest"],
            RUNTIME_CLAIMS["validFrom"],
            RUNTIME_CLAIMS["validUntil"],
        )
        self.assertEqual(
            field_to_hex(claim_commitment),
            "0x24511f1414cf62fa1c39871ef3bc9938fd2388a95ce3aa4c77a4505f96ae267d",
        )
        digest = compute_runtime_attestation_credential_digest(
            123,
            456,
            RUNTIME_CLAIMS["attestedManifestDigest"],
            RUNTIME_CLAIMS["rootClass"],
            RUNTIME_CLAIMS["rootAuthorityIdentifier"],
            RUNTIME_CLAIMS["rootMaterialDigest"],
            RUNTIME_CLAIMS["attestationEvidenceDigest"],
            RUNTIME_CLAIMS["verificationPolicyDigest"],
            RUNTIME_CLAIMS["validFrom"],
            RUNTIME_CLAIMS["validUntil"],
        )
        self.assertEqual(
            field_to_hex(digest),
            "0x275398fdceb4dd99f0b0ba46f01bb2f58233d6217f2520d1806cdbab91801de2",
        )
        self.assertEqual(
            digest_to_message_bytes(digest).hex(),
            "275398fdceb4dd99f0b0ba46f01bb2f58233d6217f2520d1806cdbab91801de2",
        )

    def test_every_signed_runtime_claim_changes_the_digest(self):
        baseline = _compute_runtime_digest(RUNTIME_CLAIMS)
        mutations = {
            "attestedManifestDigest": "sha256:" + "12" * 32,
            "rootClass": "root:tee-attestation",
            "rootAuthorityIdentifier": "example:tee-root:v1",
            "rootMaterialDigest": "sha256:" + "23" * 32,
            "attestationEvidenceDigest": "sha256:" + "34" * 32,
            "verificationPolicyDigest": "sha256:" + "45" * 32,
            "validFrom": RUNTIME_CLAIMS["validFrom"] + 1,
            "validUntil": RUNTIME_CLAIMS["validUntil"] + 1,
        }
        for name, replacement in mutations.items():
            changed = {**RUNTIME_CLAIMS, name: replacement}
            with self.subTest(claim=name):
                self.assertNotEqual(
                    _compute_runtime_digest(changed),
                    baseline,
                )

    def test_root_class_code_map_is_read_only(self):
        with self.assertRaises(TypeError):
            RUNTIME_ATTESTATION_ROOT_CLASS_CODES["root:publisher-manifest"] = 3


class SchemaTests(unittest.TestCase):
    def test_current_and_legacy_schemas_are_registered(self):
        self.assertEqual(
            sorted(SUPPORTED_SCHEMAS),
            [
                "zkc:cred:accreditation:v1",
                "zkc:cred:accreditation:v2",
                "zkc:cred:attribute-set:v1",
                "zkc:cred:attribute-set:v2",
                "zkc:cred:jurisdiction:v1",
                "zkc:cred:jurisdiction:v2",
                "zkc:cred:kyc:v1",
                "zkc:cred:runtime-attestation:v1",
                "zkc:cred:sanctions:v1",
                "zkc:cred:sanctions:v2",
                "zkc:cred:sanctions:v3",
                "zkc:cred:source:v1",
                "zkc:cred:source:v2",
                "zkc:cred:source:v3",
                "zkc:cred:tax:v1",
                "zkc:cred:tax:v2",
                "zkc:cred:tax:v3",
            ],
        )

    def test_runtime_attestation_claims_are_strict(self):
        schema = get_schema(RUNTIME_SCHEMA_ID)
        self.assertEqual(schema.normalize_claims(RUNTIME_CLAIMS), RUNTIME_CLAIMS)
        self.assertEqual(schema.credential_type, RUNTIME_SCHEMA_ID)
        self.assertEqual(schema.proof_type, "zkc:proof:runtime-attestation:v1")
        self.assertEqual(ISSUER_RUNTIME_ATTESTATION_SCHEMA_ID, RUNTIME_SCHEMA_ID)

        precomposed = {
            **RUNTIME_CLAIMS,
            "rootAuthorityIdentifier": "autorité:racine:v1",
        }
        self.assertEqual(schema.normalize_claims(precomposed), precomposed)
        byte_limit_boundary = {
            **RUNTIME_CLAIMS,
            "rootAuthorityIdentifier": "é" * 128,
        }
        self.assertEqual(
            schema.normalize_claims(byte_limit_boundary), byte_limit_boundary
        )

        invalid = (
            {**RUNTIME_CLAIMS, "rootClass": "root:publisher-manifest"},
            {**RUNTIME_CLAIMS, "rootClass": "root:unknown"},
            {**RUNTIME_CLAIMS, "attestedManifestDigest": "sha256:" + "AA" * 32},
            {**RUNTIME_CLAIMS, "rootMaterialDigest": "sha256:" + "00" * 32},
            {**RUNTIME_CLAIMS, "attestationEvidenceDigest": "sha512:" + "33" * 32},
            {**RUNTIME_CLAIMS, "verificationPolicyDigest": "sha256:1234"},
            {**RUNTIME_CLAIMS, "rootAuthorityIdentifier": ""},
            {**RUNTIME_CLAIMS, "rootAuthorityIdentifier": "e\u0301"},
            {**RUNTIME_CLAIMS, "rootAuthorityIdentifier": "invalid\ud800"},
            {**RUNTIME_CLAIMS, "rootAuthorityIdentifier": "é" * 129},
            {**RUNTIME_CLAIMS, "validFrom": True},
            {**RUNTIME_CLAIMS, "validUntil": RUNTIME_CLAIMS["validFrom"]},
            {**RUNTIME_CLAIMS, "unexpected": "claim"},
            {key: value for key, value in RUNTIME_CLAIMS.items() if key != "rootClass"},
        )
        for claims in invalid:
            with self.subTest(claims=claims):
                with self.assertRaises(AdapterError) as ctx:
                    schema.normalize_claims(claims)
                self.assertEqual(ctx.exception.code, "UNSUPPORTED_SCHEMA")

    def test_runtime_attestation_envelope_expiry_must_equal_valid_until(self):
        schema = get_schema(RUNTIME_SCHEMA_ID)
        normalized = schema.normalize_claims(RUNTIME_CLAIMS)
        with self.assertRaises(AdapterError) as ctx:
            schema.compute_digest(123, 456, normalized, RUNTIME_CLAIMS["validUntil"] + 1)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_SCHEMA")

    def test_runtime_attestation_json_schema_matches_claim_contract(self):
        schema = json.loads(
            (
                REPO_ROOT / "schemas" / "credential-runtime-attestation-v1.schema.json"
            ).read_text()
        )
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), set(RUNTIME_CLAIMS))
        self.assertEqual(set(schema["properties"]), set(RUNTIME_CLAIMS))
        self.assertEqual(
            schema["properties"]["rootClass"]["enum"],
            ["root:build-provenance", "root:tee-attestation"],
        )
        digest_pattern = "^sha256:(?!0{64}$)[0-9a-f]{64}$"
        for name in (
            "attestedManifestDigest",
            "rootMaterialDigest",
            "attestationEvidenceDigest",
            "verificationPolicyDigest",
        ):
            with self.subTest(property=name):
                self.assertEqual(
                    schema["properties"][name],
                    {"type": "string", "pattern": digest_pattern},
                )
        self.assertEqual(
            schema["properties"]["rootAuthorityIdentifier"],
            {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "$comment": (
                    "JSON Schema maxLength counts Unicode code points; the "
                    "normative issuer contract additionally enforces at most "
                    "256 UTF-8 bytes."
                ),
            },
        )
        self.assertEqual(
            schema["properties"]["validFrom"],
            {"type": "integer", "minimum": 0, "maximum": (1 << 64) - 1},
        )
        self.assertEqual(
            schema["properties"]["validUntil"],
            {"type": "integer", "minimum": 1, "maximum": (1 << 64) - 1},
        )

    def test_unknown_schema_fails_closed(self):
        with self.assertRaises(AdapterError) as ctx:
            get_schema("zkc:cred:unknown:v1")
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_SCHEMA")

    def test_kyc_claims_validation(self):
        schema = get_schema("zkc:cred:kyc:v1")
        good = schema.normalize_claims(
            {"level": 2, "verifiedAttributes": [True, False, True, False, True]}
        )
        self.assertEqual(good["level"], 2)
        for bad in (
            {"level": 0, "verifiedAttributes": [True] * 5},
            {"level": 1, "verifiedAttributes": [True] * 4},
            {"level": 1, "verifiedAttributes": [1, 0, 1, 0, 1]},
            {"level": True, "verifiedAttributes": [True] * 5},
        ):
            with self.assertRaises(AdapterError):
                schema.normalize_claims(bad)

    def test_jurisdiction_claims_validation(self):
        schema = get_schema("zkc:cred:jurisdiction:v1")
        claims = {
            "jurisdictionCode": 840,
            "claimType": 0,
            "verificationMethod": 1,
            "validFrom": 1,
            "validUntil": 2,
        }
        for code in (1, 840, 65534):
            with self.subTest(code=code):
                self.assertEqual(
                    schema.normalize_claims({**claims, "jurisdictionCode": code})["jurisdictionCode"],
                    code,
                )
        with self.assertRaises(AdapterError):
            schema.normalize_claims({**claims, "jurisdictionCode": 1 << 16})
        with self.assertRaises(AdapterError):
            schema.normalize_claims({**claims, "validUntil": 1, "validFrom": 5})

    def test_profile_schema_claim_packing(self):
        legacy_accreditation = get_schema("zkc:cred:accreditation:v1")
        self.assertFalse(legacy_accreditation.issuable)
        accreditation = get_schema("zkc:cred:accreditation:v2")
        self.assertTrue(accreditation.issuable)
        self.assertEqual(accreditation.proof_type, "zkc:proof:accreditation:v7")
        self.assertEqual(accreditation.circuit, "zkc_remaining_predicates_v7")
        claims = accreditation.normalize_claims(
            {"accreditationLevel": 3, "institutional": True, "validFrom": 1, "validUntil": 9}
        )
        self.assertEqual((claims["claim0"], claims["claim1"]), (3, 1))
        tax = get_schema("zkc:cred:tax:v2")
        claims = tax.normalize_claims(
            {"taxResidencyCode": 276, "taxYear": 2025, "validFrom": 1, "validUntil": 9}
        )
        self.assertEqual((claims["claim0"], claims["claim1"]), (276, 2025))

    def test_profile_v2_schemas_use_current_proof_and_safe_digest(self):
        expected = {
            "accreditation": "zkc:proof:accreditation:v7",
            "source": "zkc:proof:source:v7",
            "tax": "zkc:proof:tax:v7",
            "sanctions": "zkc:proof:sanctions:v7",
        }
        for name, proof_type in expected.items():
            with self.subTest(schema=name):
                legacy = get_schema(f"zkc:cred:{name}:v1")
                current = get_schema(f"zkc:cred:{name}:v2")
                self.assertFalse(legacy.issuable)
                self.assertTrue(current.issuable)
                self.assertEqual(current.proof_type, proof_type)
                self.assertEqual(current.circuit, "zkc_remaining_predicates_v7")
                claims = {
                    "accreditation": {
                        "accreditationLevel": 3, "institutional": True,
                        "validFrom": 1, "validUntil": 9,
                    },
                    "source": {"sourceOfFundsCode": 7, "validFrom": 1, "validUntil": 9},
                    "tax": {
                        "taxResidencyCode": 276, "taxYear": 2025,
                        "validFrom": 1, "validUntil": 9,
                    },
                    "sanctions": {"screeningCode": 4242, "validFrom": 1, "validUntil": 9},
                }[name]
                normalized = current.normalize_claims(claims)
                baseline = current.compute_digest(123, 456, normalized, 9)
                with self.assertRaises(AdapterError) as mismatch:
                    current.compute_digest(123, 456, normalized, 10)
                self.assertEqual(mismatch.exception.code, "UNSUPPORTED_SCHEMA")
                self.assertIn(f"zkc:cred:{name}:v2", str(mismatch.exception))
                self.assertIn("expiresAt must equal validUntil", str(mismatch.exception))
                self.assertNotEqual(
                    current.compute_digest(
                        123, 456, {**normalized, "validFrom": 2}, 9
                    ),
                    baseline,
                )


class BindingChallengeTests(unittest.TestCase):
    def test_holder_helper_matches_issuer_expectation_without_seed(self):
        cbk = derive_credential_binding_key(MASTER_SEED)
        challenge = BindingChallenge.issue(
            "subject", HOLDER_COMMITMENT_HEX, "zkc:cred:kyc:v1", now=1000
        )
        expected = compute_binding_response(
            HOLDER_COMMITMENT,
            "zkc:issuer:sandbox",
            "zkc:cred:kyc:v1",
            challenge.nonce,
            challenge.expires_at,
        )
        from_holder = holder_binding_response(
            cbk,
            "zkc:issuer:sandbox",
            "zkc:cred:kyc:v1",
            field_to_hex(challenge.nonce),
            challenge.expires_at,
        )
        self.assertEqual(from_holder, expected)
        # The response binds every tuple element.
        self.assertNotEqual(
            expected,
            compute_binding_response(
                HOLDER_COMMITMENT,
                "zkc:issuer:other",
                "zkc:cred:kyc:v1",
                challenge.nonce,
                challenge.expires_at,
            ),
        )

    def test_nonces_are_unique_and_nonzero(self):
        nonces = {
            BindingChallenge.issue("s", HOLDER_COMMITMENT_HEX, "x", now=0).nonce
            for _ in range(16)
        }
        self.assertEqual(len(nonces), 16)
        self.assertNotIn(0, nonces)


class PrivacyBoundaryTests(unittest.TestCase):
    def test_reject_forbidden_scans_nested_payloads(self):
        with self.assertRaises(AdapterError) as ctx:
            reject_forbidden({"request": {"wallet": [{"masterSeed": "x"}]}})
        self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")
        self.assertIn("masterSeed", ctx.exception.message)
        self.assertNotIn("x", ctx.exception.message.replace("masterSeed", ""))

    def test_every_stage_rejects_forbidden_material(self):
        adapter = SandboxIssuerAdapter()
        payloads = {
            adapter.verify_subject: {"schemaId": "zkc:cred:kyc:v1", "fixtureId": "f"},
            adapter.request_binding_challenge: {"subjectRef": "s"},
            adapter.bind_holder_commitment: {"nonce": "0x00"},
            adapter.issue_credential: {"subjectRef": "s"},
            adapter.publish_revocation_handle: {},
        }
        for forbidden in sorted(FORBIDDEN_FIELDS):
            for stage, payload in payloads.items():
                with self.assertRaises(AdapterError) as ctx:
                    stage({**payload, forbidden: "should-never-be-sent"})
                self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")

    def test_issued_envelope_and_metadata_carry_no_forbidden_fields(self):
        adapter, subject_ref = _bound_adapter("zkc:cred:kyc:v1", "sandbox-alice-basic")
        envelope = adapter.issue_credential(
            {"subjectRef": subject_ref, "schemaId": "zkc:cred:kyc:v1"}
        )
        for document in (envelope, adapter.issuer_metadata()):
            hits = []
            _scan_for_forbidden(document, hits)
            self.assertEqual(hits, [], f"forbidden fields leaked: {hits}")


MACHINE_PROFILES = frozenset({"human", "machine"})
SAFE_MACHINE_ERROR = "request includes forbidden privacy-boundary material"


class _MachineKycAdapter(SandboxIssuerAdapter):
    supported_schema_ids = frozenset({"zkc:cred:kyc:v1"})
    schema_required_privacy_profiles = MappingProxyType(
        {"zkc:cred:kyc:v1": frozenset({"human", "machine"})}
    )


class MachineSubjectPrivacyScannerTests(unittest.TestCase):
    def assert_machine_rejected(self, payload):
        with self.assertRaises(AdapterError) as caught:
            reject_forbidden(payload, profiles=MACHINE_PROFILES)
        self.assertEqual(caught.exception.code, "INVALID_HOLDER_CHALLENGE")
        self.assertEqual(caught.exception.message, SAFE_MACHINE_ERROR)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_rejects_direct_and_semantic_machine_identifiers(self):
        for payload in (
            {"teeQuote": {"hostSerial": "host-test-serial"}},
            {"provenance": {"buildPath": "/customers/acme/build"}},
            {"host.serialNumber": "host-test-serial"},
            {"platform": {"serial": "host-test-serial"}},
            {"chip": {"id": "chip-test-id"}},
            {"build": {"components": [{"path": "/customers/acme/component"}]}},
            {"build": {"builderIdentity": "customer-builder"}},
        ):
            with self.subTest(payload=payload):
                self.assert_machine_rejected(payload)

    def test_rejects_every_direct_name_and_normalized_spelling(self):
        direct_names = (
            "rawEvidence", "rawProvenance", "provenanceStatement",
            "transparencyInclusionProof", "inclusionPath", "logEntry", "leafBytes",
            "teeQuote", "teeReport", "rawQuote", "attestationReport",
            "rawAttestationReport", "rawTeeReport", "certificateChain",
            "endorsementChain", "endorsementArtifact", "collateral",
            "runtimeMeasurement", "reportData", "hostSerial", "hostSerialNumber",
            "platformSerial", "systemSerial", "chipId", "chipIdentifier", "hostUuid",
            "hardwareUuid", "hostId", "hardwareId", "machineId", "cloudInstanceId",
            "hostInstanceId", "vmId", "buildPath", "sourcePath", "workspacePath",
            "checkoutPath", "buildDirectory", "sourceDirectory", "workingDirectory",
            "environmentVariables", "envVars", "buildParameters", "buildInvocationId",
        )
        for name in direct_names:
            with self.subTest(name=name):
                self.assert_machine_rejected({name: "literal-value"})
        for name in ("tee.quote", "raw_evidence", "raw-evidence"):
            with self.subTest(name=name):
                self.assert_machine_rejected({name: "literal-value"})

    def test_rejects_every_suffix_and_malformed_or_noncanonical_keys(self):
        suffix_payloads = (
            {"build": {"path": "x"}},
            {"source": {"path": "x"}},
            {"workspace": {"path": "x"}},
            {"checkout": {"path": "x"}},
            {"provenance": {"build": {"path": "x"}}},
            {"build": {"components": [{"path": "x"}]}},
            {"host": {"serial": "x"}},
            {"host": {"serialNumber": "x"}},
            {"platform": {"serial": "x"}},
            {"chip": {"id": "x"}},
            {"build": {"builderIdentity": "x"}},
        )
        for payload in suffix_payloads:
            with self.subTest(payload=payload):
                self.assert_machine_rejected(payload)
        for key in (
            "build.path", "build_path", "build-path", "host.serial",
            "host.serial_number", "host.serial-number", "chip.id",
        ):
            with self.subTest(key=key):
                self.assert_machine_rejected({key: "x"})
        for key in ("", ".host", "host.", "host..serial", "---", "_"):
            with self.subTest(key=key):
                self.assert_machine_rejected({key: "x"})
        self.assert_machine_rejected({"hоstSerial": "x"})
        self.assert_machine_rejected({7: "x"})

    def test_allows_qualified_witness_and_never_scans_values(self):
        reject_forbidden({"witness": {"path": "/customers/acme/build"}}, profiles=MACHINE_PROFILES)
        reject_forbidden({"platformId": "host-test-serial"}, profiles=MACHINE_PROFILES)
        reject_forbidden({"note": "teeQuote hostSerial /customers/acme/build"}, profiles=MACHINE_PROFILES)
        for name in (
            "path", "serial", "identifier", "id", "report", "statement", "quote",
            "measurement", "digest", "platformId", "builderIdentity", "evidenceRef",
            "providerRef", "subjectRef",
        ):
            with self.subTest(name=name):
                reject_forbidden({name: "allowed"}, profiles=MACHINE_PROFILES)

    def test_rejects_noncanonical_containers_and_traversal_limits(self):
        class StringSubclass(str):
            pass

        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class TupleSubclass(tuple):
            pass

        class CustomMapping(Mapping):
            def __iter__(self):
                return iter(("safe",))

            def __len__(self):
                return 1

            def __getitem__(self, key):
                if key == "safe":
                    return "value"
                raise KeyError(key)

        for payload in (
            {StringSubclass("safe"): "value"},
            {"safe": DictSubclass()},
            {"safe": ListSubclass()},
            {"safe": TupleSubclass()},
            {"safe": CustomMapping()},
            {"x" * 4097: "value"},
        ):
            with self.subTest(payload_type=type(next(iter(payload.values()))).__name__):
                self.assert_machine_rejected(payload)

        nested = {}
        cursor = nested
        for _ in range(32):
            cursor["safe"] = {}
            cursor = cursor["safe"]
        self.assert_machine_rejected(nested)

        self.assert_machine_rejected({"safe": [None] * 4095})
        shared = {"safe": "value"}
        self.assert_machine_rejected({"first": shared, "second": shared})
        cycle = {}
        cycle["self"] = cycle
        self.assert_machine_rejected(cycle)

    def test_rejects_a_wide_single_container_at_the_node_budget(self):
        self.assert_machine_rejected({"safe": [None] * 100_000})

    def test_deep_dotted_prefix_wide_leaf_scan_keeps_only_bounded_suffix_state(self):
        dotted_prefix = ".".join(["x"] * 2_000)
        wide_leaf = {"host": {"serial": "host-test-serial"}}
        wide_leaf.update(
            {f"safe{index}": None for index in range(512)}
        )
        payload = {
            dotted_prefix: wide_leaf,
        }

        tracemalloc.start()
        try:
            with self.assertRaises(AdapterError) as caught:
                reject_forbidden(payload, profiles=MACHINE_PROFILES)
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(caught.exception.code, "INVALID_HOLDER_CHALLENGE")
        self.assertEqual(caught.exception.message, SAFE_MACHINE_ERROR)
        self.assertLess(peak_bytes, 2_000_000)

    def test_mixed_profile_human_material_uses_the_fixed_machine_error(self):
        sentinel = "customer-private-sentinel"
        with self.assertRaises(AdapterError) as caught:
            reject_forbidden(
                {"safe": {"masterSeed": sentinel}},
                profiles=MACHINE_PROFILES,
            )
        self.assertEqual(
            caught.exception.to_dict(),
            {
                "code": "INVALID_HOLDER_CHALLENGE",
                "message": SAFE_MACHINE_ERROR,
            },
        )
        self.assertNotIn(sentinel, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_legacy_human_profile_is_unchanged(self):
        reject_forbidden({"teeQuote": {"hostSerial": "x"}})
        with self.assertRaises(AdapterError) as caught:
            reject_forbidden({"masterSeed": "x"})
        self.assertEqual(
            caught.exception.to_dict(),
            {
                "code": "INVALID_HOLDER_CHALLENGE",
                "message": "request includes forbidden holder material: masterSeed",
            },
        )
        self.assertEqual(
            str(caught.exception),
            "[INVALID_HOLDER_CHALLENGE] "
            "request includes forbidden holder material: masterSeed",
        )

    def test_ordinary_scanner_failures_are_value_free_and_context_free(self):
        class ExplodingProfiles:
            def __iter__(self):
                raise RuntimeError("customer-private-detail")

        with self.assertRaises(AdapterError) as caught:
            reject_forbidden({"safe": "value"}, profiles=ExplodingProfiles())
        self.assertEqual(caught.exception.code, "INVALID_HOLDER_CHALLENGE")
        self.assertEqual(caught.exception.message, SAFE_MACHINE_ERROR)
        self.assertNotIn("customer-private-detail", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)


class AdapterCapabilityTests(unittest.TestCase):
    def test_exports_and_exact_immutable_machine_capability_declarations(self):
        self.assertEqual(HUMAN_PRIVACY_PROFILE, "human")
        self.assertEqual(MACHINE_PRIVACY_PROFILE, "machine")
        self.assertEqual(KNOWN_PRIVACY_PROFILES, frozenset({"human", "machine"}))
        adapter = _MachineKycAdapter()
        self.assertIs(type(adapter.supported_schema_ids), frozenset)
        self.assertIs(type(adapter.schema_required_privacy_profiles), MappingProxyType)
        self.assertEqual(adapter._active_privacy_profiles(), MACHINE_PROFILES)

    def test_rejects_mutable_and_invalid_capability_declarations(self):
        class EmptySchemaIds(SandboxIssuerAdapter):
            supported_schema_ids = frozenset()
            schema_required_privacy_profiles = MappingProxyType({})

        class MutableSchemaIds(SandboxIssuerAdapter):
            supported_schema_ids = {"zkc:cred:kyc:v1"}
            schema_required_privacy_profiles = MappingProxyType(
                {"zkc:cred:kyc:v1": frozenset({"human"})}
            )

        class MutableProfiles(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({"zkc:cred:kyc:v1"})
            schema_required_privacy_profiles = {"zkc:cred:kyc:v1": {"human"}}

        class MutableNestedProfiles(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({"zkc:cred:kyc:v1"})
            schema_required_privacy_profiles = MappingProxyType(
                {"zkc:cred:kyc:v1": {"human"}}
            )

        class MissingRequiredSchemaProfile(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({"zkc:cred:kyc:v1"})
            schema_required_privacy_profiles = MappingProxyType({})

        class ExtraSchemaProfile(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({"zkc:cred:kyc:v1"})
            schema_required_privacy_profiles = MappingProxyType(
                {
                    "zkc:cred:kyc:v1": frozenset({"human"}),
                    "zkc:cred:tax:v1": frozenset({"human"}),
                }
            )

        class UnknownProfile(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({"zkc:cred:kyc:v1"})
            schema_required_privacy_profiles = MappingProxyType(
                {"zkc:cred:kyc:v1": frozenset({"human", "robot"})}
            )

        class MissingHuman(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({"zkc:cred:kyc:v1"})
            schema_required_privacy_profiles = MappingProxyType(
                {"zkc:cred:kyc:v1": frozenset({"machine"})}
            )

        class UnsupportedSchema(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({"zkc:cred:missing:v1"})
            schema_required_privacy_profiles = MappingProxyType(
                {"zkc:cred:missing:v1": frozenset({"human"})}
            )

        class RuntimeWithoutMachine(SandboxIssuerAdapter):
            supported_schema_ids = frozenset(
                {ISSUER_RUNTIME_ATTESTATION_SCHEMA_ID}
            )
            schema_required_privacy_profiles = MappingProxyType(
                {
                    ISSUER_RUNTIME_ATTESTATION_SCHEMA_ID: frozenset(
                        {"human"}
                    )
                }
            )

        class LegacyProfileSchema(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({"zkc:cred:tax:v1"})
            schema_required_privacy_profiles = MappingProxyType(
                {"zkc:cred:tax:v1": frozenset({"human"})}
            )

        for adapter_type in (
            EmptySchemaIds, MutableSchemaIds, MutableProfiles, MutableNestedProfiles,
            MissingRequiredSchemaProfile, ExtraSchemaProfile, UnknownProfile,
            MissingHuman, UnsupportedSchema, RuntimeWithoutMachine,
            LegacyProfileSchema,
        ):
            with self.subTest(adapter_type=adapter_type.__name__):
                with self.assertRaises(ValueError):
                    adapter_type()

    def test_uses_only_locally_supported_schemas_and_metadata(self):
        adapter = _MachineKycAdapter()
        with self.assertRaises(AdapterError) as caught:
            adapter.verify_subject(
                {"schemaId": "zkc:cred:runtime-attestation:v1", "fixtureId": "sandbox-alice-basic"}
            )
        self.assertEqual(caught.exception.code, "UNSUPPORTED_SCHEMA")
        metadata_ids = [entry["schemaId"] for entry in adapter.issuer_metadata()["supportedSchemas"]]
        self.assertEqual(metadata_ids, ["zkc:cred:kyc:v1"])

    def test_human_reference_adapters_advertise_only_their_local_schema_sets(self):
        sandbox = SandboxIssuerAdapter()
        external = reference_external_adapter()
        self.assertEqual(
            sandbox.supported_schema_ids,
            frozenset(
                {
                    "zkc:cred:accreditation:v2",
                    "zkc:cred:attribute-set:v1",
                    "zkc:cred:attribute-set:v2",
                    "zkc:cred:jurisdiction:v1",
                    "zkc:cred:jurisdiction:v2",
                    "zkc:cred:kyc:v1",
                    "zkc:cred:sanctions:v2",
                    "zkc:cred:sanctions:v3",
                    "zkc:cred:source:v2",
                    "zkc:cred:source:v3",
                    "zkc:cred:tax:v2",
                    "zkc:cred:tax:v3",
                }
            ),
        )
        self.assertEqual(external.supported_schema_ids, frozenset({"zkc:cred:kyc:v1"}))
        for adapter in (sandbox, external):
            with self.subTest(adapter=type(adapter).__name__):
                self.assertNotIn(RUNTIME_SCHEMA_ID, adapter.supported_schema_ids)
                self.assertEqual(
                    {entry["schemaId"] for entry in adapter.issuer_metadata()["supportedSchemas"]},
                    adapter.supported_schema_ids,
                )

    def test_resolved_subject_scan_uses_only_the_resolved_schema_profiles(self):
        class MixedPrivacyAdapter(SandboxIssuerAdapter):
            supported_schema_ids = frozenset({"zkc:cred:kyc:v1", "zkc:cred:tax:v2"})
            schema_required_privacy_profiles = MappingProxyType(
                {
                    "zkc:cred:kyc:v1": frozenset({"human"}),
                    "zkc:cred:tax:v2": frozenset({"human", "machine"}),
                }
            )

            def _resolve_subject(self, schema, payload):
                return {
                    "providerRef": "provider-ref",
                    "credential": {
                        "claims": {"hostSerial": "host-test-serial"},
                        "expiresAt": 2_000_000_000,
                    },
                }

        adapter = MixedPrivacyAdapter()
        accepted = adapter.verify_subject({"schemaId": "zkc:cred:kyc:v1", "fixtureId": "ignored"})
        self.assertEqual(accepted["schemaId"], "zkc:cred:kyc:v1")
        with self.assertRaises(AdapterError) as caught:
            adapter.verify_subject({"schemaId": "zkc:cred:tax:v2", "fixtureId": "ignored"})
        self.assertEqual(caught.exception.code, "INVALID_HOLDER_CHALLENGE")
        self.assertEqual(caught.exception.message, SAFE_MACHINE_ERROR)

    def test_machine_boundary_scans_resolved_provider_shape_before_retention(self):
        class UnsafeResolvedAdapter(_MachineKycAdapter):
            def _resolve_subject(self, schema, payload):
                return {
                    "providerRef": "private-provider-reference",
                    "credential": {
                        "claims": {"level": 2, "hostSerial": "host-test-serial"},
                        "expiresAt": 2_000_000_000,
                    },
                }

        adapter = UnsafeResolvedAdapter()
        with self.assertRaises(AdapterError) as caught:
            adapter.verify_subject({"schemaId": "zkc:cred:kyc:v1", "fixtureId": "ignored"})
        self.assertEqual(caught.exception.code, "INVALID_HOLDER_CHALLENGE")
        self.assertEqual(caught.exception.message, SAFE_MACHINE_ERROR)
        self.assertEqual(adapter._verified, {})


class AdapterStageTests(unittest.TestCase):
    def test_set_credential_issuance_rejects_reserved_subjects_and_zero_jurisdiction_expiry(self):
        for schema_id, fixture_id, changes in (
            ("zkc:cred:jurisdiction:v1", "sandbox-alice-basic", {"jurisdictionCode": 0}),
            ("zkc:cred:jurisdiction:v1", "sandbox-alice-basic", {"jurisdictionCode": 65535}),
            ("zkc:cred:jurisdiction:v1", "sandbox-alice-basic", {"validUntil": 0}),
            ("zkc:cred:sanctions:v2", "sandbox-carol-institutional", {"screeningCode": 0}),
            ("zkc:cred:sanctions:v2", "sandbox-carol-institutional", {"screeningCode": 65535}),
        ):
            with self.subTest(schema_id=schema_id, changes=changes):
                entry = SANDBOX_FIXTURES[fixture_id][schema_id]
                fixture = {**entry, "claims": {**entry["claims"], **changes}}
                if changes.get("validUntil") == 0:
                    fixture["expiresAt"] = 0
                adapter, subject_ref = _bound_adapter(
                    schema_id, fixture_id, fixtures={fixture_id: {schema_id: fixture}}
                )
                with self.assertRaises(AdapterError) as caught:
                    adapter.issue_credential({"subjectRef": subject_ref, "schemaId": schema_id})
                self.assertEqual(caught.exception.code, "UNSUPPORTED_SCHEMA")
                self.assertIn(next(iter(changes)), caught.exception.message)
                self.assertEqual(adapter.accumulator.epoch, 0)

    def test_sanctions_issuance_accepts_in_domain_subjects_and_explicit_no_expiry(self):
        schema_id, fixture_id = "zkc:cred:sanctions:v2", "sandbox-carol-institutional"
        entry = SANDBOX_FIXTURES[fixture_id][schema_id]
        for code in (1, 65534):
            with self.subTest(code=code):
                fixture = {
                    **entry,
                    "claims": {**entry["claims"], "screeningCode": code, "validUntil": 0},
                    "expiresAt": 0,
                }
                adapter, subject_ref = _bound_adapter(
                    schema_id, fixture_id, fixtures={fixture_id: {schema_id: fixture}}
                )
                issued = adapter.issue_credential({"subjectRef": subject_ref, "schemaId": schema_id})
                credential = issued["credential"]
                self.assertEqual(credential["claims"]["screeningCode"], code)
                self.assertEqual(credential["claims"]["validUntil"], 0)
                self.assertEqual(credential["expiresAt"], 0)

    def test_legacy_profile_schemas_are_refused_for_new_issuance(self):
        adapter = SandboxIssuerAdapter()
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject(
                {"schemaId": "zkc:cred:tax:v1", "fixtureId": "sandbox-bob-enhanced"}
            )
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_SCHEMA")

    def test_full_issuance_for_every_fixture_and_schema(self):
        issuer_key = IssuerSigningKey.test_issuer()
        key_x, key_y = issuer_key.public_key_coordinates()
        for fixture_id, entries in SANDBOX_FIXTURES.items():
            for schema_id, entry in entries.items():
                with self.subTest(fixture=fixture_id, schema=schema_id):
                    adapter, subject_ref = _bound_adapter(schema_id, fixture_id)
                    envelope = adapter.issue_credential(
                        {"subjectRef": subject_ref, "schemaId": schema_id}
                    )
                    self.assertEqual(envelope["version"], "zkc:credential-envelope:v1")
                    credential = Credential.from_dict(envelope["credential"])
                    self.assertEqual(credential.holder_commitment, HOLDER_COMMITMENT)
                    schema = get_schema(schema_id)
                    self.assertEqual(credential.proof_type, schema.proof_type)
                    # The signature verifies over the circuit-exact digest.
                    digest = schema.compute_digest(
                        credential.holder_commitment,
                        credential.credential_id,
                        schema.normalize_claims(envelope["credential"]["claims"]),
                        credential.expires_at,
                    )
                    self.assertTrue(
                        ecdsa_verify(
                            key_x, key_y, credential.signature, digest_to_message_bytes(digest)
                        )
                    )
                    # The witness proves membership under the published root.
                    witness = credential.witness
                    self.assertEqual(
                        compute_merkle_root(
                            credential.credential_id, witness.path_index, witness.siblings
                        ),
                        witness.accumulator_root,
                    )
                    self.assertEqual(
                        field_to_hex(witness.accumulator_root),
                        envelope["revocation"]["currentRoot"],
                    )

    def test_profile_v2_issue_and_renew_sign_safe_digest(self):
        schema_id = "zkc:cred:tax:v2"
        adapter, subject_ref = _bound_adapter(schema_id, "sandbox-bob-enhanced")
        issuer_key_x, issuer_key_y = adapter._signing_key.public_key_coordinates()
        issued = adapter.issue_credential({"subjectRef": subject_ref, "schemaId": schema_id})
        with self.assertRaises(AdapterError) as mismatch:
            adapter.renew_credential(
                {
                    "credentialId": issued["credential"]["credentialId"],
                    "expiresAt": 1_900_000_000,
                }
            )
        self.assertEqual(mismatch.exception.code, "UNSUPPORTED_SCHEMA")
        renewed = adapter.renew_credential(
            {"credentialId": issued["credential"]["credentialId"]}
        )
        schema = get_schema(schema_id)
        for envelope in (issued, renewed):
            with self.subTest(renewed="renewal" in envelope):
                credential = Credential.from_dict(envelope["credential"])
                digest = schema.compute_digest(
                    credential.holder_commitment,
                    credential.credential_id,
                    schema.normalize_claims(envelope["credential"]["claims"]),
                    credential.expires_at,
                )
                self.assertTrue(
                    ecdsa_verify(
                        issuer_key_x,
                        issuer_key_y,
                        credential.signature,
                        digest_to_message_bytes(digest),
                    )
                )
                changed_claims = {
                    **envelope["credential"]["claims"],
                    "validFrom": envelope["credential"]["claims"]["validFrom"] + 1,
                }
                changed_digest = schema.compute_digest(
                    credential.holder_commitment,
                    credential.credential_id,
                    schema.normalize_claims(changed_claims),
                    credential.expires_at,
                )
                self.assertFalse(
                    ecdsa_verify(
                        issuer_key_x,
                        issuer_key_y,
                        credential.signature,
                        digest_to_message_bytes(changed_digest),
                    )
                )

    def test_verify_subject_rejections(self):
        adapter = SandboxIssuerAdapter()
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject(
                {"schemaId": "zkc:cred:unknown:v1", "fixtureId": "sandbox-alice-basic"}
            )
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_SCHEMA")
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject({"schemaId": "zkc:cred:kyc:v1", "fixtureId": "nobody"})
        self.assertEqual(ctx.exception.code, "PROVIDER_VERIFICATION_FAILED")
        # Alice has no accreditation fixture: provider verification fails.
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject(
                {"schemaId": "zkc:cred:accreditation:v2", "fixtureId": "sandbox-alice-basic"}
            )
        self.assertEqual(ctx.exception.code, "PROVIDER_VERIFICATION_FAILED")

    def test_binding_negative_paths(self):
        schema_id = "zkc:cred:kyc:v1"
        adapter = SandboxIssuerAdapter()
        subject = adapter.verify_subject(
            {"schemaId": schema_id, "fixtureId": "sandbox-alice-basic"}
        )
        base = {
            "subjectRef": subject["subjectRef"],
            "holderCommitment": HOLDER_COMMITMENT_HEX,
            "schemaId": schema_id,
        }
        challenge = adapter.request_binding_challenge(base)
        good_response = field_to_hex(
            compute_binding_response(
                HOLDER_COMMITMENT,
                adapter.issuer_id,
                schema_id,
                hex_to_field(challenge["nonce"]),
                challenge["expiresAt"],
            )
        )

        # Wrong response value.
        with self.assertRaises(AdapterError) as ctx:
            adapter.bind_holder_commitment(
                {**base, "nonce": challenge["nonce"], "challengeResponse": field_to_hex(1)}
            )
        self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")

        # Nonce is single-use: the failed attempt consumed it.
        with self.assertRaises(AdapterError) as ctx:
            adapter.bind_holder_commitment(
                {**base, "nonce": challenge["nonce"], "challengeResponse": good_response}
            )
        self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")

        # Commitment swap after challenge issuance.
        challenge = adapter.request_binding_challenge(base)
        response = field_to_hex(
            compute_binding_response(
                HOLDER_COMMITMENT,
                adapter.issuer_id,
                schema_id,
                hex_to_field(challenge["nonce"]),
                challenge["expiresAt"],
            )
        )
        with self.assertRaises(AdapterError) as ctx:
            adapter.bind_holder_commitment(
                {
                    **base,
                    "holderCommitment": field_to_hex(123),
                    "nonce": challenge["nonce"],
                    "challengeResponse": response,
                }
            )
        self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")

        # Unknown nonce.
        with self.assertRaises(AdapterError) as ctx:
            adapter.bind_holder_commitment(
                {**base, "nonce": field_to_hex(99), "challengeResponse": good_response}
            )
        self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")

    def test_expired_challenge_is_rejected(self):
        schema_id = "zkc:cred:kyc:v1"
        # Inside the default test key window: the accumulator signs genesis at this time.
        clock = {"now": 1_770_000_000}
        adapter = SandboxIssuerAdapter(clock=lambda: clock["now"], subject_session_ttl_seconds=1200)
        subject = adapter.verify_subject(
            {"schemaId": schema_id, "fixtureId": "sandbox-alice-basic"}
        )
        base = {
            "subjectRef": subject["subjectRef"],
            "holderCommitment": HOLDER_COMMITMENT_HEX,
            "schemaId": schema_id,
        }
        challenge = adapter.request_binding_challenge(base)
        response = field_to_hex(
            compute_binding_response(
                HOLDER_COMMITMENT,
                adapter.issuer_id,
                schema_id,
                hex_to_field(challenge["nonce"]),
                challenge["expiresAt"],
            )
        )
        clock["now"] = challenge["expiresAt"] + 1
        with self.assertRaises(AdapterError) as ctx:
            adapter.bind_holder_commitment(
                {**base, "nonce": challenge["nonce"], "challengeResponse": response}
            )
        self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")
        self.assertIn("expired", ctx.exception.message)

    def test_issue_requires_binding(self):
        adapter = SandboxIssuerAdapter()
        subject = adapter.verify_subject(
            {"schemaId": "zkc:cred:kyc:v1", "fixtureId": "sandbox-alice-basic"}
        )
        with self.assertRaises(AdapterError) as ctx:
            adapter.issue_credential(
                {"subjectRef": subject["subjectRef"], "schemaId": "zkc:cred:kyc:v1"}
            )
        self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")

    def test_expired_issuer_key_is_rejected_at_issuance(self):
        adapter, subject_ref = _bound_adapter(
            "zkc:cred:kyc:v1", "sandbox-alice-basic", clock=lambda: 1_770_000_000
        )
        # Expire the key while the independent subject session remains live.
        from dataclasses import replace
        adapter._signing_key = replace(adapter._signing_key, not_after="2026-01-02T00:00:00Z")
        with self.assertRaises(AdapterError) as ctx:
            adapter.issue_credential({"subjectRef": subject_ref, "schemaId": "zkc:cred:kyc:v1"})
        self.assertEqual(ctx.exception.code, "EXPIRED_ISSUER_KEY")

    def test_rate_limiting(self):
        adapter = SandboxIssuerAdapter(max_requests_per_stage=2)
        payload = {"schemaId": "zkc:cred:kyc:v1", "fixtureId": "sandbox-alice-basic"}
        adapter.verify_subject(payload)
        adapter.verify_subject(payload)
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject(payload)
        self.assertEqual(ctx.exception.code, "RATE_LIMITED")

    def test_error_codes_are_the_closed_protocol_set(self):
        self.assertEqual(len(ADAPTER_ERROR_CODES), 8)
        with self.assertRaises(ValueError):
            AdapterError("MADE_UP_CODE", "nope")
        error = AdapterError("RATE_LIMITED", "slow down")
        self.assertEqual(error.to_dict(), {"code": "RATE_LIMITED", "message": "slow down"})


class RevocationTests(unittest.TestCase):
    def test_revocation_lifecycle_and_handle_publication(self):
        adapter, subject_ref = _bound_adapter("zkc:cred:kyc:v1", "sandbox-alice-basic")
        envelope = adapter.issue_credential(
            {"subjectRef": subject_ref, "schemaId": "zkc:cred:kyc:v1"}
        )
        credential_id_hex = envelope["credential"]["credentialId"]
        credential_id = hex_to_field(credential_id_hex)
        epoch_before = adapter.accumulator.epoch
        root_before = adapter.accumulator.root()

        handle = adapter.publish_revocation_handle({"credentialId": credential_id_hex})
        self.assertEqual(handle["status"], "active")
        self.assertIn("witness", handle)

        adapter.revoke_credential(credential_id)
        self.assertEqual(adapter.accumulator.epoch, epoch_before + 1)
        self.assertNotEqual(adapter.accumulator.root(), root_before)

        handle = adapter.publish_revocation_handle({"credentialId": credential_id_hex})
        self.assertEqual(handle["status"], "revoked")
        self.assertNotIn("witness", handle)
        with self.assertRaises(AdapterError) as ctx:
            adapter.accumulator.witness(credential_id)
        self.assertEqual(ctx.exception.code, "STALE_ACCUMULATOR_WITNESS")

        unknown = adapter.publish_revocation_handle({"credentialId": field_to_hex(424242)})
        self.assertEqual(unknown["status"], "unknown")

    def test_accumulator_guards(self):
        accumulator = IssuerAccumulator("test", "https://example.invalid/v1/updates")
        with self.assertRaises(AdapterError):
            accumulator.revoke(42)  # never registered
        accumulator.register(42)
        with self.assertRaises(ValueError):
            accumulator.register(42)  # duplicate


class MetadataTests(unittest.TestCase):
    def test_generated_metadata_passes_the_repo_validator(self):
        adapter = SandboxIssuerAdapter()
        metadata = adapter.issuer_metadata()
        _load_metadata_validator().validate_metadata(metadata, require_authenticated=True)
        self.assertEqual(metadata["version"], "zkc:issuer-metadata:v2")
        self.assertIn("currentAnnouncement", metadata["revocation"])
        self.assertEqual(len(metadata["supportedSchemas"]), len(adapter.supported_schema_ids))
        self.assertEqual(metadata["revocation"]["type"], "POSEIDON2_MERKLE_ACTIVE_SET")
        self.assertEqual(metadata["revocation"]["maxEpochLag"], 10)

    def test_metadata_tracks_accumulator_state(self):
        adapter, subject_ref = _bound_adapter("zkc:cred:kyc:v1", "sandbox-alice-basic")
        before = adapter.issuer_metadata()["revocation"]["currentEpoch"]
        adapter.issue_credential({"subjectRef": subject_ref, "schemaId": "zkc:cred:kyc:v1"})
        after = adapter.issuer_metadata()["revocation"]
        self.assertEqual(after["currentEpoch"], before + 1)

    def test_well_known_publication(self):
        adapter = SandboxIssuerAdapter()
        with tempfile.TemporaryDirectory() as tmp:
            path = adapter.publish_well_known(tmp)
            self.assertEqual(
                path, pathlib.Path(tmp) / ".well-known" / "zkc-issuer.json"
            )
            published = json.loads(path.read_text())
            _load_metadata_validator().validate_metadata(
                published, require_authenticated=True
            )

    def test_build_rejects_bad_inputs(self):
        adapter = SandboxIssuerAdapter()
        from zkc_issuer import build_issuer_metadata

        key = IssuerSigningKey.test_issuer()
        schemas = list(SUPPORTED_SCHEMAS.values())
        with self.assertRaises(ValueError):
            build_issuer_metadata(
                "Bad Issuer Id", "x", [key], schemas, adapter.accumulator, "https://x.example"
            )
        with self.assertRaises(ValueError):
            build_issuer_metadata(
                "zkc:issuer:x", "x", [key], schemas, adapter.accumulator, "http://x.example"
            )
        with self.assertRaises(ValueError):
            build_issuer_metadata(
                "zkc:issuer:x", "x", [], schemas, adapter.accumulator, "https://x.example"
            )


if __name__ == "__main__":
    unittest.main()
