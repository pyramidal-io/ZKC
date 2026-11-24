#!/usr/bin/env python3
"""Adapter-protocol conformance tests for the sandbox issuer.

Successor of the original fixture-only mock issuer tests: the sandbox
adapter now lives in python/zkc_issuer and signs real ECDSA credentials.
Run from the repo root: ``python3 -m unittest tests.issuer_adapter.test_mock_issuer``.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PYTHON_DIR = REPO_ROOT / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))
# Shared test-suite setup: renews the default sandbox signing-key window once
# the real clock passes its fixed end date (tests build SandboxIssuerAdapter()).
PYTHON_TESTS_DIR = REPO_ROOT / "tests" / "python"
if str(PYTHON_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_TESTS_DIR))
import _path  # noqa: E402,F401

from zkc_crypto import derive_holder_commitment_from_seed, field_to_hex, hex_to_field  # noqa: E402
from zkc_issuer import (  # noqa: E402
    AdapterError,
    SandboxIssuerAdapter,
    compute_binding_response,
)

HOLDER_COMMITMENT = derive_holder_commitment_from_seed(7)
HOLDER_COMMITMENT_HEX = field_to_hex(HOLDER_COMMITMENT)
KYC_SCHEMA = "zkc:cred:kyc:v1"
FIXTURE = "sandbox-alice-basic"


class MockIssuerTests(unittest.TestCase):
    def _bind(self, adapter: SandboxIssuerAdapter) -> str:
        subject = adapter.verify_subject({"schemaId": KYC_SCHEMA, "fixtureId": FIXTURE})
        challenge = adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": HOLDER_COMMITMENT_HEX,
                "schemaId": KYC_SCHEMA,
            }
        )
        response = compute_binding_response(
            HOLDER_COMMITMENT,
            adapter.issuer_id,
            KYC_SCHEMA,
            hex_to_field(challenge["nonce"]),
            challenge["expiresAt"],
        )
        binding = adapter.bind_holder_commitment(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": HOLDER_COMMITMENT_HEX,
                "schemaId": KYC_SCHEMA,
                "nonce": challenge["nonce"],
                "challengeResponse": field_to_hex(response),
            }
        )
        self.assertEqual(binding["status"], "bound")
        return subject["subjectRef"]

    def test_end_to_end_sandbox_credential_issuance(self) -> None:
        adapter = SandboxIssuerAdapter()
        subject_ref = self._bind(adapter)
        envelope = adapter.issue_credential({"subjectRef": subject_ref, "schemaId": KYC_SCHEMA})
        credential = envelope["credential"]
        self.assertEqual(credential["holderCommitment"], HOLDER_COMMITMENT_HEX)
        self.assertEqual(envelope["issuer"]["scheme"], "ECDSA_SECP256K1")
        self.assertEqual(envelope["revocation"]["type"], "POSEIDON2_MERKLE_ACTIVE_SET")
        # 64-byte r||s signature over the circuit digest.
        self.assertEqual(len(bytes.fromhex(credential["signature"].removeprefix("0x"))), 64)

    def test_rejects_unsupported_schema(self) -> None:
        adapter = SandboxIssuerAdapter()
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject({"schemaId": "zkc:cred:unknown:v1", "fixtureId": FIXTURE})
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_SCHEMA")

    def test_rejects_invalid_holder_challenge(self) -> None:
        adapter = SandboxIssuerAdapter()
        subject = adapter.verify_subject({"schemaId": KYC_SCHEMA, "fixtureId": FIXTURE})
        challenge = adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": HOLDER_COMMITMENT_HEX,
                "schemaId": KYC_SCHEMA,
            }
        )
        with self.assertRaises(AdapterError) as ctx:
            adapter.bind_holder_commitment(
                {
                    "subjectRef": subject["subjectRef"],
                    "holderCommitment": HOLDER_COMMITMENT_HEX,
                    "schemaId": KYC_SCHEMA,
                    "nonce": challenge["nonce"],
                    "challengeResponse": field_to_hex(1),
                }
            )
        self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")

    def test_rejects_forbidden_wallet_material(self) -> None:
        adapter = SandboxIssuerAdapter()
        with self.assertRaises(AdapterError) as ctx:
            adapter.verify_subject(
                {"schemaId": KYC_SCHEMA, "fixtureId": FIXTURE, "masterSeed": "do-not-send"}
            )
        self.assertEqual(ctx.exception.code, "INVALID_HOLDER_CHALLENGE")

    def test_unavailable_revocation_metadata_error_shape(self) -> None:
        error = AdapterError("REVOCATION_METADATA_UNAVAILABLE", "revocation endpoint unavailable")
        self.assertEqual(
            error.to_dict(),
            {
                "code": "REVOCATION_METADATA_UNAVAILABLE",
                "message": "revocation endpoint unavailable",
            },
        )


if __name__ == "__main__":
    unittest.main()
