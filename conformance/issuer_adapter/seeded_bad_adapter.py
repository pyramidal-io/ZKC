"""Deliberately NON-CONFORMANT issuer adapter.

Exists to prove the issuer-adapter conformance kit has teeth: it violates the
contract the way a careless production integration might, and the kit MUST
fail it on specific case ids (tests/python/test_issuer_adapter_contract.py
asserts that it does).

Seeded violations:

* privacy boundary skipped at verify_subject (wallet material accepted);
* binding challenge response never checked (any response binds);
* challenge nonces are replayable (not single-use);
* issuance proceeds without a holder binding (stage-order violation).

DO NOT use this as a starting point for an implementation.
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "python") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "python"))

from zkc_issuer import (  # noqa: E402
    HUMAN_PRIVACY_PROFILE,
    RUNTIME_ATTESTATION_SCHEMA_ID,
    ProviderClient,
    ProviderDecision,
    RuntimeAttestationAdapter,
    SandboxIssuerAdapter,
)

__all__ = [
    "SeededBadIssuerAdapter",
    "SeededBadMachinePrivacyAdapter",
    "make_adapter",
    "make_machine_privacy_adapter",
]


class SeededBadIssuerAdapter(SandboxIssuerAdapter):
    def verify_subject(self, payload: dict) -> dict:
        # VIOLATION: no privacy-boundary scan, no rate limiting.
        schema = self._get_supported_schema(payload.get("schemaId"))
        resolved = self._resolve_subject(schema, payload)
        import hashlib

        subject_ref = hashlib.sha256(
            f"{self.issuer_id}|{schema.schema_id}|{resolved['providerRef']}".encode()
        ).hexdigest()
        self._verified[subject_ref] = {
            "schemaId": schema.schema_id,
            "credential": resolved["credential"],
            "providerRef": resolved["providerRef"],
            "sessionIdentity": self._authenticated_session(),
            "sessionExpiresAt": self._now() + 600,
        }
        return {"status": "verified", "subjectRef": subject_ref, "schemaId": schema.schema_id}

    def bind_holder_commitment(self, payload: dict) -> dict:
        # VIOLATION: accepts ANY response and never consumes the nonce.
        self._enter_stage("bind_holder_commitment", payload)
        challenge = self._challenges.get(payload.get("nonce"))
        if challenge is not None:
            self._bindings[challenge.subject_ref] = challenge.holder_commitment_hex
        return {
            "status": "bound",
            "subjectRef": payload.get("subjectRef"),
            "holderCommitment": payload.get("holderCommitment"),
        }

    def issue_credential(self, payload: dict) -> dict:
        # VIOLATION: issues without a holder binding (binds on the fly to
        # whatever commitment the payload claims).
        subject_ref = payload.get("subjectRef")
        if subject_ref in self._verified and subject_ref not in self._bindings:
            commitment = payload.get("holderCommitment")
            if commitment is None:
                # Fall back to an arbitrary non-zero commitment.
                from zkc_crypto import field_to_hex

                commitment = field_to_hex(1)
            self._bindings[subject_ref] = commitment
        return super().issue_credential(payload)


def make_adapter() -> SeededBadIssuerAdapter:
    return SeededBadIssuerAdapter(clock=lambda: 1_770_000_000)


class _ValidRuntimeProvider(ProviderClient):
    def verify_subject(self, schema_id: str, payload: dict, *, authenticated_session: str) -> ProviderDecision:
        if schema_id != RUNTIME_ATTESTATION_SCHEMA_ID:
            return ProviderDecision(verified=False)
        return ProviderDecision(
            verified=True,
            holder_commitment=payload.get("holderCommitment"),
            provider_ref="seeded-machine-subject",
            claims={
                "attestedManifestDigest": "sha256:" + "71" * 32,
                "rootClass": "root:tee-attestation",
                "rootAuthorityIdentifier": "example:tee-root:v1",
                "rootMaterialDigest": "sha256:" + "72" * 32,
                "attestationEvidenceDigest": "sha256:" + "73" * 32,
                "verificationPolicyDigest": "sha256:" + "74" * 32,
                "validFrom": 1_769_999_940,
                "validUntil": 1_770_003_600,
            },
            expires_at=1_770_003_600,
        )


class SeededBadMachinePrivacyAdapter(RuntimeAttestationAdapter):
    """Valid machine capability declaration with deliberately weak plumbing."""

    def _active_privacy_profiles(self) -> frozenset[str]:
        # VIOLATION: machine-capable entry points run only the legacy human scan.
        return frozenset({HUMAN_PRIVACY_PROFILE})


def make_machine_privacy_adapter() -> SeededBadMachinePrivacyAdapter:
    return SeededBadMachinePrivacyAdapter(
        _ValidRuntimeProvider(), session_identity=lambda: "test-session", clock=lambda: 1_770_000_000
    )
