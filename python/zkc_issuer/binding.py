"""Holder-binding challenge (beta profile).

Per docs/zkc_issuer_adapter_protocol_v1.md, the beta profile binds a verified
subject to ``holderCommitment = H("zkc/binding", cbk)`` with a challenge over
``(holderCommitment, issuerId, schemaId, nonce, expiresAt)``. The response
reuses the circuit claim-binding scheme (``zkc_lib::compute_claim_binding_3``)
instead of an ad-hoc hash:

    response = compute_claim_binding_3(
        holderCommitment, H(issuerId), H(schemaId),
        proof_context = nonce, timestamp = expiresAt)

Privacy: the holder NEVER sends the master seed or credential binding key —
``holder_binding_response`` derives the commitment from the binding key
locally and only the response field crosses the boundary.

The beta response is computable from public values; it is not authentication
or proof of binding-key knowledge. Subject authorization comes from the trusted
session established at stage 1 and (for runtime attestation) the provider's
evidence-to-holder binding. The response checks freshness and tuple integrity
(nonce is single-use and expiring; swapping any tuple element invalidates the response). Ultimate holder-control
enforcement is in the circuits themselves — every ZKC predicate proof asserts
``derive_holder_commitment(credential_binding_key) == holder_commitment``, so
a credential bound to a commitment whose binding key you do not control is
unusable. A direct zero-knowledge proof-of-binding-key at bind time needs a
dedicated circuit and is a candidate post-beta hardening.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from zkc_crypto import (
    FIELD_MODULUS,
    compute_claim_binding_3,
    derive_holder_commitment,
    field_to_hex,
    hex_to_field,
    string_to_field,
)

__all__ = [
    "BINDING_CHALLENGE_VERSION",
    "DEFAULT_CHALLENGE_TTL_SECONDS",
    "BindingChallenge",
    "compute_binding_response",
    "holder_binding_response",
]

BINDING_CHALLENGE_VERSION = "zkc:binding-challenge:v1"
DEFAULT_CHALLENGE_TTL_SECONDS = 600


@dataclass(frozen=True)
class BindingChallenge:
    """A single-use, expiring holder-binding challenge."""

    nonce: int
    subject_ref: str
    holder_commitment_hex: str
    schema_id: str
    issued_at: int
    expires_at: int

    def to_dict(self) -> dict:
        return {
            "challengeVersion": BINDING_CHALLENGE_VERSION,
            "nonce": field_to_hex(self.nonce),
            "subjectRef": self.subject_ref,
            "holderCommitment": self.holder_commitment_hex,
            "schemaId": self.schema_id,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
        }

    @classmethod
    def issue(
        cls,
        subject_ref: str,
        holder_commitment_hex: str,
        schema_id: str,
        now: int,
        ttl_seconds: int = DEFAULT_CHALLENGE_TTL_SECONDS,
    ) -> "BindingChallenge":
        nonce = 0
        while nonce == 0:
            nonce = secrets.randbits(250) % FIELD_MODULUS
        return cls(
            nonce=nonce,
            subject_ref=subject_ref,
            holder_commitment_hex=holder_commitment_hex,
            schema_id=schema_id,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )


def compute_binding_response(
    holder_commitment: int,
    issuer_id: str,
    schema_id: str,
    nonce: int,
    expires_at: int,
) -> int:
    """The expected challenge response (claim-binding over the beta tuple)."""
    return compute_claim_binding_3(
        holder_commitment,
        string_to_field(issuer_id),
        string_to_field(schema_id),
        nonce,
        expires_at,
    )


def holder_binding_response(
    credential_binding_key: int,
    issuer_id: str,
    schema_id: str,
    nonce_hex: str,
    expires_at: int,
) -> int:
    """Holder-side helper: derive the response from the binding key.

    The binding key stays local; only the holder commitment derivation and the
    response leave this function.
    """
    holder_commitment = derive_holder_commitment(credential_binding_key)
    return compute_binding_response(
        holder_commitment, issuer_id, schema_id, hex_to_field(nonce_hex), expires_at
    )
