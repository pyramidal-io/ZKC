"""Proof context binding (spec §2.2).

Reference construction for the "zkc:context:verifier-session:v1" profile:

    value = Poseidon2::hash(
        [DOMAIN_ZKC_CONTEXT, string_to_field(profile),
         string_to_field(verifierId), sessionId, timestamp], 5)

For the "zkc:context:purpose-bound:v1" profile (spec §2.2, verifier
accountability), the declared purpose is folded into the SAME circuit-facing
context value via a `purposeTag`, so purpose becomes a binding preimage element
rather than decoration. No new circuit family is introduced — the value still
flows through the existing `proof_context` public input:

    purposeTag = Poseidon2::hash([DOMAIN_ZKC_PURPOSE, string_to_field(canonicalPurpose)], 2)
    value      = Poseidon2::hash(
        [DOMAIN_ZKC_CONTEXT, string_to_field(profile),
         string_to_field(verifierId), sessionId, purposeTag, timestamp], 6)

`canonicalPurpose` is NFC-normalized before hashing so semantically identical
purpose strings derive the same tag. The spec leaves the context hash
deployment/profile-defined; this module pins the reference profiles used by the
ZKC reference holder SDK, verifier, and conformance suite. `DOMAIN_ZKC_CONTEXT`
and `DOMAIN_ZKC_PURPOSE` follow the canonical ZKA domain derivation for the tags
"zkc/context" and "zkc/purpose".
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from .field import derive_domain, field_to_hex, hex_to_field, string_to_field
from .poseidon2 import canonical_integer, hash_fields

__all__ = [
    "VERIFIER_SESSION_PROFILE",
    "PURPOSE_BOUND_PROFILE",
    "DOMAIN_ZKC_CONTEXT",
    "DOMAIN_ZKC_PURPOSE",
    "canonical_purpose",
    "purpose_tag",
    "ProofContext",
]

VERIFIER_SESSION_PROFILE = "zkc:context:verifier-session:v1"
PURPOSE_BOUND_PROFILE = "zkc:context:purpose-bound:v1"
DOMAIN_ZKC_CONTEXT = derive_domain("zkc/context")
DOMAIN_ZKC_PURPOSE = derive_domain("zkc/purpose")


def canonical_purpose(purpose: str) -> str:
    """NFC-normalize a declared purpose string (spec §2.2).

    Canonicalization is Unicode NFC only; the registry tag namespacing is a
    deployment concern (Safeguard 1: no mandated purpose taxonomy)."""
    if not purpose:
        raise ValueError("purpose must be a non-empty string under the purpose-bound profile")
    return unicodedata.normalize("NFC", purpose)


def purpose_tag(purpose: str) -> int:
    """purposeTag = H("zkc/purpose", canonicalPurpose) (spec §2.2)."""
    return hash_fields([DOMAIN_ZKC_PURPOSE, string_to_field(canonical_purpose(purpose))], 2)


@dataclass(frozen=True)
class ProofContext:
    """Replay context a proof is bound to."""

    profile: str
    value: int
    timestamp: int
    verifier_id: str = ""
    session_id: int = 0
    # Purpose-bound profile only; 0 / "" otherwise.
    purpose_tag: int = 0
    purpose: str = ""

    def __post_init__(self):
        canonical_integer(self.value, name="context value")
        canonical_integer(self.timestamp, 1 << 64, name="context timestamp")
        canonical_integer(self.session_id, name="context sessionId")
        canonical_integer(self.purpose_tag, name="context purposeTag")

    @classmethod
    def verifier_session(cls, verifier_id: str, session_id: int, timestamp: int) -> "ProofContext":
        """Construct the reference verifier-session context."""
        canonical_integer(timestamp, 1 << 64, name="context timestamp")
        canonical_integer(session_id, name="context sessionId")
        if timestamp <= 0:
            raise ValueError("context timestamp must be a positive integer")
        if not verifier_id:
            raise ValueError("verifier_id must be non-empty")
        value = hash_fields(
            [
                DOMAIN_ZKC_CONTEXT,
                string_to_field(VERIFIER_SESSION_PROFILE),
                string_to_field(verifier_id),
                session_id,
                timestamp,
            ],
            5,
            strict=True,
        )
        return cls(
            profile=VERIFIER_SESSION_PROFILE,
            value=value,
            timestamp=timestamp,
            verifier_id=verifier_id,
            session_id=session_id,
        )

    @classmethod
    def purpose_bound(
        cls, verifier_id: str, session_id: int, purpose: str, timestamp: int
    ) -> "ProofContext":
        """Construct the reference purpose-bound context (spec §2.2).

        The declared `purpose` is folded into `value` via `purposeTag`, so a
        proof bound under one purpose cannot be re-derived under another without
        producing a different context value (caught by CONTEXT_MISMATCH /
        PURPOSE_MISMATCH at the verifier)."""
        canonical_integer(timestamp, 1 << 64, name="context timestamp")
        canonical_integer(session_id, name="context sessionId")
        if timestamp <= 0:
            raise ValueError("context timestamp must be a positive integer")
        if not verifier_id:
            raise ValueError("verifier_id must be non-empty")
        tag = purpose_tag(purpose)
        value = hash_fields(
            [
                DOMAIN_ZKC_CONTEXT,
                string_to_field(PURPOSE_BOUND_PROFILE),
                string_to_field(verifier_id),
                session_id,
                tag,
                timestamp,
            ],
            6,
            strict=True,
        )
        return cls(
            profile=PURPOSE_BOUND_PROFILE,
            value=value,
            timestamp=timestamp,
            verifier_id=verifier_id,
            session_id=session_id,
            purpose_tag=tag,
            purpose=canonical_purpose(purpose),
        )

    def reconstructs(self) -> bool:
        """True when structured fields reproduce `value` (profile-aware)."""
        if self.profile == VERIFIER_SESSION_PROFILE:
            expected = ProofContext.verifier_session(
                self.verifier_id, self.session_id, self.timestamp
            )
            return expected.value == self.value
        if self.profile == PURPOSE_BOUND_PROFILE:
            if not self.purpose:
                # Purpose is mandatory under this profile; without it the value
                # cannot be reconstructed and the context is not trustworthy.
                return False
            expected = ProofContext.purpose_bound(
                self.verifier_id, self.session_id, self.purpose, self.timestamp
            )
            return expected.value == self.value and expected.purpose_tag == self.purpose_tag
        # Opaque profile: nothing to reconstruct; value is authoritative.
        return True

    def to_metadata(self) -> dict:
        metadata = {
            "profile": self.profile,
            "value": field_to_hex(self.value),
            "timestamp": self.timestamp,
        }
        if self.verifier_id:
            metadata["verifierId"] = self.verifier_id
            metadata["sessionId"] = field_to_hex(self.session_id)
        if self.profile == PURPOSE_BOUND_PROFILE:
            metadata["purposeTag"] = field_to_hex(self.purpose_tag)
            if self.purpose:
                metadata["purpose"] = self.purpose
        return metadata

    @classmethod
    def from_metadata(cls, metadata: dict) -> "ProofContext":
        try:
            return cls(
                profile=metadata["profile"],
                value=hex_to_field(metadata["value"]),
                timestamp=metadata["timestamp"],
                verifier_id=metadata.get("verifierId", ""),
                session_id=hex_to_field(metadata["sessionId"])
                if "sessionId" in metadata
                else 0,
                purpose_tag=hex_to_field(metadata["purposeTag"])
                if "purposeTag" in metadata
                else 0,
                purpose=metadata.get("purpose", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed proof context metadata: {exc}") from exc
