"""Holder-side credential model and trust policy / proof request types."""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from typing import Optional

from zkc_crypto import ProofContext, field_to_hex, hex_to_field, parse_attribute_layout_id
from zkc_crypto.presentation import ANONYMOUS_PROFILE

__all__ = [
    "AccumulatorWitness",
    "Credential",
    "RebindAttestation",
    "TrustedIssuer",
    "TrustPolicy",
    "ProofRequest",
]


@dataclass
class AccumulatorWitness:
    """Non-revocation witness for a credential."""

    path_index: int
    siblings: list
    accumulator_root: int
    accumulator_epoch: int

    def to_dict(self) -> dict:
        return {
            "pathIndex": self.path_index,
            "siblings": [field_to_hex(s) for s in self.siblings],
            "accumulatorRoot": field_to_hex(self.accumulator_root),
            "accumulatorEpoch": self.accumulator_epoch,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AccumulatorWitness":
        return cls(
            path_index=int(data["pathIndex"]),
            siblings=[hex_to_field(s) for s in data["siblings"]],
            accumulator_root=hex_to_field(data["accumulatorRoot"]),
            accumulator_epoch=int(data["accumulatorEpoch"]),
        )


REBIND_ATTESTATION_VERSION = "zkc:attestation:credential-rebind:v1"


@dataclass
class RebindAttestation:
    """Issuer-signed permission to rebind ONE credential (spec section 7.4.1).

    The signature covers the 32-byte big-endian
    ``compute_rebind_attestation_digest(issuerIdHash, schemaIdHash,
    holderCommitment, credentialId, validFrom, validUntil)``. Only the fields
    that are not already in the enclosing credential are carried here, so an
    attestation can never name a different credential than the one it travels
    with. It authorizes no particular target: the new holder handle is chosen
    by the holder and is not in the signed transcript.
    """

    schema_id: str
    valid_from: int
    valid_until: int
    signature: bytes
    version: str = REBIND_ATTESTATION_VERSION

    def __post_init__(self):
        if self.version != REBIND_ATTESTATION_VERSION:
            raise ValueError(f"unsupported rebind attestation version: {self.version}")
        if not isinstance(self.schema_id, str) or not self.schema_id:
            raise ValueError("rebind attestation schemaId must be a non-empty string")
        for name in ("valid_from", "valid_until"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << 64):
                raise ValueError(f"rebind attestation {name} must fit in u64")
        if self.valid_until != 0 and self.valid_until <= self.valid_from:
            raise ValueError("rebind attestation validUntil must be 0 or after validFrom")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValueError("rebind attestation signature must be 64 bytes")

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "schemaId": self.schema_id,
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
            "signature": "0x" + self.signature.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RebindAttestation":
        return cls(
            version=data.get("version", REBIND_ATTESTATION_VERSION),
            schema_id=data["schemaId"],
            valid_from=int(data["validFrom"]),
            valid_until=int(data["validUntil"]),
            signature=bytes.fromhex(str(data["signature"]).removeprefix("0x")),
        )


@dataclass
class Credential:
    """A stored ZKC credential.

    `claims` is circuit-specific; for "zkc:kyc:v1":
        {"level": int, "verifiedAttributes": [bool, bool, bool, bool, bool]}
    """

    credential_type: str
    proof_type: str
    issuer_id: str
    holder_commitment: int
    credential_id: int
    claims: dict
    expires_at: int
    signature: bytes
    witness: Optional[AccumulatorWitness] = None
    # Issuer-signed permission to rebind this credential (spec section 7.4.1).
    # Absent for credentials the issuer has not authorized for migration; the
    # authenticated rebind statements then cannot be generated at all.
    rebind_attestation: Optional[RebindAttestation] = None
    # Legacy layout declaration from authenticated issuer delivery or local
    # provisioning. It is outside the frozen v1 credential signature.
    attribute_layout_id: Optional[str] = None

    def __post_init__(self):
        if self.attribute_layout_id is not None:
            parse_attribute_layout_id(self.attribute_layout_id)

    def to_dict(self) -> dict:
        data = {
            "credentialType": self.credential_type,
            "proofType": self.proof_type,
            "issuerId": self.issuer_id,
            "holderCommitment": field_to_hex(self.holder_commitment),
            "credentialId": field_to_hex(self.credential_id),
            "claims": self.claims,
            "expiresAt": self.expires_at,
            "signature": "0x" + self.signature.hex(),
        }
        if self.witness is not None:
            data["witness"] = self.witness.to_dict()
        if self.rebind_attestation is not None:
            data["rebindAttestation"] = self.rebind_attestation.to_dict()
        if self.attribute_layout_id is not None:
            data["attributeLayoutId"] = self.attribute_layout_id
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Credential":
        signature = bytes.fromhex(data["signature"].removeprefix("0x"))
        if len(signature) != 64:
            raise ValueError("credential signature must be 64 bytes")
        return cls(
            credential_type=data["credentialType"],
            proof_type=data["proofType"],
            issuer_id=data["issuerId"],
            holder_commitment=hex_to_field(data["holderCommitment"]),
            credential_id=hex_to_field(data["credentialId"]),
            claims=data["claims"],
            expires_at=int(data["expiresAt"]),
            signature=signature,
            witness=AccumulatorWitness.from_dict(data["witness"]) if "witness" in data else None,
            rebind_attestation=(
                RebindAttestation.from_dict(data["rebindAttestation"])
                if "rebindAttestation" in data
                else None
            ),
            attribute_layout_id=data.get("attributeLayoutId"),
        )


@dataclass(frozen=True)
class TrustedIssuer:
    """An issuer entry in a verifier trust policy.

    There are NO canonical or default issuers (Freedom Safeguard 1): every
    trusted issuer is explicit verifier-local configuration.
    """

    issuer_id: str
    public_key_x: bytes
    public_key_y: bytes
    proof_types: tuple

    def __post_init__(self):
        if len(self.public_key_x) != 32 or len(self.public_key_y) != 32:
            raise ValueError("issuer public key coordinates must be 32 bytes each")


@dataclass(frozen=True)
class TrustPolicy:
    """Verifier trust policy as presented to the holder in a proof request."""

    issuers: tuple

    def issuer(self, issuer_id: str) -> Optional[TrustedIssuer]:
        for entry in self.issuers:
            if entry.issuer_id == issuer_id:
                return entry
        return None

    def trusts(self, issuer_id: str, proof_type: str) -> bool:
        entry = self.issuer(issuer_id)
        return entry is not None and proof_type in entry.proof_types


@dataclass
class ProofRequest:
    """A verifier's proof request (spec §5.2).

    ``presentation_profile`` (design §5.1/§5.2) selects the presentation
    profile the holder is willing to answer under. It is holder-local
    configuration: never populate it from verifier wire input. It defaults to
    the ambient anonymous profile — continuity (a scoped pseudonym) is always
    an explicit, signed, purpose-bound request, never the default. The
    linkable profile is not consent by itself whenever no verifier is
    authenticated: ``generate_proof``, the ``allow_unauthenticated=True``
    override of ``generate_authenticated_proof`` / ``answer_as_hosted_service``,
    and delegated generation also require the holder's explicit
    ``allow_linkable=True``. Under an authenticated APR the linkable ceiling
    plus an APR asking for linkable (or silent) is the consent. ``allow_protocol_scope``
    is the distinct consent flag a signer-local ``protocol:`` scope policy
    requires; matching names under different signing keys do not share a scope.
    ``allow_unlinked_composite`` lets the holder answer two or more proof
    types anonymously; set it only for a verifier that declares the proofs
    independent facts (spec 5.9.2 rule 5), since anonymous proofs bind to no
    single holder and a default verifier rejects them (UNBOUND_COMPOSITE).
    """

    proof_types: list
    parameters: dict
    context: ProofContext
    trust_policy: TrustPolicy
    max_proof_age: int = 3600
    current_epochs: dict = dataclass_field(default_factory=dict)
    # Exact predicate-entry v2 selectors keyed by requested proof type. These
    # may influence key selection only when an authenticated APR commits to
    # the versioned binding-selector extension.
    binding_selectors: dict = dataclass_field(default_factory=dict)
    presentation_profile: str = ANONYMOUS_PROFILE
    allow_protocol_scope: bool = False
    allow_unlinked_composite: bool = False
    # Holder-local only (spec section 7.4.4): the NEW identity of an
    # authenticated credential rebind, a ``zkc_holder.RebindSecret``. It is
    # never part of ``parameters`` -- which a verifier chooses and, on the
    # authenticated path, signs -- and never appears in repr or comparison.
    rebind_secret: object = dataclass_field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if type(self.allow_unlinked_composite) is not bool:
            raise ValueError("allow_unlinked_composite must be a boolean")

    def __repr__(self) -> str:
        from .rebind_secret import redact_secret_parameters

        return (
            f"ProofRequest(proof_types={self.proof_types!r}, "
            f"parameters={redact_secret_parameters(self.parameters)!r}, "
            f"context={self.context!r}, trust_policy={self.trust_policy!r}, "
            f"max_proof_age={self.max_proof_age!r}, current_epochs={self.current_epochs!r}, "
            f"binding_selectors={self.binding_selectors!r}, "
            f"presentation_profile={self.presentation_profile!r}, "
            f"allow_protocol_scope={self.allow_protocol_scope!r}, "
            f"allow_unlinked_composite={self.allow_unlinked_composite!r})"
        )
