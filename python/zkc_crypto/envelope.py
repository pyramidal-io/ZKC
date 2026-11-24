"""Structural validation of zkc:proof envelopes (v1 and v2).

Stdlib re-implementation of schemas/compliance-proof-v{1,2}.schema.json (the
repo is dependency-free, so no jsonschema). The unit tests cross-check these
validators against the schema documents themselves so the two cannot drift
silently. Fail closed: any deviation raises EnvelopeError.

- v1 (`zkc:proof:v1`) is the linkable profile. It requires a global
  `holderBinding` and rejects the v2-only `presentationBinding` field.
- v2 (`zkc:proof:v2`) is the presentation-profile envelope (design §3): a
  `presentationBinding` block (anonymous or scoped) replaces `holderBinding`,
  which is forbidden.

`validate_envelope` version-dispatches to the right validator.
"""

from __future__ import annotations

import re

from .presentation import ANONYMOUS_PROFILE, SCOPED_PROFILE
from zkc_registry.predicate_v2 import selector_key

__all__ = [
    "EnvelopeError",
    "validate_compliance_proof_v1",
    "validate_compliance_proof_v2",
    "validate_envelope",
]

_HEX32 = re.compile(r"^0x[0-9a-f]{64}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)

MAX_PROOFS = 8


class EnvelopeError(ValueError):
    """A zkc:proof envelope failed structural validation."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EnvelopeError(message)


def _require_keys(obj: dict, keys, where: str) -> None:
    _require(isinstance(obj, dict), f"{where} must be an object")
    for key in keys:
        _require(key in obj, f"{where} missing required field '{key}'")


def _require_hex32(value, where: str) -> None:
    _require(isinstance(value, str) and bool(_HEX32.match(value)), f"{where} must match ^0x[0-9a-f]{{64}}$")


def _validate_metadata(metadata) -> None:
    """Validate the shared `metadata` block (identical in v1 and v2)."""
    _require_keys(metadata, ["generatedAt", "expiresAt", "context"], "metadata")
    for key in ("generatedAt", "expiresAt"):
        value = metadata[key]
        _require(
            isinstance(value, str) and bool(_RFC3339.match(value)),
            f"metadata.{key} must be an RFC 3339 date-time string",
        )

    context = metadata["context"]
    _require_keys(context, ["profile", "value", "timestamp"], "metadata.context")
    _require(isinstance(context["profile"], str), "context.profile must be a string")
    _require_hex32(context["value"], "context.value")
    _require(
        isinstance(context["timestamp"], int)
        and not isinstance(context["timestamp"], bool)
        and context["timestamp"] >= 0,
        "context.timestamp must be a non-negative integer",
    )


def _validate_proofs(proofs) -> None:
    """Validate the shared `proofs` array (identical in v1 and v2)."""
    _require(isinstance(proofs, list), "proofs must be an array")
    _require(1 <= len(proofs) <= MAX_PROOFS, f"proofs must contain between 1 and {MAX_PROOFS} items")
    for index, proof in enumerate(proofs):
        where = f"proofs[{index}]"
        _require_keys(proof, ["proofType", "proof", "publicInputs", "principalConsent"], where)
        _require(isinstance(proof["proofType"], str), f"{where}.proofType must be a string")
        _require(isinstance(proof["proof"], str), f"{where}.proof must be a string")
        _require(isinstance(proof["publicInputs"], dict), f"{where}.publicInputs must be an object")
        _require(isinstance(proof["principalConsent"], bool), f"{where}.principalConsent must be a boolean")
        if "bindingSelector" in proof:
            try:
                selector_key(proof["bindingSelector"])
            except ValueError as exc:
                raise EnvelopeError(f"{where}.bindingSelector is malformed: {exc}") from exc


def _validate_aggregation(envelope) -> None:
    """Validate the optional `aggregation` block (identical in v1 and v2)."""
    if "aggregation" in envelope:
        aggregation = envelope["aggregation"]
        _require_keys(
            aggregation,
            ["proof", "inputProofCommitments", "aggregationCommitment", "aggregatedClaimBinding"],
            "aggregation",
        )
        _require(isinstance(aggregation["proof"], str), "aggregation.proof must be a string")
        commitments = aggregation["inputProofCommitments"]
        _require(isinstance(commitments, list), "aggregation.inputProofCommitments must be an array")
        _require(
            1 <= len(commitments) <= MAX_PROOFS,
            f"aggregation.inputProofCommitments must contain between 1 and {MAX_PROOFS} items",
        )
        for index, commitment in enumerate(commitments):
            _require_hex32(commitment, f"aggregation.inputProofCommitments[{index}]")
        _require_hex32(aggregation["aggregationCommitment"], "aggregation.aggregationCommitment")
        _require_hex32(aggregation["aggregatedClaimBinding"], "aggregation.aggregatedClaimBinding")


def validate_compliance_proof_v1(envelope) -> None:
    """Validate envelope structure per compliance-proof-v1.schema.json.

    Preserve the relative order and messages of the original v1 assertions.
    """
    _require_keys(envelope, ["version", "metadata", "proofs", "holderBinding"], "envelope")
    _require(envelope["version"] == "zkc:proof:v1", "version must be 'zkc:proof:v1'")

    _validate_metadata(envelope["metadata"])
    _validate_proofs(envelope["proofs"])

    holder_binding = envelope["holderBinding"]
    _require_keys(holder_binding, ["commitment"], "holderBinding")
    _require_hex32(holder_binding["commitment"], "holderBinding.commitment")

    # Prevent a linkable envelope from carrying anonymous or scoped metadata.
    _require(
        "presentationBinding" not in envelope,
        "presentationBinding is forbidden in a v1 envelope (it exists only in v2)",
    )

    _validate_aggregation(envelope)


def validate_compliance_proof_v2(envelope) -> None:
    """Validate envelope structure per compliance-proof-v2.schema.json (design §3).

    v2 replaces v1's global `holderBinding` with a `presentationBinding` block:
    profile ∈ {anonymous, scoped}; scoped carries `pseudonym` + `scopeId`,
    anonymous carries neither. `holderBinding` is forbidden in v2.
    """
    _require_keys(envelope, ["version", "metadata", "proofs", "presentationBinding"], "envelope")
    _require(envelope["version"] == "zkc:proof:v2", "version must be 'zkc:proof:v2'")

    _require(
        "holderBinding" not in envelope,
        "holderBinding is forbidden in a v2 envelope (it exists only in v1/linkable)",
    )

    _validate_metadata(envelope["metadata"])
    _validate_proofs(envelope["proofs"])

    binding = envelope["presentationBinding"]
    _require_keys(binding, ["profile"], "presentationBinding")
    profile = binding["profile"]
    _require(
        profile in (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "presentationBinding.profile must be the anonymous or scoped presentation profile",
    )

    if profile == SCOPED_PROFILE:
        _require_keys(binding, ["pseudonym", "scopeId"], "presentationBinding")
        _require_hex32(binding["pseudonym"], "presentationBinding.pseudonym")
        _require_hex32(binding["scopeId"], "presentationBinding.scopeId")
    else:  # ANONYMOUS_PROFILE
        _require(
            "pseudonym" not in binding,
            "anonymous presentationBinding must not carry a pseudonym",
        )
        _require(
            "scopeId" not in binding,
            "anonymous presentationBinding must not carry a scopeId",
        )

    _validate_aggregation(envelope)


def validate_envelope(envelope) -> None:
    """Version-dispatch structural validation for any zkc:proof envelope.

    Routes `zkc:proof:v1` to the frozen v1 validator and `zkc:proof:v2` to the
    presentation-profile validator; any other version is rejected fail-closed.
    """
    _require(isinstance(envelope, dict), "envelope must be an object")
    _require("version" in envelope, "envelope missing required field 'version'")
    version = envelope["version"]
    if version == "zkc:proof:v1":
        validate_compliance_proof_v1(envelope)
    elif version == "zkc:proof:v2":
        validate_compliance_proof_v2(envelope)
    else:
        raise EnvelopeError(f"unsupported envelope version {version!r}")
