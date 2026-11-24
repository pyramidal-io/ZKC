"""Issuer-authoritative selective-disclosure witness and constraint mirror."""

from __future__ import annotations

from zkc_crypto import (
    SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES,
    compute_merkle_root,
    compute_selective_disclosure_binding,
    compute_selective_disclosure_binding_v3,
    compute_selective_disclosure_credential_digest,
    compute_selective_disclosure_credential_digest_v2,
    derive_credential_binding_key,
    derive_holder_commitment,
    digest_to_message_bytes,
    field_to_hex,
    parse_attribute_layout_id,
)
from zkc_crypto.ecdsa_secp256k1 import verify as ecdsa_verify
from zkc_crypto.presentation import derive_presentation_pseudonym

from .accumulator import MAX_EPOCH_LAG
from .errors import ConstraintViolationError

DISCLOSURE_PROOF_TYPE = "zkc:proof:selective_disclosure:v1"
DISCLOSURE_CIRCUIT = "zkc_selective_disclosure_v1"
DISCLOSURE_V2_PROOF_TYPE = "zkc:proof:selective_disclosure:v2"
DISCLOSURE_V2_CIRCUIT = "zkc_selective_disclosure_v2"
DISCLOSURE_V3_PROOF_TYPE = "zkc:proof:selective_disclosure:v3"
DISCLOSURE_V3_CIRCUIT = "zkc_selective_disclosure_v3"

DISCLOSURE_PUBLIC_INPUT_NAMES = (
    "presentation_pseudonym",
    "scope_id",
    "claim_binding",
    "proof_context",
    "accumulator_root",
    "accumulator_epoch",
    "timestamp",
    "current_epoch",
    "issuer_public_key_x",
    "issuer_public_key_y",
    "credential_attribute_count",
    "disclosure_count",
    "disclosed_flags",
    "disclosed_attributes",
)


def build_selective_disclosure_witness(
    *,
    master_seed: int | bytes | str,
    credential,
    issuer,
    witness,
    disclosed_positions,
    proof_context: int,
    timestamp: int,
    current_epoch: int,
    scope_id: int = 0,
    layout_id: str | None = None,
) -> dict:
    """Build the fixed-shape selective-disclosure witness.

    Positions are unique zero-based indices into the issuer-signed attribute
    vector. Hidden public value slots are canonical zeroes; their public flags
    retain the semantic distinction from a disclosed attribute whose value is
    itself zero.
    """
    try:
        positions = list(disclosed_positions)
    except TypeError as exc:
        raise ConstraintViolationError("disclosed positions must be an iterable of integers") from exc
    if not all(type(position) is int for position in positions):
        raise ConstraintViolationError("disclosed positions must be integers")
    if len(set(positions)) != len(positions):
        raise ConstraintViolationError("disclosed positions must be unique")
    count = credential.claims["attributeCount"]
    if type(count) is not int or not 1 <= count <= SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES:
        raise ConstraintViolationError("credential attribute count must be between 1 and 8")
    if any(position < 0 or position >= count for position in positions):
        raise ConstraintViolationError("disclosed position is outside credential attribute count")
    attributes = list(credential.claims["attributes"])
    if len(attributes) != SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES:
        raise ConstraintViolationError("credential attributes must have exactly 8 slots")
    flags = [position in positions for position in range(SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES)]
    disclosed = [attributes[i] if flags[i] else 0 for i in range(len(attributes))]
    if layout_id is None:
        binding = compute_selective_disclosure_binding(
            count, flags, disclosed, proof_context, timestamp
        )
        layout_inputs = {}
    else:
        if (
            credential.credential_type != "zkc:cred:attribute-set:v2"
            or credential.claims.get("layoutId") != layout_id
        ):
            raise ConstraintViolationError("credential layoutId does not match the requested layout")
        layout_field = parse_attribute_layout_id(layout_id)
        binding = compute_selective_disclosure_binding_v3(
            layout_field, count, flags, disclosed, proof_context, timestamp
        )
        layout_inputs = {"layout_id": layout_field}
    credential_binding_key = derive_credential_binding_key(master_seed)
    scope_id = int(scope_id)
    pseudonym = (
        0
        if scope_id == 0
        else derive_presentation_pseudonym(credential_binding_key, scope_id)
    )
    return {
        "presentation_pseudonym": pseudonym,
        "scope_id": scope_id,
        "claim_binding": binding,
        "proof_context": int(proof_context),
        "accumulator_root": witness.accumulator_root,
        "accumulator_epoch": witness.accumulator_epoch,
        "timestamp": int(timestamp),
        "current_epoch": int(current_epoch),
        "issuer_public_key_x": list(issuer.public_key_x),
        "issuer_public_key_y": list(issuer.public_key_y),
        **layout_inputs,
        "credential_attribute_count": count,
        "disclosure_count": len(positions),
        "disclosed_flags": flags,
        "disclosed_attributes": disclosed,
        "holder_commitment": credential.holder_commitment,
        "credential_binding_key": credential_binding_key,
        "credential_holder_commitment": credential.holder_commitment,
        "credential_id": credential.credential_id,
        "credential_attributes": attributes,
        "credential_expires_at": credential.expires_at,
        "issuer_signature": list(credential.signature),
        "nonrevocation_siblings": list(witness.siblings),
        "nonrevocation_path_index": witness.path_index,
    }


def selective_disclosure_public_inputs(witness: dict, *, layout_bound: bool = False) -> dict:
    output = {}
    names = DISCLOSURE_PUBLIC_INPUT_NAMES
    if layout_bound:
        names += ("layout_id",)
    for name in names:
        value = witness[name]
        if name in ("issuer_public_key_x", "issuer_public_key_y"):
            output[name] = "0x" + bytes(value).hex()
        elif name in (
            "accumulator_epoch",
            "timestamp",
            "current_epoch",
            "credential_attribute_count",
            "disclosure_count",
        ):
            output[name] = int(value)
        elif name == "disclosed_flags":
            output[name] = [bool(flag) for flag in value]
        elif name == "disclosed_attributes":
            output[name] = [field_to_hex(item) for item in value]
        else:
            output[name] = field_to_hex(value)
    return output


def check_selective_disclosure_constraints(witness: dict, *, layout_bound: bool = False) -> None:
    def fail(message: str):
        raise ConstraintViolationError(message)

    cbk = witness["credential_binding_key"]
    holder = witness["holder_commitment"]
    if derive_holder_commitment(cbk) != holder:
        fail("holder commitment does not match credential binding key")
    if witness["credential_holder_commitment"] != holder:
        fail("credential holder commitment does not match presentation holder")

    scope_id = int(witness["scope_id"])
    pseudonym = witness["presentation_pseudonym"]
    if scope_id == 0:
        if pseudonym != 0:
            fail("anonymous profile must not carry a pseudonym")
    elif pseudonym != derive_presentation_pseudonym(cbk, scope_id):
        fail("presentation pseudonym does not derive from binding key and scope")

    count = int(witness["credential_attribute_count"])
    attributes = list(witness["credential_attributes"])
    if not 1 <= count <= SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES:
        fail("credential attribute count must be between 1 and 8")
    if len(attributes) != SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES:
        fail("credential attributes must have exactly 8 slots")
    if any(attributes[count:]):
        fail("credential padding attribute must be zero")

    credential = witness["credential_holder_commitment"], witness["credential_id"]
    claims = count, attributes, witness["credential_expires_at"]
    if layout_bound:
        digest = compute_selective_disclosure_credential_digest_v2(
            *credential, witness["layout_id"], *claims
        )
    else:
        digest = compute_selective_disclosure_credential_digest(*credential, *claims)
    if not ecdsa_verify(
        bytes(witness["issuer_public_key_x"]),
        bytes(witness["issuer_public_key_y"]),
        bytes(witness["issuer_signature"]),
        digest_to_message_bytes(digest),
    ):
        fail("invalid issuer signature")

    root = compute_merkle_root(
        witness["credential_id"],
        witness["nonrevocation_path_index"],
        witness["nonrevocation_siblings"],
    )
    fresh = (
        witness["current_epoch"] >= witness["accumulator_epoch"]
        and witness["current_epoch"] - witness["accumulator_epoch"] <= MAX_EPOCH_LAG
    )
    if root != witness["accumulator_root"] or not fresh:
        fail("credential is revoked or accumulator epoch is stale")

    flags = list(witness["disclosed_flags"])
    disclosed = list(witness["disclosed_attributes"])
    if len(flags) != SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES or len(disclosed) != len(flags):
        fail("selective disclosure must have exactly 8 public slots")
    if not all(type(flag) is bool for flag in flags):
        fail("selective disclosure flags must be booleans")
    if int(witness["disclosure_count"]) < 1:
        fail("selective disclosure must reveal at least one position")
    if sum(bool(flag) for flag in flags) != int(witness["disclosure_count"]):
        fail("disclosure count does not match flags")
    for position, (flag, value) in enumerate(zip(flags, disclosed)):
        if position >= count and flag:
            fail("cannot disclose a credential padding position")
        if flag:
            if value != attributes[position]:
                fail("disclosed value does not match signed credential position")
        elif value != 0:
            fail("hidden disclosed-attribute slot must be zero")

    expires_at = int(witness["credential_expires_at"])
    if expires_at != 0 and expires_at <= int(witness["timestamp"]):
        fail("credential expired")
    transcript = count, flags, disclosed, witness["proof_context"], witness["timestamp"]
    if layout_bound:
        expected = compute_selective_disclosure_binding_v3(witness["layout_id"], *transcript)
    else:
        expected = compute_selective_disclosure_binding(*transcript)
    if expected != witness["claim_binding"]:
        fail("selective disclosure binding mismatch")
    if witness["proof_context"] == 0:
        fail("proof context must be non-zero")
    if witness["timestamp"] == 0:
        fail("timestamp must be non-zero")
