"""Witness builders, constraint mirrors, and public-input extractors for the
five non-KYC ZKC predicate circuits.

Each circuit under ``noir/`` has a Python counterpart here so the reference
holder SDK can assemble a full witness, the StubBackend can re-evaluate the
circuit constraints in Python (fail closed before emitting a stub), and the
NargoBackend can drive ``nargo execute`` + ``bb prove`` with a real witness.

Covered circuits / proof types:

* ``zkc_jurisdiction``           — ``zkc:proof:jurisdiction:v1``
* ``zkc_remaining_predicates``   — ``zkc:proof:accreditation:v1`` (type 1),
                                   ``zkc:proof:source:v1`` (type 2),
                                   ``zkc:proof:tax:v1`` (type 3),
                                   ``zkc:proof:sanctions:v1`` (type 4)
* ``zkc_credential_rebind``      — ``zkc:proof:credential_rebind:v1``

Witness ABI order MATCHES the ``main()`` parameter order of each circuit so
``witness_to_prover_toml`` (in backend.py) produces a Prover.toml nargo
accepts. The public-input extractors mirror schemas/public-inputs/*.json.

Set-membership predicates (jurisdiction inclusion/exclusion, source-of-funds,
tax residency, sanctions clearance) need a Merkle witness against the
VERIFIER's set, which the holder obtains out of band. Builders accept that
witness via the proof request parameters; helpers in this module build the
single-leaf reference witnesses the conformance tests use.
"""

from __future__ import annotations

from zkc_crypto import (
    FIELD_MODULUS,
    MERKLE_DEPTH,
    compute_claim_binding_3,
    compute_claim_binding_4,
    compute_jurisdiction_credential_digest,
    compute_jurisdiction_leaf,
    compute_merkle_root,
    compute_profile_digest,
    compute_profile_digest_v2,
    compute_rebind_attestation_digest,
    derive_holder_commitment,
    digest_to_message_bytes,
    field_to_hex,
    string_to_field,
)
from zkc_crypto.code_spaces import (
    CODE_SPACE_CREDENTIAL_TO_KIND, CODE_SPACE_PROOF_TO_KIND, get_code_space,
    validate_claim_type, validate_verification_method,
)
from zkc_crypto.code_space_transcripts import (
    bind_code_space_digest, bind_code_space_statement, code_space_leaf,
)
from zkc_crypto.credential_id_successors import (
    NONZERO_CREDENTIAL_PROOF_PREDECESSORS,
    NONZERO_LINKABLE_PROOF_PREDECESSORS,
)
from zkc_crypto.ecdsa_secp256k1 import verify as ecdsa_verify
from zkc_crypto.presentation import derive_presentation_pseudonym

from .accumulator import MAX_EPOCH_LAG
from .credential import REBIND_ATTESTATION_VERSION
from .errors import ConstraintViolationError, HolderError

__all__ = [
    "JURISDICTION_CIRCUIT",
    "JURISDICTION_V1_CIRCUIT",
    "JURISDICTION_PROOF_TYPE",
    "JURISDICTION_V1_PROOF_TYPE",
    "JURISDICTION_V2_PROOF_TYPE",
    "JURISDICTION_V3_PROOF_TYPE",
    "JURISDICTION_V4_PROOF_TYPE",
    "JURISDICTION_V5_PROOF_TYPE",
    "REMAINING_CIRCUIT",
    "REMAINING_V3_CIRCUIT",
    "REMAINING_V5_CIRCUIT",
    "REMAINING_V6_CIRCUIT",
    "REMAINING_V7_CIRCUIT",
    "REMAINING_V8_CIRCUIT",
    "REMAINING_V9_CIRCUIT",
    "REMAINING_V10_CIRCUIT",
    "REBIND_CIRCUIT",
    "REBIND_PROOF_TYPE",
    "REBIND_BINDING_V2_CIRCUIT",
    "REBIND_BINDING_V2_PROOF_TYPE",
    "REBIND_BINDING_V2_STATEMENT_DOMAIN",
    "MEMBERSHIP_TYPE_INCLUSION",
    "MEMBERSHIP_TYPE_EXCLUSION",
    "PREDICATE_ACCREDITATION",
    "PREDICATE_SOURCE_OF_FUNDS",
    "PREDICATE_TAX_RESIDENCY",
    "PREDICATE_SANCTIONS_CLEARANCE",
    "PROFILE_PROOF_TYPES",
    "validate_profile_request_domains",
    "build_jurisdiction_witness",
    "build_profile_witness",
    "build_profile_witness_v3",
    "build_profile_witness_v5",
    "build_profile_witness_v6",
    "build_profile_witness_v7",
    "build_profile_witness_v8",
    "build_rebind_witness",
    "single_leaf_inclusion_witness",
    "single_leaf_set_root",
    "check_jurisdiction_constraints",
    "check_profile_constraints",
    "check_profile_constraints_v3",
    "check_profile_constraints_v5",
    "check_profile_constraints_v6",
    "check_profile_constraints_v7",
    "check_profile_constraints_v8",
    "check_rebind_constraints",
    "check_rebind_binding_v2_constraints",
    "jurisdiction_public_inputs",
    "profile_public_inputs",
    "rebind_public_inputs",
    # v2 (presentation-profile) additions
    "JURISDICTION_V2_CIRCUIT",
    "JURISDICTION_V3_CIRCUIT",
    "JURISDICTION_V4_CIRCUIT",
    "JURISDICTION_V5_CIRCUIT",
    "REMAINING_V2_CIRCUIT",
    "REMAINING_V4_CIRCUIT",
    "REMAINING_V6_CIRCUIT",
    "REBIND_V2_CIRCUIT",
    "REBIND_V2_BINDING_V2_CIRCUIT",
    "REBIND_V2_BINDING_V2_PROOF_TYPE",
    "REBIND_V2_BINDING_V2_STATEMENT_DOMAIN",
    "UNAUTHENTICATED_REBIND_PROOF_TYPES",
    "refuse_unauthenticated_rebind",
    "REBIND_AUTH_CIRCUIT",
    "REBIND_AUTH_PROOF_TYPE",
    "REBIND_AUTH_STATEMENT_DOMAIN",
    "REBIND_AUTH_V2_CIRCUIT",
    "REBIND_AUTH_V2_PROOF_TYPE",
    "REBIND_AUTH_V2_STATEMENT_DOMAIN",
    "REBIND_AUTH_V3_CIRCUIT",
    "REBIND_AUTH_V3_PROOF_TYPE",
    "REBIND_AUTH_PUBLIC_INPUT_NAMES",
    "REBIND_AUTH_V2_PUBLIC_INPUT_NAMES",
    "build_rebind_auth_witness",
    "build_rebind_auth_witness_v2",
    "rebind_auth_public_inputs",
    "rebind_auth_public_inputs_v2",
    "check_rebind_auth_constraints",
    "check_rebind_auth_v2_constraints",
    "build_jurisdiction_witness_v2",
    "build_profile_witness_v2",
    "build_profile_witness_v4",
    "build_profile_witness_v6",
    "build_rebind_witness_v2",
    "jurisdiction_public_inputs_v2",
    "profile_public_inputs_v2",
    "rebind_public_inputs_v2",
    "check_jurisdiction_constraints_v2",
    "check_jurisdiction_constraints_v3",
    "check_jurisdiction_constraints_v4",
    "check_profile_constraints_v2",
    "check_profile_constraints_v4",
    "check_profile_constraints_v6",
    "check_rebind_constraints_v2",
    "check_rebind_v2_binding_v2_constraints",
    "JURISDICTION_V2_PUBLIC_INPUT_NAMES",
    "PROFILE_V2_PUBLIC_INPUT_NAMES",
    "REBIND_V2_PUBLIC_INPUT_NAMES",
    "resolve_presentation_proof_type",
    "resolve_presentation_proof_type_for_request",
    "request_contract_proof_types",
    "legacy_presentation_proof_type_for_verification",
    "resolve_requested_presentation_proof_type",
    "family_for_v1_proof_type",
    "credential_proof_type_for_request",
]

# --- circuit / proof-type identifiers ----------------------------------------

JURISDICTION_V1_CIRCUIT = "zkc_jurisdiction"
JURISDICTION_V1_PROOF_TYPE = "zkc:proof:jurisdiction:v1"
JURISDICTION_V2_PROOF_TYPE = "zkc:proof:jurisdiction:v2"
JURISDICTION_V3_PROOF_TYPE = "zkc:proof:jurisdiction:v3"
JURISDICTION_V4_PROOF_TYPE = "zkc:proof:jurisdiction:v4"
JURISDICTION_V5_PROOF_TYPE = "zkc:proof:jurisdiction:v5"
JURISDICTION_V6_PROOF_TYPE = "zkc:proof:jurisdiction:v6"
JURISDICTION_V3_CIRCUIT = "zkc_jurisdiction_v3"
JURISDICTION_V4_CIRCUIT = "zkc_jurisdiction_v4"
JURISDICTION_V5_CIRCUIT = "zkc_jurisdiction_v5"
JURISDICTION_V6_CIRCUIT = "zkc_jurisdiction_v6"
# The unsuffixed API names denote the safe current linkable jurisdiction path.
JURISDICTION_CIRCUIT = JURISDICTION_V3_CIRCUIT
JURISDICTION_PROOF_TYPE = JURISDICTION_V3_PROOF_TYPE

REMAINING_CIRCUIT = "zkc_remaining_predicates"
REMAINING_V3_CIRCUIT = "zkc_remaining_predicates_v3"
REMAINING_V5_CIRCUIT = "zkc_remaining_predicates_v5"
REMAINING_V7_CIRCUIT = "zkc_remaining_predicates_v7"

REBIND_CIRCUIT = "zkc_credential_rebind"
REBIND_PROOF_TYPE = "zkc:proof:credential_rebind:v1"

# Additive successor for the frozen linkable rebind ABI.  The package name and
# proof type are deliberately distinct from the original identity: callers
# requesting the legacy type must continue to prove the legacy circuit.
REBIND_BINDING_V2_CIRCUIT = "zkc_credential_rebind_binding_v2"
REBIND_BINDING_V2_PROOF_TYPE = "zkc:proof:credential_rebind:v2"
REBIND_BINDING_V2_STATEMENT_DOMAIN = (
    0x267FC55362A61F6316556AE19EFE2589ABF268D6C8E56D417CE78B7C9CB36524
)

# v2 (presentation-profile) circuits.
JURISDICTION_V2_CIRCUIT = "zkc_jurisdiction_v2"
REMAINING_V2_CIRCUIT = "zkc_remaining_predicates_v2"
REMAINING_V4_CIRCUIT = "zkc_remaining_predicates_v4"
REMAINING_V6_CIRCUIT = "zkc_remaining_predicates_v6"
REMAINING_V8_CIRCUIT = "zkc_remaining_predicates_v8"
REMAINING_V9_CIRCUIT = "zkc_remaining_predicates_v9"
REMAINING_V10_CIRCUIT = "zkc_remaining_predicates_v10"
REMAINING_V11_CIRCUIT = "zkc_remaining_predicates_v11"
REBIND_V2_CIRCUIT = "zkc_credential_rebind_v2"
# Additive successor for the scoped rebind ABI.
REBIND_V2_BINDING_V2_CIRCUIT = "zkc_credential_rebind_v2_binding_v2"
REBIND_V2_BINDING_V2_PROOF_TYPE = "zkc:proof:rebind:v3"

# ---------------------------------------------------------------------------
# Credential-continuity containment (security remediation, 2026-09-06).
#
# All four historical credential-rebind circuits constrain only holder-key
# continuity: the credential's holder commitment, credential_id, issuer and
# schema hashes and validity bounds are unconstrained private witnesses, and
# no issuer signature or accumulator membership is verified. The holder SDK
# therefore never selects a credential for, generates, or negotiates any of
# these identities. Their builders and constraint mirrors below are retained
# verbatim as frozen references for the byte-pinned historical circuits.
# ---------------------------------------------------------------------------
UNAUTHENTICATED_REBIND_PROOF_TYPES = frozenset(
    (
        REBIND_PROOF_TYPE,
        "zkc:proof:rebind:v2",
        REBIND_BINDING_V2_PROOF_TYPE,
        REBIND_V2_BINDING_V2_PROOF_TYPE,
    )
)
_UNAUTHENTICATED_REBIND_FAMILIES = frozenset(("rebind", "rebind_binding_v2"))

# ---------------------------------------------------------------------------
# Issuer-authenticated credential-rebind successors (spec section 7.4, ADR 0004).
#
# Unlike every identity above, these statements verify an issuer signature over
# the zkc:attestation:credential-rebind:v1 transcript RECOMPUTED in-circuit from
# constrained fields, and prove fresh accumulator membership for the same
# authenticated credential id. They are the only supported rebind mechanism.
# ---------------------------------------------------------------------------
REBIND_AUTH_CIRCUIT = "zkc_credential_rebind_auth"
REBIND_AUTH_PROOF_TYPE = "zkc:proof:credential_rebind:v3"
REBIND_AUTH_V2_CIRCUIT = "zkc_credential_rebind_auth_v2"
REBIND_AUTH_V2_PROOF_TYPE = "zkc:proof:rebind:v4"
REBIND_AUTH_V3_CIRCUIT = "zkc_credential_rebind_auth_v3"
REBIND_AUTH_V3_PROOF_TYPE = "zkc:proof:rebind:v5"

# Private semantic transcript domains, cross-pinned in the circuits and in
# tests/vectors/zkc_core_vectors.json. Predicate-entry v1's beta.25 transport
# aliases deliberately retain these values because the statement is unchanged.
REBIND_AUTH_STATEMENT_DOMAIN = (
    0x14D9D998A4B387195D0525F53B070CDA77F50C2F608AA29B83B48C760307424A
)
REBIND_AUTH_V2_STATEMENT_DOMAIN = (
    0x232F4619AFFDC2A4CF3F9CA0B83EB769204A396A6731B868324A5F1422829E0E
)


def refuse_unauthenticated_rebind(proof_type: str) -> None:
    """Fail closed on a contained credential-rebind identity."""
    from .errors import UnauthenticatedProofTypeError

    if proof_type in UNAUTHENTICATED_REBIND_PROOF_TYPES:
        raise UnauthenticatedProofTypeError(
            f"proof type {proof_type} asserts credential continuity without "
            "authenticating issuance or revocation (its credential fields are "
            "unconstrained prover witnesses); the holder SDK refuses to select, "
            "generate, or migrate a live credential through it"
        )
REBIND_V2_BINDING_V2_STATEMENT_DOMAIN = (
    0x1C2381C670EC3F5155B8C670F06DCA1A0338967A88F5B8E559D22B76335B2841
)


def _presentation_pseudonym(credential_binding_key: int, scope_id: int) -> int:
    """Anonymous sentinel 0 when scope_id == 0, else the provable pseudonym."""
    if int(scope_id) == 0:
        return 0
    return derive_presentation_pseudonym(int(credential_binding_key), int(scope_id))


def _assert_presentation_binding(witness: dict) -> None:
    """Python mirror of zkc_lib::assert_presentation_binding (design §4.1).

    Shared by the jurisdiction/profile v2 constraint mirrors: scope_id == 0
    (anonymous) forces presentation_pseudonym == 0; otherwise the pseudonym must
    derive from the credential binding key and scope. Messages match the circuit.
    """
    scope_id = int(witness["scope_id"])
    pseudonym = witness["presentation_pseudonym"]
    if scope_id == 0:
        if pseudonym != 0:
            raise ConstraintViolationError("anonymous profile must not carry a pseudonym")
    else:
        expected = derive_presentation_pseudonym(
            int(witness["credential_binding_key"]), scope_id
        )
        if pseudonym != expected:
            raise ConstraintViolationError(
                "presentation pseudonym does not derive from binding key and scope"
            )

# Mirror noir/zkc_jurisdiction/src/main.nr.
MEMBERSHIP_TYPE_INCLUSION = 0
MEMBERSHIP_TYPE_EXCLUSION = 1

# Mirror noir/zkc_remaining_predicates/src/main.nr.
PREDICATE_ACCREDITATION = 1
PREDICATE_SOURCE_OF_FUNDS = 2
PREDICATE_TAX_RESIDENCY = 3
PREDICATE_SANCTIONS_CLEARANCE = 4

_CODE_SPACE_KIND_BY_SELECTOR = {
    PREDICATE_SOURCE_OF_FUNDS: "source",
    PREDICATE_TAX_RESIDENCY: "tax",
    PREDICATE_SANCTIONS_CLEARANCE: "sanctions",
}
_CODE_SPACE_SCHEMA_BY_KIND = {kind: schema for schema, kind in CODE_SPACE_CREDENTIAL_TO_KIND.items()}

PROFILE_PROOF_TYPES = {
    "zkc:proof:accreditation:v1": PREDICATE_ACCREDITATION,
    "zkc:proof:source:v1": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v1": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v1": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:accreditation:v2": PREDICATE_ACCREDITATION,
    "zkc:proof:source:v2": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v2": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v2": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:accreditation:v3": PREDICATE_ACCREDITATION,
    "zkc:proof:source:v3": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v3": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v3": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:accreditation:v4": PREDICATE_ACCREDITATION,
    "zkc:proof:source:v4": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v4": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v4": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:accreditation:v5": PREDICATE_ACCREDITATION,
    "zkc:proof:source:v5": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v5": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v5": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:accreditation:v6": PREDICATE_ACCREDITATION,
    "zkc:proof:source:v6": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v6": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v6": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:accreditation:v7": PREDICATE_ACCREDITATION,
    "zkc:proof:source:v7": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v7": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v7": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:accreditation:v8": PREDICATE_ACCREDITATION,
    "zkc:proof:source:v8": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v8": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v8": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:accreditation:v9": PREDICATE_ACCREDITATION,
    "zkc:proof:accreditation:v10": PREDICATE_ACCREDITATION,
    "zkc:proof:source:v9": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:source:v10": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v9": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:tax:v10": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v9": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:sanctions:v10": PREDICATE_SANCTIONS_CLEARANCE,
    "zkc:proof:source:v11": PREDICATE_SOURCE_OF_FUNDS,
    "zkc:proof:tax:v11": PREDICATE_TAX_RESIDENCY,
    "zkc:proof:sanctions:v11": PREDICATE_SANCTIONS_CLEARANCE,
}
PROFILE_PROOF_TYPES.update({
    successor: PROFILE_PROOF_TYPES[predecessor]
    for successor, predecessor in NONZERO_CREDENTIAL_PROOF_PREDECESSORS.items()
    if predecessor in PROFILE_PROOF_TYPES
})

_SUCCESSOR_CREDENTIAL_PROOF_TYPES = {
    "zkc:proof:kyc:v2": "zkc:proof:kyc:v1",
    "zkc:proof:kyc:v3": "zkc:proof:kyc:v1",
    "zkc:proof:community_kyc:v2": "zkc:proof:kyc:v1",
    "zkc:proof:selective_disclosure:v2": "zkc:proof:selective_disclosure:v1",
    JURISDICTION_V3_PROOF_TYPE: JURISDICTION_V1_PROOF_TYPE,
    JURISDICTION_V4_PROOF_TYPE: JURISDICTION_V1_PROOF_TYPE,
    JURISDICTION_V5_PROOF_TYPE: JURISDICTION_V3_PROOF_TYPE,
    "zkc:proof:accreditation:v3": "zkc:proof:accreditation:v1",
    "zkc:proof:source:v3": "zkc:proof:source:v1",
    "zkc:proof:tax:v3": "zkc:proof:tax:v1",
    "zkc:proof:sanctions:v3": "zkc:proof:sanctions:v1",
    "zkc:proof:accreditation:v4": "zkc:proof:accreditation:v1",
    "zkc:proof:source:v4": "zkc:proof:source:v1",
    "zkc:proof:tax:v4": "zkc:proof:tax:v1",
    "zkc:proof:sanctions:v4": "zkc:proof:sanctions:v1",
    "zkc:proof:accreditation:v5": "zkc:proof:accreditation:v1",
    "zkc:proof:source:v5": "zkc:proof:source:v1",
    "zkc:proof:tax:v5": "zkc:proof:tax:v1",
    "zkc:proof:sanctions:v5": "zkc:proof:sanctions:v1",
    "zkc:proof:accreditation:v6": "zkc:proof:accreditation:v1",
    "zkc:proof:source:v6": "zkc:proof:source:v1",
    "zkc:proof:tax:v6": "zkc:proof:tax:v1",
    "zkc:proof:sanctions:v6": "zkc:proof:sanctions:v1",
    "zkc:proof:accreditation:v8": "zkc:proof:accreditation:v7",
    "zkc:proof:source:v8": "zkc:proof:source:v7",
    "zkc:proof:tax:v8": "zkc:proof:tax:v7",
    "zkc:proof:sanctions:v8": "zkc:proof:sanctions:v7",
    "zkc:proof:accreditation:v9": "zkc:proof:accreditation:v7",
    "zkc:proof:accreditation:v10": "zkc:proof:accreditation:v7",
    "zkc:proof:source:v9": "zkc:proof:source:v7",
    "zkc:proof:source:v10": "zkc:proof:source:v7",
    "zkc:proof:tax:v9": "zkc:proof:tax:v7",
    "zkc:proof:tax:v10": "zkc:proof:tax:v7",
    "zkc:proof:sanctions:v9": "zkc:proof:sanctions:v7",
    "zkc:proof:sanctions:v10": "zkc:proof:sanctions:v7",
}


def credential_proof_type_for_request(proof_type: str) -> str:
    """Stored credential type compatible with a successor statement request.

    The issuer-signed profile digest already authenticates the predicate
    Historical v3-v6 statements use their v1 credential.  The current v8
    presentation sibling uses the validFrom-bound v7 credential and never
    falls back to a v1 credential.
    """
    return _SUCCESSOR_CREDENTIAL_PROOF_TYPES.get(proof_type, proof_type)

_ZERO_SIBLINGS = [0] * 32


# --- reference Merkle-set helpers --------------------------------------------


def single_leaf_set_root(leaf: int) -> int:
    """Root of a Merkle set holding exactly one leaf at index 0.

    Reference helper for verifiers/tests that publish a one-element set; real
    deployments build their set tree out of band.
    """
    return compute_merkle_root(leaf, 0, _ZERO_SIBLINGS)


def single_leaf_inclusion_witness() -> tuple:
    """(path_index, siblings) for the single leaf at index 0 of such a set."""
    return 0, list(_ZERO_SIBLINGS)


def _coerce_siblings(siblings) -> list:
    siblings = [int(s) for s in siblings]
    if len(siblings) != 32:
        raise ConstraintViolationError("Merkle witness must have exactly 32 siblings")
    return siblings


# --- jurisdiction predicate (zkc_jurisdiction) -------------------------------


def build_jurisdiction_witness(
    *,
    credential_binding_key: int,
    credential,
    issuer,
    witness,
    membership_type: int,
    required_claim_type: int,
    jurisdiction_set_root: int,
    membership_path_index: int,
    membership_siblings,
    predecessor_code: int,
    predecessor_path_index: int,
    predecessor_siblings,
    successor_code: int,
    successor_path_index: int,
    successor_siblings,
    proof_context: int,
    timestamp: int,
    current_epoch: int,
) -> dict:
    """Assemble the full zkc_jurisdiction witness (public + private inputs).

    Witness order matches noir/zkc_jurisdiction/src/main.nr main().
    """
    claims = credential.claims
    membership_type = int(membership_type)
    required_claim_type = int(required_claim_type)
    claim_binding = compute_claim_binding_3(
        jurisdiction_set_root,
        membership_type,
        required_claim_type,
        proof_context,
        timestamp,
    )
    return {
        # === Public inputs ===
        "holder_commitment": credential.holder_commitment,
        "claim_binding": claim_binding,
        "proof_context": proof_context,
        "jurisdiction_set_root": jurisdiction_set_root,
        "membership_type": membership_type,
        "accumulator_root": witness.accumulator_root,
        "accumulator_epoch": witness.accumulator_epoch,
        "timestamp": timestamp,
        "current_epoch": current_epoch,
        "issuer_public_key_x": list(issuer.public_key_x),
        "issuer_public_key_y": list(issuer.public_key_y),
        # === Private credential inputs ===
        "credential_binding_key": credential_binding_key,
        "credential_holder_commitment": credential.holder_commitment,
        "credential_id": credential.credential_id,
        "jurisdiction_code": int(claims["jurisdictionCode"]),
        "credential_claim_type": int(claims["claimType"]),
        "verification_method": int(claims["verificationMethod"]),
        "valid_from": int(claims["validFrom"]),
        "valid_until": int(claims["validUntil"]),
        "issuer_signature": list(credential.signature),
        # === Private predicate request inputs ===
        "required_claim_type": required_claim_type,
        # === Private jurisdiction set witness ===
        "membership_path_index": int(membership_path_index),
        "membership_siblings": _coerce_siblings(membership_siblings),
        "predecessor_code": int(predecessor_code),
        "predecessor_path_index": int(predecessor_path_index),
        "predecessor_siblings": _coerce_siblings(predecessor_siblings),
        "successor_code": int(successor_code),
        "successor_path_index": int(successor_path_index),
        "successor_siblings": _coerce_siblings(successor_siblings),
        # === Private non-revocation witness ===
        "nonrevocation_siblings": list(witness.siblings),
        "nonrevocation_path_index": witness.path_index,
    }


JURISDICTION_PUBLIC_INPUT_NAMES = (
    "holder_commitment",
    "claim_binding",
    "proof_context",
    "jurisdiction_set_root",
    "membership_type",
    "accumulator_root",
    "accumulator_epoch",
    "timestamp",
    "current_epoch",
    "issuer_public_key_x",
    "issuer_public_key_y",
)

_INT_PUBLIC_INPUTS = ("accumulator_epoch", "timestamp", "current_epoch", "membership_type")


def jurisdiction_public_inputs(witness: dict) -> dict:
    output = {}
    for name in JURISDICTION_PUBLIC_INPUT_NAMES:
        value = witness[name]
        if name in ("issuer_public_key_x", "issuer_public_key_y"):
            output[name] = "0x" + bytes(value).hex()
        elif name in _INT_PUBLIC_INPUTS:
            output[name] = int(value)
        else:
            output[name] = field_to_hex(value)
    return output


def build_jurisdiction_witness_v2(*, scope_id: int = 0, **kwargs) -> dict:
    """Assemble a zkc_jurisdiction **v2** witness (design §4.1).

    ADDITIVE: delegates to the v1 :func:`build_jurisdiction_witness`, then heads
    the witness with ``presentation_pseudonym`` + ``scope_id``. ``holder_commitment``
    remains only as a private witness (v2 extractor never surfaces it).
    """
    base = build_jurisdiction_witness(**kwargs)
    scope_id = int(scope_id)
    pseudonym = _presentation_pseudonym(kwargs["credential_binding_key"], scope_id)
    return {"presentation_pseudonym": pseudonym, "scope_id": scope_id, **base}


JURISDICTION_V2_PUBLIC_INPUT_NAMES = (
    "presentation_pseudonym",
    "scope_id",
    "claim_binding",
    "proof_context",
    "jurisdiction_set_root",
    "membership_type",
    "accumulator_root",
    "accumulator_epoch",
    "timestamp",
    "current_epoch",
    "issuer_public_key_x",
    "issuer_public_key_y",
)


def jurisdiction_public_inputs_v2(witness: dict) -> dict:
    output = {}
    for name in JURISDICTION_V2_PUBLIC_INPUT_NAMES:
        value = witness[name]
        if name in ("issuer_public_key_x", "issuer_public_key_y"):
            output[name] = "0x" + bytes(value).hex()
        elif name in _INT_PUBLIC_INPUTS:
            output[name] = int(value)
        else:
            output[name] = field_to_hex(value)
    return output


def _verify_jurisdiction_set(witness: dict, code_space_id=None) -> bool:
    """Python mirror of zkc_jurisdiction::verify_jurisdiction_set."""
    jurisdiction_code = witness["jurisdiction_code"]
    required_claim_type = witness["required_claim_type"]
    set_root = witness["jurisdiction_set_root"]
    membership_type = witness["membership_type"]
    def encode_leaf(code):
        if code_space_id is None:
            return compute_jurisdiction_leaf(code, required_claim_type)
        return code_space_leaf("jurisdiction", code_space_id, code, required_claim_type)

    leaf = encode_leaf(jurisdiction_code)
    if membership_type == MEMBERSHIP_TYPE_INCLUSION:
        return (
            compute_merkle_root(
                leaf, witness["membership_path_index"], witness["membership_siblings"]
            )
            == set_root
        )
    if membership_type == MEMBERSHIP_TYPE_EXCLUSION:
        predecessor_code = witness["predecessor_code"]
        successor_code = witness["successor_code"]
        predecessor_leaf = encode_leaf(predecessor_code)
        successor_leaf = encode_leaf(successor_code)
        predecessor_valid = (
            compute_merkle_root(
                predecessor_leaf,
                witness["predecessor_path_index"],
                witness["predecessor_siblings"],
            )
            == set_root
        )
        successor_valid = (
            compute_merkle_root(
                successor_leaf,
                witness["successor_path_index"],
                witness["successor_siblings"],
            )
            == set_root
        )
        return (
            predecessor_valid
            and successor_valid
            and predecessor_code < jurisdiction_code
            and jurisdiction_code < successor_code
        )
    return False


def check_jurisdiction_constraints(witness: dict, *, code_space_id=None) -> None:
    """Python mirror of every assert in noir/zkc_jurisdiction/src/main.nr."""

    def fail(message: str):
        raise ConstraintViolationError(message)

    if derive_holder_commitment(witness["credential_binding_key"]) != witness["holder_commitment"]:
        fail("holder commitment does not match credential binding key")
    if witness["credential_holder_commitment"] != witness["holder_commitment"]:
        fail("credential holder commitment does not match public holder commitment")
    if witness["credential_claim_type"] != witness["required_claim_type"]:
        fail("credential claim type does not match requested claim type")

    digest = compute_jurisdiction_credential_digest(
        witness["credential_holder_commitment"],
        witness["credential_id"],
        witness["jurisdiction_code"],
        witness["credential_claim_type"],
        witness["verification_method"],
        witness["valid_from"],
        witness["valid_until"],
    )
    if code_space_id is not None:
        digest = bind_code_space_digest(_CODE_SPACE_SCHEMA_BY_KIND["jurisdiction"], code_space_id, digest)
    if not ecdsa_verify(
        bytes(witness["issuer_public_key_x"]),
        bytes(witness["issuer_public_key_y"]),
        bytes(witness["issuer_signature"]),
        digest_to_message_bytes(digest),
    ):
        fail("invalid issuer signature")

    _check_nonrevocation(witness, fail)

    if not _verify_jurisdiction_set(witness, code_space_id):
        fail("jurisdiction set proof failed")

    valid_from = witness["valid_from"]
    valid_until = witness["valid_until"]
    timestamp = witness["timestamp"]
    if not (valid_from <= timestamp and valid_until >= timestamp):
        fail("jurisdiction credential not valid at timestamp")

    expected_claim_binding = compute_claim_binding_3(
        witness["jurisdiction_set_root"],
        witness["membership_type"],
        witness["required_claim_type"],
        witness["proof_context"],
        witness["timestamp"],
    )
    if code_space_id is not None:
        expected_claim_binding = bind_code_space_statement(
            "jurisdiction", code_space_id, expected_claim_binding, witness["required_verification_method"]
        )
    if expected_claim_binding != witness["claim_binding"]:
        fail("claim binding mismatch")
    if witness["proof_context"] == 0:
        fail("proof context must be non-zero")


def check_jurisdiction_constraints_v2(witness: dict) -> None:
    """Python mirror of noir/zkc_jurisdiction_v2/src/main.nr (design §4.1).

    The v1 jurisdiction constraints (``check_jurisdiction_constraints``) over a
    private holder commitment, plus the shared presentation-binding constraint."""
    check_jurisdiction_constraints(witness)
    _assert_presentation_binding(witness)


def _assert_successor_is_adjacent(witness: dict) -> None:
    """Enforce the sorted-neighbour exclusion invariant on safe successors."""
    if int(witness["successor_path_index"]) != int(witness["predecessor_path_index"]) + 1:
        raise ConstraintViolationError("sorted-neighbour exclusion witness is not adjacent")


def check_jurisdiction_constraints_v3(witness: dict) -> None:
    """Mirror the safe linkable jurisdiction successor."""
    check_jurisdiction_constraints(witness)
    if witness["membership_type"] == MEMBERSHIP_TYPE_EXCLUSION:
        _assert_successor_is_adjacent(witness)


def check_jurisdiction_constraints_v4(witness: dict) -> None:
    """Mirror the safe presentation-native jurisdiction successor."""
    check_jurisdiction_constraints_v2(witness)
    if witness["membership_type"] == MEMBERSHIP_TYPE_EXCLUSION:
        _assert_successor_is_adjacent(witness)


# --- shared non-revocation mirror --------------------------------------------


def _check_nonrevocation(witness: dict, fail) -> None:
    root = compute_merkle_root(
        witness["credential_id"],
        witness["nonrevocation_path_index"],
        witness["nonrevocation_siblings"],
    )
    epoch_fresh = (
        witness["current_epoch"] >= witness["accumulator_epoch"]
        and witness["current_epoch"] - witness["accumulator_epoch"] <= MAX_EPOCH_LAG
    )
    if root != witness["accumulator_root"] or not epoch_fresh:
        fail("credential is revoked or accumulator epoch is stale")


# --- profile predicates (zkc_remaining_predicates) ---------------------------


def _require_profile_uint(name: str, value, bits: int) -> None:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ConstraintViolationError(f"{name} must be an exact u{bits} integer")


def validate_profile_request_domains(predicate_type: int, required_0, required_1) -> None:
    """Refuse Field aliases and narrow comparison aliases before coercion.

    Frozen circuits constrain truncating casts, not the original Field range.
    This is a host admission rule; it does not change their published behavior.
    """
    for name, value, bits in (
        ("required0", required_0, 8 if predicate_type == PREDICATE_ACCREDITATION else None),
        ("required1", required_1, 64 if predicate_type == PREDICATE_TAX_RESIDENCY else None),
    ):
        if bits is not None:
            _require_profile_uint(name, value, bits)
        elif type(value) is not int or not 0 <= value < FIELD_MODULUS:
            raise ConstraintViolationError(f"{name} must be an exact canonical Field integer")


def _validate_profile_claim_domains(predicate_type: int, claim_0, claim_1) -> None:
    if predicate_type == PREDICATE_ACCREDITATION:
        _require_profile_uint("claim_0", claim_0, 8)
    elif predicate_type == PREDICATE_TAX_RESIDENCY:
        _require_profile_uint("claim_1", claim_1, 64)
    elif predicate_type == PREDICATE_SANCTIONS_CLEARANCE:
        _require_profile_uint("claim_0", claim_0, 16)


def build_profile_witness(
    *,
    predicate_type: int,
    credential_binding_key: int,
    credential,
    issuer,
    witness,
    required_0: int,
    required_1: int,
    flag_required: bool,
    set_root: int,
    path_index: int,
    siblings,
    predecessor_code: int,
    predecessor_path_index: int,
    predecessor_siblings,
    successor_code: int,
    successor_path_index: int,
    successor_siblings,
    proof_context: int,
    timestamp: int,
    current_epoch: int,
) -> dict:
    """Assemble the full zkc_remaining_predicates witness for one predicate.

    Witness order matches noir/zkc_remaining_predicates/src/main.nr main().
    The signed claim slots (claim0/claim1) come from the credential; the
    request slots (required_0/required_1/set_root/membership witness) come from
    the verifier's proof request.
    """
    claims = credential.claims
    predicate_type = int(predicate_type)
    validate_profile_request_domains(predicate_type, required_0, required_1)
    _validate_profile_claim_domains(predicate_type, claims["claim0"], claims["claim1"])
    claim_binding = compute_claim_binding_3(
        predicate_type, required_0, required_1, proof_context, timestamp
    )
    return {
        # === Public inputs ===
        "holder_commitment": credential.holder_commitment,
        "claim_binding": claim_binding,
        "proof_context": proof_context,
        "predicate_type": predicate_type,
        "set_root": int(set_root),
        "accumulator_root": witness.accumulator_root,
        "accumulator_epoch": witness.accumulator_epoch,
        "timestamp": timestamp,
        "current_epoch": current_epoch,
        "issuer_public_key_x": list(issuer.public_key_x),
        "issuer_public_key_y": list(issuer.public_key_y),
        # === Private shared credential inputs ===
        "credential_binding_key": credential_binding_key,
        "credential_holder_commitment": credential.holder_commitment,
        "credential_id": credential.credential_id,
        "claim_0": int(claims["claim0"]),
        "claim_1": int(claims["claim1"]),
        "valid_from": int(claims["validFrom"]),
        "valid_until": int(claims["validUntil"]),
        "issuer_signature": list(credential.signature),
        # === Private predicate request inputs ===
        "required_0": int(required_0),
        "required_1": int(required_1),
        "flag_required": bool(flag_required),
        "path_index": int(path_index),
        "siblings": _coerce_siblings(siblings),
        "predecessor_code": int(predecessor_code),
        "predecessor_path_index": int(predecessor_path_index),
        "predecessor_siblings": _coerce_siblings(predecessor_siblings),
        "successor_code": int(successor_code),
        "successor_path_index": int(successor_path_index),
        "successor_siblings": _coerce_siblings(successor_siblings),
        # === Private non-revocation witness ===
        "nonrevocation_siblings": list(witness.siblings),
        "nonrevocation_path_index": witness.path_index,
    }


PROFILE_PUBLIC_INPUT_NAMES = (
    "holder_commitment",
    "claim_binding",
    "proof_context",
    "predicate_type",
    "set_root",
    "accumulator_root",
    "accumulator_epoch",
    "timestamp",
    "current_epoch",
    "issuer_public_key_x",
    "issuer_public_key_y",
)

_PROFILE_INT_PUBLIC_INPUTS = (
    "predicate_type",
    "accumulator_epoch",
    "timestamp",
    "current_epoch",
)


def profile_public_inputs(witness: dict) -> dict:
    output = {}
    for name in PROFILE_PUBLIC_INPUT_NAMES:
        value = witness[name]
        if name in ("issuer_public_key_x", "issuer_public_key_y"):
            output[name] = "0x" + bytes(value).hex()
        elif name in _PROFILE_INT_PUBLIC_INPUTS:
            output[name] = int(value)
        else:
            output[name] = field_to_hex(value)
    return output


def build_profile_witness_v2(*, scope_id: int = 0, **kwargs) -> dict:
    """Assemble a zkc_remaining_predicates **v2** witness (design §4.1).

    ADDITIVE: delegates to the v1 :func:`build_profile_witness`, then heads the
    witness with ``presentation_pseudonym`` + ``scope_id``. ``holder_commitment``
    remains private only.
    """
    base = build_profile_witness(**kwargs)
    scope_id = int(scope_id)
    pseudonym = _presentation_pseudonym(kwargs["credential_binding_key"], scope_id)
    return {"presentation_pseudonym": pseudonym, "scope_id": scope_id, **base}


def build_profile_witness_v3(**kwargs) -> dict:
    """Assemble the flagRequired-bound linkable successor witness.

    Its public ABI is identical to v1, but ``claim_binding`` uses the new
    four-slot transcript. Exact boolean validation prevents JSON ``0``/``1``
    aliases from being silently coerced before APR/request comparison.
    """
    flag_required = kwargs.get("flag_required")
    if type(flag_required) is not bool:
        raise ConstraintViolationError("flag_required must be an exact boolean")
    base = build_profile_witness(**kwargs)
    base["claim_binding"] = compute_claim_binding_4(
        int(kwargs["predicate_type"]),
        int(kwargs["required_0"]),
        int(kwargs["required_1"]),
        flag_required,
        int(kwargs["proof_context"]),
        int(kwargs["timestamp"]),
    )
    return base


def build_profile_witness_v4(*, scope_id: int = 0, **kwargs) -> dict:
    """Assemble the flagRequired-bound anonymous/scoped successor witness."""
    base = build_profile_witness_v3(**kwargs)
    scope_id = int(scope_id)
    pseudonym = _presentation_pseudonym(kwargs["credential_binding_key"], scope_id)
    return {"presentation_pseudonym": pseudonym, "scope_id": scope_id, **base}


def _assert_safe_raw_code_predicate_witness(witness: dict) -> None:
    """Reject the raw-code and exclusion-witness aliases first fixed by v5/v6.

    The v1--v4 circuits are published historical behavior.  The historical
    v5/v6 successors first made the source/tax zero padding collision and
    sanctions non-adjacent-neighbour ambiguity unprovable; the current v7/v8
    successors retain those constraints and also authenticate ``validFrom``.
    Keeping this check separate makes that version boundary explicit in both
    the builder and the Python constraint mirror.
    """
    predicate_type = witness["predicate_type"]
    if predicate_type in (PREDICATE_SOURCE_OF_FUNDS, PREDICATE_TAX_RESIDENCY):
        if witness["claim_0"] == 0:
            raise ConstraintViolationError(
                "source and tax raw codes must be non-zero"
            )
    elif predicate_type == PREDICATE_SANCTIONS_CLEARANCE:
        if int(witness["successor_path_index"]) != int(witness["predecessor_path_index"]) + 1:
            raise ConstraintViolationError(
                "sanctions predecessor and successor path indices must be adjacent"
            )


def build_profile_witness_v5(**kwargs) -> dict:
    """Assemble the historical raw-code-safe linkable successor witness.

    v5 retains the four-slot claim-binding transcript introduced by v3, while
    adding the raw-code and sorted-neighbour constraints that cannot be
    retroactively imposed on the historical v1--v4 circuits.
    """
    base = build_profile_witness_v3(**kwargs)
    _assert_safe_raw_code_predicate_witness(base)
    return base


def build_profile_witness_v6(*, scope_id: int = 0, **kwargs) -> dict:
    """Assemble the historical raw-code-safe anonymous/scoped successor witness."""
    base = build_profile_witness_v5(**kwargs)
    scope_id = int(scope_id)
    pseudonym = _presentation_pseudonym(kwargs["credential_binding_key"], scope_id)
    return {"presentation_pseudonym": pseudonym, "scope_id": scope_id, **base}


def build_profile_witness_v7(**kwargs) -> dict:
    """Assemble the combined current linkable successor witness.

    v5/v6 remain published raw-code successors over the old issuer digest.
    v7 adds the versioned digest that authenticates ``validFrom`` while
    retaining every v5 raw-code and adjacency constraint.
    """
    return build_profile_witness_v5(**kwargs)


def build_profile_witness_v8(*, scope_id: int = 0, **kwargs) -> dict:
    """Assemble the combined current anonymous/scoped successor witness."""
    base = build_profile_witness_v7(**kwargs)
    scope_id = int(scope_id)
    pseudonym = _presentation_pseudonym(kwargs["credential_binding_key"], scope_id)
    return {"presentation_pseudonym": pseudonym, "scope_id": scope_id, **base}


# v2 reorders to (set_root, predicate_type) at indices 4/5 per the v2 encoder.
PROFILE_V2_PUBLIC_INPUT_NAMES = (
    "presentation_pseudonym",
    "scope_id",
    "claim_binding",
    "proof_context",
    "set_root",
    "predicate_type",
    "accumulator_root",
    "accumulator_epoch",
    "timestamp",
    "current_epoch",
    "issuer_public_key_x",
    "issuer_public_key_y",
)


def profile_public_inputs_v2(witness: dict) -> dict:
    output = {}
    for name in PROFILE_V2_PUBLIC_INPUT_NAMES:
        value = witness[name]
        if name in ("issuer_public_key_x", "issuer_public_key_y"):
            output[name] = "0x" + bytes(value).hex()
        elif name in _PROFILE_INT_PUBLIC_INPUTS:
            output[name] = int(value)
        else:
            output[name] = field_to_hex(value)
    return output


def _verify_accreditation(claim_0: int, required_0: int, flag_required: bool, claim_1: int) -> bool:
    return (claim_0 >= required_0) and ((not flag_required) or (claim_1 != 0))


def _verify_membership(leaf: int, set_root: int, path_index: int, siblings) -> bool:
    return compute_merkle_root(leaf, path_index, siblings) == set_root


def _verify_sanctions(witness: dict, code_space_id=None) -> bool:
    subject = witness["claim_0"]
    predecessor_code = witness["predecessor_code"]
    successor_code = witness["successor_code"]
    set_root = witness["set_root"]
    predecessor_leaf, successor_leaf = predecessor_code, successor_code
    if code_space_id is not None:
        predecessor_leaf = code_space_leaf("sanctions", code_space_id, predecessor_code)
        successor_leaf = code_space_leaf("sanctions", code_space_id, successor_code)
    predecessor_ok = _verify_membership(
        predecessor_leaf,
        set_root,
        witness["predecessor_path_index"],
        witness["predecessor_siblings"],
    )
    successor_ok = _verify_membership(
        successor_leaf,
        set_root,
        witness["successor_path_index"],
        witness["successor_siblings"],
    )
    return (
        predecessor_ok
        and successor_ok
        and predecessor_code < subject
        and subject < successor_code
    )


def check_profile_constraints(witness: dict) -> None:
    """Python mirror of every assert in noir/zkc_remaining_predicates/src/main.nr."""
    _check_profile_constraints(witness, bind_flag_required=False)


def _check_profile_constraints(
    witness: dict,
    *,
    bind_flag_required: bool,
    safe_raw_code_predicates: bool = False,
    bind_valid_from: bool = False,
    code_space_id=None,
) -> None:
    """Circuit mirrors plus host domain admission for frozen cast semantics.

    The range guards are deliberately stronger than the published circuits;
    both proof backends refuse those inputs before any cryptographic work.
    """
    validate_profile_request_domains(
        witness["predicate_type"], witness["required_0"], witness["required_1"]
    )
    _validate_profile_claim_domains(
        witness["predicate_type"], witness["claim_0"], witness["claim_1"]
    )

    def fail(message: str):
        raise ConstraintViolationError(message)

    if type(witness.get("flag_required")) is not bool:
        fail("flag_required must be an exact boolean")

    predicate_type = witness["predicate_type"]
    if code_space_id is not None:
        kind = _CODE_SPACE_KIND_BY_SELECTOR[predicate_type]
        _check_code_space_claim(witness, kind, code_space_id, "claim_0")
        if witness["required_0"] != 0 or witness["flag_required"]:
            fail("unused profile request slots must be zero")
        if kind != "tax" and (witness["required_1"] != 0 or witness["claim_1"] != 0):
            fail("unused year slots must be zero")

    if derive_holder_commitment(witness["credential_binding_key"]) != witness["holder_commitment"]:
        fail("holder commitment does not match binding key")
    if witness["credential_holder_commitment"] != witness["holder_commitment"]:
        fail("credential holder commitment mismatch")

    if bind_valid_from:
        digest = compute_profile_digest_v2(
            witness["credential_holder_commitment"],
            witness["credential_id"],
            witness["predicate_type"],
            witness["claim_0"],
            witness["claim_1"],
            witness["valid_from"],
            witness["valid_until"],
        )
    else:
        digest = compute_profile_digest(
            witness["credential_holder_commitment"],
            witness["credential_id"],
            witness["predicate_type"],
            witness["claim_0"],
            witness["claim_1"],
            witness["valid_until"],
        )
    if code_space_id is not None:
        digest = bind_code_space_digest(_CODE_SPACE_SCHEMA_BY_KIND[kind], code_space_id, digest)
    if not ecdsa_verify(
        bytes(witness["issuer_public_key_x"]),
        bytes(witness["issuer_public_key_y"]),
        bytes(witness["issuer_signature"]),
        digest_to_message_bytes(digest),
    ):
        fail("invalid issuer signature")

    _check_nonrevocation(witness, fail)

    valid_from = witness["valid_from"]
    valid_until = witness["valid_until"]
    timestamp = witness["timestamp"]
    if not (valid_from <= timestamp and (valid_until == 0 or valid_until >= timestamp)):
        fail("credential not valid at timestamp")

    member_leaf = witness["claim_0"]
    if code_space_id is not None and kind in ("source", "tax"):
        member_leaf = code_space_leaf(kind, code_space_id, member_leaf)
    if predicate_type == PREDICATE_ACCREDITATION:
        predicate_ok = _verify_accreditation(
            witness["claim_0"],
            witness["required_0"],
            witness["flag_required"],
            witness["claim_1"],
        )
    elif predicate_type == PREDICATE_SOURCE_OF_FUNDS:
        predicate_ok = _verify_membership(
            member_leaf, witness["set_root"], witness["path_index"], witness["siblings"]
        )
    elif predicate_type == PREDICATE_TAX_RESIDENCY:
        predicate_ok = (
            _verify_membership(
                member_leaf, witness["set_root"], witness["path_index"], witness["siblings"]
            )
            and witness["claim_1"] >= witness["required_1"]
        )
    elif predicate_type == PREDICATE_SANCTIONS_CLEARANCE:
        predicate_ok = _verify_sanctions(witness, code_space_id)
    else:
        predicate_ok = False
    if not predicate_ok:
        fail("predicate-specific requirement failed")

    if safe_raw_code_predicates:
        _assert_safe_raw_code_predicate_witness(witness)

    if bind_flag_required:
        expected_claim_binding = compute_claim_binding_4(
            predicate_type,
            witness["required_0"],
            witness["required_1"],
            witness["flag_required"],
            witness["proof_context"],
            witness["timestamp"],
        )
    else:
        expected_claim_binding = compute_claim_binding_3(
            predicate_type,
            witness["required_0"],
            witness["required_1"],
            witness["proof_context"],
            witness["timestamp"],
        )
    if code_space_id is not None:
        expected_claim_binding = bind_code_space_statement(kind, code_space_id, expected_claim_binding)
    if expected_claim_binding != witness["claim_binding"]:
        fail("claim binding mismatch")


def check_profile_constraints_v2(witness: dict) -> None:
    """Python mirror of noir/zkc_remaining_predicates_v2/src/main.nr (design §4.1).

    The v1 profile constraints (``check_profile_constraints``) over a private
    holder commitment, plus the shared presentation-binding constraint."""
    check_profile_constraints(witness)
    _assert_presentation_binding(witness)


def check_profile_constraints_v3(witness: dict) -> None:
    """Python mirror of the v3 four-slot linkable successor circuit."""
    _check_profile_constraints(witness, bind_flag_required=True)


def check_profile_constraints_v4(witness: dict) -> None:
    """Python mirror of the v4 four-slot anonymous/scoped successor circuit."""
    _check_profile_constraints(witness, bind_flag_required=True)
    _assert_presentation_binding(witness)


def check_profile_constraints_v5(witness: dict) -> None:
    """Python mirror of the v5 safe, four-slot linkable successor circuit."""
    _check_profile_constraints(
        witness, bind_flag_required=True, safe_raw_code_predicates=True
    )


def check_profile_constraints_v6(witness: dict) -> None:
    """Python mirror of the v6 safe, four-slot anonymous/scoped circuit."""
    _check_profile_constraints(
        witness, bind_flag_required=True, safe_raw_code_predicates=True
    )
    _assert_presentation_binding(witness)


def check_profile_constraints_v7(witness: dict) -> None:
    """Mirror v7: v5 raw safety plus a validFrom-bound issuer signature."""
    _check_profile_constraints(
        witness,
        bind_flag_required=True,
        safe_raw_code_predicates=True,
        bind_valid_from=True,
    )


def check_profile_constraints_v8(witness: dict) -> None:
    """Mirror v8: v7 plus anonymous/scoped presentation binding."""
    check_profile_constraints_v7(witness)
    _assert_presentation_binding(witness)


def _check_code_space_claim(witness, kind, code_space_id, claim_key):
    try:
        if type(code_space_id) is not int:
            raise ValueError("expected an exact code-space field")
        space = get_code_space(field_to_hex(code_space_id), kind)
        space.validate_code(witness[claim_key])
    except ValueError as exc:
        raise ConstraintViolationError("invalid code-space credential claim") from exc


def check_jurisdiction_constraints_v6(witness: dict) -> None:
    code_space_id = witness["code_space_id"]
    _check_code_space_claim(witness, "jurisdiction", code_space_id, "jurisdiction_code")
    required_method = witness["required_verification_method"]
    try:
        validate_claim_type(witness["required_claim_type"])
        validate_claim_type(witness["credential_claim_type"])
        validate_verification_method(witness["verification_method"])
        if type(required_method) is not int or (
            required_method != 0 and validate_verification_method(required_method) != witness["verification_method"]
        ):
            raise ValueError("credential verification method does not meet request")
    except ValueError as exc:
        raise ConstraintViolationError("invalid jurisdiction claim type or verification method") from exc
    check_jurisdiction_constraints(witness, code_space_id=code_space_id)
    _assert_presentation_binding(witness)
    if witness["membership_type"] == MEMBERSHIP_TYPE_EXCLUSION:
        _assert_successor_is_adjacent(witness)


def check_profile_constraints_v11(witness: dict) -> None:
    if witness["predicate_type"] not in _CODE_SPACE_KIND_BY_SELECTOR:
        raise ConstraintViolationError("unknown code-space profile selector")
    if type(witness["code_space_id"]) is not int:
        raise ConstraintViolationError("missing code-space field")
    _check_profile_constraints(
        witness, bind_flag_required=True, safe_raw_code_predicates=True, bind_valid_from=True,
        code_space_id=witness["code_space_id"],
    )
    _assert_presentation_binding(witness)


def jurisdiction_public_inputs_v6(witness: dict) -> dict:
    return {
        **jurisdiction_public_inputs_v2(witness),
        "code_space_id": field_to_hex(witness["code_space_id"]),
        "required_verification_method": witness["required_verification_method"],
    }


def profile_public_inputs_v11(witness: dict) -> dict:
    return {**profile_public_inputs_v2(witness), "code_space_id": field_to_hex(witness["code_space_id"])}


# --- credential rebind (zkc_credential_rebind) -------------------------------


def build_rebind_witness(
    *,
    old_credential_binding_key: int,
    new_credential_binding_key: int,
    credential,
    issuer_id_hash: int,
    schema_id_hash: int,
    proof_context: int,
    timestamp: int,
    statement_domain: int | None = None,
) -> dict:
    """Assemble the full zkc_credential_rebind witness.

    Witness order matches noir/zkc_credential_rebind/src/main.nr main(). The
    rebind circuit takes no issuer signature or accumulator witness: it proves
    re-derivation of both holder commitments from binding keys and that the
    credential's bound holder commitment / issuer / schema / validity match.
    """
    claims = credential.claims
    old_holder = derive_holder_commitment(old_credential_binding_key)
    new_holder = derive_holder_commitment(new_credential_binding_key)
    claim_binding = compute_claim_binding_3(
        old_holder, new_holder, credential.credential_id, proof_context, timestamp
    )
    output = {
        # === Public inputs ===
        "old_holder_commitment": old_holder,
        "new_holder_commitment": new_holder,
        "credential_id": credential.credential_id,
        "issuer_id_hash": int(issuer_id_hash),
        "schema_id_hash": int(schema_id_hash),
        "proof_context": proof_context,
        "timestamp": timestamp,
        "claim_binding": claim_binding,
        # === Private inputs ===
        "old_credential_binding_key": old_credential_binding_key,
        "new_credential_binding_key": new_credential_binding_key,
        "credential_holder_commitment": credential.holder_commitment,
        "credential_issuer_id_hash": int(claims["issuerIdHash"]),
        "credential_schema_id_hash": int(claims["schemaIdHash"]),
        "credential_valid_from": int(claims["validFrom"]),
        "credential_valid_until": int(claims["validUntil"]),
    }
    if statement_domain is not None:
        output["statement_domain"] = int(statement_domain)
    return output


REBIND_PUBLIC_INPUT_NAMES = (
    "old_holder_commitment",
    "new_holder_commitment",
    "credential_id",
    "issuer_id_hash",
    "schema_id_hash",
    "proof_context",
    "timestamp",
    "claim_binding",
)


def rebind_public_inputs(witness: dict) -> dict:
    output = {}
    for name in REBIND_PUBLIC_INPUT_NAMES:
        value = witness[name]
        if name == "timestamp":
            output[name] = int(value)
        else:
            output[name] = field_to_hex(value)
    return output


def build_rebind_witness_v2(
    *,
    old_credential_binding_key: int,
    new_credential_binding_key: int,
    credential,
    issuer_id_hash: int,
    schema_id_hash: int,
    proof_context: int,
    timestamp: int,
    scope_id: int,
    statement_domain: int | None = None,
) -> dict:
    """Assemble a zkc_credential_rebind **v2** witness (design §4.2).

    Rebind is verifier-facing continuity, so a v2 rebind REQUIRES a scoped
    presentation: ``scope_id`` must be non-zero. The global holder commitments
    move to private witnesses; the two presentation pseudonyms (old/new, same
    scope) become the public inputs at indices 0/1, and ``claim_binding`` v2
    commits to the pseudonyms rather than the commitments.
    """
    scope_id = int(scope_id)
    if scope_id == 0:
        raise ConstraintViolationError("rebind requires a scoped presentation (scope_id must be non-zero)")

    base = build_rebind_witness(
        old_credential_binding_key=old_credential_binding_key,
        new_credential_binding_key=new_credential_binding_key,
        credential=credential,
        issuer_id_hash=issuer_id_hash,
        schema_id_hash=schema_id_hash,
        proof_context=proof_context,
        timestamp=timestamp,
        statement_domain=statement_domain,
    )
    old_pseudonym = _presentation_pseudonym(old_credential_binding_key, scope_id)
    new_pseudonym = _presentation_pseudonym(new_credential_binding_key, scope_id)
    claim_binding = compute_claim_binding_3(
        old_pseudonym, new_pseudonym, credential.credential_id, proof_context, timestamp
    )
    # v1 base carries old/new_holder_commitment + v1 claim_binding as private
    # witnesses; the v2 extractor surfaces only the pseudonym-keyed public set.
    return {
        "old_presentation_pseudonym": old_pseudonym,
        "new_presentation_pseudonym": new_pseudonym,
        "scope_id": scope_id,
        **base,
        "claim_binding": claim_binding,
    }


REBIND_V2_PUBLIC_INPUT_NAMES = (
    "old_presentation_pseudonym",
    "new_presentation_pseudonym",
    "scope_id",
    "credential_id",
    "issuer_id_hash",
    "schema_id_hash",
    "proof_context",
    "timestamp",
    "claim_binding",
)


def rebind_public_inputs_v2(witness: dict) -> dict:
    output = {}
    for name in REBIND_V2_PUBLIC_INPUT_NAMES:
        value = witness[name]
        if name == "timestamp":
            output[name] = int(value)
        else:
            output[name] = field_to_hex(value)
    return output


# --- authenticated credential rebind (spec section 7.4) ----------------------


def _require_field(name: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < FIELD_MODULUS:
        raise ConstraintViolationError(f"{name} must be a canonical field element")
    return value


def _require_u64(name: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << 64):
        raise ConstraintViolationError(f"{name} must fit in u64")
    return value


def _require_key_coordinate(name: str, value) -> bytes:
    try:
        data = bytes(value)
    except (TypeError, ValueError):
        raise ConstraintViolationError(f"{name} must be 32 bytes") from None
    if len(data) != 32:
        raise ConstraintViolationError(f"{name} must be 32 bytes")
    if not any(data):
        raise ConstraintViolationError(f"{name} must be non-zero")
    return data


def _authenticated_rebind_base(
    *,
    old_credential_binding_key: int,
    new_credential_binding_key: int,
    credential,
    issuer_public_key_x,
    issuer_public_key_y,
    accumulator_witness,
    current_epoch: int,
    proof_context: int,
    timestamp: int,
    statement_domain: int,
) -> dict:
    """Shared witness assembly for both authenticated rebind successors.

    Fails closed BEFORE proving on missing, zero, malformed, mismatched,
    expired, stale, or revoked security material: the holder never asks the
    backend to prove a statement the circuit would reject, and never copies an
    unauthenticated credential field into the witness. Every credential value
    placed in the witness is one the issuer's signature covers.
    """
    attestation = getattr(credential, "rebind_attestation", None)
    if attestation is None:
        raise ConstraintViolationError(
            "credential carries no issuer rebind attestation; an authenticated rebind "
            "requires zkc:attestation:credential-rebind:v1 material from the issuer"
        )
    if attestation.version != REBIND_ATTESTATION_VERSION:
        raise ConstraintViolationError("unsupported rebind attestation version")

    signature = bytes(attestation.signature)
    if len(signature) != 64:
        raise ConstraintViolationError("rebind attestation signature must be 64 bytes")
    if not any(signature):
        raise ConstraintViolationError("rebind attestation signature must be non-zero")

    key_x = _require_key_coordinate("issuer_public_key_x", issuer_public_key_x)
    key_y = _require_key_coordinate("issuer_public_key_y", issuer_public_key_y)

    old_key = _require_field("old_credential_binding_key", old_credential_binding_key)
    new_key = _require_field("new_credential_binding_key", new_credential_binding_key)
    old_holder = derive_holder_commitment(old_key)
    new_holder = derive_holder_commitment(new_key)
    if old_holder == new_holder:
        raise ConstraintViolationError("rebind must change holder commitment")
    if credential.holder_commitment != old_holder:
        raise ConstraintViolationError(
            "credential is not currently bound to the old holder commitment"
        )

    credential_id = _require_field("credential_id", credential.credential_id)
    issuer_id_hash = string_to_field(credential.issuer_id)
    schema_id_hash = string_to_field(attestation.schema_id)
    valid_from = _require_u64("credential_valid_from", attestation.valid_from)
    valid_until = _require_u64("credential_valid_until", attestation.valid_until)
    timestamp = _require_u64("timestamp", timestamp)
    if timestamp == 0:
        raise ConstraintViolationError("timestamp must be non-zero")
    proof_context = _require_field("proof_context", proof_context)
    if proof_context == 0:
        raise ConstraintViolationError("proof context must be non-zero")
    if not (valid_from <= timestamp and (valid_until == 0 or valid_until >= timestamp)):
        raise ConstraintViolationError("credential is not valid at timestamp")

    digest = compute_rebind_attestation_digest(
        issuer_id_hash, schema_id_hash, old_holder, credential_id, valid_from, valid_until
    )
    if not ecdsa_verify(key_x, key_y, signature, digest_to_message_bytes(digest)):
        raise ConstraintViolationError("invalid issuer signature")

    if accumulator_witness is None:
        raise ConstraintViolationError(
            "authenticated rebind requires a non-revocation witness for the credential"
        )
    accumulator_epoch = _require_u64("accumulator_epoch", accumulator_witness.accumulator_epoch)
    current_epoch = _require_u64("current_epoch", current_epoch)
    if current_epoch < accumulator_epoch:
        raise ConstraintViolationError("accumulator epoch is ahead of the current epoch")
    if current_epoch - accumulator_epoch > MAX_EPOCH_LAG:
        raise ConstraintViolationError("credential is revoked or accumulator epoch is stale")
    siblings = list(accumulator_witness.siblings)
    if len(siblings) != MERKLE_DEPTH:
        raise ConstraintViolationError("non-revocation witness must carry 32 siblings")
    if (
        compute_merkle_root(credential_id, accumulator_witness.path_index, siblings)
        != accumulator_witness.accumulator_root
    ):
        raise ConstraintViolationError("credential is revoked or accumulator epoch is stale")

    return {
        # === Public inputs (shared tail) ===
        "old_holder_commitment": old_holder,
        "new_holder_commitment": new_holder,
        "credential_id": credential_id,
        "issuer_id_hash": issuer_id_hash,
        "schema_id_hash": schema_id_hash,
        "proof_context": proof_context,
        "timestamp": timestamp,
        "accumulator_root": accumulator_witness.accumulator_root,
        "accumulator_epoch": accumulator_epoch,
        "current_epoch": current_epoch,
        # Byte arrays enter the witness as list[int], matching every other
        # predicate builder and the Prover.toml serialization nargo consumes.
        "issuer_public_key_x": list(key_x),
        "issuer_public_key_y": list(key_y),
        # === Private inputs ===
        "old_credential_binding_key": old_key,
        "new_credential_binding_key": new_key,
        "credential_valid_from": valid_from,
        "credential_valid_until": valid_until,
        "issuer_signature": list(signature),
        "nonrevocation_siblings": siblings,
        "nonrevocation_path_index": accumulator_witness.path_index,
        "statement_domain": _require_field("statement_domain", statement_domain),
    }


def build_rebind_auth_witness(**kwargs) -> dict:
    """Assemble the linkable ``zkc_credential_rebind_auth`` witness (7.4.2)."""
    kwargs.setdefault("statement_domain", REBIND_AUTH_STATEMENT_DOMAIN)
    witness = _authenticated_rebind_base(**kwargs)
    witness["claim_binding"] = compute_claim_binding_3(
        witness["old_holder_commitment"],
        witness["new_holder_commitment"],
        witness["credential_id"],
        witness["proof_context"],
        witness["timestamp"],
    )
    return witness


def build_rebind_auth_witness_v2(*, scope_id: int, **kwargs) -> dict:
    """Assemble the scoped ``zkc_credential_rebind_auth_v2`` witness (7.4.3).

    Rebind is verifier-facing continuity, so a scoped presentation is required:
    ``scope_id`` must be non-zero (there is no anonymous rebind).
    """
    kwargs.setdefault("statement_domain", REBIND_AUTH_V2_STATEMENT_DOMAIN)
    scope_id = _require_field("scope_id", scope_id)
    if scope_id == 0:
        raise ConstraintViolationError("rebind requires a scoped presentation")
    base = _authenticated_rebind_base(**kwargs)
    old_pseudonym = derive_presentation_pseudonym(base["old_credential_binding_key"], scope_id)
    new_pseudonym = derive_presentation_pseudonym(base["new_credential_binding_key"], scope_id)
    if old_pseudonym == new_pseudonym:
        raise ConstraintViolationError("rebind must change the presentation pseudonym")
    return {
        "old_presentation_pseudonym": old_pseudonym,
        "new_presentation_pseudonym": new_pseudonym,
        "scope_id": scope_id,
        **base,
        "claim_binding": compute_claim_binding_3(
            old_pseudonym,
            new_pseudonym,
            base["credential_id"],
            base["proof_context"],
            base["timestamp"],
        ),
    }


_REBIND_AUTH_SHARED_PUBLIC_INPUT_NAMES = (
    "credential_id",
    "issuer_id_hash",
    "schema_id_hash",
    "proof_context",
    "timestamp",
    "claim_binding",
    "accumulator_root",
    "accumulator_epoch",
    "current_epoch",
    "issuer_public_key_x",
    "issuer_public_key_y",
)
REBIND_AUTH_PUBLIC_INPUT_NAMES = (
    "old_holder_commitment",
    "new_holder_commitment",
) + _REBIND_AUTH_SHARED_PUBLIC_INPUT_NAMES
REBIND_AUTH_V2_PUBLIC_INPUT_NAMES = (
    "old_presentation_pseudonym",
    "new_presentation_pseudonym",
    "scope_id",
) + _REBIND_AUTH_SHARED_PUBLIC_INPUT_NAMES
_REBIND_AUTH_INT_PUBLIC_INPUTS = ("timestamp", "accumulator_epoch", "current_epoch")


def _rebind_auth_public_inputs(witness: dict, names) -> dict:
    output = {}
    for name in names:
        value = witness[name]
        if name in ("issuer_public_key_x", "issuer_public_key_y"):
            output[name] = "0x" + bytes(value).hex()
        elif name in _REBIND_AUTH_INT_PUBLIC_INPUTS:
            output[name] = int(value)
        else:
            output[name] = field_to_hex(value)
    return output


def rebind_auth_public_inputs(witness: dict) -> dict:
    return _rebind_auth_public_inputs(witness, REBIND_AUTH_PUBLIC_INPUT_NAMES)


def rebind_auth_public_inputs_v2(witness: dict) -> dict:
    return _rebind_auth_public_inputs(witness, REBIND_AUTH_V2_PUBLIC_INPUT_NAMES)


def _check_rebind_auth_core(witness: dict, fail) -> None:
    """Mirror of zkc_rebind_auth::assert_authenticated_rebind."""
    if derive_holder_commitment(witness["old_credential_binding_key"]) != witness[
        "old_holder_commitment"
    ]:
        fail("old holder commitment does not match old binding key")
    if derive_holder_commitment(witness["new_credential_binding_key"]) != witness[
        "new_holder_commitment"
    ]:
        fail("new holder commitment does not match new binding key")
    if witness["old_holder_commitment"] == witness["new_holder_commitment"]:
        fail("rebind must change holder commitment")

    digest = compute_rebind_attestation_digest(
        witness["issuer_id_hash"],
        witness["schema_id_hash"],
        witness["old_holder_commitment"],
        witness["credential_id"],
        witness["credential_valid_from"],
        witness["credential_valid_until"],
    )
    if not ecdsa_verify(
        bytes(witness["issuer_public_key_x"]),
        bytes(witness["issuer_public_key_y"]),
        bytes(witness["issuer_signature"]),
        digest_to_message_bytes(digest),
    ):
        fail("invalid issuer signature")

    _check_nonrevocation(witness, fail)

    valid_from = witness["credential_valid_from"]
    valid_until = witness["credential_valid_until"]
    timestamp = witness["timestamp"]
    if not (valid_from <= timestamp and (valid_until == 0 or valid_until >= timestamp)):
        fail("credential is not valid at timestamp")
    if timestamp == 0:
        fail("timestamp must be non-zero")
    if witness["proof_context"] == 0:
        fail("proof context must be non-zero")


def check_rebind_auth_constraints(witness: dict) -> None:
    """Python mirror of every assert in noir/zkc_credential_rebind_auth/src/main.nr."""

    def fail(message: str):
        raise ConstraintViolationError(message)

    if witness.get("statement_domain") != REBIND_AUTH_STATEMENT_DOMAIN:
        fail("statement domain mismatch")
    _check_rebind_auth_core(witness, fail)
    expected = compute_claim_binding_3(
        witness["old_holder_commitment"],
        witness["new_holder_commitment"],
        witness["credential_id"],
        witness["proof_context"],
        witness["timestamp"],
    )
    if expected != witness["claim_binding"]:
        fail("claim binding mismatch")


def check_rebind_auth_v2_constraints(witness: dict) -> None:
    """Python mirror of every assert in noir/zkc_credential_rebind_auth_v2/src/main.nr."""

    def fail(message: str):
        raise ConstraintViolationError(message)

    if witness.get("statement_domain") != REBIND_AUTH_V2_STATEMENT_DOMAIN:
        fail("statement domain mismatch")
    scope_id = int(witness["scope_id"])
    if scope_id == 0:
        fail("rebind requires a scoped presentation")
    _check_rebind_auth_core(witness, fail)

    if witness["old_presentation_pseudonym"] != derive_presentation_pseudonym(
        int(witness["old_credential_binding_key"]), scope_id
    ):
        fail("old presentation pseudonym mismatch")
    if witness["new_presentation_pseudonym"] != derive_presentation_pseudonym(
        int(witness["new_credential_binding_key"]), scope_id
    ):
        fail("new presentation pseudonym mismatch")
    if witness["old_presentation_pseudonym"] == witness["new_presentation_pseudonym"]:
        fail("rebind must change the presentation pseudonym")

    expected = compute_claim_binding_3(
        witness["old_presentation_pseudonym"],
        witness["new_presentation_pseudonym"],
        witness["credential_id"],
        witness["proof_context"],
        witness["timestamp"],
    )
    if expected != witness["claim_binding"]:
        fail("claim binding mismatch")


# --- presentation-profile proof-type resolution ------------------------------

# (predicate family, presentation profile) -> concrete proof type.
#   linkable            -> :v1 (existing circuits, holderBinding envelope)
#   anonymous | scoped  -> :v2 (v2 circuits, presentationBinding envelope)
# Families keep their v1 spelling on the v1 side; v2 spells rebind/aggregate
# without the credential_ prefix (matches the v2 public-input encoders).
_FAMILY_V1_PROOF_TYPE = {
    "kyc": "zkc:proof:kyc:v1",
    "jurisdiction": "zkc:proof:jurisdiction:v1",
    "accreditation": "zkc:proof:accreditation:v1",
    "source": "zkc:proof:source:v1",
    "tax": "zkc:proof:tax:v1",
    "sanctions": "zkc:proof:sanctions:v1",
    "rebind": "zkc:proof:credential_rebind:v1",
    # A separate family is intentional: presentation negotiation for legacy
    # ``rebind`` remains frozen on the v1/v2 pair.
    "rebind_binding_v2": REBIND_BINDING_V2_PROOF_TYPE,
    # The issuer-authenticated successors (spec section 7.4): the only rebind
    # family that resolves to a usable statement.
    "rebind_auth": REBIND_AUTH_PROOF_TYPE,
    "selective_disclosure": "zkc:proof:selective_disclosure:v1",
    # aggregation has no distinct v1 proof-type surface in the holder SDK.
}
_FAMILY_V2_PROOF_TYPE = {
    "kyc": "zkc:proof:kyc:v2",
    "jurisdiction": "zkc:proof:jurisdiction:v2",
    "accreditation": "zkc:proof:accreditation:v2",
    "source": "zkc:proof:source:v2",
    "tax": "zkc:proof:tax:v2",
    "sanctions": "zkc:proof:sanctions:v2",
    "rebind": "zkc:proof:rebind:v2",
    "rebind_binding_v2": REBIND_V2_BINDING_V2_PROOF_TYPE,
    "rebind_auth": REBIND_AUTH_V2_PROOF_TYPE,
    "aggregate": "zkc:proof:aggregate:v2",
    # The first selective-disclosure statement is presentation-native: its
    # proof type is stable while the containing envelope selects anonymous or
    # scoped presentation semantics.
    "selective_disclosure": "zkc:proof:selective_disclosure:v1",
}

# Historical flagRequired-bound remaining-predicate release line. v3 is the
# linkable spelling and v4 its anonymous/scoped sibling. Current default
# generation uses the validFrom-bound v7/v8 line below. Other predicate
# families continue to use the frozen v1/v2 tables above.
_FAMILY_V3_PROOF_TYPE = {
    **_FAMILY_V1_PROOF_TYPE,
    "jurisdiction": JURISDICTION_V3_PROOF_TYPE,
    "accreditation": "zkc:proof:accreditation:v3",
    "source": "zkc:proof:source:v3",
    "tax": "zkc:proof:tax:v3",
    "sanctions": "zkc:proof:sanctions:v3",
}
_FAMILY_V4_PROOF_TYPE = {
    **_FAMILY_V2_PROOF_TYPE,
    "jurisdiction": JURISDICTION_V4_PROOF_TYPE,
    "accreditation": "zkc:proof:accreditation:v4",
    "source": "zkc:proof:source:v4",
    "tax": "zkc:proof:tax:v4",
    "sanctions": "zkc:proof:sanctions:v4",
}
_FAMILY_V5_PROOF_TYPE = {
    "accreditation": "zkc:proof:accreditation:v5",
    "source": "zkc:proof:source:v5",
    "tax": "zkc:proof:tax:v5",
    "sanctions": "zkc:proof:sanctions:v5",
}
_FAMILY_V6_PROOF_TYPE = {
    "accreditation": "zkc:proof:accreditation:v6",
    "source": "zkc:proof:source:v6",
    "tax": "zkc:proof:tax:v6",
    "sanctions": "zkc:proof:sanctions:v6",
}
_FAMILY_V7_PROOF_TYPE = {
    "accreditation": "zkc:proof:accreditation:v7",
    "source": "zkc:proof:source:v7",
    "tax": "zkc:proof:tax:v7",
    "sanctions": "zkc:proof:sanctions:v7",
}
_FAMILY_V8_PROOF_TYPE = {
    "accreditation": "zkc:proof:accreditation:v8",
    "source": "zkc:proof:source:v8",
    "tax": "zkc:proof:tax:v8",
    "sanctions": "zkc:proof:sanctions:v8",
}


# Reverse of _FAMILY_V1_PROOF_TYPE: a v1 proof type back to its predicate
# family, so the holder can resolve the sibling v2 proof type when a
# presentation profile selects the v2 (presentationBinding) path.
_V1_PROOF_TYPE_FAMILY = {v1: family for family, v1 in _FAMILY_V1_PROOF_TYPE.items()}
_V2_PROOF_TYPE_FAMILY = {v2: family for family, v2 in _FAMILY_V2_PROOF_TYPE.items()}
_V3_PROOF_TYPE_FAMILY = {v3: family for family, v3 in _FAMILY_V3_PROOF_TYPE.items()}
_V4_PROOF_TYPE_FAMILY = {v4: family for family, v4 in _FAMILY_V4_PROOF_TYPE.items()}
_V5_PROOF_TYPE_FAMILY = {v5: family for family, v5 in _FAMILY_V5_PROOF_TYPE.items()}
_V6_PROOF_TYPE_FAMILY = {v6: family for family, v6 in _FAMILY_V6_PROOF_TYPE.items()}
_V7_PROOF_TYPE_FAMILY = {v7: family for family, v7 in _FAMILY_V7_PROOF_TYPE.items()}
_V8_PROOF_TYPE_FAMILY = {v8: family for family, v8 in _FAMILY_V8_PROOF_TYPE.items()}


def family_for_v1_proof_type(proof_type: str) -> str:
    """Predicate family for a linkable family spelling.

    v1/v3/v5/v7 remaining-predicate spellings are all linkable request types;
    the function name is retained for compatibility with its original v1 API.
    Raises ``ValueError`` for a proof type with no linkable family surface.
    """
    family = (
        _V1_PROOF_TYPE_FAMILY.get(proof_type)
        or _V2_PROOF_TYPE_FAMILY.get(proof_type)
        or _V3_PROOF_TYPE_FAMILY.get(proof_type)
        or _V4_PROOF_TYPE_FAMILY.get(proof_type)
        or _V5_PROOF_TYPE_FAMILY.get(proof_type)
        or _V6_PROOF_TYPE_FAMILY.get(proof_type)
        or _V7_PROOF_TYPE_FAMILY.get(proof_type)
        or _V8_PROOF_TYPE_FAMILY.get(proof_type)
        or CODE_SPACE_PROOF_TO_KIND.get(proof_type)
    )
    if family is None:
        raise ConstraintViolationError(f"no predicate family for proof type {proof_type!r}")
    return family


def resolve_presentation_proof_type(family: str, presentation_profile: str) -> str:
    """Resolve ``(predicate family, presentation profile)`` to a concrete proof type.

    The current remaining-predicate family resolves to v7 for linkable and v8
    for anonymous/scoped presentation.  Other families retain their frozen
    v1/v2 ladder.  Explicit versioned requests use
    :func:`resolve_requested_presentation_proof_type` and never fall back to a
    different statement generation.
    """
    from zkc_crypto.presentation import (
        ANONYMOUS_PROFILE,
        LINKABLE_PROFILE,
        SCOPED_PROFILE,
    )

    if family == "rebind_auth" and presentation_profile == ANONYMOUS_PROFILE:
        # Rebind is verifier-facing continuity: there is no anonymous rebind
        # presentation, so this refuses rather than resolving to a statement
        # whose scope constraint would fail at proving time.
        raise ConstraintViolationError("rebind requires a scoped presentation")

    if family in _UNAUTHENTICATED_REBIND_FAMILIES:
        # Security containment: every published rebind identity is
        # unauthenticated, so there is no safe statement to resolve to and no
        # presentation profile may downgrade into one.
        for table in (_FAMILY_V1_PROOF_TYPE, _FAMILY_V2_PROOF_TYPE):
            if family in table:
                refuse_unauthenticated_rebind(table[family])
        raise ConstraintViolationError(f"no authenticated proof type for family {family!r}")

    if family == "jurisdiction":
        if presentation_profile == LINKABLE_PROFILE:
            table = _FAMILY_V3_PROOF_TYPE
        elif presentation_profile in (ANONYMOUS_PROFILE, SCOPED_PROFILE):
            table = _FAMILY_V4_PROOF_TYPE
        else:
            raise ConstraintViolationError(
                f"unknown presentation profile: {presentation_profile!r}"
            )
    elif family in _FAMILY_V7_PROOF_TYPE:
        if presentation_profile == LINKABLE_PROFILE:
            table = _FAMILY_V7_PROOF_TYPE
        elif presentation_profile in (ANONYMOUS_PROFILE, SCOPED_PROFILE):
            table = _FAMILY_V8_PROOF_TYPE
        else:
            raise ConstraintViolationError(
                f"unknown presentation profile: {presentation_profile!r}"
            )
    elif presentation_profile == LINKABLE_PROFILE:
        table = _FAMILY_V1_PROOF_TYPE
    elif presentation_profile in (ANONYMOUS_PROFILE, SCOPED_PROFILE):
        table = _FAMILY_V2_PROOF_TYPE
    else:
        raise ConstraintViolationError(f"unknown presentation profile: {presentation_profile!r}")

    proof_type = table.get(family)
    if proof_type is None:
        raise ConstraintViolationError(
            f"no {presentation_profile} proof type for predicate family {family!r}"
        )
    return proof_type


def resolve_presentation_proof_type_for_request(
    requested_proof_type: str, presentation_profile: str
) -> str:
    """Resolve a request identity to the current safe statement generation."""
    from zkc_crypto.presentation import (
        ANONYMOUS_PROFILE,
        LINKABLE_PROFILE,
        SCOPED_PROFILE,
    )

    refuse_unauthenticated_rebind(requested_proof_type)
    if requested_proof_type in NONZERO_CREDENTIAL_PROOF_PREDECESSORS:
        profiles = (ANONYMOUS_PROFILE, SCOPED_PROFILE)
        if requested_proof_type in NONZERO_LINKABLE_PROOF_PREDECESSORS:
            profiles = (LINKABLE_PROFILE,)
        elif requested_proof_type == "zkc:proof:rebind:v6":
            profiles = (SCOPED_PROFILE,)
        if presentation_profile not in profiles:
            raise ConstraintViolationError(
                f"proof type {requested_proof_type!r} does not support "
                f"presentation profile {presentation_profile!r}"
            )
        return requested_proof_type
    if requested_proof_type in CODE_SPACE_PROOF_TO_KIND:
        if presentation_profile not in (ANONYMOUS_PROFILE, SCOPED_PROFILE):
            raise ConstraintViolationError(f"proof type {requested_proof_type} requires a v2 presentation")
        return requested_proof_type
    exact_profiles = {
        "zkc:proof:community_kyc:v2": (LINKABLE_PROFILE,),
        "zkc:proof:kyc:v3": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        JURISDICTION_V5_PROOF_TYPE: (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "zkc:proof:accreditation:v9": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "zkc:proof:accreditation:v10": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "zkc:proof:source:v9": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "zkc:proof:source:v10": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "zkc:proof:tax:v9": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "zkc:proof:tax:v10": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "zkc:proof:sanctions:v9": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "zkc:proof:sanctions:v10": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        REBIND_AUTH_V3_PROOF_TYPE: (SCOPED_PROFILE,),
        "zkc:proof:selective_disclosure:v2": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
        "zkc:proof:selective_disclosure:v3": (ANONYMOUS_PROFILE, SCOPED_PROFILE),
    }
    if requested_proof_type in exact_profiles:
        if presentation_profile not in exact_profiles[requested_proof_type]:
            raise ConstraintViolationError(
                f"proof type {requested_proof_type!r} does not support "
                f"presentation profile {presentation_profile!r}"
            )
        return requested_proof_type
    family = family_for_v1_proof_type(requested_proof_type)
    return resolve_presentation_proof_type(family, presentation_profile)


def request_contract_proof_types(requested_proof_type: str, presentation_profiles) -> tuple:
    """Identities whose closed request-parameter set governs a request.

    A request names a proof type the holder may answer under another
    identity (``source:v1`` is answered as ``source:v7`` or ``:v8``). The
    verifier enforces the EMITTED identity's vocabulary, so the holder checks
    the request against every identity it could emit under the given
    presentation profiles. A request identity that resolves under none of
    them governs itself; the generation path then refuses it on its own.
    """
    resolved = []
    for profile in presentation_profiles:
        try:
            resolved.append(resolve_presentation_proof_type_for_request(requested_proof_type, profile))
        except (HolderError, KeyError, TypeError, ValueError):
            continue
    return tuple(dict.fromkeys(resolved)) or (requested_proof_type,)


def legacy_presentation_proof_type_for_verification(
    proof_type: str, presentation_profile: str
) -> str | None:
    """Return only an exact, APR-authorized historical profile identity."""
    from zkc_crypto.presentation import (
        ANONYMOUS_PROFILE,
        LINKABLE_PROFILE,
        SCOPED_PROFILE,
    )

    if presentation_profile == LINKABLE_PROFILE:
        maps = (_V1_PROOF_TYPE_FAMILY, _V3_PROOF_TYPE_FAMILY, _V5_PROOF_TYPE_FAMILY)
    elif presentation_profile in (ANONYMOUS_PROFILE, SCOPED_PROFILE):
        maps = (_V2_PROOF_TYPE_FAMILY, _V4_PROOF_TYPE_FAMILY, _V6_PROOF_TYPE_FAMILY)
    else:
        return None
    for mapping in maps:
        family = mapping.get(proof_type)
        if family in {"accreditation", "source", "tax", "sanctions"}:
            return proof_type
        if family == "jurisdiction" and mapping in (_V1_PROOF_TYPE_FAMILY, _V2_PROOF_TYPE_FAMILY):
            return proof_type
    return None


def resolve_requested_presentation_proof_type(
    requested_proof_type: str, presentation_profile: str
) -> str:
    """Compatibility spelling for current request resolution."""
    return resolve_presentation_proof_type_for_request(requested_proof_type, presentation_profile)


def check_rebind_constraints(witness: dict) -> None:
    """Python mirror of every assert in noir/zkc_credential_rebind/src/main.nr."""

    def fail(message: str):
        raise ConstraintViolationError(message)

    if (
        derive_holder_commitment(witness["old_credential_binding_key"])
        != witness["old_holder_commitment"]
    ):
        fail("old holder commitment does not match old binding key")
    if (
        derive_holder_commitment(witness["new_credential_binding_key"])
        != witness["new_holder_commitment"]
    ):
        fail("new holder commitment does not match new binding key")
    if witness["old_holder_commitment"] == witness["new_holder_commitment"]:
        fail("rebind must change holder commitment")
    if witness["credential_holder_commitment"] != witness["old_holder_commitment"]:
        fail("credential is not currently bound to the old holder commitment")
    if witness["credential_issuer_id_hash"] != witness["issuer_id_hash"]:
        fail("issuer mismatch")
    if witness["credential_schema_id_hash"] != witness["schema_id_hash"]:
        fail("schema mismatch")

    valid_from = witness["credential_valid_from"]
    valid_until = witness["credential_valid_until"]
    timestamp = witness["timestamp"]
    if not (valid_from <= timestamp and (valid_until == 0 or valid_until >= timestamp)):
        fail("credential is not valid at timestamp")
    if witness["proof_context"] == 0:
        fail("proof context must be non-zero")

    expected_claim_binding = compute_claim_binding_3(
        witness["old_holder_commitment"],
        witness["new_holder_commitment"],
        witness["credential_id"],
        witness["proof_context"],
        witness["timestamp"],
    )
    if expected_claim_binding != witness["claim_binding"]:
        fail("claim binding mismatch")


def check_rebind_binding_v2_constraints(witness: dict) -> None:
    """Successor mirror: exact private proof-type domain plus frozen semantics."""
    if witness.get("statement_domain") != REBIND_BINDING_V2_STATEMENT_DOMAIN:
        raise ConstraintViolationError("statement domain mismatch")
    check_rebind_constraints(witness)


def check_rebind_constraints_v2(witness: dict) -> None:
    """Python mirror of every assert in noir/zkc_credential_rebind_v2/src/main.nr.

    Rebind is verifier-facing continuity: scope_id must be non-zero (no
    anonymous rebind). The v1 holder-commitment derivations hold over the now
    private commitments; both pseudonyms derive in the SAME scope; the two
    pseudonyms differ; and claim_binding v2 commits to the PSEUDONYMS (§4.2).
    """

    def fail(message: str):
        raise ConstraintViolationError(message)

    scope_id = int(witness["scope_id"])
    if scope_id == 0:
        fail("rebind requires a scoped presentation")

    if (
        derive_holder_commitment(witness["old_credential_binding_key"])
        != witness["old_holder_commitment"]
    ):
        fail("old holder commitment does not match old binding key")
    if (
        derive_holder_commitment(witness["new_credential_binding_key"])
        != witness["new_holder_commitment"]
    ):
        fail("new holder commitment does not match new binding key")
    if witness["old_holder_commitment"] == witness["new_holder_commitment"]:
        fail("rebind must change holder commitment")
    if witness["credential_holder_commitment"] != witness["old_holder_commitment"]:
        fail("credential is not currently bound to the old holder commitment")

    old_expected = derive_presentation_pseudonym(
        int(witness["old_credential_binding_key"]), scope_id
    )
    if witness["old_presentation_pseudonym"] != old_expected:
        fail("old presentation pseudonym mismatch")
    new_expected = derive_presentation_pseudonym(
        int(witness["new_credential_binding_key"]), scope_id
    )
    if witness["new_presentation_pseudonym"] != new_expected:
        fail("new presentation pseudonym mismatch")
    if witness["old_presentation_pseudonym"] == witness["new_presentation_pseudonym"]:
        fail("rebind must change the presentation pseudonym")

    if witness["credential_issuer_id_hash"] != witness["issuer_id_hash"]:
        fail("issuer mismatch")
    if witness["credential_schema_id_hash"] != witness["schema_id_hash"]:
        fail("schema mismatch")

    valid_from = witness["credential_valid_from"]
    valid_until = witness["credential_valid_until"]
    timestamp = witness["timestamp"]
    if not (valid_from <= timestamp and (valid_until == 0 or valid_until >= timestamp)):
        fail("credential is not valid at timestamp")
    if witness["proof_context"] == 0:
        fail("proof context must be non-zero")

    expected_claim_binding = compute_claim_binding_3(
        witness["old_presentation_pseudonym"],
        witness["new_presentation_pseudonym"],
        witness["credential_id"],
        witness["proof_context"],
        witness["timestamp"],
    )
    if expected_claim_binding != witness["claim_binding"]:
        fail("claim binding mismatch")


def check_rebind_v2_binding_v2_constraints(witness: dict) -> None:
    """Scoped successor mirror with its exact private proof-type domain."""
    if witness.get("statement_domain") != REBIND_V2_BINDING_V2_STATEMENT_DOMAIN:
        raise ConstraintViolationError("statement domain mismatch")
    check_rebind_constraints_v2(witness)
