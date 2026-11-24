#!/usr/bin/env python3
"""Validate checked-in ZKC test vectors against source and spec pins."""

from __future__ import annotations

import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTOR_PATH = ROOT / "tests" / "vectors" / "zkc_core_vectors.json"
MASTER_SEED_VECTOR_PATH = ROOT / "tests" / "vectors" / "kdc_master_seed_v1.json"
REVOCATION_VECTOR_PATH = ROOT / "tests" / "vectors" / "revocation_equivocation_v1.json"
ZKC_LIB = ROOT / "noir" / "zkc_lib" / "src" / "lib.nr"
SPEC = ROOT / "docs" / "zkc_specification.md"

sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "conformance"))


def load_vectors() -> dict:
    return json.loads(VECTOR_PATH.read_text())


def assert_hex32(name: str, value: str) -> None:
    if not re.fullmatch(r"0x[0-9a-f]{64}", value):
        raise AssertionError(f"{name} is not a 32-byte lowercase hex field: {value}")


def walk_hex(prefix: str, value) -> list[tuple[str, str]]:
    if isinstance(value, dict):
        found: list[tuple[str, str]] = []
        for key, child in value.items():
            found.extend(walk_hex(f"{prefix}.{key}" if prefix else key, child))
        return found
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-f]{64}", value):
        return [(prefix, value)]
    return []


def main() -> int:
    from revocation_vectors import validate_vector_document
    from zkc_crypto import compute_claim_binding_4, compute_profile_digest_v2, field_to_hex

    vectors = load_vectors()
    master_seed_vectors = json.loads(MASTER_SEED_VECTOR_PATH.read_text())
    revocation_vectors = json.loads(REVOCATION_VECTOR_PATH.read_text())
    zkc_lib = ZKC_LIB.read_text()
    spec = SPEC.read_text()

    for name, value in walk_hex("", vectors):
        assert_hex32(name, value)
    for name, value in walk_hex("master_seed", master_seed_vectors):
        assert_hex32(name, value)

    required_source_values = [
        *vectors["domains"].values(),
        *vectors["poseidon2_kats"].values(),
        vectors["kdc_a6_seed_42"]["credential_binding_key"],
        vectors["kdc_a6_seed_42"]["holder_commitment"],
        vectors["claim_binding_examples"]["compute_claim_binding_2_1_31_777_12345"],
    ]
    for value in required_source_values:
        if value not in zkc_lib:
            raise AssertionError(f"{value} is missing from noir/zkc_lib/src/lib.nr")

    successor_sources = [
        (ROOT / "noir" / "zkc_remaining_predicates_v3" / "src" / "main.nr").read_text(),
        (ROOT / "noir" / "zkc_remaining_predicates_v4" / "src" / "main.nr").read_text(),
        (ROOT / "noir" / "zkc_remaining_predicates_v5" / "src" / "main.nr").read_text(),
        (ROOT / "noir" / "zkc_remaining_predicates_v6" / "src" / "main.nr").read_text(),
        (ROOT / "noir" / "zkc_remaining_predicates_v7" / "src" / "main.nr").read_text(),
        (ROOT / "noir" / "zkc_remaining_predicates_v8" / "src" / "main.nr").read_text(),
    ]
    for key in (
        "compute_claim_binding_4_1_2_0_false_777_12345",
        "compute_claim_binding_4_1_2_0_true_777_12345",
    ):
        value = vectors["claim_binding_examples"][key]
        for source in successor_sources:
            if value not in source:
                raise AssertionError(f"{value} is missing from a successor circuit KAT")

    profile_digest = vectors["profile_digest_v2"]
    actual_profile_digest = field_to_hex(
        compute_profile_digest_v2(
            int(profile_digest["holder_commitment"], 16),
            int(profile_digest["credential_id"], 16),
            profile_digest["predicate_type"],
            int(profile_digest["claim_0"], 16),
            int(profile_digest["claim_1"], 16),
            profile_digest["valid_from"],
            profile_digest["valid_until"],
        )
    )
    if actual_profile_digest != profile_digest["digest"]:
        raise AssertionError("profile digest v2 KAT mismatch")
    for source in successor_sources[-2:]:
        if profile_digest["digest"] not in source:
            raise AssertionError("profile digest v2 KAT is missing from a current circuit")

    rebind_source = (ROOT / "noir" / "zkc_credential_rebind" / "src" / "main.nr").read_text()
    for value in vectors["credential_rebind_seed_42_to_99"].values():
        if value not in rebind_source:
            raise AssertionError(f"{value} is missing from zkc_credential_rebind KATs")

    if "tests/vectors/zkc_core_vectors.json" not in spec:
        raise AssertionError("spec section 9.2 must reference tests/vectors/zkc_core_vectors.json")

    _validate_purpose_bound_kats(vectors["purpose_bound_context_v1"])

    _validate_presentation_profiles(vectors["presentation_profiles"], zkc_lib)

    _validate_selective_disclosure(vectors["selective_disclosure_v1"])
    _validate_layout_bound_disclosure()

    _validate_rebind_attestation(vectors["credential_rebind_attestation_v1"], spec)

    _validate_master_seed_vectors(master_seed_vectors, zkc_lib, spec)

    validate_vector_document(revocation_vectors)

    for flag, key in (
        (False, "compute_claim_binding_4_1_2_0_false_777_12345"),
        (True, "compute_claim_binding_4_1_2_0_true_777_12345"),
    ):
        actual = field_to_hex(compute_claim_binding_4(1, 2, 0, flag, 777, 12345))
        expected = vectors["claim_binding_examples"][key]
        if actual != expected:
            raise AssertionError(
                f"claim binding 4 flag={flag} mismatch: {actual} != {expected}"
            )

    print(
        f"validated {VECTOR_PATH.relative_to(ROOT)} and "
        f"{MASTER_SEED_VECTOR_PATH.relative_to(ROOT)}, and "
        f"{REVOCATION_VECTOR_PATH.relative_to(ROOT)} against zkc_lib and spec"
    )
    return 0


def _validate_master_seed_vectors(section: dict, zkc_lib: str, spec: str) -> None:
    from zkc_crypto import (
        FIELD_MODULUS,
        MASTER_SEED_PROFILE,
        derive_credential_binding_key,
        derive_holder_commitment_from_seed,
        field_to_hex,
        master_seed_to_field,
    )

    if section["profile"] != MASTER_SEED_PROFILE:
        raise AssertionError("master-seed profile does not match the Python reference")
    if int(section["fieldModulus"], 16) != FIELD_MODULUS:
        raise AssertionError("master-seed vector field modulus mismatch")
    if section["byteLength"] != 32 or section["byteOrder"] != "big":
        raise AssertionError("master-seed byte encoding must be fixed 32-byte big-endian")
    if section["fieldMapping"] != "unsigned-big-endian-mod-r":
        raise AssertionError("master-seed field mapping profile mismatch")

    by_name = {case["name"]: case for case in section["cases"]}
    required_names = {"zero", "one", "r_minus_1", "r", "r_plus_1", "high_bit", "asymmetric"}
    if set(by_name) != required_names:
        raise AssertionError("master-seed vectors must contain the normative boundary cases")

    for case in section["cases"]:
        seed = bytes.fromhex(case["seed"][2:])
        expected = {
            "kdcInput": field_to_hex(master_seed_to_field(seed)),
            "credentialBindingKey": field_to_hex(derive_credential_binding_key(seed)),
            "holderCommitment": field_to_hex(derive_holder_commitment_from_seed(seed)),
        }
        for key, computed in expected.items():
            if case[key] != computed:
                raise AssertionError(
                    f"master-seed {case['name']} {key} mismatch: {case[key]} != {computed}"
                )
        alias_of = case.get("kdcAliasOf")
        if alias_of and case["kdcInput"] != by_name[alias_of]["kdcInput"]:
            raise AssertionError(f"master-seed alias {case['name']} does not map to {alias_of}")

    for value in {
        case[key]
        for case in section["cases"]
        for key in ("credentialBindingKey", "holderCommitment")
    }:
        if value not in zkc_lib:
            raise AssertionError(f"master-seed KAT {value} is missing from noir/zkc_lib")
    if "tests/vectors/kdc_master_seed_v1.json" not in spec:
        raise AssertionError("spec must reference the normative master-seed vector set")


def _validate_selective_disclosure(section: dict) -> None:
    from zkc_crypto import (
        DOMAIN_ZKC_CLAIM,
        compute_selective_disclosure_binding,
        compute_selective_disclosure_credential_digest,
        field_to_hex,
        hex_to_field,
    )
    from zkc_crypto.digests import (
        SELECTIVE_DISCLOSURE_CREDENTIAL_TYPE,
        SELECTIVE_DISCLOSURE_TRANSCRIPT_TYPE,
    )

    inputs = section["inputs"]
    expected = {
        "registered_domain": field_to_hex(DOMAIN_ZKC_CLAIM),
        "credential_type_field": field_to_hex(SELECTIVE_DISCLOSURE_CREDENTIAL_TYPE),
        "transcript_type_field": field_to_hex(SELECTIVE_DISCLOSURE_TRANSCRIPT_TYPE),
        "credential_digest": field_to_hex(
            compute_selective_disclosure_credential_digest(
                hex_to_field(inputs["holder_commitment"]),
                hex_to_field(inputs["credential_id"]),
                inputs["credential_attribute_count"],
                inputs["credential_attributes"],
                inputs["credential_expires_at"],
            )
        ),
        "claim_binding": field_to_hex(
            compute_selective_disclosure_binding(
                inputs["credential_attribute_count"],
                inputs["disclosed_flags"],
                inputs["disclosed_attributes"],
                hex_to_field(inputs["proof_context"]),
                inputs["timestamp"],
            )
        ),
    }
    for key, value in expected.items():
        if section[key] != value:
            raise AssertionError(
                f"selective_disclosure_v1.{key} KAT mismatch: "
                f"vector {section[key]} != recomputed {value}"
            )
    source = (
        ROOT / "noir" / "zkc_selective_disclosure_v1" / "src" / "main.nr"
    ).read_text()
    for key in ("credential_type_field", "transcript_type_field", "claim_binding"):
        if section[key] not in source:
            raise AssertionError(
                f"selective_disclosure_v1.{key} is missing from the Noir KAT/source"
            )


def _validate_layout_bound_disclosure() -> None:
    from zkc_crypto import (
        compute_selective_disclosure_binding_v3,
        compute_selective_disclosure_credential_digest_v2,
        field_to_hex,
        hex_to_field,
        parse_attribute_layout_id,
    )

    vector_path = ROOT / "tests/vectors/selective_disclosure_v3.json"
    circuit_path = ROOT / "noir/zkc_selective_disclosure_v3/src/main.nr"
    if not vector_path.exists() and not circuit_path.exists():
        return  # The draft successor is excluded from the public snapshot.
    vector = json.loads(vector_path.read_text())
    inputs = vector["inputs"]
    layout = parse_attribute_layout_id(inputs["layout_id"])
    expected = {
        "credential_digest": field_to_hex(compute_selective_disclosure_credential_digest_v2(
            hex_to_field(inputs["holder_commitment"]), hex_to_field(inputs["credential_id"]),
            layout, inputs["credential_attribute_count"], inputs["credential_attributes"],
            inputs["credential_expires_at"],
        )),
        "claim_binding": field_to_hex(compute_selective_disclosure_binding_v3(
            layout, inputs["credential_attribute_count"], inputs["disclosed_flags"],
            inputs["disclosed_attributes"], hex_to_field(inputs["proof_context"]),
            inputs["timestamp"],
        )),
    }
    circuit = circuit_path.read_text()
    for key, actual in expected.items():
        if actual != vector[key] or actual not in circuit:
            raise AssertionError(f"selective_disclosure_v3.{key} differs between Python, Noir and the vector")


def _validate_rebind_attestation(section: dict, spec: str) -> None:
    """Recompute the issuer-authenticated rebind transcript KATs (spec section
    7.4 / ADR 0004) from the Python reference, verify the pinned TEST-ONLY
    issuer signature over the digest, and recompute both successor claim
    bindings and statement domains. The Noir cross-pin of these values lives
    with the successor circuit packages once published."""
    from zkc_crypto import (
        compute_claim_binding_3,
        derive_credential_binding_key,
        derive_holder_commitment,
        derive_presentation_pseudonym,
        digest_to_message_bytes,
        field_to_hex,
        hex_to_field,
        string_to_field,
    )
    from zkc_crypto.digests import (
        REBIND_ATTESTATION_TYPE,
        REBIND_ATTESTATION_VERSION,
        compute_rebind_attestation_digest,
    )
    from zkc_crypto.ecdsa_secp256k1 import verify

    inputs = section["inputs"]
    old_cbk = derive_credential_binding_key(inputs["master_seed"])
    new_cbk = derive_credential_binding_key(inputs["new_master_seed"])
    holder = derive_holder_commitment(old_cbk)
    new_holder = derive_holder_commitment(new_cbk)
    issuer_id_hash = string_to_field(inputs["issuer_id"])
    schema_id_hash = string_to_field(inputs["schema_id"])
    credential_id = hex_to_field(inputs["credential_id"])
    digest = compute_rebind_attestation_digest(
        issuer_id_hash,
        schema_id_hash,
        holder,
        credential_id,
        inputs["valid_from"],
        inputs["valid_until"],
    )
    context = hex_to_field(inputs["proof_context"])
    scope_id = hex_to_field(inputs["scope_id"])
    old_pseudonym = derive_presentation_pseudonym(old_cbk, scope_id)
    new_pseudonym = derive_presentation_pseudonym(new_cbk, scope_id)
    expected = {
        "attestation_version": REBIND_ATTESTATION_VERSION,
        "attestation_type_field": field_to_hex(REBIND_ATTESTATION_TYPE),
        "issuer_id_hash": field_to_hex(issuer_id_hash),
        "schema_id_hash": field_to_hex(schema_id_hash),
        "holder_commitment": field_to_hex(holder),
        "new_holder_commitment": field_to_hex(new_holder),
        "digest": field_to_hex(digest),
        "linkable_statement_domain": field_to_hex(string_to_field(section["linkable_proof_type"])),
        "linkable_claim_binding": field_to_hex(
            compute_claim_binding_3(holder, new_holder, credential_id, context, inputs["timestamp"])
        ),
        "scoped_statement_domain": field_to_hex(string_to_field(section["scoped_proof_type"])),
        "old_presentation_pseudonym": field_to_hex(old_pseudonym),
        "new_presentation_pseudonym": field_to_hex(new_pseudonym),
        "scoped_claim_binding": field_to_hex(
            compute_claim_binding_3(
                old_pseudonym, new_pseudonym, credential_id, context, inputs["timestamp"]
            )
        ),
    }
    for key, value in expected.items():
        if section[key] != value:
            raise AssertionError(
                f"credential_rebind_attestation_v1.{key} KAT mismatch: "
                f"vector {section[key]} != recomputed {value}"
            )
    if section["linkable_proof_type"] == section["scoped_proof_type"]:
        raise AssertionError("successor proof types must be distinct identities")
    if not verify(
        bytes.fromhex(section["issuer_public_key_x"][2:]),
        bytes.fromhex(section["issuer_public_key_y"][2:]),
        bytes.fromhex(section["issuer_signature"][2:]),
        digest_to_message_bytes(digest),
    ):
        raise AssertionError("credential_rebind_attestation_v1 issuer signature does not verify")
    if "zkc:attestation:credential-rebind:v1" not in spec:
        raise AssertionError("spec must define the zkc:attestation:credential-rebind:v1 transcript")


def _validate_purpose_bound_kats(section: dict) -> None:
    """Recompute the purpose-bound KATs (spec §2.2) from the reference crypto
    and assert byte-for-byte. These are off-circuit (the purpose folds into the
    existing proof_context public input), so they are NOT pinned in zkc_lib.nr;
    this recomputation is their golden-vector check."""
    from zkc_crypto import (  # local import: validator runs without the package on path otherwise
        DOMAIN_ZKC_CONTEXT,
        DOMAIN_ZKC_PURPOSE,
        ProofContext,
        field_to_hex,
        hex_to_field,
        purpose_tag,
    )

    inputs = section["inputs"]
    context = ProofContext.purpose_bound(
        inputs["verifierId"],
        hex_to_field(inputs["sessionId"]),
        inputs["canonicalPurpose"],
        int(inputs["timestamp"]),
    )
    expected = {
        "domain_zkc_purpose": field_to_hex(DOMAIN_ZKC_PURPOSE),
        "domain_zkc_context": field_to_hex(DOMAIN_ZKC_CONTEXT),
        "purpose_tag": field_to_hex(purpose_tag(inputs["canonicalPurpose"])),
        "context_value": field_to_hex(context.value),
    }
    for key, value in expected.items():
        if section[key] != value:
            raise AssertionError(
                f"purpose_bound_context_v1.{key} KAT mismatch: "
                f"vector {section[key]} != recomputed {value}"
            )
    if inputs["profile"] != context.profile:
        raise AssertionError("purpose_bound_context_v1.inputs.profile mismatch")


def _parse_noir_field_constant(name: str, source: str) -> str:
    """Return the 0x-hex literal assigned to `pub global <name>: Field = 0x…;`.

    Follows the declaration style of the domain constants in zkc_lib/src/lib.nr,
    tolerating the line break the formatter puts between `=` and the literal."""
    match = re.search(
        rf"pub global {re.escape(name)}: Field\s*=\s*(0x[0-9a-fA-F]+)\s*;",
        source,
    )
    if match is None:
        raise AssertionError(f"{name} not found as a pub global in noir/zkc_lib/src/lib.nr")
    return match.group(1).lower()


def _validate_presentation_profiles(section: dict, zkc_lib: str) -> None:
    """Recompute the presentation-profile KATs (design §2 / §8) from the Python
    reference and cross-check the pinned Noir constant.

    presentation_pseudonym is the only in-circuit derivation, so its domain
    (DOMAIN_ZKC_PRESENTATION_SCOPE) is pinned in zkc_lib.nr and parsed back out
    here; verifier_identity and scope_id are native-only, so they are checked by
    recomputation alone (as with the purpose-bound KATs above)."""
    from zkc_crypto import field_to_hex, hex_to_field  # noqa: F401
    from zkc_crypto.kdc import derive_credential_binding_key
    from zkc_crypto.presentation import (
        DOMAIN_ZKC_PRESENTATION_SCOPE,
        DOMAIN_ZKC_SCOPE,
        DOMAIN_ZKC_VERIFIER_ID,
        derive_presentation_pseudonym,
        derive_scope_id,
        derive_verifier_identity,
    )

    domains = section["domains"]
    expected_domains = {
        "zkc_presentation_scope": field_to_hex(DOMAIN_ZKC_PRESENTATION_SCOPE),
        "zkc_scope": field_to_hex(DOMAIN_ZKC_SCOPE),
        "zkc_verifier_id": field_to_hex(DOMAIN_ZKC_VERIFIER_ID),
    }
    for key, value in expected_domains.items():
        if domains[key] != value:
            raise AssertionError(
                f"presentation_profiles.domains.{key} KAT mismatch: "
                f"vector {domains[key]} != recomputed {value}"
            )

    # Cross-check the pinned Noir constant against the JSON domain (the only
    # presentation domain that is proven in-circuit).
    noir_scope_domain = _parse_noir_field_constant("DOMAIN_ZKC_PRESENTATION_SCOPE", zkc_lib)
    if noir_scope_domain != domains["zkc_presentation_scope"]:
        raise AssertionError(
            "DOMAIN_ZKC_PRESENTATION_SCOPE mismatch: "
            f"zkc_lib.nr {noir_scope_domain} != vector {domains['zkc_presentation_scope']}"
        )

    scoped = section["scoped_seed_42"]
    pubkey = bytes.fromhex(scoped["verifier_pubkey_sec1"].removeprefix("0x"))
    cbk = derive_credential_binding_key(0x2A)
    vid = derive_verifier_identity(pubkey)
    sid = derive_scope_id(vid, scoped["scope_policy"], scoped["rotation_epoch"])
    pseudonym = derive_presentation_pseudonym(cbk, sid)
    expected_scoped = {
        "verifier_identity": field_to_hex(vid),
        "scope_id": field_to_hex(sid),
        "presentation_pseudonym": field_to_hex(pseudonym),
    }
    for key, value in expected_scoped.items():
        if scoped[key] != value:
            raise AssertionError(
                f"presentation_profiles.scoped_seed_42.{key} KAT mismatch: "
                f"vector {scoped[key]} != recomputed {value}"
            )


if __name__ == "__main__":
    sys.exit(main())
