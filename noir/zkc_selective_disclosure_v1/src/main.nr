// =============================================================================
// ZKC issuer-authoritative selective disclosure v1
//
// The issuer signs a fixed eight-slot attribute credential. The proof exposes
// an explicit flag and value for every position, the credential's active slot
// count, and the disclosure count. A disclosed zero is therefore (true, 0),
// while a hidden slot is canonically (false, 0). Holder identity remains
// private under anonymous/scoped zkc:proof:v2 presentation envelopes.
// =============================================================================

use zkc_issuer_sig::{assert_issuer_signature, ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1};
use zkc_lib::{
    assert_presentation_binding, derive_holder_commitment, DOMAIN_ZKC_CLAIM, poseidon3, poseidon4,
};
use zkc_nonrevocation::{assert_nonrevocation, NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2};

pub global SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES: u32 = 8;
// string_to_field("zkc:cred:attribute-set:v1")
pub global SELECTIVE_DISCLOSURE_CREDENTIAL_TYPE: Field =
    0x01b0dd23c6a0f5754a8d19e2e3d8c292388f0e201e5fc5516a65727d507154ec;
// string_to_field("zkc:proof:selective_disclosure:v1")
pub global SELECTIVE_DISCLOSURE_TRANSCRIPT_TYPE: Field =
    0x165a29b8f7c035a2c39ed869e761a3aea32763e512b4918b8b3856a7fe427a08;

fn bool_to_field(value: bool) -> Field {
    if value {
        1
    } else {
        0
    }
}

pub fn compute_selective_disclosure_credential_digest(
    holder_commitment: Field,
    credential_id: Field,
    credential_attribute_count: u8,
    credential_attributes: [Field; 8],
    credential_expires_at: u64,
) -> Field {
    let mut acc = poseidon4(
        DOMAIN_ZKC_CLAIM,
        SELECTIVE_DISCLOSURE_CREDENTIAL_TYPE,
        credential_attribute_count as Field,
        holder_commitment,
    );
    for i in 0..SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES {
        acc = poseidon3(acc, i as Field, credential_attributes[i]);
    }
    poseidon3(acc, credential_id, credential_expires_at as Field)
}

pub fn compute_selective_disclosure_binding(
    credential_attribute_count: u8,
    disclosed_flags: [bool; 8],
    disclosed_attributes: [Field; 8],
    proof_context: Field,
    timestamp: u64,
) -> Field {
    let mut disclosure_count: u8 = 0;
    for i in 0..SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES {
        if disclosed_flags[i] {
            disclosure_count += 1;
        }
    }
    let mut acc = poseidon4(
        DOMAIN_ZKC_CLAIM,
        SELECTIVE_DISCLOSURE_TRANSCRIPT_TYPE,
        credential_attribute_count as Field,
        disclosure_count as Field,
    );
    for i in 0..SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES {
        acc = poseidon4(
            acc,
            i as Field,
            bool_to_field(disclosed_flags[i]),
            disclosed_attributes[i],
        );
    }
    poseidon3(acc, proof_context, timestamp as Field)
}

fn credential_not_expired(credential_expires_at: u64, timestamp: u64) -> bool {
    (credential_expires_at == 0) | (credential_expires_at > timestamp)
}

fn main(
    // === Public statement / presentation ===
    presentation_pseudonym: pub Field,
    scope_id: pub Field,
    claim_binding: pub Field,
    proof_context: pub Field,
    accumulator_root: pub Field,
    accumulator_epoch: pub u64,
    timestamp: pub u64,
    current_epoch: pub u64,
    issuer_public_key_x: pub [u8; 32],
    issuer_public_key_y: pub [u8; 32],
    credential_attribute_count: pub u8,
    disclosure_count: pub u8,
    disclosed_flags: pub [bool; 8],
    disclosed_attributes: pub [Field; 8],
    // === Private holder / issuer-authoritative credential ===
    holder_commitment: Field,
    credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_id: Field,
    credential_attributes: [Field; 8],
    credential_expires_at: u64,
    issuer_signature: [u8; 64],
    // === Private non-revocation witness ===
    nonrevocation_siblings: [Field; 32],
    nonrevocation_path_index: Field,
) {
    assert(
        derive_holder_commitment(credential_binding_key) == holder_commitment,
        "holder commitment does not match credential binding key",
    );
    assert(
        credential_holder_commitment == holder_commitment,
        "credential holder commitment does not match presentation holder",
    );
    assert_presentation_binding(presentation_pseudonym, scope_id, credential_binding_key);

    assert(
        credential_attribute_count > 0
            & (credential_attribute_count as u32) <= SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES,
        "credential attribute count must be between 1 and 8",
    );
    for i in 0..SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES {
        if (i as u8) >= credential_attribute_count {
            assert(credential_attributes[i] == 0, "credential padding attribute must be zero");
        }
    }

    let credential_digest = compute_selective_disclosure_credential_digest(
        credential_holder_commitment,
        credential_id,
        credential_attribute_count,
        credential_attributes,
        credential_expires_at,
    );
    assert_issuer_signature(
        ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1,
        issuer_public_key_x,
        issuer_public_key_y,
        issuer_signature,
        credential_digest.to_be_bytes(),
    );
    assert_nonrevocation(
        NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2,
        credential_id,
        nonrevocation_path_index,
        nonrevocation_siblings,
        accumulator_root,
        accumulator_epoch,
        current_epoch,
    );

    let mut counted_disclosures: u8 = 0;
    for i in 0..SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES {
        let active_position = (i as u8) < credential_attribute_count;
        if !active_position {
            assert(!disclosed_flags[i], "cannot disclose a credential padding position");
        }
        if disclosed_flags[i] {
            counted_disclosures += 1;
            assert(
                disclosed_attributes[i] == credential_attributes[i],
                "disclosed value does not match signed credential position",
            );
        } else {
            assert(disclosed_attributes[i] == 0, "hidden disclosed-attribute slot must be zero");
        }
    }
    assert(disclosure_count > 0, "selective disclosure must reveal at least one position");
    assert(counted_disclosures == disclosure_count, "disclosure count does not match flags");
    assert(credential_not_expired(credential_expires_at, timestamp), "credential expired");

    let expected_binding = compute_selective_disclosure_binding(
        credential_attribute_count,
        disclosed_flags,
        disclosed_attributes,
        proof_context,
        timestamp,
    );
    assert(expected_binding == claim_binding, "selective disclosure binding mismatch");
    assert(proof_context != 0, "proof context must be non-zero");
    assert(timestamp != 0, "timestamp must be non-zero");
}

struct DisclosureFixture {
    presentation_pseudonym: Field,
    scope_id: Field,
    claim_binding: Field,
    proof_context: Field,
    accumulator_root: Field,
    accumulator_epoch: u64,
    timestamp: u64,
    current_epoch: u64,
    issuer_public_key_x: [u8; 32],
    issuer_public_key_y: [u8; 32],
    credential_attribute_count: u8,
    disclosure_count: u8,
    disclosed_flags: [bool; 8],
    disclosed_attributes: [Field; 8],
    holder_commitment: Field,
    credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_id: Field,
    credential_attributes: [Field; 8],
    credential_expires_at: u64,
    issuer_signature: [u8; 64],
    nonrevocation_siblings: [Field; 32],
    nonrevocation_path_index: Field,
}

fn valid_fixture() -> DisclosureFixture {
    // Public deterministic test-fixture scalar derived from seed 42.
    let binding_scalar = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105;
    let holder_commitment = 0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf;
    let credential_id: Field = 707;
    let credential_attributes: [Field; 8] = [0, 11, 22, 33, 0, 0, 0, 0];
    let disclosed_flags = [true, false, true, false, false, false, false, false];
    let disclosed_attributes: [Field; 8] = [0, 0, 22, 0, 0, 0, 0, 0];
    let proof_context: Field = 777;
    let timestamp: u64 = 12345;
    let nonrevocation_siblings = [0; 32];
    let accumulator_root = zkc_lib::compute_merkle_root(credential_id, 0, nonrevocation_siblings);
    DisclosureFixture {
        presentation_pseudonym: 0,
        scope_id: 0,
        claim_binding: compute_selective_disclosure_binding(
            4,
            disclosed_flags,
            disclosed_attributes,
            proof_context,
            timestamp,
        ),
        proof_context,
        accumulator_root,
        accumulator_epoch: 1,
        timestamp,
        current_epoch: 1,
        issuer_public_key_x: [
            19, 16, 254, 66, 183, 223, 40, 186, 233, 29, 24, 232, 127, 122, 47, 12, 80, 95, 213,
            226, 0, 86, 217, 90, 75, 106, 133, 184, 217, 73, 228, 89,
        ],
        issuer_public_key_y: [
            80, 44, 64, 253, 27, 195, 61, 45, 190, 51, 103, 181, 207, 63, 72, 205, 155, 106, 202, 3,
            83, 203, 157, 52, 179, 22, 55, 20, 107, 221, 26, 134,
        ],
        credential_attribute_count: 4,
        disclosure_count: 2,
        disclosed_flags,
        disclosed_attributes,
        holder_commitment,
        credential_binding_key: binding_scalar,
        credential_holder_commitment: holder_commitment,
        credential_id,
        credential_attributes,
        credential_expires_at: 2000000,
        issuer_signature: [
            137, 64, 114, 180, 18, 160, 223, 26, 1, 145, 25, 194, 235, 126, 32, 55, 252, 126, 255,
            248, 73, 208, 35, 55, 42, 254, 240, 104, 232, 174, 105, 217, 92, 254, 127, 56, 74, 14,
            153, 60, 123, 168, 117, 99, 53, 100, 24, 165, 160, 3, 254, 142, 58, 193, 112, 221, 155,
            251, 124, 174, 45, 115, 178, 170,
        ],
        nonrevocation_siblings,
        nonrevocation_path_index: 0,
    }
}

fn run_main(f: DisclosureFixture) {
    main(
        f.presentation_pseudonym,
        f.scope_id,
        f.claim_binding,
        f.proof_context,
        f.accumulator_root,
        f.accumulator_epoch,
        f.timestamp,
        f.current_epoch,
        f.issuer_public_key_x,
        f.issuer_public_key_y,
        f.credential_attribute_count,
        f.disclosure_count,
        f.disclosed_flags,
        f.disclosed_attributes,
        f.holder_commitment,
        f.credential_binding_key,
        f.credential_holder_commitment,
        f.credential_id,
        f.credential_attributes,
        f.credential_expires_at,
        f.issuer_signature,
        f.nonrevocation_siblings,
        f.nonrevocation_path_index,
    );
}

#[test]
fn test_valid_issuer_authoritative_disclosure() {
    run_main(valid_fixture());
}

#[test]
fn kat_typed_disclosure_binding() {
    assert(
        valid_fixture().claim_binding
            == 0x2ccad330d85549090a62b55134e43ecf9e1027b9ed3e2fa7b96b302307787063,
        "typed disclosure binding KAT mismatch",
    );
}

#[test]
fn test_typed_disclosure_binding_distinguishes_disclosed_zero() {
    let disclosed = compute_selective_disclosure_binding(
        4,
        [true, false, false, false, false, false, false, false],
        [0, 0, 0, 0, 0, 0, 0, 0],
        777,
        12345,
    );
    let hidden = compute_selective_disclosure_binding(
        4,
        [false, false, false, false, false, false, false, false],
        [0, 0, 0, 0, 0, 0, 0, 0],
        777,
        12345,
    );
    assert(disclosed != hidden, "disclosed zero must differ from hidden zero");
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_rejects_self_chosen_unissued_attribute() {
    let mut f = valid_fixture();
    f.credential_attributes[2] = 999;
    f.disclosed_attributes[2] = 999;
    f.claim_binding = compute_selective_disclosure_binding(
        f.credential_attribute_count,
        f.disclosed_flags,
        f.disclosed_attributes,
        f.proof_context,
        f.timestamp,
    );
    run_main(f);
}

#[test(should_fail_with = "selective disclosure binding mismatch")]
fn test_rejects_altered_position() {
    let mut f = valid_fixture();
    f.disclosed_flags[0] = false;
    f.disclosed_flags[1] = true;
    f.disclosed_attributes[1] = 11;
    run_main(f);
}

#[test(should_fail_with = "selective disclosure binding mismatch")]
fn test_rejects_hidden_zero_substitution() {
    let mut f = valid_fixture();
    f.disclosed_flags[0] = false;
    f.disclosure_count = 1;
    run_main(f);
}

#[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
fn test_rejects_wrong_issuer_state() {
    let mut f = valid_fixture();
    f.accumulator_root += 1;
    run_main(f);
}

#[test(should_fail_with = "selective disclosure binding mismatch")]
fn test_rejects_cross_context_replay() {
    let mut f = valid_fixture();
    f.proof_context += 1;
    run_main(f);
}

#[test(should_fail_with = "disclosure count does not match flags")]
fn test_rejects_wrong_disclosure_count() {
    let mut f = valid_fixture();
    f.disclosure_count = 3;
    run_main(f);
}

#[test(should_fail_with = "credential padding attribute must be zero")]
fn test_rejects_noncanonical_credential_padding() {
    let mut f = valid_fixture();
    f.credential_attributes[7] = 1;
    run_main(f);
}
