// =============================================================================
// ZKC KYC Predicate Circuit v2 (Noir / UltraHonk / BN254)
//
// Presentation-profile ladder (design section 4.1). Public input index 0 is
// now presentation_pseudonym and index 1 is scope_id; holder_commitment is a
// private witness. scope_id == 0 is the anonymous sentinel (pseudonym forced
// to 0); scope_id != 0 is a scoped presentation whose pseudonym derives from
// the credential binding key and scope. The v1 circuit (holder_commitment
// public) stays frozen as the consent-gated linkable profile.
//
// Implements the ZKC-Core KYC predicate by composing:
//   1. holder binding: cbk -> holderCommitment (now over private values)
//   2. presentation binding: anonymous sentinel or scoped pseudonym
//   3. issuer signature verification over the credential digest
//   4. accumulator-based non-revocation with epoch freshness
//   5. KYC level and required-attribute checks
//   6. credential expiry check
//   7. claim binding to requested predicate, proof context, and timestamp
// =============================================================================

use zkc_issuer_sig::{assert_issuer_signature, ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1};
use zkc_lib::{
    assert_presentation_binding, compute_claim_binding_2, derive_holder_commitment, poseidon2,
    poseidon3,
};
use zkc_nonrevocation::{assert_nonrevocation, NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2};

pub global KYC_LEVEL_BASIC: u8 = 1;
pub global KYC_LEVEL_ENHANCED: u8 = 2;
pub global KYC_LEVEL_INSTITUTIONAL: u8 = 3;

fn bool_to_field(value: bool) -> Field {
    if value {
        1
    } else {
        0
    }
}

pub fn compute_attribute_flags_hash(attributes: [bool; 5]) -> Field {
    let mut acc: Field = 0;
    for i in 0..5 {
        acc = poseidon2(acc, bool_to_field(attributes[i]));
    }
    acc
}

pub fn compute_kyc_credential_digest(
    holder_commitment: Field,
    credential_id: Field,
    credential_level: u8,
    verified_attributes: [bool; 5],
    credential_expires_at: u64,
) -> Field {
    let attribute_hash = compute_attribute_flags_hash(verified_attributes);
    let header_hash = poseidon3(holder_commitment, credential_id, credential_level as Field);
    poseidon3(header_hash, attribute_hash, credential_expires_at as Field)
}

pub fn compute_kyc_claim_binding(
    required_level: u8,
    required_attributes: [bool; 5],
    proof_context: Field,
    timestamp: u64,
) -> Field {
    let required_attribute_hash = compute_attribute_flags_hash(required_attributes);
    compute_claim_binding_2(
        required_level as Field,
        required_attribute_hash,
        proof_context,
        timestamp as Field,
    )
}

pub fn attributes_satisfy(verified_attributes: [bool; 5], required_attributes: [bool; 5]) -> bool {
    let mut valid = true;
    for i in 0..5 {
        valid = valid & (!required_attributes[i] | verified_attributes[i]);
    }
    valid
}

pub fn credential_not_expired(credential_expires_at: u64, timestamp: u64) -> bool {
    (credential_expires_at == 0) | (credential_expires_at > timestamp)
}

fn main(
    // === Public Inputs (v2 order, design section 4.1) ===
    presentation_pseudonym: pub Field, // was: holder_commitment (now private)
    scope_id: pub Field, // new: 0 = anonymous sentinel, else scoped
    claim_binding: pub Field,
    proof_context: pub Field,
    accumulator_root: pub Field,
    accumulator_epoch: pub u64,
    timestamp: pub u64,
    current_epoch: pub u64,
    issuer_public_key_x: pub [u8; 32],
    issuer_public_key_y: pub [u8; 32],
    // === Private Presentation Witness ===
    holder_commitment: Field, // moved from public
    // === Private Credential Inputs ===
    credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_id: Field,
    credential_level: u8,
    verified_attributes: [bool; 5],
    credential_expires_at: u64,
    issuer_signature: [u8; 64],
    // === Private Predicate Request Inputs ===
    required_level: u8,
    required_attributes: [bool; 5],
    // === Private Non-Revocation Witness ===
    nonrevocation_siblings: [Field; 32],
    nonrevocation_path_index: Field,
) {
    let expected_holder_commitment = derive_holder_commitment(credential_binding_key);
    assert(
        expected_holder_commitment == holder_commitment,
        "holder commitment does not match credential binding key",
    );
    assert(
        credential_holder_commitment == holder_commitment,
        "credential holder commitment does not match public holder commitment",
    );

    // Profile binding: anonymous sentinel (scope_id 0 => pseudonym 0) or a
    // scoped pseudonym derived from the credential binding key and scope.
    assert_presentation_binding(presentation_pseudonym, scope_id, credential_binding_key);

    let credential_digest = compute_kyc_credential_digest(
        credential_holder_commitment,
        credential_id,
        credential_level,
        verified_attributes,
        credential_expires_at,
    );
    let credential_message_hash: [u8; 32] = credential_digest.to_be_bytes();
    assert_issuer_signature(
        ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1,
        issuer_public_key_x,
        issuer_public_key_y,
        issuer_signature,
        credential_message_hash,
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

    assert(credential_level >= required_level, "credential level below requested level");
    assert(
        attributes_satisfy(verified_attributes, required_attributes),
        "credential does not satisfy required KYC attributes",
    );
    assert(credential_not_expired(credential_expires_at, timestamp), "credential expired");

    let expected_claim_binding = compute_kyc_claim_binding(
        required_level,
        required_attributes,
        proof_context,
        timestamp,
    );
    assert(expected_claim_binding == claim_binding, "claim binding mismatch");
    assert(proof_context != 0, "proof context must be non-zero");
    assert(timestamp != 0, "timestamp must be non-zero");
}

#[test]
fn test_attribute_satisfaction() {
    let verified = [true, true, false, true, false];
    assert(
        attributes_satisfy(verified, [true, false, false, true, false]),
        "required verified attributes must pass",
    );
    assert(
        !attributes_satisfy(verified, [true, false, true, false, false]),
        "missing required attribute must fail",
    );
}

#[test]
fn test_expiry_rules() {
    assert(credential_not_expired(0, 100), "zero expiry means no expiry");
    assert(credential_not_expired(101, 100), "future expiry must pass");
    assert(!credential_not_expired(100, 100), "expiry at timestamp must fail");
}

struct KycFixture {
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
    holder_commitment: Field,
    credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_id: Field,
    credential_level: u8,
    verified_attributes: [bool; 5],
    credential_expires_at: u64,
    issuer_signature: [u8; 64],
    required_level: u8,
    required_attributes: [bool; 5],
    nonrevocation_siblings: [Field; 32],
    nonrevocation_path_index: Field,
}

// Scope-42 pseudonym for the seed-42 credential binding key. Cross-checked in
// zkc_lib against derive_presentation_pseudonym / poseidon3.
global SCOPED_SCOPE_ID: Field = 7;

fn valid_kyc_fixture() -> KycFixture {
    let credential_binding_key: Field =
        0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105;
    let holder_commitment: Field =
        0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf;
    let credential_id: Field = 42;
    let required_level = KYC_LEVEL_BASIC;
    let required_attributes = [true, false, true, false, false];
    let proof_context: Field = 777;
    let timestamp: u64 = 12345;
    let claim_binding = compute_kyc_claim_binding(
        required_level,
        required_attributes,
        proof_context,
        timestamp,
    );

    let nonrevocation_siblings = [0; 32];
    let accumulator_root = zkc_lib::compute_merkle_root(credential_id, 0, nonrevocation_siblings);

    // Default fixture is a scoped presentation: pseudonym derived from cbk+scope.
    let scope_id = SCOPED_SCOPE_ID;
    let presentation_pseudonym =
        zkc_lib::derive_presentation_pseudonym(credential_binding_key, scope_id);

    KycFixture {
        presentation_pseudonym,
        scope_id,
        claim_binding,
        proof_context,
        accumulator_root,
        accumulator_epoch: 100,
        timestamp,
        current_epoch: 105,
        issuer_public_key_x: [
            137, 81, 38, 98, 181, 144, 46, 180, 102, 61, 191, 66, 140, 98, 244, 92, 229, 44, 211,
            23, 36, 201, 121, 32, 86, 185, 98, 216, 108, 62, 37, 26,
        ],
        issuer_public_key_y: [
            34, 85, 29, 119, 46, 134, 16, 31, 56, 87, 20, 235, 116, 171, 39, 5, 122, 99, 146, 254,
            158, 5, 185, 45, 152, 119, 236, 243, 137, 31, 179, 114,
        ],
        holder_commitment,
        credential_binding_key,
        credential_holder_commitment: holder_commitment,
        credential_id,
        credential_level: KYC_LEVEL_ENHANCED,
        verified_attributes: [true, true, true, false, true],
        credential_expires_at: 2000000,
        issuer_signature: [
            217, 126, 200, 195, 113, 255, 24, 125, 65, 74, 79, 242, 197, 254, 34, 101, 153, 106, 13,
            117, 226, 63, 169, 8, 26, 239, 207, 147, 179, 21, 39, 31, 51, 153, 200, 96, 223, 140, 4,
            75, 129, 37, 99, 82, 104, 97, 17, 55, 123, 118, 194, 183, 39, 140, 191, 114, 252, 149,
            254, 147, 236, 154, 162, 208,
        ],
        required_level,
        required_attributes,
        nonrevocation_siblings,
        nonrevocation_path_index: 0,
    }
}

fn run_kyc_main(f: KycFixture) {
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
        f.holder_commitment,
        f.credential_binding_key,
        f.credential_holder_commitment,
        f.credential_id,
        f.credential_level,
        f.verified_attributes,
        f.credential_expires_at,
        f.issuer_signature,
        f.required_level,
        f.required_attributes,
        f.nonrevocation_siblings,
        f.nonrevocation_path_index,
    );
}

#[test]
fn test_valid_kyc_predicate() {
    run_kyc_main(valid_kyc_fixture());
}

// --- Presentation-profile tests (design section 4.1) ---------------------------

#[test]
fn test_kyc_scoped_presentation_passes() {
    // Default fixture is scoped: pseudonym derives from cbk + scope_id != 0.
    let f = valid_kyc_fixture();
    assert(f.scope_id != 0, "fixture must be scoped");
    run_kyc_main(f);
}

#[test]
fn test_kyc_anonymous_presentation_passes() {
    // Anonymous sentinel: scope_id 0 forces pseudonym 0.
    let mut f = valid_kyc_fixture();
    f.scope_id = 0;
    f.presentation_pseudonym = 0;
    run_kyc_main(f);
}

#[test(should_fail_with = "anonymous profile must not carry a pseudonym")]
fn test_kyc_rejects_pseudonym_under_anonymous_sentinel() {
    // scope_id 0 with a non-zero pseudonym violates the sentinel rule.
    let mut f = valid_kyc_fixture();
    f.scope_id = 0;
    f.presentation_pseudonym = 1;
    run_kyc_main(f);
}

#[test(should_fail_with = "presentation pseudonym does not derive from binding key and scope")]
fn test_kyc_rejects_pseudonym_from_wrong_binding_key() {
    // Scoped pseudonym derived from a different cbk must not verify.
    let mut f = valid_kyc_fixture();
    let wrong_cbk = f.credential_binding_key + 1;
    f.presentation_pseudonym = zkc_lib::derive_presentation_pseudonym(wrong_cbk, f.scope_id);
    run_kyc_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_kyc_rejects_tampered_issuer_signature() {
    let mut f = valid_kyc_fixture();
    f.issuer_signature[0] += 1;
    run_kyc_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_kyc_rejects_tampered_credential_claims() {
    // Inflating the credential level invalidates the signed credential digest.
    let mut f = valid_kyc_fixture();
    f.credential_level = KYC_LEVEL_INSTITUTIONAL;
    run_kyc_main(f);
}

#[test(should_fail_with = "credential expired")]
fn test_kyc_rejects_expired_credential() {
    let mut f = valid_kyc_fixture();
    f.timestamp = f.credential_expires_at;
    f.claim_binding = compute_kyc_claim_binding(
        f.required_level,
        f.required_attributes,
        f.proof_context,
        f.timestamp,
    );
    run_kyc_main(f);
}

#[test(should_fail_with = "claim binding mismatch")]
fn test_kyc_rejects_wrong_claim_binding() {
    let mut f = valid_kyc_fixture();
    f.claim_binding += 1;
    run_kyc_main(f);
}

#[test(should_fail_with = "holder commitment does not match credential binding key")]
fn test_kyc_rejects_wrong_holder() {
    let mut f = valid_kyc_fixture();
    f.credential_binding_key += 1;
    run_kyc_main(f);
}

#[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
fn test_kyc_rejects_stale_accumulator_epoch() {
    let mut f = valid_kyc_fixture();
    f.current_epoch = f.accumulator_epoch + zkc_nonrevocation::MAX_EPOCH_LAG + 1;
    run_kyc_main(f);
}

#[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
fn test_kyc_rejects_revoked_credential_witness() {
    // A witness for a different accumulator root models a revoked credential.
    let mut f = valid_kyc_fixture();
    f.accumulator_root += 1;
    run_kyc_main(f);
}

#[test(should_fail_with = "credential level below requested level")]
fn test_kyc_rejects_insufficient_level() {
    let mut f = valid_kyc_fixture();
    f.required_level = KYC_LEVEL_INSTITUTIONAL;
    f.claim_binding = compute_kyc_claim_binding(
        f.required_level,
        f.required_attributes,
        f.proof_context,
        f.timestamp,
    );
    run_kyc_main(f);
}

#[test(should_fail_with = "credential does not satisfy required KYC attributes")]
fn test_kyc_rejects_missing_required_attribute() {
    let mut f = valid_kyc_fixture();
    f.required_attributes = [true, false, true, true, false];
    f.claim_binding = compute_kyc_claim_binding(
        f.required_level,
        f.required_attributes,
        f.proof_context,
        f.timestamp,
    );
    run_kyc_main(f);
}
