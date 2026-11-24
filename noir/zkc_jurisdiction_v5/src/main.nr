// =============================================================================
// ZKC Jurisdiction Predicate Circuit v4 (v2 presentation ABI; Noir / UltraHonk / BN254)
//
// Presentation-profile ladder (design section 4.1). Public input index 0 is
// now presentation_pseudonym and index 1 is scope_id; holder_commitment is a
// private witness. scope_id == 0 is the anonymous sentinel (pseudonym forced
// to 0); scope_id != 0 is a scoped presentation whose pseudonym derives from
// the credential binding key and scope. The v3 sibling (holder_commitment
// public) is the consent-gated linkable profile; v1/v2 remain historical and
// deprecated.
//
// Supports:
//   - inclusion: jurisdiction code is a member of a verifier set root
//   - exclusion: sorted-neighbor non-membership against a blocked set root
// =============================================================================

use zkc_issuer_sig::{assert_issuer_signature, ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1};
use zkc_lib::{
    assert_presentation_binding, compute_claim_binding_3, derive_holder_commitment, poseidon2,
    poseidon3,
};
use zkc_nonrevocation::{assert_nonrevocation, NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2};

pub global MEMBERSHIP_TYPE_INCLUSION: u8 = 0;
pub global MEMBERSHIP_TYPE_EXCLUSION: u8 = 1;

pub fn compute_jurisdiction_leaf(jurisdiction_code: u16, claim_type: u8) -> Field {
    poseidon2(jurisdiction_code as Field, claim_type as Field)
}

pub fn compute_jurisdiction_credential_digest(
    holder_commitment: Field,
    credential_id: Field,
    jurisdiction_code: u16,
    claim_type: u8,
    verification_method: u8,
    valid_from: u64,
    valid_until: u64,
) -> Field {
    let jurisdiction_leaf = compute_jurisdiction_leaf(jurisdiction_code, claim_type);
    let header_hash = poseidon3(holder_commitment, credential_id, jurisdiction_leaf);
    let method_hash = poseidon3(
        verification_method as Field,
        valid_from as Field,
        valid_until as Field,
    );
    poseidon2(header_hash, method_hash)
}

pub fn compute_jurisdiction_claim_binding(
    jurisdiction_set_root: Field,
    membership_type: u8,
    required_claim_type: u8,
    proof_context: Field,
    timestamp: u64,
) -> Field {
    compute_claim_binding_3(
        jurisdiction_set_root,
        membership_type as Field,
        required_claim_type as Field,
        proof_context,
        timestamp as Field,
    )
}

pub fn validity_period_contains(valid_from: u64, valid_until: u64, timestamp: u64) -> bool {
    (valid_from <= timestamp) & (valid_until >= timestamp)
}

pub fn verify_jurisdiction_set(
    membership_type: u8,
    jurisdiction_code: u16,
    required_claim_type: u8,
    jurisdiction_set_root: Field,
    membership_path_index: Field,
    membership_siblings: [Field; 32],
    predecessor_code: u16,
    predecessor_path_index: Field,
    predecessor_siblings: [Field; 32],
    successor_code: u16,
    successor_path_index: Field,
    successor_siblings: [Field; 32],
) -> bool {
    let jurisdiction_leaf = compute_jurisdiction_leaf(jurisdiction_code, required_claim_type);
    if membership_type == MEMBERSHIP_TYPE_INCLUSION {
        zkc_lib::verify_merkle_membership(
            jurisdiction_leaf,
            membership_path_index,
            membership_siblings,
            jurisdiction_set_root,
        )
    } else if membership_type == MEMBERSHIP_TYPE_EXCLUSION {
        // Canonical sorted sets occupy consecutive leaf indices; requiring
        // adjacency rejects non-adjacent outer-member exclusion witnesses.
        let predecessor_leaf = compute_jurisdiction_leaf(predecessor_code, required_claim_type);
        let successor_leaf = compute_jurisdiction_leaf(successor_code, required_claim_type);
        let predecessor_valid = zkc_lib::verify_merkle_membership(
            predecessor_leaf,
            predecessor_path_index,
            predecessor_siblings,
            jurisdiction_set_root,
        );
        let successor_valid = zkc_lib::verify_merkle_membership(
            successor_leaf,
            successor_path_index,
            successor_siblings,
            jurisdiction_set_root,
        );
        predecessor_valid
            & successor_valid
            & (predecessor_code < jurisdiction_code)
            & (jurisdiction_code < successor_code)
            & (successor_path_index == predecessor_path_index + 1)
    } else {
        false
    }
}

fn main(
    // === Public Inputs (v4 order; v2 presentation ABI, design section 4.1) ===
    presentation_pseudonym: pub Field,
    scope_id: pub Field, // 0 = anonymous sentinel, else scoped
    claim_binding: pub Field,
    proof_context: pub Field,
    jurisdiction_set_root: pub Field,
    membership_type: pub u8,
    accumulator_root: pub Field,
    accumulator_epoch: pub u64,
    timestamp: pub u64,
    current_epoch: pub u64,
    issuer_public_key_x: pub [u8; 32],
    issuer_public_key_y: pub [u8; 32],
    // === Private Presentation Witness ===
    holder_commitment: Field,
    // === Private Credential Inputs ===
    credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_id: Field,
    jurisdiction_code: u16,
    credential_claim_type: u8,
    verification_method: u8,
    valid_from: u64,
    valid_until: u64,
    issuer_signature: [u8; 64],
    // === Private Predicate Request Inputs ===
    required_claim_type: u8,
    // === Private Jurisdiction Set Witness ===
    membership_path_index: Field,
    membership_siblings: [Field; 32],
    predecessor_code: u16,
    predecessor_path_index: Field,
    predecessor_siblings: [Field; 32],
    successor_code: u16,
    successor_path_index: Field,
    successor_siblings: [Field; 32],
    // === Private Non-Revocation Witness ===
    nonrevocation_siblings: [Field; 32],
    nonrevocation_path_index: Field,
) {
    assert(
        derive_holder_commitment(credential_binding_key) == holder_commitment,
        "holder commitment does not match credential binding key",
    );
    assert(
        credential_holder_commitment == holder_commitment,
        "credential holder commitment does not match public holder commitment",
    );

    // Profile binding: anonymous sentinel (scope_id 0 => pseudonym 0) or a
    // scoped pseudonym derived from the credential binding key and scope.
    assert_presentation_binding(presentation_pseudonym, scope_id, credential_binding_key);

    assert(
        credential_claim_type == required_claim_type,
        "credential claim type does not match requested claim type",
    );

    let credential_digest = compute_jurisdiction_credential_digest(
        credential_holder_commitment,
        credential_id,
        jurisdiction_code,
        credential_claim_type,
        verification_method,
        valid_from,
        valid_until,
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

    assert(
        verify_jurisdiction_set(
            membership_type,
            jurisdiction_code,
            required_claim_type,
            jurisdiction_set_root,
            membership_path_index,
            membership_siblings,
            predecessor_code,
            predecessor_path_index,
            predecessor_siblings,
            successor_code,
            successor_path_index,
            successor_siblings,
        ),
        "jurisdiction set proof failed",
    );
    assert(
        validity_period_contains(valid_from, valid_until, timestamp),
        "jurisdiction credential not valid at timestamp",
    );

    let expected_claim_binding = compute_jurisdiction_claim_binding(
        jurisdiction_set_root,
        membership_type,
        required_claim_type,
        proof_context,
        timestamp,
    );
    assert(expected_claim_binding == claim_binding, "claim binding mismatch");
    assert(proof_context != 0, "proof context must be non-zero");
}

#[test]
fn test_validity_period() {
    assert(validity_period_contains(10, 20, 10), "valid from is inclusive");
    assert(validity_period_contains(10, 20, 20), "valid until is inclusive");
    assert(!validity_period_contains(10, 20, 9), "before valid_from must fail");
    assert(!validity_period_contains(10, 20, 21), "after valid_until must fail");
}

#[test]
fn test_sorted_neighbor_exclusion_witness() {
    let mut predecessor_siblings = [0; 32];
    let mut successor_siblings = [0; 32];
    let required_claim_type = 1;
    let predecessor_code: u16 = 100;
    let jurisdiction_code: u16 = 150;
    let successor_code: u16 = 200;
    let predecessor_leaf = compute_jurisdiction_leaf(predecessor_code, required_claim_type);
    let successor_leaf = compute_jurisdiction_leaf(successor_code, required_claim_type);
    predecessor_siblings[0] = successor_leaf;
    successor_siblings[0] = predecessor_leaf;
    let blocked_set_root = zkc_lib::compute_merkle_root(predecessor_leaf, 0, predecessor_siblings);

    assert(
        verify_jurisdiction_set(
            MEMBERSHIP_TYPE_EXCLUSION,
            jurisdiction_code,
            required_claim_type,
            blocked_set_root,
            0,
            [0; 32],
            predecessor_code,
            0,
            predecessor_siblings,
            successor_code,
            1,
            successor_siblings,
        ),
        "jurisdiction between sorted neighbors must prove non-membership",
    );
}

fn jurisdiction_three_leaf_tree(
    c0: u16,
    c1: u16,
    c2: u16,
    claim_type: u8,
) -> (Field, [Field; 32], [Field; 32], [Field; 32]) {
    let l0 = compute_jurisdiction_leaf(c0, claim_type);
    let l1 = compute_jurisdiction_leaf(c1, claim_type);
    let l2 = compute_jurisdiction_leaf(c2, claim_type);
    let mut zero = [0; 32];
    for i in 1..32 {
        zero[i] = poseidon2(zero[i - 1], zero[i - 1]);
    }
    let n01 = poseidon2(l0, l1);
    let n23 = poseidon2(l2, zero[0]);
    let mut pred_sibs = [0; 32];
    pred_sibs[0] = l1;
    pred_sibs[1] = n23;
    let mut mid_sibs = [0; 32];
    mid_sibs[0] = l0;
    mid_sibs[1] = n23;
    let mut succ_sibs = [0; 32];
    succ_sibs[0] = zero[0];
    succ_sibs[1] = n01;
    for i in 2..32 {
        pred_sibs[i] = zero[i];
        mid_sibs[i] = zero[i];
        succ_sibs[i] = zero[i];
    }
    let root = zkc_lib::compute_merkle_root(l0, 0, pred_sibs);
    (root, pred_sibs, mid_sibs, succ_sibs)
}

#[test]
fn test_exclusion_outer_member_attack_unit() {
    let claim_type = 1;
    let (root, pred_sibs, mid_sibs, succ_sibs) =
        jurisdiction_three_leaf_tree(100, 150, 200, claim_type);
    assert(
        !verify_jurisdiction_set(
            MEMBERSHIP_TYPE_EXCLUSION,
            150,
            claim_type,
            root,
            0,
            [0; 32],
            100,
            0,
            pred_sibs,
            200,
            2,
            succ_sibs,
        ),
        "outer-member jurisdiction exclusion attack must be rejected",
    );
    assert(
        verify_jurisdiction_set(
            MEMBERSHIP_TYPE_EXCLUSION,
            175,
            claim_type,
            root,
            0,
            [0; 32],
            150,
            1,
            mid_sibs,
            200,
            2,
            succ_sibs,
        ),
        "adjacent-neighbour jurisdiction non-membership must verify",
    );
}

struct JurisdictionFixture {
    presentation_pseudonym: Field,
    scope_id: Field,
    claim_binding: Field,
    proof_context: Field,
    jurisdiction_set_root: Field,
    membership_type: u8,
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
    jurisdiction_code: u16,
    credential_claim_type: u8,
    verification_method: u8,
    valid_from: u64,
    valid_until: u64,
    issuer_signature: [u8; 64],
    required_claim_type: u8,
    membership_path_index: Field,
    membership_siblings: [Field; 32],
    predecessor_code: u16,
    predecessor_path_index: Field,
    predecessor_siblings: [Field; 32],
    successor_code: u16,
    successor_path_index: Field,
    successor_siblings: [Field; 32],
    nonrevocation_siblings: [Field; 32],
    nonrevocation_path_index: Field,
}

// Scoped presentation scope id for the seed-42 credential binding key. Cross-
// checked in zkc_lib against derive_presentation_pseudonym / poseidon3.
global SCOPED_SCOPE_ID: Field = 7;

fn valid_jurisdiction_inclusion_fixture() -> JurisdictionFixture {
    let credential_binding_key: Field =
        0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105;
    let holder_commitment: Field =
        0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf;
    let credential_id: Field = 42;
    let jurisdiction_code: u16 = 840;
    let claim_type: u8 = 1;
    let proof_context: Field = 777;
    let timestamp: u64 = 12345;

    let membership_siblings = [0; 32];
    let jurisdiction_leaf = compute_jurisdiction_leaf(jurisdiction_code, claim_type);
    let jurisdiction_set_root =
        zkc_lib::compute_merkle_root(jurisdiction_leaf, 0, membership_siblings);
    let claim_binding = compute_jurisdiction_claim_binding(
        jurisdiction_set_root,
        MEMBERSHIP_TYPE_INCLUSION,
        claim_type,
        proof_context,
        timestamp,
    );

    let nonrevocation_siblings = [0; 32];
    let accumulator_root = zkc_lib::compute_merkle_root(credential_id, 0, nonrevocation_siblings);

    // Default fixture is a scoped presentation: pseudonym derived from cbk+scope.
    let scope_id = SCOPED_SCOPE_ID;
    let presentation_pseudonym =
        zkc_lib::derive_presentation_pseudonym(credential_binding_key, scope_id);

    JurisdictionFixture {
        presentation_pseudonym,
        scope_id,
        claim_binding,
        proof_context,
        jurisdiction_set_root,
        membership_type: MEMBERSHIP_TYPE_INCLUSION,
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
        jurisdiction_code,
        credential_claim_type: claim_type,
        verification_method: 1,
        valid_from: 1000,
        valid_until: 2000000,
        issuer_signature: [
            141, 200, 199, 55, 7, 182, 196, 43, 135, 166, 93, 51, 106, 171, 253, 180, 142, 114, 254,
            6, 19, 209, 84, 180, 94, 141, 199, 208, 80, 205, 89, 43, 85, 174, 115, 227, 33, 9, 239,
            61, 125, 122, 143, 109, 216, 207, 200, 25, 36, 53, 96, 12, 48, 157, 149, 114, 21, 125,
            98, 143, 126, 142, 185, 33,
        ],
        required_claim_type: claim_type,
        membership_path_index: 0,
        membership_siblings,
        predecessor_code: 0,
        predecessor_path_index: 0,
        predecessor_siblings: [0; 32],
        successor_code: 0,
        successor_path_index: 0,
        successor_siblings: [0; 32],
        nonrevocation_siblings,
        nonrevocation_path_index: 0,
    }
}

fn run_jurisdiction_main(f: JurisdictionFixture) {
    main(
        f.presentation_pseudonym,
        f.scope_id,
        f.claim_binding,
        f.proof_context,
        f.jurisdiction_set_root,
        f.membership_type,
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
        f.jurisdiction_code,
        f.credential_claim_type,
        f.verification_method,
        f.valid_from,
        f.valid_until,
        f.issuer_signature,
        f.required_claim_type,
        f.membership_path_index,
        f.membership_siblings,
        f.predecessor_code,
        f.predecessor_path_index,
        f.predecessor_siblings,
        f.successor_code,
        f.successor_path_index,
        f.successor_siblings,
        f.nonrevocation_siblings,
        f.nonrevocation_path_index,
    );
}

#[test]
fn test_valid_jurisdiction_inclusion_predicate() {
    run_jurisdiction_main(valid_jurisdiction_inclusion_fixture());
}

#[test(should_fail_with = "jurisdiction set proof failed")]
fn test_jurisdiction_rejects_outer_member_attack_full() {
    let mut f = valid_jurisdiction_inclusion_fixture();
    let claim_type = f.required_claim_type;
    let (root, pred_sibs, _mid, succ_sibs) =
        jurisdiction_three_leaf_tree(700, 840, 900, claim_type);
    f.membership_type = MEMBERSHIP_TYPE_EXCLUSION;
    f.jurisdiction_set_root = root;
    f.predecessor_code = 700;
    f.predecessor_path_index = 0;
    f.predecessor_siblings = pred_sibs;
    f.successor_code = 900;
    f.successor_path_index = 2;
    f.successor_siblings = succ_sibs;
    f.claim_binding = compute_jurisdiction_claim_binding(
        f.jurisdiction_set_root,
        f.membership_type,
        f.required_claim_type,
        f.proof_context,
        f.timestamp,
    );
    run_jurisdiction_main(f);
}

// --- Presentation-profile tests (design section 4.1) ---------------------------

#[test]
fn test_jurisdiction_scoped_presentation_passes() {
    // Default fixture is scoped: pseudonym derives from cbk + scope_id != 0.
    let f = valid_jurisdiction_inclusion_fixture();
    assert(f.scope_id != 0, "fixture must be scoped");
    run_jurisdiction_main(f);
}

#[test]
fn test_jurisdiction_anonymous_presentation_passes() {
    // Anonymous sentinel: scope_id 0 forces pseudonym 0.
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.scope_id = 0;
    f.presentation_pseudonym = 0;
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "anonymous profile must not carry a pseudonym")]
fn test_jurisdiction_rejects_pseudonym_under_anonymous_sentinel() {
    // scope_id 0 with a non-zero pseudonym violates the sentinel rule.
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.scope_id = 0;
    f.presentation_pseudonym = 1;
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "presentation pseudonym does not derive from binding key and scope")]
fn test_jurisdiction_rejects_pseudonym_from_wrong_binding_key() {
    // Scoped pseudonym derived from a different cbk must not verify.
    let mut f = valid_jurisdiction_inclusion_fixture();
    let wrong_cbk = f.credential_binding_key + 1;
    f.presentation_pseudonym = zkc_lib::derive_presentation_pseudonym(wrong_cbk, f.scope_id);
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "jurisdiction set proof failed")]
fn test_jurisdiction_rejects_blocked_jurisdiction() {
    // Exclusion-mode claim against a blocked set that CONTAINS the
    // credential's jurisdiction: no sorted-neighbor witness can exist.
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.membership_type = MEMBERSHIP_TYPE_EXCLUSION;
    let blocked_leaf = compute_jurisdiction_leaf(f.jurisdiction_code, f.required_claim_type);
    f.jurisdiction_set_root = zkc_lib::compute_merkle_root(blocked_leaf, 0, [0; 32]);
    f.claim_binding = compute_jurisdiction_claim_binding(
        f.jurisdiction_set_root,
        f.membership_type,
        f.required_claim_type,
        f.proof_context,
        f.timestamp,
    );
    f.predecessor_code = 100;
    f.successor_code = 200;
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "jurisdiction set proof failed")]
fn test_jurisdiction_rejects_non_member_inclusion() {
    // Inclusion claim against a verifier set that does not contain the
    // credential's jurisdiction code.
    let mut f = valid_jurisdiction_inclusion_fixture();
    let other_leaf = compute_jurisdiction_leaf(826, f.required_claim_type);
    f.jurisdiction_set_root = zkc_lib::compute_merkle_root(other_leaf, 0, [0; 32]);
    f.claim_binding = compute_jurisdiction_claim_binding(
        f.jurisdiction_set_root,
        f.membership_type,
        f.required_claim_type,
        f.proof_context,
        f.timestamp,
    );
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_jurisdiction_rejects_tampered_issuer_signature() {
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.issuer_signature[0] += 1;
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_jurisdiction_rejects_wrong_issuer() {
    // A different (valid) issuer key: the ZKC test issuer from
    // tools/zkc_test_issuer.py. The credential signature does not verify
    // under it.
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.issuer_public_key_x = [
        19, 16, 254, 66, 183, 223, 40, 186, 233, 29, 24, 232, 127, 122, 47, 12, 80, 95, 213, 226, 0,
        86, 217, 90, 75, 106, 133, 184, 217, 73, 228, 89,
    ];
    f.issuer_public_key_y = [
        80, 44, 64, 253, 27, 195, 61, 45, 190, 51, 103, 181, 207, 63, 72, 205, 155, 106, 202, 3, 83,
        203, 157, 52, 179, 22, 55, 20, 107, 221, 26, 134,
    ];
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_jurisdiction_rejects_tampered_credential_claims() {
    // Changing the signed jurisdiction code invalidates the credential digest.
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.jurisdiction_code = 826;
    let leaf = compute_jurisdiction_leaf(f.jurisdiction_code, f.required_claim_type);
    f.jurisdiction_set_root = zkc_lib::compute_merkle_root(leaf, 0, f.membership_siblings);
    f.claim_binding = compute_jurisdiction_claim_binding(
        f.jurisdiction_set_root,
        f.membership_type,
        f.required_claim_type,
        f.proof_context,
        f.timestamp,
    );
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "claim binding mismatch")]
fn test_jurisdiction_rejects_wrong_claim_binding() {
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.claim_binding += 1;
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "holder commitment does not match credential binding key")]
fn test_jurisdiction_rejects_wrong_holder() {
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.credential_binding_key += 1;
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "credential claim type does not match requested claim type")]
fn test_jurisdiction_rejects_claim_type_mismatch() {
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.required_claim_type = 2;
    f.claim_binding = compute_jurisdiction_claim_binding(
        f.jurisdiction_set_root,
        f.membership_type,
        f.required_claim_type,
        f.proof_context,
        f.timestamp,
    );
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
fn test_jurisdiction_rejects_stale_accumulator_epoch() {
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.current_epoch = f.accumulator_epoch + zkc_nonrevocation::MAX_EPOCH_LAG + 1;
    run_jurisdiction_main(f);
}

#[test(should_fail_with = "jurisdiction credential not valid at timestamp")]
fn test_jurisdiction_rejects_expired_credential() {
    let mut f = valid_jurisdiction_inclusion_fixture();
    f.timestamp = f.valid_until + 1;
    f.claim_binding = compute_jurisdiction_claim_binding(
        f.jurisdiction_set_root,
        f.membership_type,
        f.required_claim_type,
        f.proof_context,
        f.timestamp,
    );
    run_jurisdiction_main(f);
}
