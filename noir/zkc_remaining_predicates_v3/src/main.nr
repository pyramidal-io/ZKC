// =============================================================================
// ZKC Remaining Predicate Profiles v3 (flagRequired-bound linkable profile)
//
// A shared circuit profile for accreditation, source-of-funds, tax-residency,
// and sanctions-clearance predicates. Predicate-specific rules are selected by
// `predicate_type`; all profiles share holder binding, issuer signature,
// non-revocation, validity, and claim binding.
// =============================================================================

use zkc_issuer_sig::{assert_issuer_signature, ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1};
use zkc_lib::{derive_holder_commitment, DOMAIN_ZKC_CLAIM, poseidon2, poseidon3, poseidon4};
use zkc_nonrevocation::{assert_nonrevocation, NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2};

pub global PREDICATE_ACCREDITATION: u8 = 1;
pub global PREDICATE_SOURCE_OF_FUNDS: u8 = 2;
pub global PREDICATE_TAX_RESIDENCY: u8 = 3;
pub global PREDICATE_SANCTIONS_CLEARANCE: u8 = 4;

pub fn validity_period_contains(valid_from: u64, valid_until: u64, timestamp: u64) -> bool {
    (valid_from <= timestamp) & ((valid_until == 0) | (valid_until >= timestamp))
}

pub fn compute_profile_digest(
    holder_commitment: Field,
    credential_id: Field,
    predicate_type: u8,
    claim_0: Field,
    claim_1: Field,
    valid_until: u64,
) -> Field {
    let header = poseidon4(
        holder_commitment,
        credential_id,
        predicate_type as Field,
        valid_until as Field,
    );
    poseidon3(header, claim_0, claim_1)
}

pub fn compute_profile_claim_binding(
    predicate_type: u8,
    required_0: Field,
    required_1: Field,
    flag_required: bool,
    proof_context: Field,
    timestamp: u64,
) -> Field {
    // Keep this helper local: zkc_lib is in the immutable dependency closure
    // of the published v1/v2 circuits and cannot be changed retroactively.
    let inner = poseidon4(
        DOMAIN_ZKC_CLAIM,
        predicate_type as Field,
        required_0,
        required_1,
    );
    let claim_hash = poseidon2(inner, flag_required as Field);
    poseidon3(claim_hash, proof_context, timestamp as Field)
}

// `is_institutional` MUST be derived from issuer-signed claims (the signed
// `claim_1` slot), never from a prover-supplied request input: a self-asserted
// flag would let any holder claim institutional status.
pub fn verify_accreditation(
    actual_level: u8,
    required_level: u8,
    institutional_required: bool,
    is_institutional: bool,
) -> bool {
    (actual_level >= required_level) & (!institutional_required | is_institutional)
}

pub fn verify_source_of_funds(
    source_code: Field,
    accepted_root: Field,
    path_index: Field,
    siblings: [Field; 32],
) -> bool {
    zkc_lib::verify_merkle_membership(source_code, path_index, siblings, accepted_root)
}

pub fn verify_tax_residency(
    tax_jurisdiction_code: Field,
    accepted_root: Field,
    path_index: Field,
    siblings: [Field; 32],
    credential_tax_year: u64,
    required_min_tax_year: u64,
) -> bool {
    zkc_lib::verify_merkle_membership(tax_jurisdiction_code, path_index, siblings, accepted_root)
        & (credential_tax_year >= required_min_tax_year)
}

pub fn verify_sanctions_clearance(
    subject_screening_code: u16,
    blocked_root: Field,
    predecessor_code: u16,
    predecessor_path_index: Field,
    predecessor_siblings: [Field; 32],
    successor_code: u16,
    successor_path_index: Field,
    successor_siblings: [Field; 32],
) -> bool {
    let predecessor_leaf = predecessor_code as Field;
    let successor_leaf = successor_code as Field;
    zkc_lib::verify_merkle_membership(
        predecessor_leaf,
        predecessor_path_index,
        predecessor_siblings,
        blocked_root,
    )
        & zkc_lib::verify_merkle_membership(
            successor_leaf,
            successor_path_index,
            successor_siblings,
            blocked_root,
        )
        & (predecessor_code < subject_screening_code)
        & (subject_screening_code < successor_code)
}

fn main(
    // === Public Inputs ===
    holder_commitment: pub Field,
    claim_binding: pub Field,
    proof_context: pub Field,
    predicate_type: pub u8,
    set_root: pub Field,
    accumulator_root: pub Field,
    accumulator_epoch: pub u64,
    timestamp: pub u64,
    current_epoch: pub u64,
    issuer_public_key_x: pub [u8; 32],
    issuer_public_key_y: pub [u8; 32],
    // === Private Shared Credential Inputs ===
    credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_id: Field,
    claim_0: Field,
    claim_1: Field,
    valid_from: u64,
    valid_until: u64,
    issuer_signature: [u8; 64],
    // === Private Predicate Request Inputs ===
    required_0: Field,
    required_1: Field,
    flag_required: bool,
    path_index: Field,
    siblings: [Field; 32],
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
        "holder commitment does not match binding key",
    );
    assert(
        credential_holder_commitment == holder_commitment,
        "credential holder commitment mismatch",
    );

    let digest = compute_profile_digest(
        credential_holder_commitment,
        credential_id,
        predicate_type,
        claim_0,
        claim_1,
        valid_until,
    );
    let message_hash: [u8; 32] = digest.to_be_bytes();
    assert_issuer_signature(
        ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1,
        issuer_public_key_x,
        issuer_public_key_y,
        issuer_signature,
        message_hash,
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
        validity_period_contains(valid_from, valid_until, timestamp),
        "credential not valid at timestamp",
    );

    let predicate_ok = if predicate_type == PREDICATE_ACCREDITATION {
        // The institutional flag is bound to the issuer-signed claim_1 slot
        // (covered by compute_profile_digest), so it cannot be self-asserted.
        verify_accreditation(claim_0 as u8, required_0 as u8, flag_required, claim_1 != 0)
    } else if predicate_type == PREDICATE_SOURCE_OF_FUNDS {
        verify_source_of_funds(claim_0, set_root, path_index, siblings)
    } else if predicate_type == PREDICATE_TAX_RESIDENCY {
        verify_tax_residency(
            claim_0,
            set_root,
            path_index,
            siblings,
            claim_1 as u64,
            required_1 as u64,
        )
    } else if predicate_type == PREDICATE_SANCTIONS_CLEARANCE {
        verify_sanctions_clearance(
            claim_0 as u16,
            set_root,
            predecessor_code,
            predecessor_path_index,
            predecessor_siblings,
            successor_code,
            successor_path_index,
            successor_siblings,
        )
    } else {
        false
    };
    assert(predicate_ok, "predicate-specific requirement failed");

    let expected_claim_binding = compute_profile_claim_binding(
        predicate_type,
        required_0,
        required_1,
        flag_required,
        proof_context,
        timestamp,
    );
    assert(expected_claim_binding == claim_binding, "claim binding mismatch");
}

#[test]
fn test_accreditation_rules() {
    assert(verify_accreditation(2, 1, false, false), "level should satisfy");
    assert(verify_accreditation(3, 2, true, true), "institutional flag should satisfy");
    assert(!verify_accreditation(1, 2, false, false), "low level must fail");
    assert(!verify_accreditation(3, 2, true, false), "missing institutional flag must fail");
}

#[test]
fn test_source_of_funds_membership() {
    let siblings = [0; 32];
    let source_code: Field = 7;
    let root = zkc_lib::compute_merkle_root(source_code, 0, siblings);
    assert(verify_source_of_funds(source_code, root, 0, siblings), "source membership must verify");
    assert(!verify_source_of_funds(8, root, 0, siblings), "wrong source must fail");
}

#[test]
fn test_tax_residency_rules() {
    let siblings = [0; 32];
    let tax_code: Field = 840;
    let root = zkc_lib::compute_merkle_root(tax_code, 0, siblings);
    assert(
        verify_tax_residency(tax_code, root, 0, siblings, 2026, 2025),
        "tax jurisdiction and year must satisfy",
    );
    assert(
        !verify_tax_residency(tax_code, root, 0, siblings, 2024, 2025),
        "old tax year must fail",
    );
}

#[test]
fn test_sanctions_sorted_neighbor_exclusion() {
    let mut predecessor_siblings = [0; 32];
    let mut successor_siblings = [0; 32];
    let predecessor_code: u16 = 100;
    let subject_code: u16 = 150;
    let successor_code: u16 = 200;
    predecessor_siblings[0] = successor_code as Field;
    successor_siblings[0] = predecessor_code as Field;
    let root = zkc_lib::compute_merkle_root(predecessor_code as Field, 0, predecessor_siblings);
    assert(
        verify_sanctions_clearance(
            subject_code,
            root,
            predecessor_code,
            0,
            predecessor_siblings,
            successor_code,
            1,
            successor_siblings,
        ),
        "subject between blocked-list neighbors must prove clearance",
    );
}

// =============================================================================
// Full-circuit test fixtures
//
// Signed by the deterministic ZKC test issuer (tools/zkc_test_issuer.py).
// The profile digest KATs below pin the exact messages the signatures cover.
// =============================================================================

struct ProfileFixture {
    holder_commitment: Field,
    claim_binding: Field,
    proof_context: Field,
    predicate_type: u8,
    set_root: Field,
    accumulator_root: Field,
    accumulator_epoch: u64,
    timestamp: u64,
    current_epoch: u64,
    issuer_public_key_x: [u8; 32],
    issuer_public_key_y: [u8; 32],
    credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_id: Field,
    claim_0: Field,
    claim_1: Field,
    valid_from: u64,
    valid_until: u64,
    issuer_signature: [u8; 64],
    required_0: Field,
    required_1: Field,
    flag_required: bool,
    path_index: Field,
    siblings: [Field; 32],
    predecessor_code: u16,
    predecessor_path_index: Field,
    predecessor_siblings: [Field; 32],
    successor_code: u16,
    successor_path_index: Field,
    successor_siblings: [Field; 32],
    nonrevocation_siblings: [Field; 32],
    nonrevocation_path_index: Field,
}

global TEST_ISSUER_PUBLIC_KEY_X: [u8; 32] = [
    19, 16, 254, 66, 183, 223, 40, 186, 233, 29, 24, 232, 127, 122, 47, 12, 80, 95, 213, 226, 0, 86,
    217, 90, 75, 106, 133, 184, 217, 73, 228, 89,
];
global TEST_ISSUER_PUBLIC_KEY_Y: [u8; 32] = [
    80, 44, 64, 253, 27, 195, 61, 45, 190, 51, 103, 181, 207, 63, 72, 205, 155, 106, 202, 3, 83,
    203, 157, 52, 179, 22, 55, 20, 107, 221, 26, 134,
];

fn base_profile_fixture(
    predicate_type: u8,
    claim_0: Field,
    claim_1: Field,
    required_0: Field,
    required_1: Field,
    flag_required: bool,
    issuer_signature: [u8; 64],
) -> ProfileFixture {
    let credential_binding_key: Field =
        0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105;
    let holder_commitment: Field =
        0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf;
    let credential_id: Field = 42;
    let proof_context: Field = 777;
    let timestamp: u64 = 12345;
    let claim_binding = compute_profile_claim_binding(
        predicate_type,
        required_0,
        required_1,
        flag_required,
        proof_context,
        timestamp,
    );
    let nonrevocation_siblings = [0; 32];
    let accumulator_root = zkc_lib::compute_merkle_root(credential_id, 0, nonrevocation_siblings);

    ProfileFixture {
        holder_commitment,
        claim_binding,
        proof_context,
        predicate_type,
        set_root: 0,
        accumulator_root,
        accumulator_epoch: 100,
        timestamp,
        current_epoch: 105,
        issuer_public_key_x: TEST_ISSUER_PUBLIC_KEY_X,
        issuer_public_key_y: TEST_ISSUER_PUBLIC_KEY_Y,
        credential_binding_key,
        credential_holder_commitment: holder_commitment,
        credential_id,
        claim_0,
        claim_1,
        valid_from: 1000,
        valid_until: 2000000,
        issuer_signature,
        required_0,
        required_1,
        flag_required,
        path_index: 0,
        siblings: [0; 32],
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

fn valid_accreditation_fixture() -> ProfileFixture {
    // claim_0 = accreditation level 3, claim_1 = institutional flag (1).
    base_profile_fixture(
        PREDICATE_ACCREDITATION,
        3,
        1,
        2,
        0,
        true,
        [
            27, 250, 49, 216, 197, 113, 237, 128, 157, 91, 146, 0, 38, 27, 37, 86, 97, 232, 233,
            125, 228, 79, 193, 168, 55, 136, 50, 105, 57, 42, 184, 226, 95, 131, 106, 224, 60, 253,
            87, 2, 136, 135, 118, 149, 192, 4, 149, 224, 229, 11, 28, 201, 37, 251, 89, 135, 66, 74,
            50, 97, 250, 7, 206, 167,
        ],
    )
}

fn non_institutional_accreditation_fixture() -> ProfileFixture {
    // claim_0 = accreditation level 3, claim_1 = institutional flag (0):
    // the issuer signed a NON-institutional credential.
    base_profile_fixture(
        PREDICATE_ACCREDITATION,
        3,
        0,
        2,
        0,
        false,
        [
            210, 67, 123, 229, 139, 47, 26, 151, 35, 36, 89, 42, 212, 207, 112, 130, 135, 104, 175,
            231, 36, 169, 208, 30, 236, 26, 82, 165, 204, 115, 194, 49, 82, 63, 149, 214, 24, 223,
            150, 46, 228, 224, 70, 52, 90, 224, 46, 27, 144, 114, 111, 36, 130, 234, 214, 16, 14,
            180, 161, 129, 237, 21, 128, 87,
        ],
    )
}

fn valid_source_of_funds_fixture() -> ProfileFixture {
    // claim_0 = source code 7, member of the verifier's accepted-source set.
    let mut f = base_profile_fixture(
        PREDICATE_SOURCE_OF_FUNDS,
        7,
        0,
        0,
        0,
        false,
        [
            240, 41, 154, 175, 135, 179, 179, 123, 15, 180, 51, 68, 247, 96, 59, 164, 43, 71, 160,
            3, 153, 124, 87, 214, 219, 132, 254, 171, 186, 40, 7, 119, 26, 116, 177, 238, 223, 63,
            75, 34, 124, 137, 81, 102, 155, 43, 180, 99, 75, 151, 230, 119, 14, 199, 149, 189, 67,
            162, 13, 159, 81, 64, 131, 31,
        ],
    );
    f.set_root = zkc_lib::compute_merkle_root(f.claim_0, 0, f.siblings);
    f
}

fn run_profile_main(f: ProfileFixture) {
    main(
        f.holder_commitment,
        f.claim_binding,
        f.proof_context,
        f.predicate_type,
        f.set_root,
        f.accumulator_root,
        f.accumulator_epoch,
        f.timestamp,
        f.current_epoch,
        f.issuer_public_key_x,
        f.issuer_public_key_y,
        f.credential_binding_key,
        f.credential_holder_commitment,
        f.credential_id,
        f.claim_0,
        f.claim_1,
        f.valid_from,
        f.valid_until,
        f.issuer_signature,
        f.required_0,
        f.required_1,
        f.flag_required,
        f.path_index,
        f.siblings,
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
fn kat_profile_digests() {
    // Pins the credential digests the test issuer signatures cover.
    // Regenerate signatures with tools/zkc_test_issuer.py if these change.
    let holder: Field = 0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf;
    assert(
        compute_profile_digest(holder, 42, PREDICATE_ACCREDITATION, 3, 1, 2000000)
            == 0x2dc81a5616770b2ceef674b5cc7b14b0a74f3441fd04afcbbfdf4113eae72fd7,
        "accreditation digest KAT mismatch",
    );
    assert(
        compute_profile_digest(holder, 42, PREDICATE_ACCREDITATION, 3, 0, 2000000)
            == 0x2605527f864b40b25cd08f360f6c142ba4450e5067e966f4404e5053202c88cb,
        "non-institutional accreditation digest KAT mismatch",
    );
    assert(
        compute_profile_digest(holder, 42, PREDICATE_SOURCE_OF_FUNDS, 7, 0, 2000000)
            == 0x06bd842d08c7c2c3e713f312308efc5d8b0bc2c818684916d9a8ae12d35a17be,
        "source-of-funds digest KAT mismatch",
    );
    assert(
        compute_profile_digest(holder, 42, PREDICATE_TAX_RESIDENCY, 840, 2026, 2000000)
            == 0x212faadcde940e4e4beb145a438eddf2aa9b18b79a2a5bc0bd3ef9f4a6ed6dfe,
        "tax residency digest KAT mismatch",
    );
    assert(
        compute_profile_digest(holder, 42, PREDICATE_SANCTIONS_CLEARANCE, 150, 0, 2000000)
            == 0x21a39da221c61b87c10e0de193553bf59d4a51d7e69749802d69714f07a37295,
        "sanctions clearance digest KAT mismatch",
    );
}

#[test]
fn kat_flag_required_claim_bindings() {
    assert(
        compute_profile_claim_binding(PREDICATE_ACCREDITATION, 2, 0, false, 777, 12345)
            == 0x2658922a90baec88a41740805ebf83e157d143e7c34ce27c97d459a01321e617,
        "flagRequired=false claim-binding KAT mismatch",
    );
    assert(
        compute_profile_claim_binding(PREDICATE_ACCREDITATION, 2, 0, true, 777, 12345)
            == 0x0929a36b948240f87847bc2d150d7c86aa593e67750ba4d1447842b0aedde520,
        "flagRequired=true claim-binding KAT mismatch",
    );
}

fn valid_tax_residency_fixture() -> ProfileFixture {
    // claim_0 = tax jurisdiction 840, claim_1 = tax year 2026; verifier
    // requires membership of the accepted set and tax year >= 2025.
    let mut f = base_profile_fixture(
        PREDICATE_TAX_RESIDENCY,
        840,
        2026,
        0,
        2025,
        false,
        [
            253, 12, 136, 194, 224, 183, 15, 28, 143, 198, 1, 79, 247, 51, 201, 2, 139, 232, 20,
            248, 176, 103, 76, 41, 36, 113, 164, 213, 206, 96, 202, 249, 46, 60, 47, 40, 249, 128,
            200, 15, 138, 240, 136, 244, 154, 94, 232, 30, 154, 244, 97, 148, 246, 204, 110, 200,
            225, 217, 241, 157, 37, 206, 132, 145,
        ],
    );
    f.set_root = zkc_lib::compute_merkle_root(f.claim_0, 0, f.siblings);
    f
}

fn valid_sanctions_clearance_fixture() -> ProfileFixture {
    // claim_0 = subject screening code 150; the blocked set holds sorted
    // neighbors 100 and 200, so 150 proves non-membership.
    let mut f = base_profile_fixture(
        PREDICATE_SANCTIONS_CLEARANCE,
        150,
        0,
        0,
        0,
        false,
        [
            125, 70, 97, 23, 176, 109, 116, 85, 150, 47, 144, 179, 10, 124, 1, 82, 231, 128, 168,
            201, 105, 230, 52, 208, 178, 176, 177, 8, 242, 0, 112, 83, 109, 117, 44, 189, 171, 130,
            221, 83, 223, 61, 226, 109, 187, 208, 91, 172, 89, 60, 122, 56, 43, 147, 30, 186, 115,
            17, 99, 221, 255, 247, 227, 213,
        ],
    );
    f.predecessor_code = 100;
    f.successor_code = 200;
    let mut predecessor_siblings = [0; 32];
    let mut successor_siblings = [0; 32];
    predecessor_siblings[0] = f.successor_code as Field;
    successor_siblings[0] = f.predecessor_code as Field;
    f.predecessor_siblings = predecessor_siblings;
    f.successor_siblings = successor_siblings;
    f.predecessor_path_index = 0;
    f.successor_path_index = 1;
    f.set_root = zkc_lib::compute_merkle_root(f.predecessor_code as Field, 0, predecessor_siblings);
    f
}

#[test]
fn test_valid_tax_residency_predicate() {
    run_profile_main(valid_tax_residency_fixture());
}

#[test]
fn test_valid_sanctions_clearance_predicate() {
    run_profile_main(valid_sanctions_clearance_fixture());
}

#[test(should_fail_with = "predicate-specific requirement failed")]
fn test_tax_residency_rejects_old_tax_year() {
    let mut f = valid_tax_residency_fixture();
    f.required_1 = 2027;
    f.claim_binding = compute_profile_claim_binding(
        f.predicate_type,
        f.required_0,
        f.required_1,
        f.flag_required,
        f.proof_context,
        f.timestamp,
    );
    run_profile_main(f);
}

#[test(should_fail_with = "predicate-specific requirement failed")]
fn test_tax_residency_rejects_unaccepted_jurisdiction() {
    // The verifier's accepted tax-jurisdiction set does not contain the
    // credential's jurisdiction.
    let mut f = valid_tax_residency_fixture();
    f.set_root = zkc_lib::compute_merkle_root(826, 0, f.siblings);
    run_profile_main(f);
}

#[test(should_fail_with = "predicate-specific requirement failed")]
fn test_sanctions_rejects_sanctioned_subject() {
    // The blocked set contains the subject's screening code itself: no
    // sorted-neighbor witness can prove clearance.
    let mut f = valid_sanctions_clearance_fixture();
    f.set_root = zkc_lib::compute_merkle_root(f.claim_0, 0, [0; 32]);
    run_profile_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_tax_residency_rejects_tampered_issuer_signature() {
    let mut f = valid_tax_residency_fixture();
    f.issuer_signature[0] += 1;
    run_profile_main(f);
}

#[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
fn test_tax_residency_rejects_stale_accumulator_epoch() {
    let mut f = valid_tax_residency_fixture();
    f.current_epoch = f.accumulator_epoch + zkc_nonrevocation::MAX_EPOCH_LAG + 1;
    run_profile_main(f);
}

#[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
fn test_sanctions_rejects_stale_accumulator_epoch() {
    let mut f = valid_sanctions_clearance_fixture();
    f.current_epoch = f.accumulator_epoch + zkc_nonrevocation::MAX_EPOCH_LAG + 1;
    run_profile_main(f);
}

#[test]
fn test_valid_accreditation_predicate() {
    run_profile_main(valid_accreditation_fixture());
}

#[test]
fn test_valid_source_of_funds_predicate() {
    run_profile_main(valid_source_of_funds_fixture());
}

#[test(should_fail_with = "predicate-specific requirement failed")]
fn test_accreditation_rejects_insufficient_level() {
    let mut f = valid_accreditation_fixture();
    f.required_0 = 4;
    f.claim_binding = compute_profile_claim_binding(
        f.predicate_type,
        f.required_0,
        f.required_1,
        f.flag_required,
        f.proof_context,
        f.timestamp,
    );
    run_profile_main(f);
}

#[test(should_fail_with = "predicate-specific requirement failed")]
fn test_accreditation_rejects_missing_institutional_flag() {
    // The issuer signed claim_1 = 0 (non-institutional). With the flag bound
    // to the signed claims, a prover holding this credential cannot satisfy
    // an institutional requirement no matter what request inputs they choose:
    // the former self-asserted `flag_actual` input no longer exists.
    let mut f = non_institutional_accreditation_fixture();
    f.flag_required = true;
    run_profile_main(f);
}

#[test(should_fail_with = "claim binding mismatch")]
fn test_profile_rejects_flag_required_downgrade() {
    // The request commits to true, but the malicious witness tries false.
    let mut f = non_institutional_accreditation_fixture();
    f.claim_binding = compute_profile_claim_binding(
        f.predicate_type,
        f.required_0,
        f.required_1,
        true,
        f.proof_context,
        f.timestamp,
    );
    run_profile_main(f);
}

#[test]
fn test_non_institutional_accreditation_passes_without_flag_requirement() {
    // The same non-institutional credential is fine when the verifier does
    // not require the institutional flag.
    run_profile_main(non_institutional_accreditation_fixture());
}

#[test(should_fail_with = "predicate-specific requirement failed")]
fn test_source_of_funds_rejects_unacceptable_source() {
    // The verifier's accepted-source set does not contain the credential's
    // source code.
    let mut f = valid_source_of_funds_fixture();
    f.set_root = zkc_lib::compute_merkle_root(8, 0, f.siblings);
    run_profile_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_profile_rejects_tampered_issuer_signature() {
    let mut f = valid_accreditation_fixture();
    f.issuer_signature[0] += 1;
    run_profile_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_profile_rejects_wrong_issuer() {
    // A different (valid) issuer key: the original zkc_issuer_sig KAT key.
    let mut f = valid_accreditation_fixture();
    f.issuer_public_key_x = [
        137, 81, 38, 98, 181, 144, 46, 180, 102, 61, 191, 66, 140, 98, 244, 92, 229, 44, 211, 23,
        36, 201, 121, 32, 86, 185, 98, 216, 108, 62, 37, 26,
    ];
    f.issuer_public_key_y = [
        34, 85, 29, 119, 46, 134, 16, 31, 56, 87, 20, 235, 116, 171, 39, 5, 122, 99, 146, 254, 158,
        5, 185, 45, 152, 119, 236, 243, 137, 31, 179, 114,
    ];
    run_profile_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_profile_rejects_tampered_credential_claims() {
    // Inflating the signed accreditation level invalidates the digest.
    let mut f = valid_accreditation_fixture();
    f.claim_0 = 4;
    run_profile_main(f);
}

#[test(should_fail_with = "claim binding mismatch")]
fn test_profile_rejects_wrong_claim_binding() {
    let mut f = valid_source_of_funds_fixture();
    f.claim_binding += 1;
    run_profile_main(f);
}

#[test(should_fail_with = "holder commitment does not match binding key")]
fn test_profile_rejects_wrong_holder() {
    let mut f = valid_source_of_funds_fixture();
    f.credential_binding_key += 1;
    run_profile_main(f);
}

#[test(should_fail_with = "credential not valid at timestamp")]
fn test_profile_rejects_expired_credential() {
    let mut f = valid_accreditation_fixture();
    f.timestamp = f.valid_until + 1;
    f.claim_binding = compute_profile_claim_binding(
        f.predicate_type,
        f.required_0,
        f.required_1,
        f.flag_required,
        f.proof_context,
        f.timestamp,
    );
    run_profile_main(f);
}
