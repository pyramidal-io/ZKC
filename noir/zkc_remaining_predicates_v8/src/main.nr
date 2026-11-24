// =============================================================================
// ZKC Remaining Predicate Profiles v8 (validity-bound hardened presentations)
//
// A shared circuit profile for accreditation, source-of-funds, tax-residency,
// and sanctions-clearance predicates. Predicate-specific rules are selected by
// `predicate_type`; all profiles share holder binding, issuer signature,
// non-revocation, validity, and claim binding.
//
// Presentation-profile ladder (design section 4.1). Public input index 0 is
// now presentation_pseudonym and index 1 is scope_id; holder_commitment is a
// private witness. scope_id == 0 is the anonymous sentinel (pseudonym forced
// to 0); scope_id != 0 is a scoped presentation whose pseudonym derives from
// the credential binding key and scope. predicate_type keeps its index (now
// index 5). The v1 circuit (holder_commitment public) stays frozen as the
// consent-gated linkable profile.
// =============================================================================

use zkc_issuer_sig::{assert_issuer_signature, ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1};
use zkc_lib::{
    assert_presentation_binding, derive_holder_commitment, DOMAIN_ZKC_CLAIM, poseidon2, poseidon3,
    poseidon4,
};
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
    valid_from: u64,
    valid_until: u64,
) -> Field {
    let header = poseidon4(
        holder_commitment,
        credential_id,
        predicate_type as Field,
        valid_from as Field,
    );
    poseidon4(header, claim_0, claim_1, valid_until as Field)
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
    (source_code != 0)
        & zkc_lib::verify_merkle_membership(source_code, path_index, siblings, accepted_root)
}

pub fn verify_tax_residency(
    tax_jurisdiction_code: Field,
    accepted_root: Field,
    path_index: Field,
    siblings: [Field; 32],
    credential_tax_year: u64,
    required_min_tax_year: u64,
) -> bool {
    (tax_jurisdiction_code != 0)
        & zkc_lib::verify_merkle_membership(
            tax_jurisdiction_code,
            path_index,
            siblings,
            accepted_root,
        )
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
        & (successor_path_index == predecessor_path_index + 1)
}

fn main(
    // === Public Inputs (v2 order, design section 4.1) ===
    presentation_pseudonym: pub Field, // was: holder_commitment (now private)
    scope_id: pub Field, // new: 0 = anonymous sentinel, else scoped
    claim_binding: pub Field,
    proof_context: pub Field,
    set_root: pub Field,
    predicate_type: pub u8, // keeps index 5 (analogous to membership_type)
    accumulator_root: pub Field,
    accumulator_epoch: pub u64,
    timestamp: pub u64,
    current_epoch: pub u64,
    issuer_public_key_x: pub [u8; 32],
    issuer_public_key_y: pub [u8; 32],
    // === Private Presentation Witness ===
    holder_commitment: Field, // moved from public
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

    // Profile binding: anonymous sentinel (scope_id 0 => pseudonym 0) or a
    // scoped pseudonym derived from the credential binding key and scope.
    assert_presentation_binding(presentation_pseudonym, scope_id, credential_binding_key);

    let digest = compute_profile_digest(
        credential_holder_commitment,
        credential_id,
        predicate_type,
        claim_0,
        claim_1,
        valid_from,
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
fn test_source_of_funds_rejects_zero_padding_leaf() {
    let siblings = [0; 32];
    let root = zkc_lib::compute_merkle_root(0, 0, siblings);
    assert(
        zkc_lib::verify_merkle_membership(0, 0, siblings, root),
        "zero must satisfy raw zero-padded membership precondition",
    );
    assert(
        !verify_source_of_funds(0, root, 0, siblings),
        "zero padding must not be a valid source code",
    );
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
fn test_tax_residency_rejects_zero_padding_leaf() {
    let siblings = [0; 32];
    let root = zkc_lib::compute_merkle_root(0, 0, siblings);
    assert(
        zkc_lib::verify_merkle_membership(0, 0, siblings, root),
        "zero must satisfy raw zero-padded membership precondition",
    );
    assert(
        !verify_tax_residency(0, root, 0, siblings, 2026, 2025),
        "zero padding must not be a valid tax jurisdiction code",
    );
}

#[test]
fn test_high_nonzero_field_codes_are_accepted() {
    let siblings = [0; 32];
    let high_code: Field = 70000;
    let root = zkc_lib::compute_merkle_root(high_code, 0, siblings);
    assert(
        verify_source_of_funds(high_code, root, 0, siblings),
        "high nonzero source code must remain valid",
    );
    assert(
        verify_tax_residency(high_code, root, 0, siblings, 2026, 2025),
        "high nonzero tax jurisdiction code must remain valid",
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

#[test]
fn test_sanctions_rejects_nonadjacent_members() {
    let mut predecessor_siblings = [0; 32];
    let mut successor_siblings = [0; 32];
    let predecessor_code: u16 = 100;
    let subject_code: u16 = 150;
    let successor_code: u16 = 200;
    predecessor_siblings[1] = poseidon2(successor_code as Field, 0);
    successor_siblings[1] = poseidon2(predecessor_code as Field, 0);
    let root = zkc_lib::compute_merkle_root(predecessor_code as Field, 0, predecessor_siblings);
    assert(
        zkc_lib::verify_merkle_membership(predecessor_code as Field, 0, predecessor_siblings, root),
        "predecessor membership precondition must hold",
    );
    assert(
        zkc_lib::verify_merkle_membership(successor_code as Field, 2, successor_siblings, root),
        "successor membership precondition must hold",
    );
    assert(
        !verify_sanctions_clearance(
            subject_code,
            root,
            predecessor_code,
            0,
            predecessor_siblings,
            successor_code,
            2,
            successor_siblings,
        ),
        "nonadjacent blocked-set members must not prove clearance",
    );
}

// =============================================================================
// Full-circuit test fixtures
//
// Signed by the deterministic ZKC test issuer (tools/zkc_test_issuer.py).
// The profile digest KATs below pin the exact messages the signatures cover.
// =============================================================================

struct ProfileFixture {
    presentation_pseudonym: Field,
    scope_id: Field,
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

// Scoped presentation scope id for the seed-42 credential binding key. Cross-
// checked in zkc_lib against derive_presentation_pseudonym / poseidon3.
global SCOPED_SCOPE_ID: Field = 7;

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

    // Default fixture is a scoped presentation: pseudonym derived from cbk+scope.
    let scope_id = SCOPED_SCOPE_ID;
    let presentation_pseudonym =
        zkc_lib::derive_presentation_pseudonym(credential_binding_key, scope_id);

    ProfileFixture {
        presentation_pseudonym,
        scope_id,
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
            187, 93, 255, 156, 169, 61, 233, 117, 139, 188, 101, 207, 195, 8, 120, 198, 47, 186, 44,
            169, 88, 27, 103, 174, 239, 93, 58, 79, 189, 107, 2, 131, 95, 108, 230, 15, 22, 197, 57,
            121, 186, 221, 129, 21, 8, 239, 230, 161, 227, 38, 7, 9, 82, 127, 79, 47, 33, 172, 6,
            152, 127, 86, 116, 196,
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
            165, 67, 95, 248, 122, 136, 185, 99, 140, 251, 134, 176, 164, 246, 22, 208, 10, 246,
            172, 156, 49, 233, 159, 216, 231, 154, 71, 239, 202, 216, 8, 73, 88, 218, 169, 217, 54,
            56, 64, 252, 228, 107, 190, 188, 198, 183, 25, 110, 237, 5, 171, 11, 164, 185, 231, 225,
            152, 43, 141, 198, 79, 236, 56, 181,
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
            99, 250, 93, 29, 47, 31, 218, 168, 127, 248, 182, 242, 154, 146, 120, 118, 232, 178,
            147, 142, 119, 5, 20, 204, 159, 164, 154, 163, 14, 92, 232, 205, 2, 19, 179, 14, 30,
            202, 182, 235, 226, 192, 148, 159, 201, 26, 49, 159, 236, 53, 154, 164, 130, 166, 93,
            253, 249, 52, 154, 18, 230, 110, 252, 244,
        ],
    );
    f.set_root = zkc_lib::compute_merkle_root(f.claim_0, 0, f.siblings);
    f
}

fn run_profile_main(f: ProfileFixture) {
    main(
        f.presentation_pseudonym,
        f.scope_id,
        f.claim_binding,
        f.proof_context,
        f.set_root,
        f.predicate_type,
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

// --- Presentation-profile tests (design section 4.1) ---------------------------

#[test]
fn test_remaining_predicates_scoped_presentation_passes() {
    // Default fixture is scoped: pseudonym derives from cbk + scope_id != 0.
    let f = valid_source_of_funds_fixture();
    assert(f.scope_id != 0, "fixture must be scoped");
    run_profile_main(f);
}

#[test]
fn test_remaining_predicates_anonymous_presentation_passes() {
    // Anonymous sentinel: scope_id 0 forces pseudonym 0.
    let mut f = valid_source_of_funds_fixture();
    f.scope_id = 0;
    f.presentation_pseudonym = 0;
    run_profile_main(f);
}

#[test(should_fail_with = "anonymous profile must not carry a pseudonym")]
fn test_remaining_predicates_rejects_pseudonym_under_anonymous_sentinel() {
    // scope_id 0 with a non-zero pseudonym violates the sentinel rule.
    let mut f = valid_source_of_funds_fixture();
    f.scope_id = 0;
    f.presentation_pseudonym = 1;
    run_profile_main(f);
}

#[test(should_fail_with = "presentation pseudonym does not derive from binding key and scope")]
fn test_remaining_predicates_rejects_pseudonym_from_wrong_binding_key() {
    // Scoped pseudonym derived from a different cbk must not verify.
    let mut f = valid_source_of_funds_fixture();
    let wrong_cbk = f.credential_binding_key + 1;
    f.presentation_pseudonym = zkc_lib::derive_presentation_pseudonym(wrong_cbk, f.scope_id);
    run_profile_main(f);
}

#[test]
fn kat_profile_digests() {
    // Pins the credential digests the test issuer signatures cover.
    // Regenerate signatures with tools/zkc_test_issuer.py if these change.
    let holder: Field = 0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf;
    assert(
        compute_profile_digest(holder, 42, PREDICATE_ACCREDITATION, 3, 1, 1000, 2000000)
            == 0x2cf3e7bb34fb8b4cbec3cdb53207577497374512187df6cbfaec1f5d9ee2f49b,
        "accreditation digest KAT mismatch",
    );
    assert(
        compute_profile_digest(holder, 42, PREDICATE_ACCREDITATION, 3, 0, 1000, 2000000)
            == 0x15aaa0628222cdb633e8bd922da4ded6818fd516625877e614737e509c25f50e,
        "non-institutional accreditation digest KAT mismatch",
    );
    assert(
        compute_profile_digest(holder, 42, PREDICATE_SOURCE_OF_FUNDS, 7, 0, 1000, 2000000)
            == 0x14e94ef874f020dbfa424198c21aa9c28be22aef8f0df9c34f4919e787d33091,
        "source-of-funds digest KAT mismatch",
    );
    assert(
        compute_profile_digest(
            holder,
            42,
            PREDICATE_TAX_RESIDENCY,
            840,
            2026,
            1000,
            2000000,
        )
            == 0x0d06f040ec2ec68e770e951053f065ad2f7bea3c3bb1675898486deb37e201ba,
        "tax residency digest KAT mismatch",
    );
    assert(
        compute_profile_digest(
            holder,
            42,
            PREDICATE_SANCTIONS_CLEARANCE,
            150,
            0,
            1000,
            2000000,
        )
            == 0x05d25816247d59c3a8c94d5f875a9d6a1ba12a866cf42ae5d0db0e1f844f5bea,
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
            111, 248, 141, 29, 90, 173, 34, 113, 35, 199, 72, 250, 249, 79, 34, 37, 141, 158, 213,
            45, 246, 129, 167, 56, 103, 72, 155, 36, 96, 114, 1, 117, 78, 16, 1, 197, 17, 222, 141,
            159, 75, 246, 206, 182, 3, 228, 53, 40, 16, 161, 244, 106, 16, 197, 217, 73, 123, 193,
            123, 1, 171, 219, 146, 127,
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
            179, 119, 125, 220, 0, 16, 101, 147, 151, 127, 3, 117, 22, 32, 104, 18, 14, 196, 91,
            225, 137, 167, 235, 105, 90, 101, 73, 38, 188, 149, 79, 77, 36, 73, 141, 59, 144, 135,
            89, 36, 79, 108, 217, 134, 194, 172, 216, 34, 241, 124, 243, 245, 222, 185, 93, 140,
            103, 32, 234, 74, 111, 34, 45, 204,
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
fn test_sanctions_rejects_outer_member_attack_full() {
    let mut f = valid_sanctions_clearance_fixture();
    let mut predecessor_siblings = [0; 32];
    let mut successor_siblings = [0; 32];
    let left = poseidon2(f.predecessor_code as Field, 125);
    let right = poseidon2(f.successor_code as Field, 0);
    predecessor_siblings[0] = 125;
    predecessor_siblings[1] = right;
    successor_siblings[1] = left;
    f.predecessor_siblings = predecessor_siblings;
    f.successor_siblings = successor_siblings;
    f.predecessor_path_index = 0;
    f.successor_path_index = 2;
    f.set_root = zkc_lib::compute_merkle_root(
        f.predecessor_code as Field,
        f.predecessor_path_index,
        predecessor_siblings,
    );
    // The valid v8 signature, accumulator, claim and presentation bindings
    // are unchanged, and both blocked-set memberships resolve to the same
    // root. Only the selected outer members at paths 0 and 2 are not adjacent.
    run_profile_main(f);
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
fn test_profile_rejects_tampered_valid_from() {
    let mut f = valid_accreditation_fixture();
    f.valid_from -= 1;
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
