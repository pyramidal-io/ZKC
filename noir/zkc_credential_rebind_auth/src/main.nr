// =============================================================================
// ZKC Authenticated Credential Rebind Circuit (linkable profile)
//
// zkc:proof:credential_rebind:v3 -- spec section 7.4.2, ADR 0004.
//
// Proves that an ISSUER-CREATED, NON-REVOKED credential bound to the public
// old holder commitment migrates to the public new holder commitment: the
// issuer signature is verified over the zkc:attestation:credential-rebind:v1
// transcript recomputed from constrained fields, accumulator membership is
// proven for the same credential id, and both holder commitments are derived
// from private binding keys. Additive successor to the deprecated
// zkc_credential_rebind / zkc_credential_rebind_binding_v2 statements, which
// authenticated no credential at all.
// =============================================================================

use zkc_rebind_auth::{
    assert_authenticated_rebind, compute_rebind_attestation_digest, compute_rebind_claim_binding,
};

// Private proof-type domain: string_to_field("zkc:proof:credential_rebind:v3").
// Gives this statement a distinct constraint system and verification key.
global STATEMENT_DOMAIN: Field = 0x14d9d998a4b387195d0525f53b070cda77f50c2f608aa29b83b48c760307424a;

fn main(
    // === Public Inputs (spec section 7.4.2 order) ===
    old_holder_commitment: pub Field,
    new_holder_commitment: pub Field,
    credential_id: pub Field,
    issuer_id_hash: pub Field,
    schema_id_hash: pub Field,
    proof_context: pub Field,
    timestamp: pub u64,
    claim_binding: pub Field,
    accumulator_root: pub Field,
    accumulator_epoch: pub u64,
    current_epoch: pub u64,
    issuer_public_key_x: pub [u8; 32],
    issuer_public_key_y: pub [u8; 32],
    // === Private Inputs ===
    old_credential_binding_key: Field,
    new_credential_binding_key: Field,
    credential_valid_from: u64,
    credential_valid_until: u64,
    issuer_signature: [u8; 64],
    nonrevocation_siblings: [Field; 32],
    nonrevocation_path_index: Field,
    statement_domain: Field,
) {
    assert(statement_domain == STATEMENT_DOMAIN, "statement domain mismatch");

    assert_authenticated_rebind(
        old_holder_commitment,
        new_holder_commitment,
        credential_id,
        issuer_id_hash,
        schema_id_hash,
        proof_context,
        timestamp,
        accumulator_root,
        accumulator_epoch,
        current_epoch,
        issuer_public_key_x,
        issuer_public_key_y,
        old_credential_binding_key,
        new_credential_binding_key,
        credential_valid_from,
        credential_valid_until,
        issuer_signature,
        nonrevocation_siblings,
        nonrevocation_path_index,
    );

    let expected_claim_binding = compute_rebind_claim_binding(
        old_holder_commitment,
        new_holder_commitment,
        credential_id,
        proof_context,
        timestamp,
    );
    assert(expected_claim_binding == claim_binding, "claim binding mismatch");
}

struct RebindFixture {
    old_holder_commitment: Field,
    new_holder_commitment: Field,
    credential_id: Field,
    issuer_id_hash: Field,
    schema_id_hash: Field,
    proof_context: Field,
    timestamp: u64,
    claim_binding: Field,
    accumulator_root: Field,
    accumulator_epoch: u64,
    current_epoch: u64,
    issuer_public_key_x: [u8; 32],
    issuer_public_key_y: [u8; 32],
    old_credential_binding_key: Field,
    new_credential_binding_key: Field,
    credential_valid_from: u64,
    credential_valid_until: u64,
    issuer_signature: [u8; 64],
    nonrevocation_siblings: [Field; 32],
    nonrevocation_path_index: Field,
    statement_domain: Field,
}

// Shared authenticated fixture (credential_rebind_attestation_v1 vector):
// holder seed 42, new seed 99, credential id 42, issuer did:zkc:test-issuer,
// schema zkc:cred:kyc:v1, validity 1000..2000000, TEST-ONLY issuer key.
global OLD_CBK: Field = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105;
global OLD_HOLDER: Field = 0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf;
global NEW_CBK: Field = 0x062c4390e12a851c21fcd86d13f3f823cdfe520007d641f107af2ccb31a74100;
global NEW_HOLDER: Field = 0x1cad89fa2a3fc0eae6c094c9949aa7342838cc220f500e993563a2c16ab7e938;
global CREDENTIAL_ID: Field = 42;
global ISSUER_ID_HASH: Field = 0x1ab792b1777260d562c10d81aa74a124c5438335065138da7e2a2e7a63b0a911;
global SCHEMA_ID_HASH: Field = 0x2625058d446eada5e7efa789c1356af408e40278649d8504c2088c764e85d5e2;
global VALID_FROM: u64 = 1000;
global VALID_UNTIL: u64 = 2000000;
global PROOF_CONTEXT: Field = 777;
global TIMESTAMP: u64 = 12345;
global ACCUMULATOR_EPOCH: u64 = 100;
global CURRENT_EPOCH: u64 = 105;

fn issuer_public_key_x() -> [u8; 32] {
    [
        19, 16, 254, 66, 183, 223, 40, 186, 233, 29, 24, 232, 127, 122, 47, 12, 80, 95, 213, 226, 0,
        86, 217, 90, 75, 106, 133, 184, 217, 73, 228, 89,
    ]
}

fn issuer_public_key_y() -> [u8; 32] {
    [
        80, 44, 64, 253, 27, 195, 61, 45, 190, 51, 103, 181, 207, 63, 72, 205, 155, 106, 202, 3, 83,
        203, 157, 52, 179, 22, 55, 20, 107, 221, 26, 134,
    ]
}

fn issuer_signature() -> [u8; 64] {
    [
        107, 176, 155, 189, 115, 38, 41, 121, 113, 226, 76, 201, 200, 116, 247, 35, 9, 9, 20, 224,
        125, 103, 56, 89, 144, 131, 252, 227, 75, 246, 185, 236, 97, 133, 246, 9, 197, 174, 124, 39,
        38, 247, 251, 20, 66, 203, 221, 208, 60, 63, 178, 38, 182, 41, 150, 135, 175, 188, 105, 173,
        8, 138, 179, 247,
    ]
}

fn valid_fixture() -> RebindFixture {
    let siblings = [0; 32];
    let accumulator_root = zkc_lib::compute_merkle_root(CREDENTIAL_ID, 0, siblings);
    RebindFixture {
        old_holder_commitment: OLD_HOLDER,
        new_holder_commitment: NEW_HOLDER,
        credential_id: CREDENTIAL_ID,
        issuer_id_hash: ISSUER_ID_HASH,
        schema_id_hash: SCHEMA_ID_HASH,
        proof_context: PROOF_CONTEXT,
        timestamp: TIMESTAMP,
        claim_binding: compute_rebind_claim_binding(
            OLD_HOLDER,
            NEW_HOLDER,
            CREDENTIAL_ID,
            PROOF_CONTEXT,
            TIMESTAMP,
        ),
        accumulator_root,
        accumulator_epoch: ACCUMULATOR_EPOCH,
        current_epoch: CURRENT_EPOCH,
        issuer_public_key_x: issuer_public_key_x(),
        issuer_public_key_y: issuer_public_key_y(),
        old_credential_binding_key: OLD_CBK,
        new_credential_binding_key: NEW_CBK,
        credential_valid_from: VALID_FROM,
        credential_valid_until: VALID_UNTIL,
        issuer_signature: issuer_signature(),
        nonrevocation_siblings: siblings,
        nonrevocation_path_index: 0,
        statement_domain: STATEMENT_DOMAIN,
    }
}

fn rebind_claim_binding(f: RebindFixture) -> Field {
    compute_rebind_claim_binding(
        f.old_holder_commitment,
        f.new_holder_commitment,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    )
}

fn run_main(f: RebindFixture) {
    main(
        f.old_holder_commitment,
        f.new_holder_commitment,
        f.credential_id,
        f.issuer_id_hash,
        f.schema_id_hash,
        f.proof_context,
        f.timestamp,
        f.claim_binding,
        f.accumulator_root,
        f.accumulator_epoch,
        f.current_epoch,
        f.issuer_public_key_x,
        f.issuer_public_key_y,
        f.old_credential_binding_key,
        f.new_credential_binding_key,
        f.credential_valid_from,
        f.credential_valid_until,
        f.issuer_signature,
        f.nonrevocation_siblings,
        f.nonrevocation_path_index,
        f.statement_domain,
    );
}

#[test]
fn test_valid_authenticated_rebind() {
    let f = valid_fixture();
    // KATs pinned by tests/vectors/zkc_core_vectors.json credential_rebind_attestation_v1.
    assert(
        compute_rebind_attestation_digest(
            f.issuer_id_hash,
            f.schema_id_hash,
            f.old_holder_commitment,
            f.credential_id,
            f.credential_valid_from,
            f.credential_valid_until,
        )
            == 0x246ce8deb13dab22a5c07b087024aa58dd42732cd17003f17a003e94638639f7,
        "rebind attestation digest KAT mismatch",
    );
    assert(
        f.claim_binding == 0x2a4c18b8312ee5e45735df6f4e8bb2e56805da612036f3b8f64ff34025e528c5,
        "linkable rebind claim binding KAT mismatch",
    );
    assert(
        f.statement_domain == 0x14d9d998a4b387195d0525f53b070cda77f50c2f608aa29b83b48c760307424a,
        "linkable statement domain KAT mismatch",
    );
    run_main(f);
}

#[test(should_fail_with = "statement domain mismatch")]
fn test_rejects_wrong_statement_domain() {
    let mut f = valid_fixture();
    f.statement_domain += 1;
    run_main(f);
}

// A zero signature is rejected by the ECDSA black box itself, one level below
// the "invalid issuer signature" assertion, so this test pins that exact
// lower-level message. Either way the statement fails closed: an absent
// signature can never authenticate a credential.
#[test(should_fail_with = "Signature provided for ECDSA verification is zero")]
fn test_rejects_zero_signature() {
    let mut f = valid_fixture();
    f.issuer_signature = [0; 64];
    run_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_rejects_tampered_signature() {
    let mut f = valid_fixture();
    f.issuer_signature[0] += 1;
    run_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_rejects_changed_credential_id() {
    let mut f = valid_fixture();
    f.credential_id += 1;
    f.accumulator_root = zkc_lib::compute_merkle_root(f.credential_id, 0, f.nonrevocation_siblings);
    f.claim_binding = rebind_claim_binding(f);
    run_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_rejects_changed_issuer() {
    let mut f = valid_fixture();
    f.issuer_id_hash += 1;
    run_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_rejects_changed_schema() {
    let mut f = valid_fixture();
    f.schema_id_hash += 1;
    run_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_rejects_changed_valid_from() {
    let mut f = valid_fixture();
    f.credential_valid_from += 1;
    run_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_rejects_changed_valid_until() {
    let mut f = valid_fixture();
    f.credential_valid_until += 1;
    run_main(f);
}

#[test(should_fail_with = "invalid issuer signature")]
fn test_rejects_credential_issued_to_a_different_holder() {
    // An attacker with a consistent key pair of their own: the transcript is
    // recomputed over THEIR holder commitment, which the issuer never signed.
    let mut f = valid_fixture();
    f.old_credential_binding_key = zkc_lib::derive_credential_binding_key(0xBAD5EED);
    f.old_holder_commitment = zkc_lib::derive_holder_commitment(f.old_credential_binding_key);
    f.claim_binding = rebind_claim_binding(f);
    run_main(f);
}

#[test(should_fail_with = "old holder commitment does not match old binding key")]
fn test_rejects_wrong_old_binding_key() {
    let mut f = valid_fixture();
    f.old_credential_binding_key += 1;
    run_main(f);
}

#[test(should_fail_with = "new holder commitment does not match new binding key")]
fn test_rejects_wrong_new_binding_key() {
    let mut f = valid_fixture();
    f.new_credential_binding_key += 1;
    run_main(f);
}

#[test(should_fail_with = "rebind must change holder commitment")]
fn test_rejects_unchanged_holder() {
    let mut f = valid_fixture();
    f.new_credential_binding_key = f.old_credential_binding_key;
    f.new_holder_commitment = f.old_holder_commitment;
    f.claim_binding = rebind_claim_binding(f);
    run_main(f);
}

#[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
fn test_rejects_revoked_membership() {
    let mut f = valid_fixture();
    f.accumulator_root += 1;
    run_main(f);
}

#[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
fn test_rejects_stale_epoch() {
    let mut f = valid_fixture();
    f.current_epoch = f.accumulator_epoch + zkc_nonrevocation::MAX_EPOCH_LAG + 1;
    run_main(f);
}

#[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
fn test_rejects_future_epoch() {
    let mut f = valid_fixture();
    f.accumulator_epoch = f.current_epoch + 1;
    run_main(f);
}

#[test(should_fail_with = "credential is not valid at timestamp")]
fn test_rejects_expired_credential() {
    let mut f = valid_fixture();
    f.timestamp = f.credential_valid_until + 1;
    f.claim_binding = rebind_claim_binding(f);
    run_main(f);
}

#[test(should_fail_with = "credential is not valid at timestamp")]
fn test_rejects_not_yet_valid_credential() {
    let mut f = valid_fixture();
    f.timestamp = f.credential_valid_from - 1;
    f.claim_binding = rebind_claim_binding(f);
    run_main(f);
}

#[test(should_fail_with = "credential is not valid at timestamp")]
fn test_rejects_zero_timestamp() {
    let mut f = valid_fixture();
    f.timestamp = 0;
    f.claim_binding = rebind_claim_binding(f);
    run_main(f);
}

#[test(should_fail_with = "proof context must be non-zero")]
fn test_rejects_zero_proof_context() {
    let mut f = valid_fixture();
    f.proof_context = 0;
    f.claim_binding = rebind_claim_binding(f);
    run_main(f);
}

#[test(should_fail_with = "claim binding mismatch")]
fn test_rejects_wrong_claim_binding() {
    let mut f = valid_fixture();
    f.claim_binding += 1;
    run_main(f);
}

#[test(should_fail_with = "claim binding mismatch")]
fn test_rejects_swapped_context() {
    let mut f = valid_fixture();
    f.proof_context += 1;
    run_main(f);
}
