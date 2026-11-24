// =============================================================================
// ZKC Credential Rebind Circuit
//
// Proves a credential can migrate from an old holder commitment to a new holder
// commitment without revealing either credential binding key or any ZKA address.
// =============================================================================

use zkc_lib::{compute_claim_binding_3, derive_holder_commitment};

pub fn validity_period_contains(valid_from: u64, valid_until: u64, timestamp: u64) -> bool {
    (valid_from <= timestamp) & ((valid_until == 0) | (valid_until >= timestamp))
}

pub fn compute_rebind_claim_binding(
    old_holder_commitment: Field,
    new_holder_commitment: Field,
    credential_id: Field,
    proof_context: Field,
    timestamp: u64,
) -> Field {
    compute_claim_binding_3(
        old_holder_commitment,
        new_holder_commitment,
        credential_id,
        proof_context,
        timestamp as Field,
    )
}

fn main(
    // === Public Inputs ===
    old_holder_commitment: pub Field,
    new_holder_commitment: pub Field,
    credential_id: pub Field,
    issuer_id_hash: pub Field,
    schema_id_hash: pub Field,
    proof_context: pub Field,
    timestamp: pub u64,
    claim_binding: pub Field,
    // === Private Inputs ===
    old_credential_binding_key: Field,
    new_credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_issuer_id_hash: Field,
    credential_schema_id_hash: Field,
    credential_valid_from: u64,
    credential_valid_until: u64,
) {
    assert(
        derive_holder_commitment(old_credential_binding_key) == old_holder_commitment,
        "old holder commitment does not match old binding key",
    );
    assert(
        derive_holder_commitment(new_credential_binding_key) == new_holder_commitment,
        "new holder commitment does not match new binding key",
    );
    assert(old_holder_commitment != new_holder_commitment, "rebind must change holder commitment");
    assert(
        credential_holder_commitment == old_holder_commitment,
        "credential is not currently bound to the old holder commitment",
    );
    assert(credential_issuer_id_hash == issuer_id_hash, "issuer mismatch");
    assert(credential_schema_id_hash == schema_id_hash, "schema mismatch");
    assert(
        validity_period_contains(credential_valid_from, credential_valid_until, timestamp),
        "credential is not valid at timestamp",
    );
    assert(proof_context != 0, "proof context must be non-zero");
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
    old_credential_binding_key: Field,
    new_credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_issuer_id_hash: Field,
    credential_schema_id_hash: Field,
    credential_valid_from: u64,
    credential_valid_until: u64,
}

fn valid_rebind_fixture() -> RebindFixture {
    let old_cbk: Field = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105;
    let old_holder: Field = 0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf;
    let new_cbk = zkc_lib::derive_credential_binding_key(99);
    let new_holder = derive_holder_commitment(new_cbk);
    let credential_id: Field = 42;
    let proof_context: Field = 777;
    let timestamp: u64 = 12345;
    let claim_binding = compute_rebind_claim_binding(
        old_holder,
        new_holder,
        credential_id,
        proof_context,
        timestamp,
    );

    RebindFixture {
        old_holder_commitment: old_holder,
        new_holder_commitment: new_holder,
        credential_id,
        issuer_id_hash: 1001,
        schema_id_hash: 2002,
        proof_context,
        timestamp,
        claim_binding,
        old_credential_binding_key: old_cbk,
        new_credential_binding_key: new_cbk,
        credential_holder_commitment: old_holder,
        credential_issuer_id_hash: 1001,
        credential_schema_id_hash: 2002,
        credential_valid_from: 1000,
        credential_valid_until: 2000000,
    }
}

fn run_rebind_main(f: RebindFixture) {
    main(
        f.old_holder_commitment,
        f.new_holder_commitment,
        f.credential_id,
        f.issuer_id_hash,
        f.schema_id_hash,
        f.proof_context,
        f.timestamp,
        f.claim_binding,
        f.old_credential_binding_key,
        f.new_credential_binding_key,
        f.credential_holder_commitment,
        f.credential_issuer_id_hash,
        f.credential_schema_id_hash,
        f.credential_valid_from,
        f.credential_valid_until,
    );
}

#[test]
fn test_valid_rebind() {
    let f = valid_rebind_fixture();
    assert(
        f.new_credential_binding_key
            == 0x062c4390e12a851c21fcd86d13f3f823cdfe520007d641f107af2ccb31a74100,
        "new credential binding key KAT mismatch",
    );
    assert(
        f.new_holder_commitment
            == 0x1cad89fa2a3fc0eae6c094c9949aa7342838cc220f500e993563a2c16ab7e938,
        "new holder commitment KAT mismatch",
    );
    assert(
        f.claim_binding == 0x2a4c18b8312ee5e45735df6f4e8bb2e56805da612036f3b8f64ff34025e528c5,
        "rebind claim binding KAT mismatch",
    );
    run_rebind_main(f);
}

#[test(should_fail_with = "old holder commitment does not match old binding key")]
fn test_rebind_rejects_wrong_old_holder() {
    let mut f = valid_rebind_fixture();
    f.old_credential_binding_key += 1;
    run_rebind_main(f);
}

#[test(should_fail_with = "new holder commitment does not match new binding key")]
fn test_rebind_rejects_wrong_new_holder() {
    let mut f = valid_rebind_fixture();
    f.new_credential_binding_key += 1;
    run_rebind_main(f);
}

#[test(should_fail_with = "rebind must change holder commitment")]
fn test_rebind_rejects_unchanged_holder() {
    let mut f = valid_rebind_fixture();
    f.new_credential_binding_key = f.old_credential_binding_key;
    f.new_holder_commitment = f.old_holder_commitment;
    f.claim_binding = compute_rebind_claim_binding(
        f.old_holder_commitment,
        f.new_holder_commitment,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    );
    run_rebind_main(f);
}

#[test(should_fail_with = "credential is not currently bound to the old holder commitment")]
fn test_rebind_rejects_credential_bound_to_other_holder() {
    let mut f = valid_rebind_fixture();
    f.credential_holder_commitment = f.new_holder_commitment;
    run_rebind_main(f);
}

#[test(should_fail_with = "issuer mismatch")]
fn test_rebind_rejects_wrong_issuer() {
    let mut f = valid_rebind_fixture();
    f.credential_issuer_id_hash += 1;
    run_rebind_main(f);
}

#[test(should_fail_with = "schema mismatch")]
fn test_rebind_rejects_wrong_schema() {
    let mut f = valid_rebind_fixture();
    f.credential_schema_id_hash += 1;
    run_rebind_main(f);
}

#[test(should_fail_with = "credential is not valid at timestamp")]
fn test_rebind_rejects_expired_credential() {
    let mut f = valid_rebind_fixture();
    f.timestamp = f.credential_valid_until + 1;
    f.claim_binding = compute_rebind_claim_binding(
        f.old_holder_commitment,
        f.new_holder_commitment,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    );
    run_rebind_main(f);
}

#[test(should_fail_with = "credential is not valid at timestamp")]
fn test_rebind_rejects_not_yet_valid_credential() {
    let mut f = valid_rebind_fixture();
    f.timestamp = f.credential_valid_from - 1;
    f.claim_binding = compute_rebind_claim_binding(
        f.old_holder_commitment,
        f.new_holder_commitment,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    );
    run_rebind_main(f);
}

#[test(should_fail_with = "claim binding mismatch")]
fn test_rebind_rejects_wrong_claim_binding() {
    let mut f = valid_rebind_fixture();
    f.claim_binding += 1;
    run_rebind_main(f);
}

#[test(should_fail_with = "proof context must be non-zero")]
fn test_rebind_rejects_zero_proof_context() {
    let mut f = valid_rebind_fixture();
    f.proof_context = 0;
    f.claim_binding = compute_rebind_claim_binding(
        f.old_holder_commitment,
        f.new_holder_commitment,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    );
    run_rebind_main(f);
}

#[test]
fn test_rebind_claim_binding_changes_with_context() {
    let old_holder: Field = 1;
    let new_holder: Field = 2;
    let credential_id: Field = 3;
    let binding = compute_rebind_claim_binding(old_holder, new_holder, credential_id, 777, 12345);
    assert(
        binding != compute_rebind_claim_binding(old_holder, new_holder, credential_id, 778, 12345),
        "context must affect rebind claim binding",
    );
}

#[test]
fn test_validity_period() {
    assert(validity_period_contains(10, 0, 100), "zero valid_until means no expiry");
    assert(validity_period_contains(10, 20, 20), "valid_until is inclusive");
    assert(!validity_period_contains(10, 20, 21), "expired credential must fail");
}
