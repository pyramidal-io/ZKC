// =============================================================================
// ZKC Authenticated Credential Rebind Circuit (scoped profile)
//
// zkc:proof:rebind:v4 -- spec section 7.4.3, ADR 0004.
//
// The scoped, pseudonym-keyed form of zkc_credential_rebind_auth: public
// inputs 0/1 are the old/new presentation pseudonyms sharing one non-zero
// scope_id, the holder commitments are private, and the same
// issuer-authenticated core (recomputed signed transcript + non-revocation
// for the authenticated credential id) is enforced over the private old
// holder commitment. Rebind is verifier-facing continuity, so scope_id == 0
// (the anonymous sentinel) is rejected. Additive successor to the deprecated
// zkc_credential_rebind_v2 / zkc_credential_rebind_v2_binding_v2 statements.
// =============================================================================

use zkc_lib::{DOMAIN_ZKC_PRESENTATION_SCOPE, poseidon3};
use zkc_rebind_auth::{
    assert_authenticated_rebind, compute_rebind_attestation_digest, compute_rebind_claim_binding,
};

// Private proof-type domain: string_to_field("zkc:proof:rebind:v4").
global STATEMENT_DOMAIN: Field = 0x232f4619affdc2a4cf3f9ca0b83eb769204a396a6731b868324a5f1422829e0e;

fn main(
    // === Public Inputs (spec section 7.4.3 order) ===
    old_presentation_pseudonym: pub Field,
    new_presentation_pseudonym: pub Field,
    scope_id: pub Field,
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
    // === Private Presentation Witness ===
    old_holder_commitment: Field,
    new_holder_commitment: Field,
    // === Private Credential Inputs ===
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
    // Rebind is verifier-facing continuity: no anonymous rebind.
    assert(scope_id != 0, "rebind requires a scoped presentation");

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

    // Both pseudonyms derive in the SAME scope from their binding keys.
    assert(
        old_presentation_pseudonym
            == poseidon3(
                DOMAIN_ZKC_PRESENTATION_SCOPE,
                old_credential_binding_key,
                scope_id,
            ),
        "old presentation pseudonym mismatch",
    );
    assert(
        new_presentation_pseudonym
            == poseidon3(
                DOMAIN_ZKC_PRESENTATION_SCOPE,
                new_credential_binding_key,
                scope_id,
            ),
        "new presentation pseudonym mismatch",
    );
    assert(
        old_presentation_pseudonym != new_presentation_pseudonym,
        "rebind must change the presentation pseudonym",
    );

    let expected_claim_binding = compute_rebind_claim_binding(
        old_presentation_pseudonym,
        new_presentation_pseudonym,
        credential_id,
        proof_context,
        timestamp,
    );
    assert(expected_claim_binding == claim_binding, "claim binding mismatch");
}

struct RebindFixture {
    old_presentation_pseudonym: Field,
    new_presentation_pseudonym: Field,
    scope_id: Field,
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
    old_holder_commitment: Field,
    new_holder_commitment: Field,
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

// Scope shared by both pseudonyms (credential_rebind_attestation_v1 vector).
global SCOPED_SCOPE_ID: Field = 7;

fn valid_fixture() -> RebindFixture {
    let siblings = [0; 32];
    let accumulator_root = zkc_lib::compute_merkle_root(CREDENTIAL_ID, 0, siblings);
    let old_pseudonym = zkc_lib::derive_presentation_pseudonym(OLD_CBK, SCOPED_SCOPE_ID);
    let new_pseudonym = zkc_lib::derive_presentation_pseudonym(NEW_CBK, SCOPED_SCOPE_ID);
    RebindFixture {
        old_presentation_pseudonym: old_pseudonym,
        new_presentation_pseudonym: new_pseudonym,
        scope_id: SCOPED_SCOPE_ID,
        credential_id: CREDENTIAL_ID,
        issuer_id_hash: ISSUER_ID_HASH,
        schema_id_hash: SCHEMA_ID_HASH,
        proof_context: PROOF_CONTEXT,
        timestamp: TIMESTAMP,
        claim_binding: compute_rebind_claim_binding(
            old_pseudonym,
            new_pseudonym,
            CREDENTIAL_ID,
            PROOF_CONTEXT,
            TIMESTAMP,
        ),
        accumulator_root,
        accumulator_epoch: ACCUMULATOR_EPOCH,
        current_epoch: CURRENT_EPOCH,
        issuer_public_key_x: issuer_public_key_x(),
        issuer_public_key_y: issuer_public_key_y(),
        old_holder_commitment: OLD_HOLDER,
        new_holder_commitment: NEW_HOLDER,
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
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    )
}

fn run_main(f: RebindFixture) {
    main(
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
        f.scope_id,
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
        f.old_holder_commitment,
        f.new_holder_commitment,
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
fn test_valid_scoped_authenticated_rebind() {
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
        f.old_presentation_pseudonym
            == 0x02af556638a0909bdfbda62d1c6302c6d6d6a69a312cf4a97e2e431a9636d71e,
        "old pseudonym KAT mismatch",
    );
    assert(
        f.new_presentation_pseudonym
            == 0x1e444759df97c15a4abd1039ed8f0a8c37ca650c7af5bc20f2911171958f469e,
        "new pseudonym KAT mismatch",
    );
    assert(
        f.claim_binding == 0x2cc9e01540a215af8701690a65f9e48b92c0a28635f0ead06f34582bc7f4dc04,
        "scoped rebind claim binding KAT mismatch",
    );
    assert(
        f.statement_domain == 0x232f4619affdc2a4cf3f9ca0b83eb769204a396a6731b868324a5f1422829e0e,
        "scoped statement domain KAT mismatch",
    );
    run_main(f);
}

#[test(should_fail_with = "statement domain mismatch")]
fn test_rejects_wrong_statement_domain() {
    let mut f = valid_fixture();
    f.statement_domain += 1;
    run_main(f);
}

#[test(should_fail_with = "rebind requires a scoped presentation")]
fn test_rejects_anonymous_scope() {
    let mut f = valid_fixture();
    f.scope_id = 0;
    f.old_presentation_pseudonym = 0;
    f.new_presentation_pseudonym = 0;
    f.claim_binding = rebind_claim_binding(f);
    run_main(f);
}

#[test(should_fail_with = "old presentation pseudonym mismatch")]
fn test_rejects_wrong_scope_for_old_pseudonym() {
    let mut f = valid_fixture();
    f.scope_id += 1;
    run_main(f);
}

#[test(should_fail_with = "new presentation pseudonym mismatch")]
fn test_rejects_new_pseudonym_from_wrong_key() {
    let mut f = valid_fixture();
    f.new_presentation_pseudonym =
        zkc_lib::derive_presentation_pseudonym(f.new_credential_binding_key + 1, f.scope_id);
    f.claim_binding = rebind_claim_binding(f);
    run_main(f);
}

#[test(should_fail_with = "rebind must change holder commitment")]
fn test_rejects_unchanged_holder() {
    let mut f = valid_fixture();
    f.new_credential_binding_key = f.old_credential_binding_key;
    f.new_holder_commitment = f.old_holder_commitment;
    f.new_presentation_pseudonym = f.old_presentation_pseudonym;
    f.claim_binding = rebind_claim_binding(f);
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
    f.issuer_signature[63] += 1;
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
    let mut f = valid_fixture();
    f.old_credential_binding_key = zkc_lib::derive_credential_binding_key(0xBAD5EED);
    f.old_holder_commitment = zkc_lib::derive_holder_commitment(f.old_credential_binding_key);
    f.old_presentation_pseudonym =
        zkc_lib::derive_presentation_pseudonym(f.old_credential_binding_key, f.scope_id);
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
