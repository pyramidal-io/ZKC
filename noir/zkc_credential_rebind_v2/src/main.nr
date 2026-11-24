// =============================================================================
// ZKC Credential Rebind Circuit v2 (Noir / UltraHonk / BN254)
//
// Proves a credential can migrate from an old holder commitment to a new holder
// commitment without revealing either credential binding key or any ZKA address.
//
// Presentation-profile ladder (design section 4.2). Public inputs 0 and 1 are
// now old/new presentation_pseudonym and index 2 is scope_id; the old and new
// global holder commitments are private witnesses. Rebind is verifier-facing
// continuity by definition, so scope_id == 0 (the anonymous sentinel) is
// rejected -- there is no anonymous rebind presentation. Both pseudonyms derive
// in the SAME scope from their respective binding keys, and claim_binding v2
// commits to the pseudonyms rather than the commitments. The v1 circuit
// (old/new holder commitments public) stays frozen as the consent-gated
// linkable profile.
// =============================================================================

use zkc_lib::{
    compute_claim_binding_3, derive_holder_commitment, derive_presentation_pseudonym,
    DOMAIN_ZKC_PRESENTATION_SCOPE, poseidon3,
};

pub fn validity_period_contains(valid_from: u64, valid_until: u64, timestamp: u64) -> bool {
    (valid_from <= timestamp) & ((valid_until == 0) | (valid_until >= timestamp))
}

pub fn compute_rebind_claim_binding(
    old_presentation_pseudonym: Field,
    new_presentation_pseudonym: Field,
    credential_id: Field,
    proof_context: Field,
    timestamp: u64,
) -> Field {
    compute_claim_binding_3(
        old_presentation_pseudonym,
        new_presentation_pseudonym,
        credential_id,
        proof_context,
        timestamp as Field,
    )
}

fn main(
    // === Public Inputs (v2 order, design section 4.2) ===
    old_presentation_pseudonym: pub Field, // was: old_holder_commitment (now private)
    new_presentation_pseudonym: pub Field, // was: new_holder_commitment (now private)
    scope_id: pub Field, // new: shared scope for both pseudonyms; 0 rejected
    credential_id: pub Field,
    issuer_id_hash: pub Field,
    schema_id_hash: pub Field,
    proof_context: pub Field,
    timestamp: pub u64,
    claim_binding: pub Field,
    // === Private Presentation Witness ===
    old_holder_commitment: Field, // moved from public
    new_holder_commitment: Field, // moved from public
    // === Private Shared Credential Inputs ===
    old_credential_binding_key: Field,
    new_credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_issuer_id_hash: Field,
    credential_schema_id_hash: Field,
    credential_valid_from: u64,
    credential_valid_until: u64,
) {
    // Rebind is verifier-facing continuity: no anonymous rebind.
    assert(scope_id != 0, "rebind requires a scoped presentation");

    // Retained v1 assertions, now over private values only.
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

    assert(credential_issuer_id_hash == issuer_id_hash, "issuer mismatch");
    assert(credential_schema_id_hash == schema_id_hash, "schema mismatch");
    assert(
        validity_period_contains(credential_valid_from, credential_valid_until, timestamp),
        "credential is not valid at timestamp",
    );
    assert(proof_context != 0, "proof context must be non-zero");

    // claim_binding v2 commits to the PSEUDONYMS (design section 4.2).
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
    old_holder_commitment: Field,
    new_holder_commitment: Field,
    old_credential_binding_key: Field,
    new_credential_binding_key: Field,
    credential_holder_commitment: Field,
    credential_issuer_id_hash: Field,
    credential_schema_id_hash: Field,
    credential_valid_from: u64,
    credential_valid_until: u64,
}

// Scoped presentation scope id shared by the old and new pseudonyms. Cross-
// checked in zkc_lib against derive_presentation_pseudonym / poseidon3.
global SCOPED_SCOPE_ID: Field = 7;

fn valid_rebind_fixture() -> RebindFixture {
    let old_cbk: Field = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105;
    let old_holder: Field = 0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf;
    let new_cbk = zkc_lib::derive_credential_binding_key(99);
    let new_holder = derive_holder_commitment(new_cbk);
    let credential_id: Field = 42;
    let proof_context: Field = 777;
    let timestamp: u64 = 12345;

    let scope_id = SCOPED_SCOPE_ID;
    let old_pseudonym = derive_presentation_pseudonym(old_cbk, scope_id);
    let new_pseudonym = derive_presentation_pseudonym(new_cbk, scope_id);
    let claim_binding = compute_rebind_claim_binding(
        old_pseudonym,
        new_pseudonym,
        credential_id,
        proof_context,
        timestamp,
    );

    RebindFixture {
        old_presentation_pseudonym: old_pseudonym,
        new_presentation_pseudonym: new_pseudonym,
        scope_id,
        credential_id,
        issuer_id_hash: 1001,
        schema_id_hash: 2002,
        proof_context,
        timestamp,
        claim_binding,
        old_holder_commitment: old_holder,
        new_holder_commitment: new_holder,
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
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
        f.scope_id,
        f.credential_id,
        f.issuer_id_hash,
        f.schema_id_hash,
        f.proof_context,
        f.timestamp,
        f.claim_binding,
        f.old_holder_commitment,
        f.new_holder_commitment,
        f.old_credential_binding_key,
        f.new_credential_binding_key,
        f.credential_holder_commitment,
        f.credential_issuer_id_hash,
        f.credential_schema_id_hash,
        f.credential_valid_from,
        f.credential_valid_until,
    );
}

// --- Presentation-profile tests (design section 4.2) ---------------------------

#[test]
fn test_scoped_rebind_passes() {
    // Default fixture is a scoped rebind: both pseudonyms derive from their
    // binding keys in the same non-zero scope.
    let f = valid_rebind_fixture();
    assert(f.scope_id != 0, "fixture must be scoped");
    // Pin the retained holder KATs that do not depend on the new derivations.
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
    run_rebind_main(f);
}

#[test(should_fail_with = "rebind requires a scoped presentation")]
fn test_rebind_rejects_anonymous_scope() {
    // scope_id 0 is the anonymous sentinel and has no rebind presentation.
    let mut f = valid_rebind_fixture();
    f.scope_id = 0;
    run_rebind_main(f);
}

#[test(should_fail_with = "rebind must change holder commitment")]
fn test_rebind_rejects_unchanged_binding_key() {
    // old == new credential binding key: the holder commitment cannot change.
    let mut f = valid_rebind_fixture();
    f.new_credential_binding_key = f.old_credential_binding_key;
    f.new_holder_commitment = f.old_holder_commitment;
    f.new_presentation_pseudonym =
        derive_presentation_pseudonym(f.new_credential_binding_key, f.scope_id);
    f.claim_binding = compute_rebind_claim_binding(
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    );
    run_rebind_main(f);
}

#[test(should_fail_with = "old presentation pseudonym mismatch")]
fn test_rebind_rejects_pseudonym_from_wrong_scope() {
    // An old pseudonym derived under a different scope must not verify.
    let mut f = valid_rebind_fixture();
    f.old_presentation_pseudonym =
        derive_presentation_pseudonym(f.old_credential_binding_key, f.scope_id + 1);
    f.claim_binding = compute_rebind_claim_binding(
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    );
    run_rebind_main(f);
}

// --- Retained v1 negative tests (now over private values) ----------------------

#[test(should_fail_with = "old holder commitment does not match old binding key")]
fn test_rebind_rejects_wrong_old_holder() {
    let mut f = valid_rebind_fixture();
    f.old_credential_binding_key += 1;
    // Keep the pseudonym consistent with the tampered key so the holder
    // commitment assertion is what fires, not the pseudonym assertion.
    f.old_presentation_pseudonym =
        derive_presentation_pseudonym(f.old_credential_binding_key, f.scope_id);
    f.claim_binding = compute_rebind_claim_binding(
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    );
    run_rebind_main(f);
}

#[test(should_fail_with = "new holder commitment does not match new binding key")]
fn test_rebind_rejects_wrong_new_holder() {
    let mut f = valid_rebind_fixture();
    f.new_credential_binding_key += 1;
    f.new_presentation_pseudonym =
        derive_presentation_pseudonym(f.new_credential_binding_key, f.scope_id);
    f.claim_binding = compute_rebind_claim_binding(
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
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
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
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
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
        f.credential_id,
        f.proof_context,
        f.timestamp,
    );
    run_rebind_main(f);
}

#[test(should_fail_with = "proof context must be non-zero")]
fn test_rebind_rejects_zero_proof_context() {
    let mut f = valid_rebind_fixture();
    f.proof_context = 0;
    f.claim_binding = compute_rebind_claim_binding(
        f.old_presentation_pseudonym,
        f.new_presentation_pseudonym,
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

#[test]
fn test_rebind_claim_binding_changes_with_context() {
    let old_pseudonym: Field = 1;
    let new_pseudonym: Field = 2;
    let credential_id: Field = 3;
    let binding =
        compute_rebind_claim_binding(old_pseudonym, new_pseudonym, credential_id, 777, 12345);
    assert(
        binding
            != compute_rebind_claim_binding(old_pseudonym, new_pseudonym, credential_id, 778, 12345)
            ,
        "context must affect rebind claim binding",
    );
}

#[test]
fn test_validity_period() {
    assert(validity_period_contains(10, 0, 100), "zero valid_until means no expiry");
    assert(validity_period_contains(10, 20, 20), "valid_until is inclusive");
    assert(!validity_period_contains(10, 20, 21), "expired credential must fail");
}
