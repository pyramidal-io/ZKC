// =============================================================================
// ZKC Aggregation Circuit v2 (Noir / UltraHonk / BN254)
//
// Aggregates up to 8 atomic predicate proofs. This profile mirrors the current
// ZKA simulated-recursion pattern: inner proof verification is represented by a
// commitment over verification key, proof bytes, public inputs, and proof type
// until native `std::verify_proof` recursion is stable for the target backend.
//
// Presentation-profile ladder (design section 4.3). Same-holder aggregation is
// a continuity claim, so public input 2 is now presentation_pseudonym (replacing
// holder_commitment) and public input 3 (after aggregated_claim_binding) is
// scope_id. Aggregation v2 requires scope_id != 0 (the anonymous sentinel is
// rejected) -- anonymous-profile proofs are not aggregable as same-holder. Every
// active component proof must carry the same presentation_pseudonym. The v1
// circuit (holder_commitment public) stays frozen as the consent-gated linkable
// path, where stable-holder aggregation across scopes lives.
// =============================================================================

use zkc_lib::{poseidon2, poseidon4};

pub global MAX_AGGREGATED_PROOFS: u32 = 8;
pub global VK_SIZE: u32 = 64;
pub global PROOF_SIZE: u32 = 64;
pub global PUBLIC_INPUT_SIZE: u32 = 12;
pub global DOMAIN_ZKC_AGGREGATION_SEED: Field =
    0x11aa333333333333333333333333333333333333333333333333333333333333;
pub global DOMAIN_ZKC_AGGREGATION_VERIFY: Field =
    0x11aa444444444444444444444444444444444444444444444444444444444444;

fn verify_inner_proof(
    verification_key: [Field; 64],
    proof: [Field; 64],
    public_inputs: [Field; 12],
    proof_type: Field,
) -> Field {
    let mut vk_acc = DOMAIN_ZKC_AGGREGATION_VERIFY;
    for i in 0..VK_SIZE {
        vk_acc = poseidon2(vk_acc, verification_key[i]);
    }
    let mut proof_acc = DOMAIN_ZKC_AGGREGATION_VERIFY;
    for i in 0..PROOF_SIZE {
        proof_acc = poseidon2(proof_acc, proof[i]);
    }
    let mut input_acc = DOMAIN_ZKC_AGGREGATION_VERIFY;
    for i in 0..PUBLIC_INPUT_SIZE {
        input_acc = poseidon2(input_acc, public_inputs[i]);
    }
    poseidon4(vk_acc, proof_acc, input_acc, proof_type)
}

pub fn aggregate_commitments(
    context: Field,
    presentation_pseudonym: Field,
    num_proofs: u32,
    proof_commitments: [Field; 8],
    proof_types: [Field; 8],
    consent_flags: [bool; 8],
) -> Field {
    let mut acc = poseidon2(DOMAIN_ZKC_AGGREGATION_SEED, context);
    acc = poseidon2(acc, presentation_pseudonym);
    for i in 0..MAX_AGGREGATED_PROOFS {
        let contribution = if (i as u32) < num_proofs {
            assert(consent_flags[i], "missing consent for aggregated proof");
            poseidon2(proof_commitments[i], proof_types[i])
        } else {
            0
        };
        acc = poseidon2(acc, contribution);
    }
    acc
}

fn main(
    // === Public Inputs (v2 order, design section 4.3) ===
    aggregation_commitment: pub Field,
    aggregated_claim_binding: pub Field,
    presentation_pseudonym: pub Field, // was: holder_commitment
    scope_id: pub Field, // new: scoped continuity; 0 rejected
    context: pub Field,
    num_proofs: pub u32,
    input_proof_commitments: pub [Field; 8],
    // === Private Inputs ===
    verification_keys: [[Field; 64]; 8],
    proofs: [[Field; 64]; 8],
    proof_public_inputs: [[Field; 12]; 8],
    proof_types: [Field; 8],
    proof_presentation_pseudonyms: [Field; 8],
    consent_flags: [bool; 8],
) {
    // Same-holder aggregation is verifier-facing continuity: no anonymous
    // aggregation.
    assert(scope_id != 0, "aggregation requires a scoped presentation");
    assert(num_proofs >= 1, "num_proofs must be at least 1");
    assert(num_proofs <= MAX_AGGREGATED_PROOFS, "num_proofs must be at most 8");
    assert(context != 0, "context must be non-zero");
    assert(presentation_pseudonym != 0, "presentation pseudonym must be non-zero");

    let mut computed_commitments = [0; 8];
    for i in 0..MAX_AGGREGATED_PROOFS {
        let proof_hash = verify_inner_proof(
            verification_keys[i],
            proofs[i],
            proof_public_inputs[i],
            proof_types[i],
        );
        if (i as u32) < num_proofs {
            assert(
                proof_presentation_pseudonyms[i] == presentation_pseudonym,
                "aggregated proofs must share presentation pseudonym",
            );
            // Bind the same-holder witness to the COMMITTED public inputs:
            // every v2 predicate circuit carries its presentation pseudonym at
            // public-input index 0 (design section 4), so the free witness
            // above is anchored to what verify_inner_proof actually commits.
            // (v1 aggregation has the analogous free-witness property for
            // holder_commitment; end-to-end it is enforced by per-proof SDK
            // verification. v2 enforces it in-circuit as well.)
            assert(
                proof_public_inputs[i][0] == presentation_pseudonym,
                "inner proof public inputs must carry the shared presentation pseudonym",
            );
            computed_commitments[i] = proof_hash;
            assert(input_proof_commitments[i] == proof_hash, "input proof commitment mismatch");
        } else {
            computed_commitments[i] = 0;
            assert(input_proof_commitments[i] == 0, "inactive proof commitment must be zero");
        }
    }

    let expected_aggregation = aggregate_commitments(
        context,
        presentation_pseudonym,
        num_proofs,
        computed_commitments,
        proof_types,
        consent_flags,
    );
    assert(expected_aggregation == aggregation_commitment, "aggregation commitment mismatch");
    assert(
        poseidon2(expected_aggregation, context) == aggregated_claim_binding,
        "aggregated claim binding mismatch",
    );
}

fn mock_array64(seed: Field) -> [Field; 64] {
    let mut values = [0; 64];
    for i in 0..64 {
        values[i] = poseidon2(seed, i as Field);
    }
    values
}

fn mock_public_inputs(seed: Field, pseudonym: Field) -> [Field; 12] {
    let mut values = [0; 12];
    values[0] = pseudonym;
    for i in 1..12 {
        values[i] = poseidon2(seed, i as Field);
    }
    values
}

struct AggregationFixture {
    aggregation_commitment: Field,
    aggregated_claim_binding: Field,
    presentation_pseudonym: Field,
    scope_id: Field,
    context: Field,
    num_proofs: u32,
    input_proof_commitments: [Field; 8],
    verification_keys: [[Field; 64]; 8],
    proofs: [[Field; 64]; 8],
    proof_public_inputs: [[Field; 12]; 8],
    proof_types: [Field; 8],
    proof_presentation_pseudonyms: [Field; 8],
    consent_flags: [bool; 8],
}

fn valid_two_proof_fixture() -> AggregationFixture {
    let context: Field = 777;
    // A scoped presentation pseudonym (non-zero) and its scope.
    let pseudonym: Field = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105;
    let scope_id: Field = 7;
    let num_proofs: u32 = 2;
    let vk0 = mock_array64(10);
    let vk1 = mock_array64(11);
    let proof0 = mock_array64(20);
    let proof1 = mock_array64(21);
    let pi0 = mock_public_inputs(30, pseudonym);
    let pi1 = mock_public_inputs(31, pseudonym);
    let verification_keys = [vk0, vk1, [0; 64], [0; 64], [0; 64], [0; 64], [0; 64], [0; 64]];
    let proofs = [proof0, proof1, [0; 64], [0; 64], [0; 64], [0; 64], [0; 64], [0; 64]];
    let proof_public_inputs = [pi0, pi1, [0; 12], [0; 12], [0; 12], [0; 12], [0; 12], [0; 12]];
    let proof_types: [Field; 8] = [1, 2, 0, 0, 0, 0, 0, 0];
    let proof_presentation_pseudonyms: [Field; 8] = [pseudonym, pseudonym, 0, 0, 0, 0, 0, 0];
    let consent_flags = [true, true, false, false, false, false, false, false];
    let mut input_proof_commitments = [0; 8];
    input_proof_commitments[0] = verify_inner_proof(vk0, proof0, pi0, 1);
    input_proof_commitments[1] = verify_inner_proof(vk1, proof1, pi1, 2);
    let aggregation_commitment = aggregate_commitments(
        context,
        pseudonym,
        num_proofs,
        input_proof_commitments,
        proof_types,
        consent_flags,
    );

    AggregationFixture {
        aggregation_commitment,
        aggregated_claim_binding: poseidon2(aggregation_commitment, context),
        presentation_pseudonym: pseudonym,
        scope_id,
        context,
        num_proofs,
        input_proof_commitments,
        verification_keys,
        proofs,
        proof_public_inputs,
        proof_types,
        proof_presentation_pseudonyms,
        consent_flags,
    }
}

fn run_aggregation_main(f: AggregationFixture) {
    main(
        f.aggregation_commitment,
        f.aggregated_claim_binding,
        f.presentation_pseudonym,
        f.scope_id,
        f.context,
        f.num_proofs,
        f.input_proof_commitments,
        f.verification_keys,
        f.proofs,
        f.proof_public_inputs,
        f.proof_types,
        f.proof_presentation_pseudonyms,
        f.consent_flags,
    );
}

#[test]
fn test_valid_scoped_two_proof_aggregation() {
    run_aggregation_main(valid_two_proof_fixture());
}

#[test]
fn test_aggregation_changes_with_consent() {
    let commitments: [Field; 8] = [10, 20, 0, 0, 0, 0, 0, 0];
    let proof_types: [Field; 8] = [1, 2, 0, 0, 0, 0, 0, 0];
    let a = aggregate_commitments(
        777,
        42,
        1,
        commitments,
        proof_types,
        [true, false, false, false, false, false, false, false],
    );
    let b = aggregate_commitments(
        777,
        42,
        2,
        commitments,
        proof_types,
        [true, true, false, false, false, false, false, false],
    );
    assert(a != b, "adding a consented proof must change aggregation commitment");
}

#[test(should_fail_with = "inner proof public inputs must carry the shared presentation pseudonym")]
fn test_aggregation_rejects_inner_pseudonym_not_in_committed_inputs() {
    let mut f = valid_two_proof_fixture();
    // Inner proof 1's COMMITTED public inputs carry a different pseudonym even
    // though the free witness claims the shared one (PR #57 review finding):
    // the binding assert must reject this in-circuit.
    f.proof_public_inputs[1][0] = f.proof_public_inputs[1][0] + 1;
    f.input_proof_commitments[1] = verify_inner_proof(
        f.verification_keys[1],
        f.proofs[1],
        f.proof_public_inputs[1],
        2,
    );
    run_aggregation_main(f);
}

#[test(should_fail_with = "aggregation requires a scoped presentation")]
fn test_aggregation_rejects_anonymous_scope() {
    let mut f = valid_two_proof_fixture();
    f.scope_id = 0;
    run_aggregation_main(f);
}

#[test(should_fail_with = "aggregated proofs must share presentation pseudonym")]
fn test_aggregation_rejects_mixed_pseudonyms() {
    let mut f = valid_two_proof_fixture();
    // A second, distinct pseudonym on the second slot: not the same holder.
    f.proof_presentation_pseudonyms[1] =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    run_aggregation_main(f);
}

#[test(should_fail_with = "input proof commitment mismatch")]
fn test_aggregation_rejects_tampered_component_proof() {
    let mut f = valid_two_proof_fixture();
    f.proofs[0][0] += 1;
    run_aggregation_main(f);
}

#[test(should_fail_with = "input proof commitment mismatch")]
fn test_aggregation_rejects_tampered_component_vk() {
    let mut f = valid_two_proof_fixture();
    f.verification_keys[1][0] += 1;
    run_aggregation_main(f);
}

#[test(should_fail_with = "input proof commitment mismatch")]
fn test_aggregation_rejects_tampered_component_public_inputs() {
    let mut f = valid_two_proof_fixture();
    f.proof_public_inputs[1][3] += 1;
    run_aggregation_main(f);
}

#[test(should_fail_with = "missing consent for aggregated proof")]
fn test_aggregation_rejects_missing_consent() {
    let mut f = valid_two_proof_fixture();
    f.consent_flags[1] = false;
    run_aggregation_main(f);
}

#[test(should_fail_with = "aggregation commitment mismatch")]
fn test_aggregation_rejects_wrong_aggregation_commitment() {
    let mut f = valid_two_proof_fixture();
    f.aggregation_commitment += 1;
    run_aggregation_main(f);
}

#[test(should_fail_with = "aggregated claim binding mismatch")]
fn test_aggregation_rejects_wrong_aggregated_claim_binding() {
    let mut f = valid_two_proof_fixture();
    f.aggregated_claim_binding += 1;
    run_aggregation_main(f);
}

#[test(should_fail_with = "inactive proof commitment must be zero")]
fn test_aggregation_rejects_nonzero_inactive_commitment() {
    let mut f = valid_two_proof_fixture();
    f.input_proof_commitments[5] = 1;
    run_aggregation_main(f);
}

#[test(should_fail_with = "num_proofs must be at least 1")]
fn test_aggregation_rejects_zero_proofs() {
    let mut f = valid_two_proof_fixture();
    f.num_proofs = 0;
    run_aggregation_main(f);
}

#[test(should_fail_with = "context must be non-zero")]
fn test_aggregation_rejects_zero_context() {
    let mut f = valid_two_proof_fixture();
    f.context = 0;
    run_aggregation_main(f);
}

#[test(should_fail_with = "presentation pseudonym must be non-zero")]
fn test_aggregation_rejects_zero_pseudonym() {
    // A zero pseudonym is the anonymous sentinel; force it directly while
    // keeping scope_id non-zero so the pseudonym check is the one that fires.
    let mut f = valid_two_proof_fixture();
    f.presentation_pseudonym = 0;
    f.proof_presentation_pseudonyms = [0; 8];
    f.aggregation_commitment = aggregate_commitments(
        f.context,
        0,
        f.num_proofs,
        f.input_proof_commitments,
        f.proof_types,
        f.consent_flags,
    );
    f.aggregated_claim_binding = poseidon2(f.aggregation_commitment, f.context);
    run_aggregation_main(f);
}
