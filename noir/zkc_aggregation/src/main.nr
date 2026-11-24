// =============================================================================
// ZKC Aggregation Circuit
//
// Aggregates up to 8 atomic predicate proofs. This profile mirrors the current
// ZKA simulated-recursion pattern: inner proof verification is represented by a
// commitment over verification key, proof bytes, public inputs, and proof type
// until native `std::verify_proof` recursion is stable for the target backend.
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
    holder_commitment: Field,
    num_proofs: u32,
    proof_commitments: [Field; 8],
    proof_types: [Field; 8],
    consent_flags: [bool; 8],
) -> Field {
    let mut acc = poseidon2(DOMAIN_ZKC_AGGREGATION_SEED, context);
    acc = poseidon2(acc, holder_commitment);
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
    // === Public Inputs ===
    aggregation_commitment: pub Field,
    aggregated_claim_binding: pub Field,
    holder_commitment: pub Field,
    context: pub Field,
    num_proofs: pub u32,
    input_proof_commitments: pub [Field; 8],
    // === Private Inputs ===
    verification_keys: [[Field; 64]; 8],
    proofs: [[Field; 64]; 8],
    proof_public_inputs: [[Field; 12]; 8],
    proof_types: [Field; 8],
    proof_holder_commitments: [Field; 8],
    consent_flags: [bool; 8],
) {
    assert(num_proofs >= 1, "num_proofs must be at least 1");
    assert(num_proofs <= MAX_AGGREGATED_PROOFS, "num_proofs must be at most 8");
    assert(context != 0, "context must be non-zero");
    assert(holder_commitment != 0, "holder commitment must be non-zero");

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
                proof_holder_commitments[i] == holder_commitment,
                "aggregated proofs must share holder commitment",
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
        holder_commitment,
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

fn mock_public_inputs(seed: Field, holder: Field) -> [Field; 12] {
    let mut values = [0; 12];
    values[0] = holder;
    for i in 1..12 {
        values[i] = poseidon2(seed, i as Field);
    }
    values
}

#[test]
fn test_valid_two_proof_aggregation() {
    let context: Field = 777;
    let holder: Field = 42;
    let num_proofs: u32 = 2;
    let vk0 = mock_array64(10);
    let vk1 = mock_array64(11);
    let proof0 = mock_array64(20);
    let proof1 = mock_array64(21);
    let pi0 = mock_public_inputs(30, holder);
    let pi1 = mock_public_inputs(31, holder);
    let verification_keys = [vk0, vk1, [0; 64], [0; 64], [0; 64], [0; 64], [0; 64], [0; 64]];
    let proofs = [proof0, proof1, [0; 64], [0; 64], [0; 64], [0; 64], [0; 64], [0; 64]];
    let proof_public_inputs = [pi0, pi1, [0; 12], [0; 12], [0; 12], [0; 12], [0; 12], [0; 12]];
    let proof_types: [Field; 8] = [1, 2, 0, 0, 0, 0, 0, 0];
    let holders: [Field; 8] = [holder, holder, 0, 0, 0, 0, 0, 0];
    let consent = [true, true, false, false, false, false, false, false];
    let mut commitments = [0; 8];
    commitments[0] = verify_inner_proof(vk0, proof0, pi0, 1);
    commitments[1] = verify_inner_proof(vk1, proof1, pi1, 2);
    let aggregation = aggregate_commitments(
        context,
        holder,
        num_proofs,
        commitments,
        proof_types,
        consent,
    );
    let aggregated_claim_binding = poseidon2(aggregation, context);

    main(
        aggregation,
        aggregated_claim_binding,
        holder,
        context,
        num_proofs,
        commitments,
        verification_keys,
        proofs,
        proof_public_inputs,
        proof_types,
        holders,
        consent,
    );
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

struct AggregationFixture {
    aggregation_commitment: Field,
    aggregated_claim_binding: Field,
    holder_commitment: Field,
    context: Field,
    num_proofs: u32,
    input_proof_commitments: [Field; 8],
    verification_keys: [[Field; 64]; 8],
    proofs: [[Field; 64]; 8],
    proof_public_inputs: [[Field; 12]; 8],
    proof_types: [Field; 8],
    proof_holder_commitments: [Field; 8],
    consent_flags: [bool; 8],
}

fn valid_two_proof_fixture() -> AggregationFixture {
    let context: Field = 777;
    let holder: Field = 42;
    let num_proofs: u32 = 2;
    let vk0 = mock_array64(10);
    let vk1 = mock_array64(11);
    let proof0 = mock_array64(20);
    let proof1 = mock_array64(21);
    let pi0 = mock_public_inputs(30, holder);
    let pi1 = mock_public_inputs(31, holder);
    let verification_keys = [vk0, vk1, [0; 64], [0; 64], [0; 64], [0; 64], [0; 64], [0; 64]];
    let proofs = [proof0, proof1, [0; 64], [0; 64], [0; 64], [0; 64], [0; 64], [0; 64]];
    let proof_public_inputs = [pi0, pi1, [0; 12], [0; 12], [0; 12], [0; 12], [0; 12], [0; 12]];
    let proof_types: [Field; 8] = [1, 2, 0, 0, 0, 0, 0, 0];
    let proof_holder_commitments: [Field; 8] = [holder, holder, 0, 0, 0, 0, 0, 0];
    let consent_flags = [true, true, false, false, false, false, false, false];
    let mut input_proof_commitments = [0; 8];
    input_proof_commitments[0] = verify_inner_proof(vk0, proof0, pi0, 1);
    input_proof_commitments[1] = verify_inner_proof(vk1, proof1, pi1, 2);
    let aggregation_commitment = aggregate_commitments(
        context,
        holder,
        num_proofs,
        input_proof_commitments,
        proof_types,
        consent_flags,
    );

    AggregationFixture {
        aggregation_commitment,
        aggregated_claim_binding: poseidon2(aggregation_commitment, context),
        holder_commitment: holder,
        context,
        num_proofs,
        input_proof_commitments,
        verification_keys,
        proofs,
        proof_public_inputs,
        proof_types,
        proof_holder_commitments,
        consent_flags,
    }
}

fn run_aggregation_main(f: AggregationFixture) {
    main(
        f.aggregation_commitment,
        f.aggregated_claim_binding,
        f.holder_commitment,
        f.context,
        f.num_proofs,
        f.input_proof_commitments,
        f.verification_keys,
        f.proofs,
        f.proof_public_inputs,
        f.proof_types,
        f.proof_holder_commitments,
        f.consent_flags,
    );
}

#[test]
fn test_valid_two_proof_aggregation_fixture() {
    run_aggregation_main(valid_two_proof_fixture());
}

#[test(should_fail_with = "input proof commitment mismatch")]
fn test_aggregation_rejects_tampered_component_proof() {
    // Tampering one byte of a component proof changes its commitment, which
    // no longer matches the public input commitment.
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

#[test(should_fail_with = "aggregated proofs must share holder commitment")]
fn test_aggregation_rejects_mismatched_holder_commitment() {
    let mut f = valid_two_proof_fixture();
    f.proof_holder_commitments[1] = 43;
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
