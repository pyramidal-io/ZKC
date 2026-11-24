// =============================================================================
// ZKC Authenticated Credential Rebind Gadgets
//
// Shared by the issuer-authenticated rebind successor circuits
// (spec section 7.4, ADR 0004). A rebind statement built on these gadgets
// authenticates the credential it migrates: the issuer signature is verified
// over the zkc:attestation:credential-rebind:v1 transcript RECOMPUTED from
// constrained fields (there is no digest input), and non-revocation is proven
// for the same credential identifier the transcript binds.
//
// The deprecated zkc_credential_rebind* circuits constrained none of this;
// their credential fields were unconstrained prover witnesses.
// =============================================================================

use zkc_issuer_sig::{assert_issuer_signature, ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1};
use zkc_lib::{
    compute_claim_binding_3, derive_holder_commitment, DOMAIN_ZKC_CLAIM, poseidon2, poseidon4,
};
use zkc_nonrevocation::{assert_nonrevocation, NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2};

// string_to_field("zkc:attestation:credential-rebind:v1"). Cross-checked by
// tests/vectors/validate_zkc_vectors.py (credential_rebind_attestation_v1).
pub global REBIND_ATTESTATION_TYPE: Field =
    0x26917ee154a7287e2e9b947c5ad1324ebbaee4d38c1c3c734684c1ded13588ea;

/// Issuer-signed rebind attestation digest (spec section 7.4.1):
///   header = Poseidon4(DOMAIN_ZKC_CLAIM, REBIND_ATTESTATION_TYPE, issuer_id_hash, schema_id_hash)
///   body   = Poseidon4(holder_commitment, credential_id, valid_from, valid_until)
///   digest = Poseidon2(header, body)
pub fn compute_rebind_attestation_digest(
    issuer_id_hash: Field,
    schema_id_hash: Field,
    holder_commitment: Field,
    credential_id: Field,
    valid_from: u64,
    valid_until: u64,
) -> Field {
    let header = poseidon4(
        DOMAIN_ZKC_CLAIM,
        REBIND_ATTESTATION_TYPE,
        issuer_id_hash,
        schema_id_hash,
    );
    let body = poseidon4(
        holder_commitment,
        credential_id,
        valid_from as Field,
        valid_until as Field,
    );
    poseidon2(header, body)
}

pub fn validity_period_contains(valid_from: u64, valid_until: u64, timestamp: u64) -> bool {
    (valid_from <= timestamp) & ((valid_until == 0) | (valid_until >= timestamp))
}

/// Claim binding shared by both successors: the profile's old/new handles,
/// the authenticated credential id, and the request context + timestamp.
pub fn compute_rebind_claim_binding(
    old_handle: Field,
    new_handle: Field,
    credential_id: Field,
    proof_context: Field,
    timestamp: u64,
) -> Field {
    compute_claim_binding_3(
        old_handle,
        new_handle,
        credential_id,
        proof_context,
        timestamp as Field,
    )
}

/// The complete authenticated-rebind core. Every field of the signed
/// transcript is either a public input (issuer_id_hash, schema_id_hash,
/// credential_id), derived in-circuit from a private key (the old holder
/// commitment), or a private witness whose only accepted values are the ones
/// the issuer signed (both validity bounds).
pub fn assert_authenticated_rebind(
    old_holder_commitment: Field,
    new_holder_commitment: Field,
    credential_id: Field,
    issuer_id_hash: Field,
    schema_id_hash: Field,
    proof_context: Field,
    timestamp: u64,
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
) {
    // 1. Holder control over both handles; the rebind must move.
    assert(
        derive_holder_commitment(old_credential_binding_key) == old_holder_commitment,
        "old holder commitment does not match old binding key",
    );
    assert(
        derive_holder_commitment(new_credential_binding_key) == new_holder_commitment,
        "new holder commitment does not match new binding key",
    );
    assert(old_holder_commitment != new_holder_commitment, "rebind must change holder commitment");

    // 2. Issuer authentication over the RECOMPUTED transcript. The old holder
    //    commitment in the transcript is the one derived above, so a
    //    signature can only verify for the holder the issuer actually bound.
    let digest = compute_rebind_attestation_digest(
        issuer_id_hash,
        schema_id_hash,
        old_holder_commitment,
        credential_id,
        credential_valid_from,
        credential_valid_until,
    );
    let message_hash: [u8; 32] = digest.to_be_bytes();
    assert_issuer_signature(
        ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1,
        issuer_public_key_x,
        issuer_public_key_y,
        issuer_signature,
        message_hash,
    );

    // 3. Non-revocation for the SAME authenticated credential id, with the
    //    in-circuit epoch freshness bound.
    assert_nonrevocation(
        NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2,
        credential_id,
        nonrevocation_path_index,
        nonrevocation_siblings,
        accumulator_root,
        accumulator_epoch,
        current_epoch,
    );

    // 4. Signed validity window contains the request timestamp.
    assert(
        validity_period_contains(credential_valid_from, credential_valid_until, timestamp),
        "credential is not valid at timestamp",
    );
    assert(timestamp != 0, "timestamp must be non-zero");
    assert(proof_context != 0, "proof context must be non-zero");
}

#[test]
fn kat_rebind_attestation_digest_seed_42() {
    // credential_rebind_attestation_v1 vector: holder from seed 42, credential
    // id 42, schema zkc:cred:kyc:v1, issuer did:zkc:test-issuer, 1000..2000000.
    let digest = compute_rebind_attestation_digest(
        0x1ab792b1777260d562c10d81aa74a124c5438335065138da7e2a2e7a63b0a911,
        0x2625058d446eada5e7efa789c1356af408e40278649d8504c2088c764e85d5e2,
        0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf,
        42,
        1000,
        2000000,
    );
    assert(
        digest == 0x246ce8deb13dab22a5c07b087024aa58dd42732cd17003f17a003e94638639f7,
        "rebind attestation digest KAT mismatch",
    );
}

#[test]
fn test_attestation_digest_binds_every_field() {
    let base = compute_rebind_attestation_digest(1, 2, 3, 4, 5, 6);
    assert(base != compute_rebind_attestation_digest(9, 2, 3, 4, 5, 6), "issuer must bind");
    assert(base != compute_rebind_attestation_digest(1, 9, 3, 4, 5, 6), "schema must bind");
    assert(base != compute_rebind_attestation_digest(1, 2, 9, 4, 5, 6), "holder must bind");
    assert(base != compute_rebind_attestation_digest(1, 2, 3, 9, 5, 6), "credential id must bind");
    assert(base != compute_rebind_attestation_digest(1, 2, 3, 4, 9, 6), "valid_from must bind");
    assert(base != compute_rebind_attestation_digest(1, 2, 3, 4, 5, 9), "valid_until must bind");
}

#[test]
fn test_validity_period() {
    assert(validity_period_contains(10, 0, 100), "zero valid_until means no expiry");
    assert(validity_period_contains(10, 20, 20), "valid_until is inclusive");
    assert(!validity_period_contains(10, 20, 21), "expired credential must fail");
    assert(!validity_period_contains(10, 20, 9), "not-yet-valid credential must fail");
}
