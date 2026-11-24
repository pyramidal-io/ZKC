// =============================================================================
// ZKC Non-Revocation Verification
//
// Initial conformance profile: a Poseidon2 Merkle accumulator whose leaves are
// active credential IDs. Revocation removes a credential from future roots; it
// does not affect any underlying ZKA note or asset validity.
// =============================================================================

use zkc_lib::{compute_merkle_root, verify_merkle_membership};

pub global MAX_EPOCH_LAG: u64 = 10;
pub global NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2: u8 = 1;

pub fn verify_epoch_freshness(accumulator_epoch: u64, current_epoch: u64) -> bool {
    if current_epoch < accumulator_epoch {
        false
    } else {
        current_epoch - accumulator_epoch <= MAX_EPOCH_LAG
    }
}

pub fn compute_nonrevocation_root(
    credential_id: Field,
    witness_path_index: Field,
    witness_siblings: [Field; 32],
) -> Field {
    compute_merkle_root(credential_id, witness_path_index, witness_siblings)
}

pub fn verify_nonrevocation_membership(
    credential_id: Field,
    witness_path_index: Field,
    witness_siblings: [Field; 32],
    accumulator_root: Field,
) -> bool {
    verify_merkle_membership(
        credential_id,
        witness_path_index,
        witness_siblings,
        accumulator_root,
    )
}

pub fn verify_nonrevocation(
    accumulator_scheme: u8,
    credential_id: Field,
    witness_path_index: Field,
    witness_siblings: [Field; 32],
    accumulator_root: Field,
    accumulator_epoch: u64,
    current_epoch: u64,
) -> bool {
    if accumulator_scheme != NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2 {
        false
    } else {
        verify_nonrevocation_membership(
            credential_id,
            witness_path_index,
            witness_siblings,
            accumulator_root,
        )
            & verify_epoch_freshness(accumulator_epoch, current_epoch)
    }
}

pub fn assert_nonrevocation(
    accumulator_scheme: u8,
    credential_id: Field,
    witness_path_index: Field,
    witness_siblings: [Field; 32],
    accumulator_root: Field,
    accumulator_epoch: u64,
    current_epoch: u64,
) {
    assert(
        verify_nonrevocation(
            accumulator_scheme,
            credential_id,
            witness_path_index,
            witness_siblings,
            accumulator_root,
            accumulator_epoch,
            current_epoch,
        ),
        "credential is revoked or accumulator epoch is stale",
    );
}

#[test]
fn test_epoch_freshness_accepts_current_and_lagged_epochs() {
    assert(verify_epoch_freshness(100, 100), "same epoch must be fresh");
    assert(verify_epoch_freshness(90, 100), "max lag must be accepted");
}

#[test]
fn test_epoch_freshness_rejects_future_and_stale_epochs() {
    assert(!verify_epoch_freshness(101, 100), "future accumulator epoch must reject");
    assert(!verify_epoch_freshness(89, 100), "epoch lag above MAX_EPOCH_LAG must reject");
}

#[test]
fn test_nonrevocation_membership_accepts_valid_witness() {
    let siblings = [0; 32];
    let credential_id: Field = 42;
    let accumulator_root = compute_nonrevocation_root(credential_id, 0, siblings);

    assert(
        verify_nonrevocation(
            NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2,
            credential_id,
            0,
            siblings,
            accumulator_root,
            100,
            105,
        ),
        "valid credential witness and fresh epoch must verify",
    );
}

#[test]
fn test_nonrevocation_rejects_wrong_credential() {
    let siblings = [0; 32];
    let accumulator_root = compute_nonrevocation_root(42, 0, siblings);

    assert(
        !verify_nonrevocation(
            NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2,
            43,
            0,
            siblings,
            accumulator_root,
            100,
            105,
        ),
        "different credential ID must not verify against the same witness",
    );
}

#[test]
fn test_nonrevocation_rejects_stale_epoch() {
    let siblings = [0; 32];
    let credential_id: Field = 42;
    let accumulator_root = compute_nonrevocation_root(credential_id, 0, siblings);

    assert(
        !verify_nonrevocation(
            NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2,
            credential_id,
            0,
            siblings,
            accumulator_root,
            90,
            101,
        ),
        "stale accumulator epoch must reject even with a valid witness",
    );
}

#[test]
fn test_nonrevocation_rejects_unknown_scheme() {
    let siblings = [0; 32];
    let credential_id: Field = 42;
    let accumulator_root = compute_nonrevocation_root(credential_id, 0, siblings);

    assert(
        !verify_nonrevocation(0, credential_id, 0, siblings, accumulator_root, 100, 100),
        "unknown accumulator scheme must reject",
    );
}
