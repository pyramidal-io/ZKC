// =============================================================================
// ZKC Shared Library for Noir Circuits
//
// Canonical cryptographic primitives used by ZKC credential and predicate
// circuits. These wrappers pin the same Poseidon2 BN254 parameterization used
// by ZKA zka_lib while exposing ZKC-specific KDC derivations.
// =============================================================================

use poseidon::poseidon2::Poseidon2;

// =============================================================================
// Domain Separators
//
// Each constant = Blake2b512("ZKA-Domain-{tag}") mod BN254.Fr, matching the
// canonical ZKA/KDC domain derivation. ZKC reuses these pinned Field constants
// byte-for-byte so ZKA<->ZKC credential binding remains interoperable.
// =============================================================================

pub global DOMAIN_ZKC_CREDENTIAL: Field =
    0x3010b194aeae94550e7a48d065d9dc931108c2d15136704bf4ad78eae07f0e26;
pub global DOMAIN_ZKC_BINDING: Field =
    0x12b8b6de2c8fc6b63102155d15c31799845a1f360ab0df6266284bde48e3a93f;
pub global DOMAIN_ZKC_CLAIM: Field =
    0x0b929496a58d5a41cba03a3302b92f5d7781ad2913285aec7a5431647c50c9d4;

// Pinned: derive_domain("zkc/presentation-scope:v1") -- cross-checked by
// tests/vectors/validate_zkc_vectors.py against the Python reference.
pub global DOMAIN_ZKC_PRESENTATION_SCOPE: Field =
    0x2f7a94a38bb647d343fc7abc74b6466fe1eb566d71c185cc9537b7e768c466ae;

pub global MERKLE_DEPTH: u32 = 32;

// =============================================================================
// Poseidon2 Hash Wrappers
// =============================================================================

pub fn poseidon2(a: Field, b: Field) -> Field {
    Poseidon2::hash([a, b], 2)
}

pub fn poseidon3(a: Field, b: Field, c: Field) -> Field {
    Poseidon2::hash([a, b, c], 3)
}

pub fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    Poseidon2::hash([a, b, c, d], 4)
}

// =============================================================================
// KDC Credential Binding
//
// AFP-KDC v1.0.3 is the current registry authority; the field-derivation
// profile and KAT provenance remain the immutable AFP-KDC v1.0.2 evidence.
// Host code maps the exact 32 seed bytes as unsigned big-endian modulo r
// before supplying this Field to a circuit:
//   cbk              = H("zkc/credential", seedToField(masterSeed))
//   holderCommitment = H("zkc/binding", cbk)
// The full seed bytes are intentionally unavailable inside Noir. Callers must
// retain them for byte-domain receipt, audit, and delegation key derivations.
// =============================================================================

pub fn derive_credential_binding_key(master_seed: Field) -> Field {
    poseidon2(DOMAIN_ZKC_CREDENTIAL, master_seed)
}

pub fn derive_holder_commitment(credential_binding_key: Field) -> Field {
    poseidon2(DOMAIN_ZKC_BINDING, credential_binding_key)
}

pub fn derive_holder_commitment_from_seed(master_seed: Field) -> Field {
    let credential_binding_key = derive_credential_binding_key(master_seed);
    derive_holder_commitment(credential_binding_key)
}

// =============================================================================
// Presentation Pseudonym
//
// Presentation-profile ladder (design doc section 2). scope_id 0 is the
// anonymous sentinel and never has a pseudonym; a non-zero scope_id yields a
// scope-exclusive pseudonym provable in-circuit.
// =============================================================================

/// presentationPseudonym = H("zkc/presentation-scope:v1", cbk, scope_id).
/// scope_id 0 is the anonymous sentinel and never has a pseudonym.
pub fn derive_presentation_pseudonym(credential_binding_key: Field, scope_id: Field) -> Field {
    assert(scope_id != 0, "scope_id 0 is the anonymous sentinel");
    poseidon3(
        DOMAIN_ZKC_PRESENTATION_SCOPE,
        credential_binding_key,
        scope_id,
    )
}

/// Profile constraint shared by all v2 circuits (design section 4.1).
/// scope_id == 0 (anonymous) => pseudonym must be 0.
/// scope_id != 0 (scoped)    => pseudonym must derive from cbk and scope_id.
pub fn assert_presentation_binding(
    presentation_pseudonym: Field,
    scope_id: Field,
    credential_binding_key: Field,
) {
    if scope_id == 0 {
        assert(presentation_pseudonym == 0, "anonymous profile must not carry a pseudonym");
    } else {
        assert(
            presentation_pseudonym
                == poseidon3(
                    DOMAIN_ZKC_PRESENTATION_SCOPE,
                    credential_binding_key,
                    scope_id,
                ),
            "presentation pseudonym does not derive from binding key and scope",
        );
    }
}

// =============================================================================
// Claim Binding
//
// ZKC predicate circuits bind each proof to its requested claim, replay context,
// and freshness timestamp using the ZKC claim domain.
// =============================================================================

pub fn compute_claim_binding_2(
    claim_parameter_0: Field,
    claim_parameter_1: Field,
    proof_context: Field,
    timestamp: Field,
) -> Field {
    let claim_hash = poseidon3(DOMAIN_ZKC_CLAIM, claim_parameter_0, claim_parameter_1);
    poseidon3(claim_hash, proof_context, timestamp)
}

pub fn compute_claim_binding_3(
    claim_parameter_0: Field,
    claim_parameter_1: Field,
    claim_parameter_2: Field,
    proof_context: Field,
    timestamp: Field,
) -> Field {
    let claim_hash = poseidon4(
        DOMAIN_ZKC_CLAIM,
        claim_parameter_0,
        claim_parameter_1,
        claim_parameter_2,
    );
    poseidon3(claim_hash, proof_context, timestamp)
}

// =============================================================================
// Merkle Tree Verification
// =============================================================================

pub fn compute_merkle_root(leaf: Field, path_index: Field, siblings: [Field; 32]) -> Field {
    let index_bits: [bool; 32] = path_index.to_be_bits();
    let mut current = leaf;
    for i in 0..32 {
        let is_right = index_bits[31 - i];
        let left = if is_right { siblings[i] } else { current };
        let right = if is_right { current } else { siblings[i] };
        current = poseidon2(left, right);
    }
    current
}

pub fn verify_merkle_membership(
    leaf: Field,
    path_index: Field,
    siblings: [Field; 32],
    expected_root: Field,
) -> bool {
    compute_merkle_root(leaf, path_index, siblings) == expected_root
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_domain_separators_unique() {
    assert(DOMAIN_ZKC_CREDENTIAL != DOMAIN_ZKC_BINDING, "credential != binding");
    assert(DOMAIN_ZKC_CREDENTIAL != DOMAIN_ZKC_CLAIM, "credential != claim");
    assert(DOMAIN_ZKC_BINDING != DOMAIN_ZKC_CLAIM, "binding != claim");
}

#[test]
fn test_holder_commitment_derivation_order() {
    let seed: Field = 42;
    let cbk = derive_credential_binding_key(seed);
    let holder_commitment = derive_holder_commitment(cbk);

    assert(cbk == poseidon2(DOMAIN_ZKC_CREDENTIAL, seed), "cbk uses credential domain");
    assert(
        holder_commitment == poseidon2(DOMAIN_ZKC_BINDING, cbk),
        "holder commitment uses binding domain",
    );
    assert(
        holder_commitment == derive_holder_commitment_from_seed(seed),
        "seed helper must match two-step derivation",
    );
}

#[test]
fn test_holder_commitment_domain_order_is_not_reversed() {
    let seed: Field = 42;
    let cbk = derive_credential_binding_key(seed);
    let holder_commitment = derive_holder_commitment(cbk);
    let reversed = poseidon2(DOMAIN_ZKC_CREDENTIAL, poseidon2(DOMAIN_ZKC_BINDING, seed));

    assert(holder_commitment != reversed, "KDC domain order must not be reversed");
}

#[test]
fn test_claim_binding_changes_with_context_and_timestamp() {
    let claim_binding = compute_claim_binding_2(1, 31, 777, 12345);

    assert(
        claim_binding != compute_claim_binding_2(1, 31, 778, 12345),
        "proof context must affect claim binding",
    );
    assert(
        claim_binding != compute_claim_binding_2(1, 31, 777, 12346),
        "timestamp must affect claim binding",
    );
}

#[test]
fn test_merkle_membership_verifier() {
    let siblings = [0; 32];
    let root = compute_merkle_root(42, 0, siblings);
    assert(verify_merkle_membership(42, 0, siblings, root), "membership root must verify");
    assert(
        !verify_merkle_membership(43, 0, siblings, root),
        "different leaf must not verify against same root",
    );
}

#[test]
fn kat_poseidon2_of_1_2() {
    assert(
        poseidon2(1, 2) == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
        "poseidon2(1,2) KAT mismatch: Poseidon2 parameterization changed",
    );
}

#[test]
fn kat_poseidon3_of_1_2_3() {
    assert(
        poseidon3(1, 2, 3) == 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
        "poseidon3(1,2,3) KAT mismatch: Poseidon2 parameterization changed",
    );
}

#[test]
fn kat_poseidon4_of_1_2_3_4() {
    assert(
        poseidon4(1, 2, 3, 4) == 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9,
        "poseidon4(1,2,3,4) KAT mismatch: Poseidon2 parameterization changed",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p0_empty() {
    assert(
        Poseidon2::hash([], 0)
            == 0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e,
        "AFP-KDC v1.0.2 P0 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p1_one() {
    assert(
        Poseidon2::hash([1], 1)
            == 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
        "AFP-KDC v1.0.2 P1 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p2_two() {
    assert(
        Poseidon2::hash([1, 2], 2)
            == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
        "AFP-KDC v1.0.2 P2 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p3_three() {
    assert(
        Poseidon2::hash([1, 2, 3], 3)
            == 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
        "AFP-KDC v1.0.2 P3 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p4_four() {
    assert(
        Poseidon2::hash([1, 2, 3, 4], 4)
            == 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9,
        "AFP-KDC v1.0.2 P4 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p6_six() {
    assert(
        Poseidon2::hash([1, 2, 3, 4, 5, 6], 6)
            == 0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a,
        "AFP-KDC v1.0.2 P6 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p7_seven() {
    assert(
        Poseidon2::hash([1, 2, 3, 4, 5, 6, 7], 7)
            == 0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238,
        "AFP-KDC v1.0.2 P7 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_zkc_holder_commitment_from_seed_42() {
    let seed: Field = 42;
    let cbk = derive_credential_binding_key(seed);
    let holder_commitment = derive_holder_commitment(cbk);

    assert(
        cbk == 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105,
        "credential binding key KAT mismatch",
    );
    assert(
        holder_commitment == 0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf,
        "holder commitment KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v101_master_seed_boundaries() {
    // Host seed 0 and host seed r both map to Field 0 under AFP-KDC v1.0.1.
    assert(
        derive_credential_binding_key(0)
            == 0x214266e62f30fbe36989a56722253ef4b4f05c73e7e6e79561523f86bbc0bf69,
        "zero/r alias cbk KAT mismatch",
    );
    assert(
        derive_holder_commitment_from_seed(0)
            == 0x26911baa3a91df3ae99b57264dd8ffc1a774b75adb6bc44f801eab9a28dbb85c,
        "zero/r alias holder KAT mismatch",
    );

    // Host seed 1 and host seed r+1 both map to Field 1.
    assert(
        derive_credential_binding_key(1)
            == 0x156363709184916cfd39a0ff03728d2f61eeb21db527764a632ced26248620a9,
        "one/r+1 alias cbk KAT mismatch",
    );
    assert(
        derive_holder_commitment_from_seed(1)
            == 0x1b5da79c042b6f60628ca40f9f36af41ba93a4e0706f18d63918ead501bded10,
        "one/r+1 alias holder KAT mismatch",
    );

    let r_minus_1: Field = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    assert(
        derive_credential_binding_key(r_minus_1)
            == 0x0f9ae0ed0936446399b4d8860ba56fad98f3cde0e234351498f9b47157e47770,
        "r-1 cbk KAT mismatch",
    );
    assert(
        derive_holder_commitment_from_seed(r_minus_1)
            == 0x0f93ef96e2e9889be72f147c815effddd4836f6a03c133b9383eaa4c0237d9ae,
        "r-1 holder KAT mismatch",
    );

    let high_bit_mapped: Field = 0x1f37631a3d9cbfac8f5f7492fcfd4f45af982f6f0c8d1edd783c14d81ffffffe;
    assert(
        derive_credential_binding_key(high_bit_mapped)
            == 0x2e0ec1d6d13e07e096d6e97072ada506cfd048265c8e715b48cdb52222211acc,
        "high-bit cbk KAT mismatch",
    );
    assert(
        derive_holder_commitment_from_seed(high_bit_mapped)
            == 0x20bdb27ab52177af841502649fae65d8f7ad2456c92afa3392c75e40fd4854e3,
        "high-bit holder KAT mismatch",
    );

    let asymmetric: Field = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
    assert(
        derive_credential_binding_key(asymmetric)
            == 0x13f7a19491d111e859b706bbf4ac09ae04b9ae617fd9810f2c2abc79498b25f7,
        "asymmetric cbk KAT mismatch",
    );
    assert(
        derive_holder_commitment_from_seed(asymmetric)
            == 0x168c18b64068e5507de96921fc526999752d8df4413ec276a3ab7cd2b57f6223,
        "asymmetric holder KAT mismatch",
    );
}

#[test]
fn kat_zkc_claim_binding_2() {
    assert(
        compute_claim_binding_2(1, 31, 777, 12345)
            == 0x08e653806388ce8f7484bbe88e58b05bed1f59b4f20ff1728a73ead636de2864,
        "claim binding KAT mismatch",
    );
}

#[test]
fn test_presentation_pseudonym_matches_manual_poseidon() {
    let cbk = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105; // seed-42 KAT
    let pseudonym = derive_presentation_pseudonym(cbk, 7);
    assert(pseudonym == poseidon3(DOMAIN_ZKC_PRESENTATION_SCOPE, cbk, 7));
    assert(pseudonym != derive_presentation_pseudonym(cbk, 8));
}

#[test]
fn test_assert_presentation_binding_anonymous() {
    let cbk = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105; // seed-42 KAT
    // Anonymous sentinel: scope_id 0 with pseudonym 0 must pass.
    assert_presentation_binding(0, 0, cbk);
}

#[test]
fn test_assert_presentation_binding_scoped() {
    let cbk = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105; // seed-42 KAT
    let scope_id = 7;
    let pseudonym = derive_presentation_pseudonym(cbk, scope_id);
    assert_presentation_binding(pseudonym, scope_id, cbk);
}

#[test(should_fail_with = "anonymous profile must not carry a pseudonym")]
fn test_assert_presentation_binding_rejects_pseudonym_under_anonymous() {
    let cbk = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105; // seed-42 KAT
    assert_presentation_binding(1, 0, cbk);
}

#[test(should_fail_with = "presentation pseudonym does not derive from binding key and scope")]
fn test_assert_presentation_binding_rejects_wrong_pseudonym() {
    let cbk = 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105; // seed-42 KAT
    let scope_id = 7;
    let wrong = derive_presentation_pseudonym(cbk, scope_id) + 1;
    assert_presentation_binding(wrong, scope_id, cbk);
}
