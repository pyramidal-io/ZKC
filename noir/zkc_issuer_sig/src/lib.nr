// =============================================================================
// ZKC Issuer Signature Verification
//
// The initial issuer-attestation profile uses Noir's secp256k1 ECDSA black-box
// verifier over a 32-byte credential digest. Predicate circuits compose this
// library to prove that credential claims were signed by a trusted issuer key.
// =============================================================================

pub global ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1: u8 = 1;

pub fn verify_issuer_signature_secp256k1(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    credential_message_hash: [u8; 32],
) -> bool {
    std::ecdsa_secp256k1::verify_signature(
        public_key_x,
        public_key_y,
        signature,
        credential_message_hash,
    )
}

pub fn verify_issuer_signature(
    scheme: u8,
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    credential_message_hash: [u8; 32],
) -> bool {
    if scheme != ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1 {
        false
    } else {
        verify_issuer_signature_secp256k1(
            public_key_x,
            public_key_y,
            signature,
            credential_message_hash,
        )
    }
}

pub fn assert_issuer_signature(
    scheme: u8,
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    credential_message_hash: [u8; 32],
) {
    assert(
        verify_issuer_signature(
            scheme,
            public_key_x,
            public_key_y,
            signature,
            credential_message_hash,
        ),
        "invalid issuer signature",
    );
}

#[test]
fn kat_valid_issuer_signature_secp256k1() {
    let public_key_x: [u8; 32] = [
        137, 81, 38, 98, 181, 144, 46, 180, 102, 61, 191, 66, 140, 98, 244, 92, 229, 44, 211, 23,
        36, 201, 121, 32, 86, 185, 98, 216, 108, 62, 37, 26,
    ];
    let public_key_y: [u8; 32] = [
        34, 85, 29, 119, 46, 134, 16, 31, 56, 87, 20, 235, 116, 171, 39, 5, 122, 99, 146, 254, 158,
        5, 185, 45, 152, 119, 236, 243, 137, 31, 179, 114,
    ];
    let credential_message_hash: [u8; 32] = [
        219, 230, 201, 83, 210, 164, 56, 223, 229, 121, 220, 109, 44, 226, 5, 186, 73, 118, 161, 46,
        56, 46, 45, 182, 179, 179, 208, 119, 134, 28, 37, 110,
    ];
    let signature: [u8; 64] = [
        127, 242, 233, 19, 129, 223, 126, 197, 228, 106, 54, 18, 192, 184, 118, 140, 152, 55, 241,
        255, 40, 185, 103, 179, 102, 150, 220, 48, 226, 220, 176, 143, 19, 107, 60, 33, 245, 230,
        34, 119, 197, 192, 86, 17, 119, 230, 92, 52, 135, 208, 246, 154, 147, 76, 98, 39, 55, 114,
        112, 220, 49, 36, 226, 246,
    ];

    assert(
        verify_issuer_signature(
            ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1,
            public_key_x,
            public_key_y,
            signature,
            credential_message_hash,
        ),
        "valid secp256k1 issuer signature must verify",
    );
}

#[test]
fn test_rejects_wrong_scheme() {
    let public_key_x = [0; 32];
    let public_key_y = [0; 32];
    let signature = [0; 64];
    let credential_message_hash = [0; 32];

    assert(
        !verify_issuer_signature(
            0,
            public_key_x,
            public_key_y,
            signature,
            credential_message_hash,
        ),
        "unsupported scheme must be rejected before predicate composition",
    );
}

#[test]
fn test_rejects_tampered_message_hash() {
    let public_key_x: [u8; 32] = [
        137, 81, 38, 98, 181, 144, 46, 180, 102, 61, 191, 66, 140, 98, 244, 92, 229, 44, 211, 23,
        36, 201, 121, 32, 86, 185, 98, 216, 108, 62, 37, 26,
    ];
    let public_key_y: [u8; 32] = [
        34, 85, 29, 119, 46, 134, 16, 31, 56, 87, 20, 235, 116, 171, 39, 5, 122, 99, 146, 254, 158,
        5, 185, 45, 152, 119, 236, 243, 137, 31, 179, 114,
    ];
    let signature: [u8; 64] = [
        127, 242, 233, 19, 129, 223, 126, 197, 228, 106, 54, 18, 192, 184, 118, 140, 152, 55, 241,
        255, 40, 185, 103, 179, 102, 150, 220, 48, 226, 220, 176, 143, 19, 107, 60, 33, 245, 230,
        34, 119, 197, 192, 86, 17, 119, 230, 92, 52, 135, 208, 246, 154, 147, 76, 98, 39, 55, 114,
        112, 220, 49, 36, 226, 246,
    ];
    let tampered_message_hash: [u8; 32] = [
        218, 230, 201, 83, 210, 164, 56, 223, 229, 121, 220, 109, 44, 226, 5, 186, 73, 118, 161, 46,
        56, 46, 45, 182, 179, 179, 208, 119, 134, 28, 37, 110,
    ];

    assert(
        !verify_issuer_signature(
            ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1,
            public_key_x,
            public_key_y,
            signature,
            tampered_message_hash,
        ),
        "tampered credential digest must not verify",
    );
}
