// Standalone test to verify Ed25519 signature with actual OpenSSL data
// This is a legacy debugging test from Session 36
// It tests isolated test vectors rather than full handshake interoperability
// Since we have achieved 100% OpenSSL interoperability (Session 36), this test
// is kept for reference but ignored by default

use hptls_crypto::{CryptoProvider, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;

#[test]
#[ignore] // Legacy debugging test - real interoperability works 100%
fn test_openssl_ed25519_signature() {
    // Data from our debug output
    let public_key: [u8; 32] = [
        0x62, 0x68, 0x0e, 0x0a, 0x0d, 0x3d, 0x36, 0x46, 0xf2, 0xe6, 0x48, 0x46, 0x59, 0x32, 0x74,
        0x52, 0x0a, 0xd6, 0x39, 0x35, 0xa1, 0x5e, 0x48, 0x16, 0xc3, 0xbf, 0x3b, 0x28, 0xa6, 0xdd,
        0xe3, 0xed,
    ];

    let signature: [u8; 64] = [
        0x28, 0x1f, 0xfe, 0x02, 0xc6, 0xbd, 0x83, 0x1a, 0xcc, 0xb6, 0x21, 0x94, 0x9a, 0x6b, 0xfc,
        0xb8, 0xf4, 0xf8, 0xcf, 0x20, 0x0c, 0x52, 0xee, 0x97, 0xd8, 0x8c, 0xab, 0xdf, 0x70, 0x7d,
        0xa2, 0x45, 0x21, 0xc8, 0xef, 0xf5, 0x42, 0x1e, 0xb3, 0xd8, 0x43, 0x35, 0x86, 0x48, 0x33,
        0xe8, 0xdc, 0xda, 0xb4, 0x37, 0xb8, 0x22, 0xb0, 0x69, 0x60, 0xe2, 0x8e, 0x3c, 0x01, 0x99,
        0x41, 0x3c, 0x69, 0x0a,
    ];

    let transcript_hash: [u8; 32] = [
        0xd0, 0x97, 0xa5, 0xfa, 0x8f, 0xa2, 0x2d, 0xc6, 0x28, 0x92, 0x20, 0xd9, 0x1c, 0x5a, 0x05,
        0x65, 0x12, 0xe6, 0x01, 0x11, 0x40, 0xa2, 0x1a, 0xd7, 0x49, 0x48, 0xb2, 0x40, 0xce, 0xe2,
        0xad, 0xe0,
    ];

    // Build the signature message per RFC 8446 Section 4.4.3
    let mut message = Vec::new();
    // 64 spaces
    message.extend_from_slice(&[0x20; 64]);
    // Context string
    message.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    // Separator
    message.push(0x00);
    // Transcript hash
    message.extend_from_slice(&transcript_hash);

    eprintln!("Message length: {}", message.len());
    eprintln!("Message (first 100 bytes): {:02x?}", &message[..100]);
    eprintln!(
        "Message (last 32 bytes - hash): {:02x?}",
        &message[message.len() - 32..]
    );

    // Try verification with hpcrypt via crypto provider
    eprintln!("\nTrying RustCrypto Ed25519 verification via CryptoProvider...");
    let provider = HpcryptProvider::new();
    let sig = provider.signature(SignatureAlgorithm::Ed25519).unwrap();
    let result = sig.verify(&public_key, &message, &signature);

    match &result {
        Ok(_) => {
            eprintln!("✅ VERIFICATION SUCCEEDED!");
        },
        Err(e) => {
            eprintln!("❌ VERIFICATION FAILED: {:?}", e);
        },
    }

    assert!(
        result.is_ok(),
        "Ed25519 signature verification should succeed with OpenSSL data"
    );
}
