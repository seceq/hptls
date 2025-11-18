//! RSA-PSS OpenSSL Interoperability Tests
//!
//! These tests verify that our RSA-PSS implementation is compatible with OpenSSL-generated
//! keys and signatures. This ensures standards compliance and real-world interoperability.

use hptls_crypto::{CryptoProvider, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;
use num_traits::Zero;

/// Test data generated with OpenSSL commands:
///
/// ```bash
/// # Generate 2048-bit RSA key
/// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_test_key.pem
///
/// # Convert to PKCS#8 DER
/// openssl pkcs8 -topk8 -nocrypt -in rsa_test_key.pem -outform DER -out rsa_private_pkcs8.der
///
/// # Extract public key in X.509 SPKI DER format
/// openssl rsa -in rsa_test_key.pem -pubout -outform DER -out rsa_public_spki.der
///
/// # Sign test message with RSA-PSS-SHA256
/// echo -n "Test message for RSA-PSS signature verification" > test_message.txt
/// openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
///         -sign rsa_test_key.pem -out test_signature.bin test_message.txt
/// ```

const RSA_PRIVATE_KEY_PKCS8: &[u8] = include_bytes!("data/rsa_private_pkcs8.der");
const RSA_PUBLIC_KEY_SPKI: &[u8] = include_bytes!("data/rsa_public_spki.der");
const TEST_MESSAGE: &[u8] = include_bytes!("data/test_message.txt");
const OPENSSL_SIGNATURE: &[u8] = include_bytes!("data/test_signature.bin");

#[test]
fn test_parse_pkcs8_private_key() {
    // Test that we can successfully parse an OpenSSL-generated PKCS#8 private key
    use hptls_crypto_hpcrypt::der::parse_rsa_private_key_pkcs8;

    let result = parse_rsa_private_key_pkcs8(RSA_PRIVATE_KEY_PKCS8);
    assert!(
        result.is_ok(),
        "Failed to parse PKCS#8 private key: {:?}",
        result.err()
    );

    let components = result.unwrap();

    // Verify it's a 2048-bit key
    assert_eq!(components.n.bits(), 2048, "Expected 2048-bit modulus");

    // Verify public exponent is 65537 (standard)
    assert_eq!(
        components.e,
        num_bigint::BigUint::from(65537u32),
        "Expected e=65537"
    );

    // Verify we have all CRT components
    assert!(components.p.bits() > 1000, "Prime p should be ~1024 bits");
    assert!(components.q.bits() > 1000, "Prime q should be ~1024 bits");
    assert!(!components.dp.is_zero(), "dp should not be zero");
    assert!(!components.dq.is_zero(), "dq should not be zero");
    assert!(!components.qinv.is_zero(), "qinv should not be zero");
}

#[test]
fn test_parse_spki_public_key() {
    // Test that we can successfully parse an OpenSSL-generated X.509 SPKI public key
    use hptls_crypto_hpcrypt::der::parse_rsa_public_key_spki;

    let result = parse_rsa_public_key_spki(RSA_PUBLIC_KEY_SPKI);
    assert!(
        result.is_ok(),
        "Failed to parse SPKI public key: {:?}",
        result.err()
    );

    let components = result.unwrap();

    // Verify it's a 2048-bit key
    assert_eq!(components.n.bits(), 2048, "Expected 2048-bit modulus");

    // Verify public exponent is 65537
    assert_eq!(
        components.e,
        num_bigint::BigUint::from(65537u32),
        "Expected e=65537"
    );
}

#[test]
fn test_verify_openssl_signature() {
    // Test that we can verify a signature created by OpenSSL
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create RSA-PSS-SHA256 signature algorithm");

    // Verify the OpenSSL-generated signature
    let result = sig.verify(RSA_PUBLIC_KEY_SPKI, TEST_MESSAGE, OPENSSL_SIGNATURE);

    assert!(
        result.is_ok(),
        "Failed to verify OpenSSL signature: {:?}",
        result.err()
    );

    println!("✅ Successfully verified OpenSSL RSA-PSS-SHA256 signature");
}

#[test]
fn test_sign_and_verify_roundtrip() {
    // Test that we can sign with our implementation and verify with our implementation
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create RSA-PSS-SHA256 signature algorithm");

    // Sign the test message
    let signature = sig
        .sign(RSA_PRIVATE_KEY_PKCS8, TEST_MESSAGE)
        .expect("Failed to sign message");

    // Verify we got a 256-byte signature (2048-bit key)
    assert_eq!(
        signature.len(),
        256,
        "Expected 256-byte signature for 2048-bit key"
    );

    // Verify our own signature
    let result = sig.verify(RSA_PUBLIC_KEY_SPKI, TEST_MESSAGE, &signature);
    assert!(
        result.is_ok(),
        "Failed to verify our own signature: {:?}",
        result.err()
    );

    println!("✅ RSA-PSS-SHA256 sign/verify roundtrip successful");
}

#[test]
fn test_signature_verification_fails_on_wrong_message() {
    // Test that verification fails when the message is different
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create RSA-PSS-SHA256 signature algorithm");

    let wrong_message = b"This is a different message";

    // Try to verify OpenSSL signature with wrong message
    let result = sig.verify(RSA_PUBLIC_KEY_SPKI, wrong_message, OPENSSL_SIGNATURE);

    assert!(
        result.is_err(),
        "Verification should fail with wrong message"
    );

    println!("✅ Signature verification correctly rejected tampered message");
}

#[test]
fn test_signature_verification_fails_on_tampered_signature() {
    // Test that verification fails when the signature is tampered
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create RSA-PSS-SHA256 signature algorithm");

    // Tamper with the signature
    let mut tampered_sig = OPENSSL_SIGNATURE.to_vec();
    tampered_sig[0] ^= 0xFF; // Flip bits in first byte

    // Try to verify tampered signature
    let result = sig.verify(RSA_PUBLIC_KEY_SPKI, TEST_MESSAGE, &tampered_sig);

    assert!(
        result.is_err(),
        "Verification should fail with tampered signature"
    );

    println!("✅ Signature verification correctly rejected tampered signature");
}

#[test]
fn test_rsa_pss_sha384_roundtrip() {
    // Test RSA-PSS with SHA-384
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha384)
        .expect("Failed to create RSA-PSS-SHA384 signature algorithm");

    // Sign with SHA-384
    let signature = sig
        .sign(RSA_PRIVATE_KEY_PKCS8, TEST_MESSAGE)
        .expect("Failed to sign with SHA-384");

    assert_eq!(signature.len(), 256, "Expected 256-byte signature");

    // Verify
    let result = sig.verify(RSA_PUBLIC_KEY_SPKI, TEST_MESSAGE, &signature);
    assert!(result.is_ok(), "Failed to verify SHA-384 signature");

    println!("✅ RSA-PSS-SHA384 sign/verify successful");
}

#[test]
fn test_rsa_pss_sha512_roundtrip() {
    // Test RSA-PSS with SHA-512
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha512)
        .expect("Failed to create RSA-PSS-SHA512 signature algorithm");

    // Sign with SHA-512
    let signature = sig
        .sign(RSA_PRIVATE_KEY_PKCS8, TEST_MESSAGE)
        .expect("Failed to sign with SHA-512");

    assert_eq!(signature.len(), 256, "Expected 256-byte signature");

    // Verify
    let result = sig.verify(RSA_PUBLIC_KEY_SPKI, TEST_MESSAGE, &signature);
    assert!(result.is_ok(), "Failed to verify SHA-512 signature");

    println!("✅ RSA-PSS-SHA512 sign/verify successful");
}

#[test]
fn test_multiple_messages_different_signatures() {
    // Test that signing the same message multiple times produces different signatures
    // (due to randomized salt in PSS)
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create RSA-PSS-SHA256 signature algorithm");

    let sig1 = sig
        .sign(RSA_PRIVATE_KEY_PKCS8, TEST_MESSAGE)
        .expect("Failed to sign");
    let sig2 = sig
        .sign(RSA_PRIVATE_KEY_PKCS8, TEST_MESSAGE)
        .expect("Failed to sign");

    // Signatures should be different (probabilistic due to random salt)
    assert_ne!(
        sig1, sig2,
        "RSA-PSS signatures should be different (randomized salt)"
    );

    // But both should verify
    assert!(sig.verify(RSA_PUBLIC_KEY_SPKI, TEST_MESSAGE, &sig1).is_ok());
    assert!(sig.verify(RSA_PUBLIC_KEY_SPKI, TEST_MESSAGE, &sig2).is_ok());

    println!("✅ RSA-PSS correctly produces different signatures for same message");
}
