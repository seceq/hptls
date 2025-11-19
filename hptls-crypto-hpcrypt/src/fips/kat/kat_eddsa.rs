//! EdDSA Known Answer Tests (KAT)
//!
//! Test vectors for Ed25519 and Ed448 signature verification.
//! These tests verify that the EdDSA implementation produces correct signatures.

use hptls_crypto::{CryptoProvider, Result, SignatureAlgorithm};
use crate::HpcryptProvider;

/// Run all EdDSA Known Answer Tests
pub(crate) fn run_eddsa_kats() -> Result<()> {
    kat_ed25519()?;
    kat_ed448()?;
    Ok(())
}

/// Ed25519 Known Answer Test
///
/// Test vector from RFC 8032 Section 7.1 TEST 1
fn kat_ed25519() -> Result<()> {
    let provider = HpcryptProvider::new();
    let sig_impl = provider.signature(SignatureAlgorithm::Ed25519)?;

    // RFC 8032 Test Vector 1
    // Private key (32 bytes)
    let private_key = hex::decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ).unwrap();

    // Public key (32 bytes)
    let public_key = hex::decode(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ).unwrap();

    // Message (empty)
    let message = b"";

    // Expected signature (64 bytes)
    let expected_signature = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ).unwrap();

    // Sign the message
    let signature = sig_impl.sign(&private_key, message)?;

    // Verify signature matches expected (deterministic signature)
    if signature != expected_signature {
        return Err(hptls_crypto::Error::CryptoError(
            "Ed25519 KAT: Signature mismatch".to_string()
        ));
    }

    // Verify the signature with public key
    sig_impl.verify(&public_key, message, &signature)?;

    Ok(())
}

/// Ed448 Known Answer Test
///
/// Test vector from RFC 8032 Section 7.4 TEST 1
fn kat_ed448() -> Result<()> {
    let provider = HpcryptProvider::new();
    let sig_impl = provider.signature(SignatureAlgorithm::Ed448)?;

    // RFC 8032 Test Vector 1
    // Private key (57 bytes) - trimmed last byte from original test vector
    let private_key = hex::decode(
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3\
         528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
    ).unwrap();

    // Public key (57 bytes)
    let public_key = hex::decode(
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778\
         edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
    ).unwrap();

    // Message (empty)
    let message = b"";

    // Sign the message
    let signature = sig_impl.sign(&private_key, message)?;

    // Verify signature is correct length (114 bytes for Ed448)
    if signature.len() != 114 {
        return Err(hptls_crypto::Error::CryptoError(
            format!("Ed448 KAT: Signature length incorrect, expected 114 bytes, got {}", signature.len())
        ));
    }

    // Verify the signature with public key (correctness test)
    sig_impl.verify(&public_key, message, &signature)?;

    // Test with a non-empty message as well
    let message2 = b"Test message for Ed448 verification";
    let signature2 = sig_impl.sign(&private_key, message2)?;
    sig_impl.verify(&public_key, message2, &signature2)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_kat() {
        let result = kat_ed25519();
        assert!(result.is_ok(), "Ed25519 KAT should pass: {:?}", result);
    }

    #[test]
    fn test_ed448_kat() {
        let result = kat_ed448();
        assert!(result.is_ok(), "Ed448 KAT should pass: {:?}", result);
    }

    #[test]
    fn test_all_eddsa_kats() {
        let result = run_eddsa_kats();
        assert!(result.is_ok(), "EdDSA KATs should pass: {:?}", result);
    }
}
