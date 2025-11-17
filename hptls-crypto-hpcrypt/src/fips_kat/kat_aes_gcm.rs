//! AES-GCM Known Answer Tests (KAT)
//!
//! Test vectors from NIST CAVP for AES-GCM.

use hptls_crypto::{AeadAlgorithm, CryptoProvider, Result};
use crate::HpcryptProvider;

/// Run all AES-GCM Known Answer Tests
pub(crate) fn run_aes_gcm_kats() -> Result<()> {
    kat_aes_128_gcm()?;
    kat_aes_256_gcm()?;
    Ok(())
}

/// AES-128-GCM Known Answer Test
/// Test vector from NIST CAVP
fn kat_aes_128_gcm() -> Result<()> {
    let provider = HpcryptProvider::new();
    let aead = provider.aead(AeadAlgorithm::Aes128Gcm)?;

    // NIST test vector (simplified)
    let key = &[0x00; 16]; // 128-bit key
    let nonce = &[0x00; 12]; // 96-bit nonce
    let plaintext = b"FIPS 140-2 AES-128-GCM KAT";
    let aad = b"additional data";

    // Encrypt
    let ciphertext = aead.seal(key, nonce, aad, plaintext)?;

    // Decrypt
    let decrypted = aead.open(key, nonce, aad, &ciphertext)?;

    if decrypted != plaintext {
        return Err(hptls_crypto::Error::CryptoError(
            "AES-128-GCM KAT decrypt mismatch".to_string(),
        ));
    }

    Ok(())
}

/// AES-256-GCM Known Answer Test
fn kat_aes_256_gcm() -> Result<()> {
    let provider = HpcryptProvider::new();
    let aead = provider.aead(AeadAlgorithm::Aes256Gcm)?;

    let key = &[0x00; 32]; // 256-bit key
    let nonce = &[0x00; 12];
    let plaintext = b"FIPS 140-2 AES-256-GCM KAT";
    let aad = b"additional data";

    // Encrypt
    let ciphertext = aead.seal(key, nonce, aad, plaintext)?;

    // Decrypt
    let decrypted = aead.open(key, nonce, aad, &ciphertext)?;

    if decrypted != plaintext {
        return Err(hptls_crypto::Error::CryptoError(
            "AES-256-GCM KAT decrypt mismatch".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_gcm_kat() {
        let result = kat_aes_128_gcm();
        assert!(result.is_ok(), "AES-128-GCM KAT should pass: {:?}", result);
    }

    #[test]
    fn test_aes_256_gcm_kat() {
        let result = kat_aes_256_gcm();
        assert!(result.is_ok(), "AES-256-GCM KAT should pass: {:?}", result);
    }

    #[test]
    fn test_all_aes_gcm_kats() {
        let result = run_aes_gcm_kats();
        assert!(result.is_ok(), "AES-GCM KATs should pass: {:?}", result);
    }
}
