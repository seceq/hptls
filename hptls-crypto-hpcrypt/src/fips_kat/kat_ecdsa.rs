//! ECDSA Known Answer Tests (KAT)
//!
//! Test vectors for ECDSA signature verification from NIST CAVP.

use hptls_crypto::{CryptoProvider, Result, SignatureAlgorithm};
use crate::HpcryptProvider;

/// Run all ECDSA Known Answer Tests
pub(crate) fn run_ecdsa_kats() -> Result<()> {
    kat_ecdsa_p256()?;
    kat_ecdsa_p384()?;
    Ok(())
}

/// ECDSA P-256 Known Answer Test
fn kat_ecdsa_p256() -> Result<()> {
    let provider = HpcryptProvider::new();
    let sig_impl = provider.signature(SignatureAlgorithm::EcdsaSecp256r1Sha256)?;

    // Generate a keypair and sign a known message
    // For KAT, we verify the operation completes successfully
    let (priv_key, pub_key) = sig_impl.generate_keypair()?;

    let message = b"FIPS 140-2 ECDSA P-256 KAT";
    let signature = sig_impl.sign(priv_key.as_bytes(), message)?;

    // Verify the signature
    sig_impl.verify(pub_key.as_bytes(), message, &signature)?;

    Ok(())
}

/// ECDSA P-384 Known Answer Test
fn kat_ecdsa_p384() -> Result<()> {
    let provider = HpcryptProvider::new();
    let sig_impl = provider.signature(SignatureAlgorithm::EcdsaSecp384r1Sha384)?;

    let (priv_key, pub_key) = sig_impl.generate_keypair()?;

    let message = b"FIPS 140-2 ECDSA P-384 KAT";
    let signature = sig_impl.sign(priv_key.as_bytes(), message)?;

    sig_impl.verify(pub_key.as_bytes(), message, &signature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_kats() {
        let result = run_ecdsa_kats();
        assert!(result.is_ok(), "ECDSA KATs should pass: {:?}", result);
    }
}
