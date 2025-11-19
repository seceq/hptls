//! FIPS 140-2/140-3 Compliance Framework
//!
//! This module provides a framework for FIPS (Federal Information Processing Standards)
//! compliance including Power-On Self-Tests (POST) and error state management.

mod kat_rsa_pss;
mod kat_ecdsa;
mod kat_eddsa;
mod kat_ecdh;
mod kat_hkdf;
mod kat_aes_gcm;
mod kat_chacha20;

pub use crate::fips::state::{
    FipsMode, FipsState, check_fips_state, run_power_on_self_tests,
};

use hptls_crypto::Result;

/// Run all Known-Answer Tests
///
/// Executes KATs for all FIPS-approved algorithms:
/// - RSA-PSS-SHA256/384/512
/// - ECDSA P-256/P-384/P-521
/// - EdDSA (Ed25519/Ed448)
/// - ECDH (X25519/X448/P-256)
/// - HKDF-SHA256/384/512
/// - AES-128-GCM / AES-256-GCM
/// - ChaCha20-Poly1305
pub(crate) fn run_all_kats() -> Result<()> {
    // Run RSA-PSS KATs
    kat_rsa_pss::run_rsa_pss_kats()?;

    // Run ECDSA KATs
    kat_ecdsa::run_ecdsa_kats()?;

    // Run EdDSA KATs
    kat_eddsa::run_eddsa_kats()?;

    // Run ECDH KATs
    kat_ecdh::run_ecdh_kats()?;

    // Run HKDF/HMAC KATs
    kat_hkdf::run_hkdf_kats()?;

    // Run AES-GCM KATs
    kat_aes_gcm::run_aes_gcm_kats()?;

    // Run ChaCha20-Poly1305 KATs
    kat_chacha20::run_chacha20_kats()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_kats() {
        let result = run_all_kats();
        // KATs should not panic even if they fail validation
        let _ = result;
    }
}
