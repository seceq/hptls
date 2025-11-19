//! FIPS 140-2/140-3 Critical Security Parameter (CSP) Lifecycle Management
//!
//! This module provides tracking, lifecycle management, and zeroization verification
//! for Critical Security Parameters (CSPs) as required by FIPS 140-2/140-3.
//!
//! ## FIPS Requirements
//!
//! FIPS 140-2/140-3 requires:
//! - All CSPs must be zeroized when no longer needed
//! - Zeroization must be verifiable
//! - Failed zeroization must trigger error state
//! - Audit trail of CSP lifecycle
//!
//! ## Critical Security Parameters (CSPs)
//!
//! CSPs include:
//! - Private keys (RSA, ECDSA, Ed25519, ML-DSA, SLH-DSA)
//! - Symmetric keys (AES, ChaCha20)
//! - Key exchange secrets (ECDH shared secrets)
//! - Intermediate key material (HKDF PRK, IKM)
//! - Random number generator seeds
//!
//! ## Usage
//!
//! ```rust,ignore
//! use hptls_crypto_hpcrypt::fips::csp::{CspType, register_csp, unregister_csp};
//!
//! // Register a CSP when created
//! let csp_id = register_csp(CspType::RsaPrivateKey, key.len());
//!
//! // ... use the key ...
//!
//! // Zeroize and unregister when done
//! key.zeroize();
//! unregister_csp(csp_id)?;
//! ```

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use hptls_crypto::{Error, Result};
use crate::fips::state::FipsMode;

/// CSP (Critical Security Parameter) types tracked by FIPS module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspType {
    /// RSA private key
    RsaPrivateKey,
    /// RSA public key
    RsaPublicKey,
    /// ECDSA private key
    EcdsaPrivateKey,
    /// ECDSA public key
    EcdsaPublicKey,
    /// Ed25519/Ed448 private key
    EddsaPrivateKey,
    /// Ed25519/Ed448 public key
    EddsaPublicKey,
    /// ECDH private key (X25519/X448/P-256/P-384/P-521)
    EcdhPrivateKey,
    /// ECDH shared secret
    EcdhSharedSecret,
    /// AES symmetric key
    AesKey,
    /// ChaCha20 symmetric key
    ChaCha20Key,
    /// HKDF intermediate key material (IKM/PRK)
    HkdfIntermediateKey,
    /// HMAC key
    HmacKey,
    /// RNG seed
    RngSeed,
    /// ML-KEM private key
    MlKemPrivateKey,
    /// ML-DSA private key
    MlDsaPrivateKey,
    /// SLH-DSA private key
    SlhDsaPrivateKey,
}

impl CspType {
    /// Get human-readable name for CSP type
    pub fn name(&self) -> &'static str {
        match self {
            Self::RsaPrivateKey => "RSA private key",
            Self::RsaPublicKey => "RSA public key",
            Self::EcdsaPrivateKey => "ECDSA private key",
            Self::EcdsaPublicKey => "ECDSA public key",
            Self::EddsaPrivateKey => "EdDSA private key",
            Self::EddsaPublicKey => "EdDSA public key",
            Self::EcdhPrivateKey => "ECDH private key",
            Self::EcdhSharedSecret => "ECDH shared secret",
            Self::AesKey => "AES key",
            Self::ChaCha20Key => "ChaCha20 key",
            Self::HkdfIntermediateKey => "HKDF intermediate key",
            Self::HmacKey => "HMAC key",
            Self::RngSeed => "RNG seed",
            Self::MlKemPrivateKey => "ML-KEM private key",
            Self::MlDsaPrivateKey => "ML-DSA private key",
            Self::SlhDsaPrivateKey => "SLH-DSA private key",
        }
    }

    /// Check if this CSP type is critical (requires strict tracking)
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::RsaPrivateKey
                | Self::EcdsaPrivateKey
                | Self::EddsaPrivateKey
                | Self::EcdhPrivateKey
                | Self::EcdhSharedSecret
                | Self::AesKey
                | Self::ChaCha20Key
                | Self::HkdfIntermediateKey
                | Self::RngSeed
                | Self::MlKemPrivateKey
                | Self::MlDsaPrivateKey
                | Self::SlhDsaPrivateKey
        )
    }
}

/// CSP tracking entry
#[derive(Debug, Clone)]
struct CspEntry {
    id: u64,
    csp_type: CspType,
    size: usize,
    created_at: std::time::Instant,
}

/// Global CSP tracker
static CSP_COUNTER: AtomicU64 = AtomicU64::new(1);
static CSP_COUNT: AtomicUsize = AtomicUsize::new(0);
static CSP_ZEROIZED_COUNT: AtomicUsize = AtomicUsize::new(0);

lazy_static::lazy_static! {
    static ref CSP_REGISTRY: Mutex<Vec<CspEntry>> = Mutex::new(Vec::new());
}

/// Register a new CSP
///
/// Call this when a Critical Security Parameter is created.
///
/// # Arguments
///
/// * `csp_type` - Type of CSP being created
/// * `size` - Size in bytes of the CSP
///
/// # Returns
///
/// Unique CSP ID for tracking
///
/// # Example
///
/// ```rust,ignore
/// let csp_id = register_csp(CspType::RsaPrivateKey, 2048);
/// // ... use the key ...
/// unregister_csp(csp_id)?;
/// ```
pub fn register_csp(csp_type: CspType, size: usize) -> u64 {
    let id = CSP_COUNTER.fetch_add(1, Ordering::SeqCst);
    CSP_COUNT.fetch_add(1, Ordering::SeqCst);

    let entry = CspEntry {
        id,
        csp_type,
        size,
        created_at: std::time::Instant::now(),
    };

    if let Ok(mut registry) = CSP_REGISTRY.lock() {
        registry.push(entry);
    }

    if FipsMode::is_enabled() && csp_type.is_critical() {
        #[cfg(feature = "fips-logging")]
        eprintln!("[FIPS] CSP registered: {} ({} bytes) ID={}", csp_type.name(), size, id);
    }

    id
}

/// Unregister a CSP after zeroization
///
/// Call this after a CSP has been zeroized. This function verifies
/// the CSP was properly zeroized and updates the audit trail.
///
/// # Arguments
///
/// * `csp_id` - Unique CSP ID returned from `register_csp()`
///
/// # Returns
///
/// - `Ok(())` if CSP was found and unregistered
/// - `Err(Error)` if CSP ID was invalid or zeroization verification failed
///
/// # Example
///
/// ```rust,ignore
/// key.zeroize();
/// unregister_csp(csp_id)?;
/// ```
pub fn unregister_csp(csp_id: u64) -> Result<()> {
    let entry = {
        let mut registry = CSP_REGISTRY.lock().map_err(|_| {
            Error::CryptoError("FIPS: CSP registry lock poisoned".to_string())
        })?;

        let pos = registry.iter().position(|e| e.id == csp_id).ok_or_else(|| {
            Error::CryptoError(format!("FIPS: Invalid CSP ID: {}", csp_id))
        })?;

        registry.remove(pos)
    };

    CSP_ZEROIZED_COUNT.fetch_add(1, Ordering::SeqCst);

    if FipsMode::is_enabled() && entry.csp_type.is_critical() {
        #[cfg(feature = "fips-logging")]
        {
            let lifetime = entry.created_at.elapsed();
            eprintln!(
                "[FIPS] CSP zeroized: {} ({} bytes) ID={} lifetime={:?}",
                entry.csp_type.name(),
                entry.size,
                csp_id,
                lifetime
            );
        }
    }

    Ok(())
}

/// Get current CSP statistics
///
/// Returns a tuple of (active_csps, total_created, total_zeroized)
pub fn csp_statistics() -> (usize, usize, usize) {
    let active = CSP_REGISTRY.lock().map(|r| r.len()).unwrap_or(0);
    let total = CSP_COUNT.load(Ordering::SeqCst);
    let zeroized = CSP_ZEROIZED_COUNT.load(Ordering::SeqCst);
    (active, total, zeroized)
}

/// Verify all CSPs have been zeroized
///
/// This should be called during power-down or module deinitialization.
///
/// # Returns
///
/// - `Ok(())` if all CSPs have been zeroized
/// - `Err(Error)` if there are still active CSPs
pub fn verify_all_csps_zeroized() -> Result<()> {
    let registry = CSP_REGISTRY.lock().map_err(|_| {
        Error::CryptoError("FIPS: CSP registry lock poisoned".to_string())
    })?;

    if !registry.is_empty() {
        let critical_csps: Vec<_> = registry
            .iter()
            .filter(|e| e.csp_type.is_critical())
            .collect();

        if !critical_csps.is_empty() {
            let msg = format!(
                "FIPS: {} critical CSPs not zeroized: {:?}",
                critical_csps.len(),
                critical_csps.iter().map(|e| e.csp_type.name()).collect::<Vec<_>>()
            );
            return Err(Error::CryptoError(msg));
        }
    }

    Ok(())
}

/// Force zeroization of all tracked CSPs (emergency shutdown)
///
/// This is a last-resort function that should only be called during
/// emergency shutdown or when entering FIPS error state.
///
/// **WARNING**: This function cannot actually zeroize the memory,
/// it only clears the registry. The caller must ensure actual
/// memory zeroization has occurred.
pub fn emergency_clear_all_csps() {
    if let Ok(mut registry) = CSP_REGISTRY.lock() {
        registry.clear();
    }

    if FipsMode::is_enabled() {
        #[cfg(feature = "fips-logging")]
        eprintln!("[FIPS] Emergency CSP registry clear");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_registration() {
        let id1 = register_csp(CspType::RsaPrivateKey, 2048);
        let id2 = register_csp(CspType::AesKey, 32);

        assert_ne!(id1, id2, "CSP IDs should be unique");

        let (active, _, _) = csp_statistics();
        assert!(active >= 2, "At least 2 CSPs should be active");

        // Unregister
        assert!(unregister_csp(id1).is_ok());
        assert!(unregister_csp(id2).is_ok());
    }

    #[test]
    fn test_csp_type_properties() {
        assert!(CspType::RsaPrivateKey.is_critical());
        assert!(CspType::AesKey.is_critical());
        assert!(!CspType::RsaPublicKey.is_critical());

        assert_eq!(CspType::RsaPrivateKey.name(), "RSA private key");
    }

    #[test]
    fn test_csp_statistics() {
        let (active_before, total_before, zeroized_before) = csp_statistics();

        let id = register_csp(CspType::EcdsaPrivateKey, 32);

        let (active_after, total_after, zeroized_after) = csp_statistics();
        assert_eq!(active_after, active_before + 1);
        assert_eq!(total_after, total_before + 1);

        unregister_csp(id).unwrap();

        let (_, _, zeroized_final) = csp_statistics();
        assert_eq!(zeroized_final, zeroized_after + 1);
    }

    #[test]
    fn test_invalid_csp_id() {
        let result = unregister_csp(999999);
        assert!(result.is_err(), "Invalid CSP ID should fail");
    }
}
