//! # hpcrypt-based Cryptography Provider for HPTLS
//!
//! This crate provides a cryptography provider implementation for HPTLS using the
//! [hpcrypt](https://github.com/seceq/hpcrypt) library as the underlying cryptographic backend.
//!
//! ## Features
//!
//! - **100% Safe Rust** - hpcrypt is implemented in pure safe Rust
//! - **Constant-Time Operations** - Protection against timing side-channels
//! - **Standards Compliant** - Full RFC and NIST FIPS compliance
//! - **High Performance** - Optimized implementations with hardware acceleration
//!
//! ## Supported Algorithms
//!
//! ### Classical Cryptography
//! - **AEAD**: AES-128-GCM, AES-256-GCM, AES-128-CCM, AES-128-CCM-8, ChaCha20-Poly1305
//! - **Hash**: SHA-256, SHA-384, SHA-512
//! - **HMAC**: With SHA-256, SHA-384, SHA-512
//! - **KDF**: HKDF-Extract, HKDF-Expand
//! - **Key Exchange**: X25519, X448, ECDH P-256, P-384, P-521
//! - **Signatures**: Ed25519, Ed448, ECDSA P-256, P-384, RSA-PSS
//! - **RNG**: Cryptographically secure random number generation
//!
//! ### Post-Quantum Cryptography (FIPS 203-205)
//! - **ML-KEM**: Key encapsulation (512, 768, 1024)
//! - **ML-DSA**: Digital signatures (44, 65, 87)
//! - **SLH-DSA**: Hash-based signatures (SHA2-128f, 192f, 256f)
//! - **Hybrid**: X25519+ML-KEM-768, P-256+ML-KEM-768
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use hptls_crypto::CryptoProvider;
//! use hptls_crypto_hpcrypt::HpcryptProvider;
//!
//! // Create the provider
//! let provider = HpcryptProvider::new();
//!
//! // Use it with HPTLS
//! // let config = TlsConfig::builder()
//! //     .crypto_provider(provider)
//! //     .build()?;
//! ```

#![deny(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_qualifications,
    missing_debug_implementations
)]

use hptls_crypto::{
    Aead, AeadAlgorithm, CryptoProvider, HardwareFeatures, Hash, HashAlgorithm,
    HeaderProtection, HeaderProtectionAlgorithm, Hmac, Hpke, HpkeCipherSuite, Kdf, KdfAlgorithm,
    KeyExchange, KeyExchangeAlgorithm, Random, Result, Signature, SignatureAlgorithm,
};

pub mod aead;
pub mod der;
pub mod fips_kat;
mod fips_root;
pub mod hash;
pub mod header_protection;
pub mod hkdf;
pub mod hmac;
pub mod hpke_adapter;
pub mod kex;
pub mod random;
mod rsa_bridge;
pub mod signature;

// Post-Quantum Cryptography modules
pub mod mlkem;
pub mod mldsa;
pub mod slhdsa;
pub mod hybrid_kem;

use random::HpcryptRandom;

/// Cryptography provider using hpcrypt implementations.
///
/// This provider implements all cryptographic operations required by HPTLS
/// using the hpcrypt library as the backend.
///
/// # Thread Safety
///
/// This provider is `Send + Sync` and can be safely shared across threads.
///
/// # Example
///
/// ```rust,no_run
/// use hptls_crypto::CryptoProvider;
/// use hptls_crypto_hpcrypt::HpcryptProvider;
///
/// let provider = HpcryptProvider::new();
/// ```
#[derive(Debug)]
pub struct HpcryptProvider {
    /// Random number generator instance
    random: HpcryptRandom,
    /// Detected hardware features
    hardware_features: HardwareFeatures,
}

impl Default for HpcryptProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoProvider for HpcryptProvider {
    fn new() -> Self {
        Self {
            random: HpcryptRandom,
            hardware_features: HardwareFeatures::detect(),
        }
    }

    fn aead(&self, algorithm: AeadAlgorithm) -> Result<Box<dyn Aead>> {
        aead::create_aead(algorithm)
    }

    fn hash(&self, algorithm: HashAlgorithm) -> Result<Box<dyn Hash>> {
        hash::create_hash(algorithm)
    }

    fn hmac(&self, algorithm: HashAlgorithm, key: &[u8]) -> Result<Box<dyn Hmac>> {
        hmac::create_hmac(algorithm, key)
    }

    fn kdf(&self, algorithm: KdfAlgorithm) -> Result<Box<dyn Kdf>> {
        hkdf::create_kdf(algorithm)
    }

    fn random(&self) -> &dyn Random {
        &self.random
    }

    fn key_exchange(&self, algorithm: KeyExchangeAlgorithm) -> Result<Box<dyn KeyExchange>> {
        kex::create_key_exchange(algorithm)
    }

    fn signature(&self, algorithm: SignatureAlgorithm) -> Result<Box<dyn Signature>> {
        signature::create_signature(algorithm)
    }

    fn header_protection(
        &self,
        algorithm: HeaderProtectionAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn HeaderProtection>> {
        header_protection::create_header_protection(algorithm, key)
    }

    fn hpke(&self, cipher_suite: HpkeCipherSuite) -> Result<Box<dyn Hpke>> {
        hpke_adapter::create_hpke(cipher_suite)
    }

    fn hardware_features(&self) -> HardwareFeatures {
        self.hardware_features
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = HpcryptProvider::new();
        let features = provider.hardware_features();
        println!("Hardware features: {:?}", features);
    }

    #[test]
    fn test_aead_support() {
        let provider = HpcryptProvider::new();
        assert!(provider.supports_aead(AeadAlgorithm::Aes128Gcm));
        assert!(provider.supports_aead(AeadAlgorithm::Aes256Gcm));
        assert!(provider.supports_aead(AeadAlgorithm::ChaCha20Poly1305));
    }

    #[test]
    fn test_key_exchange_support() {
        let provider = HpcryptProvider::new();
        assert!(provider.supports_key_exchange(KeyExchangeAlgorithm::X25519));
        assert!(provider.supports_key_exchange(KeyExchangeAlgorithm::Secp256r1));
    }

    #[test]
    fn test_signature_support() {
        let provider = HpcryptProvider::new();
        assert!(provider.supports_signature(SignatureAlgorithm::Ed25519));
        assert!(provider.supports_signature(SignatureAlgorithm::EcdsaSecp256r1Sha256));
    }
}
