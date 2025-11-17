//! # HPTLS Cryptographic Provider Interface
//!
//! This crate defines the cryptographic abstraction layer for HPTLS.
//! It provides trait-based interfaces that allow pluggable cryptographic backends.
//!
//! ## Design Goals
//!
//! 1. **Pluggable:** Support multiple crypto libraries (your custom library, ring, aws-lc-rs, etc.)
//! 2. **Zero-cost:** Traits compile to static dispatch where possible
//! 3. **Type-safe:** Leverage Rust's type system to prevent misuse
//! 4. **Hardware-aware:** Auto-detect and use CPU features (AES-NI, SHA extensions)
//! 5. **Constant-time:** All security-critical operations must be constant-time
//!
//! ## Architecture
//!
//! ```text
//! CryptoProvider (main trait)
//! ├── Aead (AEAD ciphers: AES-GCM, ChaCha20-Poly1305)
//! ├── Hash (SHA-256, SHA-384, SHA-512)
//! ├── Hmac (HMAC with various hash functions)
//! ├── Kdf (HKDF, TLS PRF)
//! ├── Random (CSPRNG)
//! ├── KeyExchange (ECDHE, DHE, ML-KEM)
//! └── Signature (ECDSA, EdDSA, RSA-PSS, ML-DSA)
//! ```
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use hptls_crypto::{CryptoProvider, AeadAlgorithm, Error};
//!
//! fn example() -> Result<(), Error> {
//!     // Provider auto-detects best implementation (AES-NI, etc.)
//!     let provider = YourCryptoProvider::new();
//!
//!     // Get an AEAD cipher
//!     let aead = provider.aead(AeadAlgorithm::Aes128Gcm)?;
//!
//!     // Encrypt
//!     let ciphertext = aead.seal(key, nonce, aad, plaintext)?;
//!
//!     // Decrypt
//!     let plaintext = aead.open(key, nonce, aad, ciphertext)?;
//!
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_qualifications,
    missing_debug_implementations
)]

pub mod aead;
pub mod error;
pub mod hash;
pub mod header_protection;
pub mod hmac;
pub mod hpke;
pub mod kdf;
pub mod key_exchange;
pub mod random;
pub mod signature;

pub use aead::{Aead, AeadAlgorithm};
pub use error::{Error, Result};
pub use hash::{Hash, HashAlgorithm};
pub use header_protection::{HeaderProtection, HeaderProtectionAlgorithm};
pub use hmac::Hmac;
pub use hpke::{Hpke, HpkeAead, HpkeCipherSuite, HpkeContext, HpkeKdf, HpkeKem};
pub use kdf::{Kdf, KdfAlgorithm};
pub use key_exchange::{KeyExchange, KeyExchangeAlgorithm};
pub use random::Random;
pub use signature::{Signature, SignatureAlgorithm};

/// The main cryptographic provider trait.
///
/// Implementations of this trait provide all cryptographic operations
/// needed by HPTLS. The trait is designed to be object-safe where possible,
/// allowing for dynamic dispatch, but also supports static dispatch for
/// zero-cost abstractions.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to allow use in multi-threaded
/// environments.
///
/// # Hardware Detection
///
/// Implementations should detect available CPU features (AES-NI, SHA extensions,
/// AVX2, etc.) in their `new()` method and select the fastest available
/// implementation.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Create a new instance of the crypto provider.
    ///
    /// This method should detect available CPU features and select the
    /// optimal implementation for the current platform.
    fn new() -> Self
    where
        Self: Sized;

    /// Get an AEAD cipher instance.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The AEAD algorithm to use
    ///
    /// # Returns
    ///
    /// An AEAD cipher instance, or an error if the algorithm is not supported.
    fn aead(&self, algorithm: AeadAlgorithm) -> Result<Box<dyn Aead>>;

    /// Get a hash function instance.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The hash algorithm to use
    ///
    /// # Returns
    ///
    /// A hash function instance, or an error if the algorithm is not supported.
    fn hash(&self, algorithm: HashAlgorithm) -> Result<Box<dyn Hash>>;

    /// Get an HMAC instance.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The hash algorithm to use for HMAC
    /// * `key` - The HMAC key
    ///
    /// # Returns
    ///
    /// An HMAC instance, or an error if the algorithm is not supported.
    fn hmac(&self, algorithm: HashAlgorithm, key: &[u8]) -> Result<Box<dyn Hmac>>;

    /// Get a KDF (Key Derivation Function) instance.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The KDF algorithm to use
    ///
    /// # Returns
    ///
    /// A KDF instance, or an error if the algorithm is not supported.
    fn kdf(&self, algorithm: KdfAlgorithm) -> Result<Box<dyn Kdf>>;

    /// Get the random number generator.
    ///
    /// # Returns
    ///
    /// A cryptographically secure random number generator.
    fn random(&self) -> &dyn Random;

    /// Get a key exchange instance.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The key exchange algorithm to use
    ///
    /// # Returns
    ///
    /// A key exchange instance, or an error if the algorithm is not supported.
    fn key_exchange(&self, algorithm: KeyExchangeAlgorithm) -> Result<Box<dyn KeyExchange>>;

    /// Get a signature scheme instance.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The signature algorithm to use
    ///
    /// # Returns
    ///
    /// A signature instance, or an error if the algorithm is not supported.
    fn signature(&self, algorithm: SignatureAlgorithm) -> Result<Box<dyn Signature>>;

    /// Get a QUIC header protection instance.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The header protection algorithm to use
    /// * `key` - The header protection key
    ///
    /// # Returns
    ///
    /// A header protection instance, or an error if the algorithm is not supported.
    fn header_protection(
        &self,
        algorithm: HeaderProtectionAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn HeaderProtection>>;

    /// Get an HPKE (Hybrid Public Key Encryption) instance.
    ///
    /// HPKE is used for Encrypted Client Hello (ECH) and other privacy features
    /// that require authenticated encryption for the first message in a protocol.
    ///
    /// # Arguments
    ///
    /// * `cipher_suite` - The HPKE cipher suite (KEM + KDF + AEAD combination)
    ///
    /// # Returns
    ///
    /// An HPKE instance, or an error if the cipher suite is not supported.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use hptls_crypto::{CryptoProvider, HpkeCipherSuite};
    ///
    /// let provider = YourCryptoProvider::new();
    /// let hpke = provider.hpke(HpkeCipherSuite::ech_default_p256())?;
    ///
    /// // Generate keypair for recipient
    /// let (sk, pk) = hpke.generate_keypair()?;
    ///
    /// // Encrypt a message
    /// let enc_and_ct = hpke.seal_base(&pk, b"info", b"aad", b"plaintext")?;
    ///
    /// // Decrypt the message
    /// let plaintext = hpke.open_base(&enc_and_ct, &sk, b"info", b"aad")?;
    /// ```
    fn hpke(&self, cipher_suite: HpkeCipherSuite) -> Result<Box<dyn Hpke>>;

    /// Check if the provider supports a specific AEAD algorithm.
    ///
    /// This can be used to query capabilities without instantiating.
    fn supports_aead(&self, algorithm: AeadAlgorithm) -> bool {
        self.aead(algorithm).is_ok()
    }

    /// Check if the provider supports a specific key exchange algorithm.
    fn supports_key_exchange(&self, algorithm: KeyExchangeAlgorithm) -> bool {
        self.key_exchange(algorithm).is_ok()
    }

    /// Check if the provider supports a specific signature algorithm.
    fn supports_signature(&self, algorithm: SignatureAlgorithm) -> bool {
        self.signature(algorithm).is_ok()
    }

    /// Get information about hardware acceleration support.
    ///
    /// Returns a bitmask of supported CPU features.
    fn hardware_features(&self) -> HardwareFeatures {
        HardwareFeatures::default()
    }
}

/// Hardware features detected by the crypto provider.
#[derive(Debug, Clone, Copy, Default)]
pub struct HardwareFeatures {
    /// AES-NI instructions available
    pub aes_ni: bool,
    /// SHA extensions available
    pub sha_ext: bool,
    /// AVX2 available
    pub avx2: bool,
    /// AVX-512 available
    pub avx512: bool,
    /// ARM NEON available
    pub neon: bool,
    /// ARM Crypto Extensions available
    pub arm_crypto: bool,
}

impl HardwareFeatures {
    /// Detect available hardware features on the current platform.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn detect() -> Self {
        Self {
            aes_ni: is_x86_feature_detected!("aes"),
            sha_ext: is_x86_feature_detected!("sha"),
            avx2: is_x86_feature_detected!("avx2"),
            avx512: is_x86_feature_detected!("avx512f"),
            neon: false,
            arm_crypto: false,
        }
    }

    /// Detect available hardware features on the current platform.
    #[cfg(target_arch = "aarch64")]
    pub fn detect() -> Self {
        Self {
            aes_ni: false,
            sha_ext: false,
            avx2: false,
            avx512: false,
            neon: cfg!(target_feature = "neon"),
            arm_crypto: cfg!(target_feature = "aes") && cfg!(target_feature = "sha2"),
        }
    }

    /// Detect available hardware features on the current platform.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn detect() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_feature_detection() {
        let features = HardwareFeatures::detect();
        println!("Detected hardware features: {:?}", features);
        // Just verify it doesn't panic
    }
}
