//! Key Derivation Function (KDF) interface.

use crate::{HashAlgorithm, Result};

/// KDF algorithms supported by HPTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfAlgorithm {
    /// HKDF with SHA-256 (TLS 1.3)
    HkdfSha256,
    /// HKDF with SHA-384 (TLS 1.3)
    HkdfSha384,
    /// HKDF with SHA-512
    HkdfSha512,
    /// TLS 1.2 PRF with SHA-256
    TlsPrfSha256,
    /// TLS 1.2 PRF with SHA-384
    TlsPrfSha384,
}

impl KdfAlgorithm {
    /// Get the underlying hash algorithm.
    pub const fn hash_algorithm(self) -> HashAlgorithm {
        match self {
            KdfAlgorithm::HkdfSha256 | KdfAlgorithm::TlsPrfSha256 => HashAlgorithm::Sha256,
            KdfAlgorithm::HkdfSha384 | KdfAlgorithm::TlsPrfSha384 => HashAlgorithm::Sha384,
            KdfAlgorithm::HkdfSha512 => HashAlgorithm::Sha512,
        }
    }

    /// Get the name of this KDF algorithm.
    pub const fn name(self) -> &'static str {
        match self {
            KdfAlgorithm::HkdfSha256 => "HKDF-SHA256",
            KdfAlgorithm::HkdfSha384 => "HKDF-SHA384",
            KdfAlgorithm::HkdfSha512 => "HKDF-SHA512",
            KdfAlgorithm::TlsPrfSha256 => "TLS-PRF-SHA256",
            KdfAlgorithm::TlsPrfSha384 => "TLS-PRF-SHA384",
        }
    }
}

/// KDF trait.
///
/// Provides key derivation functions for TLS.
///
/// # TLS 1.3 Key Schedule
///
/// TLS 1.3 uses HKDF for all key derivation:
/// - Extract: `HKDF-Extract(salt, IKM) -> PRK`
/// - Expand: `HKDF-Expand(PRK, info, length) -> OKM`
///
/// # TLS 1.2 PRF
///
/// TLS 1.2 uses a custom PRF based on HMAC:
/// - `PRF(secret, label, seed) = HMAC(secret, label + seed)`
///
/// # Example (HKDF)
///
/// ```rust,no_run
/// use hptls_crypto::Kdf;
///
/// fn derive_keys(kdf: &dyn Kdf) -> Vec<u8> {
///     let salt = b"salt";
///     let ikm = b"input key material";
///
///     // Extract
///     let prk = kdf.extract(salt, ikm);
///
///     // Expand
///     let info = b"application info";
///     let okm = kdf.expand(&prk, info, 32).unwrap();
///
///     okm
/// }
/// ```
pub trait Kdf: Send + Sync {
    /// HKDF-Extract: Extract a pseudorandom key from input key material.
    ///
    /// # Arguments
    ///
    /// * `salt` - Optional salt (can be empty)
    /// * `ikm` - Input key material
    ///
    /// # Returns
    ///
    /// Pseudorandom key (PRK) of length `hash_output_size`
    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8>;

    /// HKDF-Expand: Expand a pseudorandom key to desired length.
    ///
    /// # Arguments
    ///
    /// * `prk` - Pseudorandom key from extract()
    /// * `info` - Context and application specific information
    /// * `length` - Desired output length in bytes
    ///
    /// # Returns
    ///
    /// Output key material (OKM) of requested length
    ///
    /// # Errors
    ///
    /// Returns error if `length` is too large (> 255 * hash_output_size)
    fn expand(&self, prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>>;

    /// HKDF: Combined extract and expand in one operation.
    ///
    /// Convenience method equivalent to:
    /// ```text
    /// prk = extract(salt, ikm)
    /// okm = expand(prk, info, length)
    /// ```
    fn derive(&self, salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        let prk = self.extract(salt, ikm);
        self.expand(&prk, info, length)
    }

    /// Get the KDF algorithm.
    fn algorithm(&self) -> KdfAlgorithm;

    /// Get the output size of the underlying hash function.
    fn hash_output_size(&self) -> usize {
        self.algorithm().hash_algorithm().output_size()
    }
}
