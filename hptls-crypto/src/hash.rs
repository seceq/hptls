//! Hash function interface.

use crate::kdf::KdfAlgorithm;

/// Hash algorithms supported by HPTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-256 (32 bytes output)
    Sha256,
    /// SHA-384 (48 bytes output)
    Sha384,
    /// SHA-512 (64 bytes output)
    Sha512,
}

impl HashAlgorithm {
    /// Get the output size in bytes for this hash algorithm.
    pub const fn output_size(self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    /// Get the name of this algorithm.
    pub const fn name(self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha384 => "SHA-384",
            HashAlgorithm::Sha512 => "SHA-512",
        }
    }

    /// Get the corresponding KDF algorithm for this hash algorithm.
    ///
    /// This is used to derive the HKDF variant matching the hash function.
    pub const fn to_kdf_algorithm(self) -> KdfAlgorithm {
        match self {
            HashAlgorithm::Sha256 => KdfAlgorithm::HkdfSha256,
            HashAlgorithm::Sha384 => KdfAlgorithm::HkdfSha384,
            HashAlgorithm::Sha512 => KdfAlgorithm::HkdfSha512,
        }
    }
}

/// Hash function trait.
///
/// Provides cryptographic hash functions for TLS.
///
/// # Example
///
/// ```rust,ignore
/// use hptls_crypto::Hash;
///
/// fn hash_example(hash: &mut dyn Hash) -> Vec<u8> {
///     hash.update(b"Hello, ");
///     hash.update(b"world!");
///     hash.finalize()
/// }
/// ```
pub trait Hash: Send {
    /// Update the hash state with more data.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to hash
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash and return the digest.
    ///
    /// This consumes the hash state. After calling finalize(),
    /// the hash object should not be used again.
    ///
    /// # Returns
    ///
    /// The hash digest (size depends on algorithm).
    fn finalize(self: Box<Self>) -> Vec<u8>;

    /// Get the output size in bytes for this hash function.
    fn output_size(&self) -> usize;

    /// Get the algorithm this hash implements.
    fn algorithm(&self) -> HashAlgorithm;

    /// Convenience method: hash data in one call.
    ///
    /// This is equivalent to creating a new hash, calling update() once,
    /// and calling finalize().
    fn hash_once(data: &[u8]) -> Vec<u8>
    where
        Self: Sized + Default,
    {
        let mut hash = Self::default();
        hash.update(data);
        Box::new(hash).finalize()
    }

    /// Reset the hash state (optional, for reusable hash objects).
    ///
    /// Default implementation does nothing.
    /// Providers can override if they support reusable hash objects.
    fn reset(&mut self) {
        // Default: no-op (hash is consumed by finalize())
    }
}
