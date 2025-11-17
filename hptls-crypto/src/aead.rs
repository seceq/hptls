//! AEAD (Authenticated Encryption with Associated Data) cipher interface.

use crate::{Error, Result};

/// AEAD cipher algorithms supported by HPTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadAlgorithm {
    /// AES-128-GCM (TLS 1.3 mandatory cipher)
    Aes128Gcm,
    /// AES-256-GCM (TLS 1.3 mandatory cipher)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (TLS 1.3 mandatory cipher)
    ChaCha20Poly1305,
    /// AES-128-CCM (TLS 1.3 optional, for constrained devices)
    Aes128Ccm,
    /// AES-128-CCM-8 (TLS 1.3 optional, for IoT)
    Aes128Ccm8,
}

impl AeadAlgorithm {
    /// Get the key size in bytes for this algorithm.
    pub const fn key_size(self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => 32,
            AeadAlgorithm::ChaCha20Poly1305 => 32,
            AeadAlgorithm::Aes128Ccm => 16,
            AeadAlgorithm::Aes128Ccm8 => 16,
        }
    }

    /// Get the nonce size in bytes for this algorithm.
    pub const fn nonce_size(self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 12,
            AeadAlgorithm::Aes256Gcm => 12,
            AeadAlgorithm::ChaCha20Poly1305 => 12,
            AeadAlgorithm::Aes128Ccm => 12,
            AeadAlgorithm::Aes128Ccm8 => 12,
        }
    }

    /// Get the authentication tag size in bytes for this algorithm.
    pub const fn tag_size(self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => 16,
            AeadAlgorithm::ChaCha20Poly1305 => 16,
            AeadAlgorithm::Aes128Ccm => 16,
            AeadAlgorithm::Aes128Ccm8 => 8,
        }
    }

    /// Get the name of this algorithm as used in TLS.
    pub const fn name(self) -> &'static str {
        match self {
            AeadAlgorithm::Aes128Gcm => "AES_128_GCM",
            AeadAlgorithm::Aes256Gcm => "AES_256_GCM",
            AeadAlgorithm::ChaCha20Poly1305 => "CHACHA20_POLY1305",
            AeadAlgorithm::Aes128Ccm => "AES_128_CCM",
            AeadAlgorithm::Aes128Ccm8 => "AES_128_CCM_8",
        }
    }
}

/// AEAD cipher trait.
///
/// AEAD ciphers provide authenticated encryption with associated data.
/// They are used in TLS 1.3 and TLS 1.2 (with GCM/ChaCha20-Poly1305 cipher suites).
///
/// # Security Requirements
///
/// - All operations MUST be constant-time with respect to the plaintext/ciphertext
/// - Tag verification MUST be constant-time
/// - Nonces MUST NOT be reused with the same key
///
/// # Example
///
/// ```rust,no_run
/// use hptls_crypto::{Aead, AeadAlgorithm};
///
/// fn encrypt_example(aead: &dyn Aead) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
///     let key = &[0u8; 16]; // In practice, use a proper key
///     let nonce = &[0u8; 12]; // In practice, use a unique nonce
///     let aad = b"additional data";
///     let plaintext = b"secret message";
///
///     let ciphertext = aead.seal(key, nonce, aad, plaintext)?;
///     Ok(ciphertext)
/// }
/// ```
pub trait Aead: Send + Sync {
    /// Encrypt and authenticate plaintext.
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key (size must match algorithm)
    /// * `nonce` - Nonce/IV (size must match algorithm, MUST be unique per encryption)
    /// * `aad` - Additional authenticated data (can be empty)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Ciphertext with authentication tag appended.
    ///
    /// # Errors
    ///
    /// - `InvalidKeySize` if key size doesn't match
    /// - `InvalidNonceSize` if nonce size doesn't match
    /// - `CryptoError` for other errors
    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt and verify ciphertext.
    ///
    /// # Arguments
    ///
    /// * `key` - Decryption key (size must match algorithm)
    /// * `nonce` - Nonce/IV (size must match algorithm)
    /// * `aad` - Additional authenticated data (must match what was used in encryption)
    /// * `ciphertext` - Ciphertext with authentication tag appended
    ///
    /// # Returns
    ///
    /// Plaintext if authentication succeeds.
    ///
    /// # Errors
    ///
    /// - `InvalidKeySize` if key size doesn't match
    /// - `InvalidNonceSize` if nonce size doesn't match
    /// - `AuthenticationFailed` if tag verification fails (MUST be constant-time)
    /// - `CryptoError` for other errors
    ///
    /// # Security
    ///
    /// This function MUST verify the authentication tag in constant time
    /// to prevent timing attacks.
    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Encrypt in-place (zero-copy variant).
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key
    /// * `nonce` - Nonce/IV
    /// * `aad` - Additional authenticated data
    /// * `buffer` - Buffer containing plaintext on input, ciphertext+tag on output
    ///
    /// # Returns
    ///
    /// Number of bytes written (plaintext_len + tag_size)
    ///
    /// # Note
    ///
    /// Buffer must have `plaintext.len() + tag_size()` capacity.
    fn seal_in_place(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize> {
        // Default implementation using seal()
        // Providers can override for zero-copy optimization
        if plaintext_len > buffer.len() {
            return Err(Error::Internal("Buffer too small".to_string()));
        }

        let plaintext = &buffer[..plaintext_len];
        let ciphertext = self.seal(key, nonce, aad, plaintext)?;

        if ciphertext.len() > buffer.len() {
            return Err(Error::Internal(
                "Buffer too small for ciphertext+tag".to_string(),
            ));
        }

        buffer[..ciphertext.len()].copy_from_slice(&ciphertext);
        Ok(ciphertext.len())
    }

    /// Decrypt in-place (zero-copy variant).
    ///
    /// # Arguments
    ///
    /// * `key` - Decryption key
    /// * `nonce` - Nonce/IV
    /// * `aad` - Additional authenticated data
    /// * `buffer` - Buffer containing ciphertext+tag on input, plaintext on output
    ///
    /// # Returns
    ///
    /// Number of bytes written (plaintext length)
    fn open_in_place(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize> {
        // Default implementation using open()
        // Providers can override for zero-copy optimization
        let ciphertext = &buffer[..];
        let plaintext = self.open(key, nonce, aad, ciphertext)?;

        if plaintext.len() > buffer.len() {
            return Err(Error::Internal(
                "Buffer too small for plaintext".to_string(),
            ));
        }

        buffer[..plaintext.len()].copy_from_slice(&plaintext);
        Ok(plaintext.len())
    }

    /// Get the algorithm this cipher implements.
    fn algorithm(&self) -> AeadAlgorithm;

    /// Get the key size in bytes.
    fn key_size(&self) -> usize {
        self.algorithm().key_size()
    }

    /// Get the nonce size in bytes.
    fn nonce_size(&self) -> usize {
        self.algorithm().nonce_size()
    }

    /// Get the authentication tag size in bytes.
    fn tag_size(&self) -> usize {
        self.algorithm().tag_size()
    }
}
