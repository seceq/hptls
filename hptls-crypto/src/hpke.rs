//! HPKE (Hybrid Public Key Encryption) - RFC 9180
//!
//! This module provides the HPKE interface for ECH (Encrypted Client Hello).
//!
//! HPKE combines asymmetric and symmetric encryption to provide authenticated
//! encryption for the first message in a protocol.

use crate::Result;

/// HPKE KEM (Key Encapsulation Mechanism) algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HpkeKem {
    /// DHKEM with P-256 and HKDF-SHA256
    DhkemP256HkdfSha256,
    /// DHKEM with X25519 and HKDF-SHA256
    DhkemX25519HkdfSha256,
}

/// HPKE KDF (Key Derivation Function) algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HpkeKdf {
    /// HKDF with SHA-256
    HkdfSha256,
    /// HKDF with SHA-384
    HkdfSha384,
    /// HKDF with SHA-512
    HkdfSha512,
}

/// HPKE AEAD algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HpkeAead {
    /// AES-128-GCM
    Aes128Gcm,
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

/// HPKE cipher suite combining KEM, KDF, and AEAD
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeCipherSuite {
    /// Key Encapsulation Mechanism
    pub kem: HpkeKem,
    /// Key Derivation Function
    pub kdf: HpkeKdf,
    /// AEAD cipher
    pub aead: HpkeAead,
}

impl HpkeCipherSuite {
    /// Create a new HPKE cipher suite
    pub fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self {
        Self { kem, kdf, aead }
    }

    /// Get the length of the encapsulated key for this KEM
    pub fn nenc(&self) -> usize {
        match self.kem {
            HpkeKem::DhkemP256HkdfSha256 => 65, // Uncompressed P-256 point
            HpkeKem::DhkemX25519HkdfSha256 => 32, // X25519 public key
        }
    }

    /// Get the recommended cipher suite for ECH with P-256
    pub fn ech_default_p256() -> Self {
        Self {
            kem: HpkeKem::DhkemP256HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::Aes128Gcm,
        }
    }

    /// Get cipher suite with X25519 (if supported)
    pub fn ech_x25519() -> Self {
        Self {
            kem: HpkeKem::DhkemX25519HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::Aes128Gcm,
        }
    }
}

/// HPKE context for sequential encrypt/decrypt operations
pub trait HpkeContext: Send + Sync {
    /// Encrypt a message with associated data
    ///
    /// # Arguments
    ///
    /// * `aad` - Associated authenticated data
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Ciphertext (including authentication tag)
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt a message with associated data
    ///
    /// # Arguments
    ///
    /// * `aad` - Associated authenticated data
    /// * `ciphertext` - Data to decrypt (including authentication tag)
    ///
    /// # Returns
    ///
    /// Plaintext if authentication succeeds
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Export a secret from the HPKE context
    ///
    /// # Arguments
    ///
    /// * `context` - Application-specific context string
    /// * `length` - Desired output length
    ///
    /// # Returns
    ///
    /// Derived secret of requested length
    fn export(&self, context: &[u8], length: usize) -> Vec<u8>;
}

/// HPKE (Hybrid Public Key Encryption) operations
///
/// This trait provides HPKE functionality for ECH and other use cases.
/// It supports both single-shot and context-based operations.
pub trait Hpke: Send + Sync {
    /// Get the cipher suite this HPKE instance uses
    fn cipher_suite(&self) -> HpkeCipherSuite;

    /// Generate a new HPKE keypair
    ///
    /// # Returns
    ///
    /// (secret_key, public_key) as raw bytes
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Setup sender context in base mode
    ///
    /// # Arguments
    ///
    /// * `pk_r` - Recipient's public key
    /// * `info` - Application-specific context information
    ///
    /// # Returns
    ///
    /// (encapsulated_key, sender_context)
    fn setup_base_sender(
        &self,
        pk_r: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, Box<dyn HpkeContext>)>;

    /// Setup recipient context in base mode
    ///
    /// # Arguments
    ///
    /// * `enc` - Encapsulated key from sender
    /// * `sk_r` - Recipient's secret key
    /// * `info` - Application-specific context information
    ///
    /// # Returns
    ///
    /// Recipient context for decryption
    fn setup_base_recipient(
        &self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
    ) -> Result<Box<dyn HpkeContext>>;

    /// Single-shot encryption in base mode
    ///
    /// This is the most common operation for ECH. It encrypts a single
    /// message and returns enc || ciphertext.
    ///
    /// # Arguments
    ///
    /// * `pk_r` - Recipient's public key
    /// * `info` - Application-specific context information
    /// * `aad` - Associated authenticated data
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Encapsulated key concatenated with ciphertext
    fn seal_base(&self, pk_r: &[u8], info: &[u8], aad: &[u8], plaintext: &[u8])
        -> Result<Vec<u8>>;

    /// Single-shot decryption in base mode
    ///
    /// This decrypts a message encrypted with `seal_base`.
    ///
    /// # Arguments
    ///
    /// * `enc_and_ciphertext` - Encapsulated key || ciphertext
    /// * `sk_r` - Recipient's secret key
    /// * `info` - Application-specific context information
    /// * `aad` - Associated authenticated data
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    fn open_base(
        &self,
        enc_and_ciphertext: &[u8],
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;
}
