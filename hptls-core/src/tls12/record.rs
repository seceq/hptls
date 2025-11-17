//! TLS 1.2 Record Protection (AEAD Encryption/Decryption)
//!
//! This module implements the AEAD encryption and decryption for TLS 1.2 records
//! as specified in RFC 5246.
//!
//! # TLS 1.2 vs TLS 1.3 Differences
//!
//! TLS 1.2 AEAD construction differs from TLS 1.3:
//! - **Explicit nonce**: TLS 1.2 uses explicit nonce in the record (first 8 bytes)
//! - **No encrypted content type**: Content type is in plaintext (not encrypted)
//! - **Different AD**: Additional Data includes sequence number explicitly
//! - **Key derivation**: Uses key_block from PRF, not HKDF
//!
//! # Nonce Construction (RFC 5246 Section 6.2.3.3)
//!
//! ```text
//! GenericAEADCipher:
//!   nonce = fixed_iv_client XOR explicit_nonce (for client)
//!   nonce = fixed_iv_server XOR explicit_nonce (for server)
//!
//! Where:
//!   - fixed_iv: 4 bytes from key_block
//!   - explicit_nonce: 8 bytes, included in record
//! ```
//!
//! # Additional Data (RFC 5246)
//!
//! ```text
//! additional_data = seq_num (8 bytes) +
//!                   TLSCompressed.type (1 byte) +
//!                   TLSCompressed.version (2 bytes) +
//!                   TLSCompressed.length (2 bytes)
//! Total: 13 bytes
//! ```

use crate::error::{Error, Result};
use crate::protocol::{ContentType, ProtocolVersion};
use crate::tls12::cipher_suites::Tls12CipherSuite;
use hptls_crypto::CryptoProvider;
use zeroize::Zeroizing;

/// TLS 1.2 Record Protection
///
/// Manages encryption/decryption for TLS 1.2 records using AEAD ciphers.
pub struct Tls12RecordProtection {
    /// Cipher suite in use
    cipher_suite: Tls12CipherSuite,
    /// AEAD key (from key_block)
    key: Zeroizing<Vec<u8>>,
    /// Fixed IV (from key_block, 4 bytes for GCM, 12 bytes for ChaCha20-Poly1305)
    fixed_iv: Zeroizing<Vec<u8>>,
    /// Sequence number (incremented per record)
    sequence_number: u64,
}

impl Tls12RecordProtection {
    /// Create a new TLS 1.2 record protection instance.
    ///
    /// # Arguments
    /// * `cipher_suite` - TLS 1.2 cipher suite
    /// * `key` - Encryption key from key_block
    /// * `fixed_iv` - Fixed IV from key_block (4 bytes for GCM, 12 bytes for ChaCha20-Poly1305)
    pub fn new(
        cipher_suite: Tls12CipherSuite,
        key: Vec<u8>,
        fixed_iv: Vec<u8>,
    ) -> Self {
        Self {
            cipher_suite,
            key: Zeroizing::new(key),
            fixed_iv: Zeroizing::new(fixed_iv),
            sequence_number: 0,
        }
    }

    /// Encrypt a TLS 1.2 record.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `content_type` - Content type of the plaintext
    /// * `plaintext` - Plaintext data to encrypt
    ///
    /// # Returns
    /// Encrypted record bytes (including explicit nonce)
    pub fn encrypt(
        &mut self,
        provider: &dyn CryptoProvider,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        // Generate explicit nonce (8 bytes random)
        let mut explicit_nonce = vec![0u8; 8];
        provider
            .random()
            .fill(&mut explicit_nonce)
            .map_err(|e| Error::CryptoError(format!("Failed to generate nonce: {}", e)))?;

        // Construct full nonce (12 bytes for both GCM and ChaCha20-Poly1305)
        // GCM: nonce = fixed_iv (4 bytes) || explicit_nonce (8 bytes)
        // ChaCha20-Poly1305 (RFC 7905): nonce = fixed_iv (12 bytes) XOR (0000 || sequence_number || explicit_nonce)
        let nonce = if self.fixed_iv.len() == 12 {
            // ChaCha20-Poly1305: XOR fixed_iv with explicit_nonce
            let mut nonce = self.fixed_iv.to_vec();
            // XOR last 8 bytes with explicit nonce
            for i in 0..8 {
                nonce[4 + i] ^= explicit_nonce[i];
            }
            nonce
        } else {
            // GCM: concatenate fixed_iv (4 bytes) || explicit_nonce (8 bytes)
            let mut nonce = Vec::with_capacity(12);
            nonce.extend_from_slice(&self.fixed_iv);
            nonce.extend_from_slice(&explicit_nonce);
            nonce
        };

        // Construct Additional Data (13 bytes)
        let additional_data = self.construct_additional_data(
            content_type,
            plaintext.len() as u16,
        );

        // Get AEAD cipher
        let aead = provider
            .aead(self.cipher_suite.aead_algorithm())
            .map_err(|e| Error::CryptoError(format!("Failed to get AEAD: {}", e)))?;

        // Encrypt
        let ciphertext = aead
            .seal(&self.key, &nonce, &additional_data, plaintext)
            .map_err(|e| Error::CryptoError(format!("AEAD encryption failed: {}", e)))?;

        // Increment sequence number
        self.sequence_number = self.sequence_number.wrapping_add(1);

        // Return: explicit_nonce || ciphertext
        let mut result = Vec::with_capacity(8 + ciphertext.len());
        result.extend_from_slice(&explicit_nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt a TLS 1.2 record.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `content_type` - Expected content type
    /// * `encrypted_record` - Encrypted record (explicit_nonce || ciphertext)
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt(
        &mut self,
        provider: &dyn CryptoProvider,
        content_type: ContentType,
        encrypted_record: &[u8],
    ) -> Result<Vec<u8>> {
        // Extract explicit nonce (first 8 bytes)
        if encrypted_record.len() < 8 {
            return Err(Error::InvalidMessage(
                "Encrypted record too short for explicit nonce".into(),
            ));
        }

        let explicit_nonce = &encrypted_record[0..8];
        let ciphertext = &encrypted_record[8..];

        // Construct full nonce (12 bytes for both GCM and ChaCha20-Poly1305)
        // GCM: nonce = fixed_iv (4 bytes) || explicit_nonce (8 bytes)
        // ChaCha20-Poly1305 (RFC 7905): nonce = fixed_iv (12 bytes) XOR (0000 || sequence_number || explicit_nonce)
        let nonce = if self.fixed_iv.len() == 12 {
            // ChaCha20-Poly1305: XOR fixed_iv with explicit_nonce
            let mut nonce = self.fixed_iv.to_vec();
            // XOR last 8 bytes with explicit nonce
            for i in 0..8 {
                nonce[4 + i] ^= explicit_nonce[i];
            }
            nonce
        } else {
            // GCM: concatenate fixed_iv (4 bytes) || explicit_nonce (8 bytes)
            let mut nonce = Vec::with_capacity(12);
            nonce.extend_from_slice(&self.fixed_iv);
            nonce.extend_from_slice(explicit_nonce);
            nonce
        };

        // Calculate plaintext length (ciphertext - tag size)
        let tag_size = 16; // GCM/ChaCha20-Poly1305 tag is 16 bytes
        if ciphertext.len() < tag_size {
            return Err(Error::InvalidMessage("Ciphertext too short".into()));
        }
        let plaintext_len = ciphertext.len() - tag_size;

        // Construct Additional Data (13 bytes)
        let additional_data = self.construct_additional_data(
            content_type,
            plaintext_len as u16,
        );

        // Get AEAD cipher
        let aead = provider
            .aead(self.cipher_suite.aead_algorithm())
            .map_err(|e| Error::CryptoError(format!("Failed to get AEAD: {}", e)))?;

        // Decrypt
        let plaintext = aead
            .open(&self.key, &nonce, &additional_data, ciphertext)
            .map_err(|_| Error::DecryptionFailed)?;

        // Increment sequence number
        self.sequence_number = self.sequence_number.wrapping_add(1);

        Ok(plaintext)
    }

    /// Construct Additional Data for AEAD.
    ///
    /// TLS 1.2 Additional Data (13 bytes):
    /// - sequence_number: 8 bytes
    /// - content_type: 1 byte
    /// - protocol_version: 2 bytes (0x0303 for TLS 1.2)
    /// - length: 2 bytes (plaintext length)
    fn construct_additional_data(
        &self,
        content_type: ContentType,
        plaintext_length: u16,
    ) -> Vec<u8> {
        let mut ad = Vec::with_capacity(13);

        // Sequence number (8 bytes, big-endian)
        ad.extend_from_slice(&self.sequence_number.to_be_bytes());

        // Content type (1 byte)
        ad.push(content_type.to_u8());

        // Protocol version (2 bytes) - TLS 1.2 = 0x0303
        ad.extend_from_slice(&ProtocolVersion::Tls12.to_u16().to_be_bytes());

        // Plaintext length (2 bytes)
        ad.extend_from_slice(&plaintext_length.to_be_bytes());

        ad
    }

    /// Get the current sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Reset sequence number (used after ChangeCipherSpec).
    pub fn reset_sequence_number(&mut self) {
        self.sequence_number = 0;
    }
}

/// Derive encryption keys from key_block.
///
/// TLS 1.2 key_block is partitioned as:
/// - client_write_key
/// - server_write_key
/// - client_write_IV (fixed_iv)
/// - server_write_IV (fixed_iv)
///
/// # Arguments
/// * `key_block` - Key block from PRF
/// * `cipher_suite` - Cipher suite (determines key/IV sizes)
/// * `is_client` - True for client keys, false for server keys
///
/// # Returns
/// (key, fixed_iv)
pub fn derive_keys_from_key_block(
    key_block: &[u8],
    cipher_suite: Tls12CipherSuite,
    is_client: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (key_len, iv_len) = match cipher_suite.aead_algorithm() {
        hptls_crypto::AeadAlgorithm::Aes128Gcm => (16, 4),
        hptls_crypto::AeadAlgorithm::Aes256Gcm => (32, 4),
        hptls_crypto::AeadAlgorithm::ChaCha20Poly1305 => (32, 12),
        _ => return Err(Error::UnsupportedFeature("Unsupported AEAD algorithm".into())),
    };

    let expected_len = 2 * (key_len + iv_len);
    if key_block.len() < expected_len {
        return Err(Error::InvalidMessage(format!(
            "Key block too short: expected at least {}, got {}",
            expected_len,
            key_block.len()
        )));
    }

    // Parse key_block:
    // [client_write_key | server_write_key | client_write_IV | server_write_IV]
    let (client_key, server_key, client_iv, server_iv) = if is_client {
        let client_key = &key_block[0..key_len];
        let server_key = &key_block[key_len..2 * key_len];
        let client_iv = &key_block[2 * key_len..2 * key_len + iv_len];
        let server_iv = &key_block[2 * key_len + iv_len..2 * key_len + 2 * iv_len];
        (client_key, server_key, client_iv, server_iv)
    } else {
        let client_key = &key_block[0..key_len];
        let server_key = &key_block[key_len..2 * key_len];
        let client_iv = &key_block[2 * key_len..2 * key_len + iv_len];
        let server_iv = &key_block[2 * key_len + iv_len..2 * key_len + 2 * iv_len];
        (client_key, server_key, client_iv, server_iv)
    };

    // Select appropriate key and IV based on role
    let (key, iv) = if is_client {
        (client_key.to_vec(), client_iv.to_vec())
    } else {
        (server_key.to_vec(), server_iv.to_vec())
    };

    Ok((key, iv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls12::cipher_suites::Tls12CipherSuite;
    use hptls_crypto_hpcrypt::HpcryptProvider;

    #[test]
    fn test_additional_data_construction() {
        let cipher_suite = Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256;
        let protection = Tls12RecordProtection::new(
            cipher_suite,
            vec![0u8; 16],
            vec![0u8; 4],
        );

        let ad = protection.construct_additional_data(
            ContentType::ApplicationData,
            42,
        );

        assert_eq!(ad.len(), 13);
        // Sequence number should be 0
        assert_eq!(&ad[0..8], &[0u8; 8]);
        // Content type
        assert_eq!(ad[8], ContentType::ApplicationData.to_u8());
        // Version (TLS 1.2 = 0x0303)
        assert_eq!(&ad[9..11], &[0x03, 0x03]);
        // Length
        assert_eq!(&ad[11..13], &[0x00, 0x2A]); // 42 in big-endian
    }

    #[test]
    fn test_sequence_number_increment() {
        let cipher_suite = Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256;
        let provider = HpcryptProvider::new();
        let mut protection = Tls12RecordProtection::new(
            cipher_suite,
            vec![0u8; 16],
            vec![0u8; 4],
        );

        assert_eq!(protection.sequence_number(), 0);

        // Encrypt should increment sequence number
        let _ = protection.encrypt(&provider, ContentType::ApplicationData, b"test");
        assert_eq!(protection.sequence_number(), 1);

        let _ = protection.encrypt(&provider, ContentType::ApplicationData, b"test");
        assert_eq!(protection.sequence_number(), 2);
    }

    #[test]
    fn test_reset_sequence_number() {
        let cipher_suite = Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256;
        let mut protection = Tls12RecordProtection::new(
            cipher_suite,
            vec![0u8; 16],
            vec![0u8; 4],
        );

        protection.sequence_number = 42;
        protection.reset_sequence_number();
        assert_eq!(protection.sequence_number(), 0);
    }

    #[test]
    fn test_derive_keys_aes128gcm() {
        // AES-128-GCM: 16 byte key, 4 byte IV
        // Key block: client_key (16) | server_key (16) | client_iv (4) | server_iv (4) = 40 bytes
        let key_block = vec![
            // Client key (16 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            // Server key (16 bytes)
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            // Client IV (4 bytes)
            0xA1, 0xA2, 0xA3, 0xA4,
            // Server IV (4 bytes)
            0xB1, 0xB2, 0xB3, 0xB4,
        ];

        let cipher_suite = Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256;

        // Client keys
        let (client_key, client_iv) = derive_keys_from_key_block(&key_block, cipher_suite, true).unwrap();
        assert_eq!(client_key.len(), 16);
        assert_eq!(client_iv.len(), 4);
        assert_eq!(&client_key[0..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&client_iv, &[0xA1, 0xA2, 0xA3, 0xA4]);

        // Server keys
        let (server_key, server_iv) = derive_keys_from_key_block(&key_block, cipher_suite, false).unwrap();
        assert_eq!(server_key.len(), 16);
        assert_eq!(server_iv.len(), 4);
        assert_eq!(&server_key[0..4], &[0x11, 0x12, 0x13, 0x14]);
        assert_eq!(&server_iv, &[0xB1, 0xB2, 0xB3, 0xB4]);
    }
}
