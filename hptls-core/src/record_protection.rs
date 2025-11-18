//! TLS 1.3 Record Protection (AEAD Encryption/Decryption)
//!
//! This module implements the AEAD encryption and decryption for TLS 1.3 records
//! as specified in RFC 8446 Section 5.2.
//! # TLS 1.3 AEAD Construction
//! TLS 1.3 uses AEAD ciphers to protect records. The construction is:
//! - Additional Data (AD): record header (type, version, length)
//! - Nonce: per-record nonce derived from IV and sequence number
//! - Plaintext: content + content_type + optional padding
//! - Output: encrypted_record = AEAD-Encrypt(key, nonce, plaintext, ad)
//! # Nonce Construction (RFC 8446 Section 5.3)
//! ```text
//! nonce = per_record_nonce XOR iv
//! where per_record_nonce = sequence_number (padded to IV length)
//! ```

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};
use crate::protocol::{ContentType, ProtocolVersion};
use crate::record::{TlsPlaintext, RECORD_HEADER_SIZE};
use hptls_crypto::{Aead, CryptoProvider};
use zeroize::Zeroizing;
/// TLS 1.3 encrypted record (TLSCiphertext).
#[derive(Debug, Clone)]
pub struct TlsCiphertext {
    /// Opaque type (always ApplicationData in TLS 1.3 for encrypted records)
    pub opaque_type: ContentType,
    /// Legacy protocol version (always 0x0303 for TLS 1.3)
    pub legacy_version: ProtocolVersion,
    /// Encrypted fragment (ciphertext + auth tag)
    pub encrypted_record: Vec<u8>,
}
impl TlsCiphertext {
    /// Create a new ciphertext record.
    pub fn new(encrypted_record: Vec<u8>) -> Self {
        Self {
            opaque_type: ContentType::ApplicationData, // Always for encrypted records
            legacy_version: ProtocolVersion::Tls12,    // Always 0x0303
            encrypted_record,
        }
    }
    /// Encode to wire format.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(RECORD_HEADER_SIZE + self.encrypted_record.len());
        // Type (1 byte)
        buf.push(self.opaque_type.to_u8());
        // Version (2 bytes)
        buf.extend_from_slice(&self.legacy_version.to_u16().to_be_bytes());
        // Length (2 bytes)
        buf.extend_from_slice(&(self.encrypted_record.len() as u16).to_be_bytes());
        // Encrypted fragment
        buf.extend_from_slice(&self.encrypted_record);
        Ok(buf)
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < RECORD_HEADER_SIZE {
            return Err(Error::InvalidMessage("Ciphertext record too short".into()));
        }
        let content_type = ContentType::from_u8(data[0])
            .ok_or_else(|| Error::InvalidMessage("Invalid content type".into()))?;
        let version_raw = u16::from_be_bytes([data[1], data[2]]);
        let legacy_version = ProtocolVersion::from_u16(version_raw)
            .ok_or_else(|| Error::InvalidMessage("Invalid protocol version".into()))?;
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < RECORD_HEADER_SIZE + length {
            return Err(Error::InvalidMessage("Incomplete ciphertext record".into()));
        }
        let encrypted_record = data[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + length].to_vec();
        Ok(Self {
            opaque_type: content_type,
            legacy_version,
            encrypted_record,
        })
    }
}

/// Record protection state for encrypting/decrypting records.
///
/// Maintains encryption keys, IVs, and sequence numbers for a single direction
/// (either read or write).
pub struct RecordProtection {
    /// Cipher suite in use
    cipher_suite: CipherSuite,
    /// Traffic secret (write_key or read_key derived from this)
    traffic_secret: Zeroizing<Vec<u8>>,
    /// AEAD key
    key: Zeroizing<Vec<u8>>,
    /// AEAD IV (12 bytes for TLS 1.3)
    iv: Zeroizing<Vec<u8>>,
    /// Sequence number (incremented per record)
    sequence_number: u64,
}

impl RecordProtection {
    /// Create a new record protection instance.
    ///
    /// Derives the key and IV from the traffic secret using HKDF-Expand-Label.
    /// # Arguments
    /// * `provider` - Crypto provider for key derivation
    /// * `cipher_suite` - Cipher suite in use
    /// * `traffic_secret` - Traffic secret (client/server handshake or application)
    pub fn new(
        provider: &dyn CryptoProvider,
        cipher_suite: CipherSuite,
        traffic_secret: &[u8],
    ) -> Result<Self> {
        let hash_algorithm = cipher_suite.hash_algorithm();
        let key_length = cipher_suite.key_length();
        // Derive write_key = HKDF-Expand-Label(traffic_secret, "key", "", key_length)
        let key = crate::transcript::hkdf_expand_label(
            provider,
            hash_algorithm,
            traffic_secret,
            b"key",
            &[],
            key_length,
        )?;
        // Derive write_iv = HKDF-Expand-Label(traffic_secret, "iv", "", 12)
        let iv = crate::transcript::hkdf_expand_label(
            provider,
            hash_algorithm,
            traffic_secret,
            b"iv",
            &[],
            12, // TLS 1.3 uses 12-byte IVs
        )?;

        Ok(Self {
            cipher_suite,
            traffic_secret: Zeroizing::new(traffic_secret.to_vec()),
            key: Zeroizing::new(key),
            iv: Zeroizing::new(iv),
            sequence_number: 0,
        })
    }

    /// Encrypt a plaintext record using AEAD.
    /// # TLS 1.3 Encryption Process
    /// 1. Build plaintext: content || content_type || padding
    /// 2. Compute nonce: sequence_number XOR iv
    /// 3. Build additional_data: opaque_type || version || length
    /// 4. Encrypt: ciphertext = AEAD-Encrypt(key, nonce, plaintext, additional_data)
    /// 5. Increment sequence number
    /// # Arguments
    /// * `provider` - Crypto provider for AEAD operations
    /// * `content_type` - Actual content type of the plaintext
    /// * `fragment` - Plaintext fragment to encrypt
    pub fn encrypt(
        &mut self,
        provider: &dyn CryptoProvider,
        content_type: ContentType,
        fragment: &[u8],
    ) -> Result<TlsCiphertext> {
        // Step 1: Build TLSInnerPlaintext = fragment || content_type || zeros*
        let mut plaintext = Vec::with_capacity(fragment.len() + 1);
        plaintext.extend_from_slice(fragment);
        plaintext.push(content_type.to_u8()); // Real content type
                                              // No padding for now (padding is optional in TLS 1.3)
                                              // Step 2: Compute per-record nonce
        let nonce = self.compute_nonce();
        // Step 3: Build additional_data (TLSCiphertext header)
        let encrypted_length = plaintext.len() + 16; // plaintext + auth tag
        let additional_data = self.build_additional_data(encrypted_length)?;
        // Step 4: Encrypt using AEAD
        let aead_algorithm = self.cipher_suite.aead_algorithm();
        let aead = provider.aead(aead_algorithm)?;

        // Encrypt using seal()
        let ciphertext = aead.seal(&self.key, &nonce, &additional_data, &plaintext)?;
        // Step 5: Increment sequence number
        self.sequence_number = self
            .sequence_number
            .checked_add(1)
            .ok_or_else(|| Error::InternalError("Sequence number overflow".to_string()))?;
        Ok(TlsCiphertext::new(ciphertext))
    }

    /// Decrypt a ciphertext record using AEAD.
    /// # TLS 1.3 Decryption Process
    /// 1. Compute nonce: sequence_number XOR iv
    /// 2. Build additional_data from ciphertext header
    /// 3. Decrypt: plaintext = AEAD-Decrypt(key, nonce, ciphertext, additional_data)
    /// 4. Extract content_type from end of plaintext (remove padding)
    /// # Arguments
    /// * `provider` - Crypto provider for AEAD operations
    /// * `ciphertext` - Encrypted record to decrypt
    /// # Returns
    /// Decrypted plaintext record with actual content type.
    pub fn decrypt(
        &mut self,
        provider: &dyn CryptoProvider,
        ciphertext: &TlsCiphertext,
    ) -> Result<TlsPlaintext> {
        eprintln!(
            "[DEBUG] Decrypt - sequence: {}, ciphertext len: {}",
            self.sequence_number,
            ciphertext.encrypted_record.len()
        );
        // Step 1: Compute per-record nonce
        let nonce = self.compute_nonce();
        eprintln!(
            "[DEBUG] Decrypt - nonce ({} bytes): {:02x?}",
            nonce.len(),
            &nonce
        );
        eprintln!(
            "[DEBUG] Decrypt - iv ({} bytes): {:02x?}",
            self.iv.len(),
            &self.iv[..]
        );
        eprintln!(
            "[DEBUG] Decrypt - key ({} bytes): {:02x?}",
            self.key.len(),
            &self.key[..]
        );
        // Step 2: Build additional_data
        let additional_data = self.build_additional_data(ciphertext.encrypted_record.len())?;
        eprintln!("[DEBUG] Decrypt - AAD: {:02x?}", &additional_data);
        // Step 3: Decrypt using AEAD
        let aead_algorithm = self.cipher_suite.aead_algorithm();
        let aead = provider.aead(aead_algorithm)?;
        // Decrypt using open()
        eprintln!(
            "[DEBUG] Calling aead.open() with ciphertext ({} bytes)",
            ciphertext.encrypted_record.len()
        );
        eprintln!(
            "[DEBUG] First 20 bytes of ciphertext: {:02x?}",
            &ciphertext.encrypted_record[..ciphertext.encrypted_record.len().min(20)]
        );
        let buffer = aead.open(
            &self.key,
            &nonce,
            &additional_data,
            &ciphertext.encrypted_record,
        )?;
        eprintln!(
            "[DEBUG] aead.open() succeeded, got buffer ({} bytes)",
            buffer.len()
        );
        eprintln!(
            "[DEBUG] First 20 bytes of decrypted buffer: {:02x?}",
            &buffer[..buffer.len().min(20)]
        );
        // Step 4: Extract content type (last non-zero byte)
        // TLSInnerPlaintext = content || content_type || zeros*
        let mut content_type_pos = buffer.len();
        while content_type_pos > 0 && buffer[content_type_pos - 1] == 0 {
            content_type_pos -= 1;
        }
        if content_type_pos == 0 {
            return Err(Error::DecryptionFailed);
        }
        let content_type_byte = buffer[content_type_pos - 1];
        eprintln!("[DEBUG] Decrypted content_type_byte: {} (0x{:02x}), buffer len: {}, content_type_pos: {}",
            content_type_byte, content_type_byte, buffer.len(), content_type_pos);
        eprintln!(
            "[DEBUG] Last 10 bytes of buffer: {:?}",
            &buffer[buffer.len().saturating_sub(10)..]
        );
        let content_type = ContentType::from_u8(content_type_byte).ok_or_else(|| {
            Error::InvalidMessage(format!(
                "Invalid content type in decrypted record: {} (0x{:02x})",
                content_type_byte, content_type_byte
            ))
        })?;
        // Extract fragment (everything before content_type)
        let fragment = buffer[..content_type_pos - 1].to_vec();
        // Step 5: Increment sequence number
        self.sequence_number = self
            .sequence_number
            .checked_add(1)
            .ok_or_else(|| Error::InternalError("Sequence number overflow".to_string()))?;

        Ok(TlsPlaintext::new(
            content_type,
            ProtocolVersion::Tls13,
            fragment,
        ))
    }

    /// Compute the per-record nonce.
    /// Per RFC 8446 Section 5.3:
    /// ```text
    /// The per-record nonce is formed by XORing the 64-bit record sequence
    /// number with the static IV (left-padded with zeros).
    /// ```
    fn compute_nonce(&self) -> Vec<u8> {
        let mut nonce = self.iv.to_vec();
        // XOR the last 8 bytes of IV with sequence number (big-endian)
        let seq_bytes = self.sequence_number.to_be_bytes();
        let iv_len = nonce.len();
        for (i, &byte) in seq_bytes.iter().enumerate() {
            nonce[iv_len - 8 + i] ^= byte;
        }
        nonce
    }

    /// Build additional authenticated data for AEAD.
    /// Per RFC 8446 Section 5.2:
    /// additional_data = TLSCiphertext.opaque_type ||
    ///                   TLSCiphertext.legacy_record_version ||
    ///                   TLSCiphertext.length
    fn build_additional_data(&self, encrypted_length: usize) -> Result<Vec<u8>> {
        let mut ad = Vec::with_capacity(5);
        // Opaque type (always ApplicationData for encrypted records)
        ad.push(ContentType::ApplicationData.to_u8());
        // Legacy version (always 0x0303 for TLS 1.3)
        ad.extend_from_slice(&ProtocolVersion::Tls12.to_u16().to_be_bytes());
        if encrypted_length > u16::MAX as usize {
            return Err(Error::InvalidMessage("Encrypted record too large".into()));
        }
        ad.extend_from_slice(&(encrypted_length as u16).to_be_bytes());
        Ok(ad)
    }

    /// Get the current sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Reset sequence number (for testing or key updates).
    pub fn reset_sequence_number(&mut self) {
        self.sequence_number = 0;
    }

    /// Set sequence number to a specific value.
    /// This is useful for testing or when manually managing record processing.
    /// * `seq` - The sequence number to set
    pub fn set_sequence_number(&mut self, seq: u64) {
        self.sequence_number = seq;
    }

    /// Update traffic secret and re-derive keys.
    /// This is used when processing a KeyUpdate message. After updating the traffic secret
    /// using the key schedule, this method re-derives the encryption key and IV from the
    /// new traffic secret and resets the sequence number to 0.
    /// * `new_traffic_secret` - The updated traffic secret (from KeySchedule::update_*_traffic_secret)
    /// # RFC 8446 Section 4.6.3
    /// When a KeyUpdate is received:
    /// 1. Update the traffic secret: secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length)
    /// 2. Re-derive key and IV from the new secret
    /// 3. Reset sequence number to 0
    pub fn update_traffic_secret(
        &mut self,
        provider: &dyn CryptoProvider,
        new_traffic_secret: &[u8],
    ) -> Result<()> {
        let hash_algorithm = self.cipher_suite.hash_algorithm();
        let key_length = self.cipher_suite.key_length();
        // Re-derive write_key = HKDF-Expand-Label(new_traffic_secret, "key", "", key_length)
        let key = crate::transcript::hkdf_expand_label(
            provider,
            hash_algorithm,
            new_traffic_secret,
            b"key",
            &[],
            key_length,
        )?;
        // Re-derive write_iv = HKDF-Expand-Label(new_traffic_secret, "iv", "", 12)
        let iv = crate::transcript::hkdf_expand_label(
            provider,
            hash_algorithm,
            new_traffic_secret,
            b"iv",
            &[],
            12,
        )?;
        // Update state
        self.traffic_secret = Zeroizing::new(new_traffic_secret.to_vec());
        self.key = Zeroizing::new(key);
        self.iv = Zeroizing::new(iv);
        self.sequence_number = 0; // Reset sequence number on key update
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::CipherSuite;
    use hptls_crypto::CryptoProvider;
    use hptls_crypto_hpcrypt::HpcryptProvider;
    #[test]
    fn test_nonce_computation() {
        let provider = HpcryptProvider::new();
        let traffic_secret = vec![0u8; 32];
        let mut protection =
            RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &traffic_secret)
                .unwrap();
        // First nonce
        let nonce1 = protection.compute_nonce();
        assert_eq!(nonce1.len(), 12);
        // Increment sequence number
        protection.sequence_number = 1;
        let nonce2 = protection.compute_nonce();
        // Nonces should be different
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let provider = HpcryptProvider::new();
        let traffic_secret = vec![1u8; 32];
        let mut encryptor =
            RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &traffic_secret)
                .unwrap();
        let mut decryptor =
            RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &traffic_secret)
                .unwrap();
        let plaintext = b"Hello, TLS 1.3!";
        let content_type = ContentType::ApplicationData;
        // Encrypt
        let ciphertext = encryptor.encrypt(&provider, content_type, plaintext).unwrap();
        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.encrypted_record.as_slice(), plaintext);
        // Decrypt
        let decrypted = decryptor.decrypt(&provider, &ciphertext).unwrap();
        // Verify
        assert_eq!(decrypted.content_type, content_type);
        assert_eq!(decrypted.fragment.as_slice(), plaintext);
    }

    #[test]
    fn test_sequence_number_increments() {
        let provider = HpcryptProvider::new();
        let traffic_secret = vec![1u8; 32];
        let mut protection =
            RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &traffic_secret)
                .unwrap();
        assert_eq!(protection.sequence_number(), 0);
        // Encrypt a record
        protection.encrypt(&provider, ContentType::ApplicationData, b"test1").unwrap();
        assert_eq!(protection.sequence_number(), 1);
        // Encrypt another record
        protection.encrypt(&provider, ContentType::ApplicationData, b"test2").unwrap();
        assert_eq!(protection.sequence_number(), 2);
    }

    #[test]
    fn test_different_cipher_suites() {
        let provider = HpcryptProvider::new();
        // Test AES-128-GCM (SHA-256 produces 32-byte secrets)
        let traffic_secret_256 = vec![1u8; 32];
        let mut aes128 =
            RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &traffic_secret_256)
                .unwrap();
        let ct_aes128 = aes128.encrypt(&provider, ContentType::Handshake, b"test").unwrap();
        // Test AES-256-GCM (SHA-384 produces 48-byte secrets)
        let traffic_secret_384 = vec![2u8; 48];
        let mut aes256 =
            RecordProtection::new(&provider, CipherSuite::Aes256GcmSha384, &traffic_secret_384)
                .unwrap();
        let ct_aes256 = aes256.encrypt(&provider, ContentType::Handshake, b"test").unwrap();
        // Ciphertexts should be different (different keys)
        assert_ne!(ct_aes128.encrypted_record, ct_aes256.encrypted_record);
    }

    #[test]
    fn test_ciphertext_encode_decode() {
        let encrypted_data = vec![1, 2, 3, 4, 5];
        let ciphertext = TlsCiphertext::new(encrypted_data.clone());
        let encoded = ciphertext.encode().unwrap();
        let decoded = TlsCiphertext::decode(&encoded).unwrap();
        assert_eq!(decoded.opaque_type, ContentType::ApplicationData);
        assert_eq!(decoded.legacy_version, ProtocolVersion::Tls12);
        assert_eq!(decoded.encrypted_record, encrypted_data);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let provider = HpcryptProvider::new();
        let traffic_secret1 = vec![1u8; 32];
        let traffic_secret2 = vec![2u8; 32]; // Different key
        let mut encryptor =
            RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &traffic_secret1)
                .unwrap();
        let mut decryptor =
            RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &traffic_secret2)
                .unwrap();
        let ciphertext =
            encryptor.encrypt(&provider, ContentType::ApplicationData, b"secret").unwrap();
        // Decryption with wrong key should fail
        let result = decryptor.decrypt(&provider, &ciphertext);
        assert!(result.is_err());
    }
}
