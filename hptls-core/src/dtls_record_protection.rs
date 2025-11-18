//! DTLS 1.3 Record Protection (AEAD Encryption/Decryption)
//!
//! This module implements the AEAD encryption and decryption for DTLS 1.3 records
//! as specified in RFC 9147 Section 4.
//!
//! # DTLS 1.3 AEAD Construction
//!
//! DTLS 1.3 uses the same AEAD construction as TLS 1.3, with the key differences:
//! - Nonce includes epoch and sequence number
//! - Additional data includes the 13-byte DTLS record header
//! - Per-epoch key tracking
//!
//! # Nonce Construction (RFC 9147 Section 4.2.3)
//!
//! ```text
//! nonce = per_record_nonce XOR iv
//! where per_record_nonce = epoch || sequence_number (padded to IV length)
//! ```
//!
//! # Record Format
//!
//! ```text
//! struct {
//!     ContentType type;
//!     ProtocolVersion legacy_record_version = 0xFEFD; /* DTLS 1.2 */
//!     uint16 epoch;
//!     uint48 sequence_number;
//!     uint16 length;
//!     opaque encrypted_record[length];
//! } DTLSCiphertext;
//! ```

use crate::cipher::CipherSuite;
use crate::dtls::{DtlsRecordHeader, Epoch, SequenceNumber};
use crate::error::{Error, Result};
use crate::protocol::{ContentType, ProtocolVersion};
use crate::record::TlsPlaintext;
use hptls_crypto::{Aead, CryptoProvider};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// DTLS 1.3 encrypted record
#[derive(Debug, Clone)]
pub struct DtlsCiphertext {
    /// DTLS record header (13 bytes)
    pub header: DtlsRecordHeader,
    /// Encrypted fragment (ciphertext + auth tag)
    pub encrypted_record: Vec<u8>,
}

impl DtlsCiphertext {
    /// Create a new DTLS ciphertext record
    pub fn new(header: DtlsRecordHeader, encrypted_record: Vec<u8>) -> Self {
        Self {
            header,
            encrypted_record,
        }
    }

    /// Encode to wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(DtlsRecordHeader::SIZE + self.encrypted_record.len());
        // Header (13 bytes)
        buf.extend_from_slice(&self.header.encode());
        // Encrypted fragment
        buf.extend_from_slice(&self.encrypted_record);
        buf
    }

    /// Decode from wire format
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < DtlsRecordHeader::SIZE {
            return Err(Error::InvalidMessage("DTLS ciphertext too short".into()));
        }

        let header = DtlsRecordHeader::decode(&data[..DtlsRecordHeader::SIZE])?;
        let encrypted_record = data[DtlsRecordHeader::SIZE..].to_vec();

        // Verify length field matches actual data
        if encrypted_record.len() != header.length as usize {
            return Err(Error::InvalidMessage(
                "DTLS record length mismatch".into(),
            ));
        }

        Ok(Self {
            header,
            encrypted_record,
        })
    }
}

/// DTLS record protection for a single epoch
///
/// Each epoch has its own encryption keys and sequence number tracking
pub struct DtlsEpochProtection {
    /// Epoch number
    epoch: Epoch,
    /// Cipher suite in use
    cipher_suite: CipherSuite,
    /// Traffic secret
    traffic_secret: Zeroizing<Vec<u8>>,
    /// AEAD key
    key: Zeroizing<Vec<u8>>,
    /// AEAD IV (12 bytes for DTLS 1.3)
    iv: Zeroizing<Vec<u8>>,
}

impl DtlsEpochProtection {
    /// Create a new epoch protection instance
    ///
    /// # Arguments
    /// * `provider` - Crypto provider for key derivation
    /// * `epoch` - Epoch number
    /// * `cipher_suite` - Cipher suite in use
    /// * `traffic_secret` - Traffic secret for this epoch
    pub fn new(
        provider: &dyn CryptoProvider,
        epoch: Epoch,
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
            12, // DTLS 1.3 uses 12-byte IVs
        )?;

        Ok(Self {
            epoch,
            cipher_suite,
            traffic_secret: Zeroizing::new(traffic_secret.to_vec()),
            key: Zeroizing::new(key),
            iv: Zeroizing::new(iv),
        })
    }

    /// Encrypt a plaintext record using AEAD
    ///
    /// # DTLS 1.3 Encryption Process
    /// 1. Build plaintext: content || content_type || padding
    /// 2. Compute nonce: (epoch || sequence_number) XOR iv
    /// 3. Build additional_data: DTLS record header (13 bytes)
    /// 4. Encrypt: ciphertext = AEAD-Encrypt(key, nonce, plaintext, additional_data)
    ///
    /// # Arguments
    /// * `provider` - Crypto provider for AEAD operations
    /// * `content_type` - Actual content type of the plaintext
    /// * `fragment` - Plaintext fragment to encrypt
    /// * `sequence_number` - Sequence number for this record
    pub fn encrypt(
        &self,
        provider: &dyn CryptoProvider,
        content_type: ContentType,
        fragment: &[u8],
        sequence_number: SequenceNumber,
    ) -> Result<DtlsCiphertext> {
        // Step 1: Build DTLSInnerPlaintext = fragment || content_type || zeros*
        let mut plaintext = Vec::with_capacity(fragment.len() + 1);
        plaintext.extend_from_slice(fragment);
        plaintext.push(content_type.to_u8()); // Real content type
                                              // No padding for now (optional in DTLS 1.3)

        // Step 2: Compute per-record nonce (DTLS-specific)
        let nonce = self.compute_nonce(sequence_number);

        // Step 3: Build additional_data (DTLS record header - 13 bytes)
        // NOTE: We need to create the header with the correct length BEFORE encryption
        // because the header is used as additional authenticated data.
        // For AEAD, ciphertext.len() = plaintext.len() + tag_length (16 bytes for AES-GCM)
        let encrypted_length = plaintext.len() + 16; // plaintext + auth tag
        let mut header = DtlsRecordHeader {
            content_type: ContentType::ApplicationData, // Always for encrypted records
            legacy_version: 0xFEFD,                     // DTLS 1.2 for compatibility
            epoch: self.epoch,
            sequence_number,
            length: encrypted_length as u16,
        };
        let additional_data = header.encode();

        // Step 4: Encrypt using AEAD
        let aead_algorithm = self.cipher_suite.aead_algorithm();
        let aead = provider.aead(aead_algorithm)?;

        let ciphertext = aead.seal(&self.key, &nonce, &additional_data, &plaintext)?;

        // Verify that the actual ciphertext length matches our expectation
        if ciphertext.len() != encrypted_length {
            return Err(Error::InternalError(format!(
                "AEAD ciphertext length mismatch: expected {}, got {}",
                encrypted_length,
                ciphertext.len()
            )));
        }

        Ok(DtlsCiphertext::new(header, ciphertext))
    }

    /// Decrypt a ciphertext record using AEAD
    ///
    /// # DTLS 1.3 Decryption Process
    /// 1. Compute nonce: (epoch || sequence_number) XOR iv
    /// 2. Build additional_data from DTLS record header
    /// 3. Decrypt: plaintext = AEAD-Decrypt(key, nonce, ciphertext, additional_data)
    /// 4. Extract content_type from end of plaintext
    ///
    /// # Arguments
    /// * `provider` - Crypto provider for AEAD operations
    /// * `ciphertext` - Encrypted record to decrypt
    ///
    /// # Returns
    /// Decrypted plaintext record with actual content type
    pub fn decrypt(
        &self,
        provider: &dyn CryptoProvider,
        ciphertext: &DtlsCiphertext,
    ) -> Result<TlsPlaintext> {
        // Verify epoch matches
        if ciphertext.header.epoch != self.epoch {
            return Err(Error::DecryptionFailed);
        }

        // Step 1: Compute per-record nonce
        let nonce = self.compute_nonce(ciphertext.header.sequence_number);

        // Step 2: Build additional_data (DTLS record header)
        let additional_data = ciphertext.header.encode();

        // Step 3: Decrypt using AEAD
        let aead_algorithm = self.cipher_suite.aead_algorithm();
        let aead = provider.aead(aead_algorithm)?;

        let buffer = aead.open(
            &self.key,
            &nonce,
            &additional_data,
            &ciphertext.encrypted_record,
        )?;

        // Step 4: Extract content type (last non-zero byte)
        // DTLSInnerPlaintext = content || content_type || zeros*
        let mut content_type_pos = buffer.len();
        while content_type_pos > 0 && buffer[content_type_pos - 1] == 0 {
            content_type_pos -= 1;
        }

        if content_type_pos == 0 {
            return Err(Error::DecryptionFailed);
        }

        let content_type_byte = buffer[content_type_pos - 1];
        let content_type = ContentType::from_u8(content_type_byte).ok_or_else(|| {
            Error::InvalidMessage(format!("Invalid content type: {}", content_type_byte))
        })?;

        // Extract fragment (everything before content_type)
        let fragment = buffer[..content_type_pos - 1].to_vec();

        Ok(TlsPlaintext::new(
            content_type,
            ProtocolVersion::Dtls13,
            fragment,
        ))
    }

    /// Compute the per-record nonce for DTLS 1.3
    ///
    /// Per RFC 9147 Section 4.2.3:
    /// ```text
    /// The nonce is formed by XORing the 64-bit epoch and sequence number
    /// with the static IV (left-padded with zeros).
    /// ```
    fn compute_nonce(&self, sequence_number: SequenceNumber) -> Vec<u8> {
        let mut nonce = self.iv.to_vec();

        // Construct 8-byte value: epoch (2 bytes) || sequence_number (6 bytes)
        let mut epoch_seq = [0u8; 8];
        epoch_seq[0..2].copy_from_slice(&self.epoch.0.to_be_bytes());
        epoch_seq[2..8].copy_from_slice(&sequence_number.to_bytes());

        // XOR the last 8 bytes of IV with epoch||sequence_number
        let iv_len = nonce.len();
        for (i, &byte) in epoch_seq.iter().enumerate() {
            nonce[iv_len - 8 + i] ^= byte;
        }

        nonce
    }

    /// Get the epoch number
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

/// DTLS record protection manager
///
/// Manages per-epoch encryption/decryption state with separate read/write keys.
/// In TLS 1.3, client and server use different traffic secrets for sending and
/// receiving, so we maintain separate protection instances for each direction.
pub struct DtlsRecordProtection {
    /// Per-epoch protection instances for writing (sending)
    write_epochs: HashMap<Epoch, DtlsEpochProtection>,
    /// Per-epoch protection instances for reading (receiving)
    read_epochs: HashMap<Epoch, DtlsEpochProtection>,
    /// Current write epoch
    write_epoch: Epoch,
    /// Current read epoch
    read_epoch: Epoch,
}

impl DtlsRecordProtection {
    /// Create a new DTLS record protection manager
    pub fn new() -> Self {
        Self {
            write_epochs: HashMap::new(),
            read_epochs: HashMap::new(),
            write_epoch: Epoch::INITIAL,
            read_epoch: Epoch::INITIAL,
        }
    }

    /// Add a new epoch with separate read and write traffic secrets
    ///
    /// This is the correct method for TLS 1.3 DTLS where client and server
    /// use different secrets for sending vs receiving.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `epoch` - Epoch number
    /// * `cipher_suite` - Cipher suite for this epoch
    /// * `write_secret` - Traffic secret for encrypting outgoing records
    /// * `read_secret` - Traffic secret for decrypting incoming records
    pub fn add_epoch_bidirectional(
        &mut self,
        provider: &dyn CryptoProvider,
        epoch: Epoch,
        cipher_suite: CipherSuite,
        write_secret: &[u8],
        read_secret: &[u8],
    ) -> Result<()> {
        let write_protection = DtlsEpochProtection::new(provider, epoch, cipher_suite, write_secret)?;
        let read_protection = DtlsEpochProtection::new(provider, epoch, cipher_suite, read_secret)?;

        self.write_epochs.insert(epoch, write_protection);
        self.read_epochs.insert(epoch, read_protection);
        Ok(())
    }

    /// Add a new epoch with a single traffic secret (for both read and write)
    ///
    /// This is a convenience method for cases where the same secret is used
    /// for both directions (e.g., DTLS 1.2 or testing). For TLS 1.3 DTLS,
    /// use `add_epoch_bidirectional` instead.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `epoch` - Epoch number
    /// * `cipher_suite` - Cipher suite for this epoch
    /// * `traffic_secret` - Traffic secret for key derivation (used for both directions)
    pub fn add_epoch(
        &mut self,
        provider: &dyn CryptoProvider,
        epoch: Epoch,
        cipher_suite: CipherSuite,
        traffic_secret: &[u8],
    ) -> Result<()> {
        // Use the same secret for both read and write
        self.add_epoch_bidirectional(provider, epoch, cipher_suite, traffic_secret, traffic_secret)
    }

    /// Set the current write epoch
    pub fn set_write_epoch(&mut self, epoch: Epoch) -> Result<()> {
        if !self.write_epochs.contains_key(&epoch) {
            return Err(Error::InternalError(format!(
                "Write epoch {} not initialized",
                epoch.0
            )));
        }
        self.write_epoch = epoch;
        Ok(())
    }

    /// Set the current read epoch
    pub fn set_read_epoch(&mut self, epoch: Epoch) -> Result<()> {
        if !self.read_epochs.contains_key(&epoch) {
            return Err(Error::InternalError(format!(
                "Read epoch {} not initialized",
                epoch.0
            )));
        }
        self.read_epoch = epoch;
        Ok(())
    }

    /// Encrypt a record using the current write epoch
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `content_type` - Content type of the plaintext
    /// * `fragment` - Plaintext fragment
    /// * `sequence_number` - Sequence number for this record
    pub fn encrypt(
        &self,
        provider: &dyn CryptoProvider,
        content_type: ContentType,
        fragment: &[u8],
        sequence_number: SequenceNumber,
    ) -> Result<DtlsCiphertext> {
        let epoch_protection = self.write_epochs.get(&self.write_epoch).ok_or_else(|| {
            Error::InternalError(format!("Write epoch {} not found", self.write_epoch.0))
        })?;

        epoch_protection.encrypt(provider, content_type, fragment, sequence_number)
    }

    /// Decrypt a record
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `ciphertext` - Encrypted record to decrypt
    ///
    /// # Note
    /// The epoch is extracted from the ciphertext header and used to select
    /// the appropriate decryption keys from the read epochs.
    pub fn decrypt(
        &self,
        provider: &dyn CryptoProvider,
        ciphertext: &DtlsCiphertext,
    ) -> Result<TlsPlaintext> {
        let epoch = ciphertext.header.epoch;
        let epoch_protection = self.read_epochs.get(&epoch).ok_or_else(|| {
            Error::InvalidMessage(format!("Unknown read epoch: {}", epoch.0))
        })?;

        epoch_protection.decrypt(provider, ciphertext)
    }

    /// Get the current write epoch
    pub fn write_epoch(&self) -> Epoch {
        self.write_epoch
    }

    /// Get the current read epoch
    pub fn read_epoch(&self) -> Epoch {
        self.read_epoch
    }

    /// Remove old epochs to free memory
    ///
    /// # Arguments
    /// * `keep_epoch` - Keep this epoch and all newer ones
    pub fn remove_old_epochs(&mut self, keep_epoch: Epoch) {
        self.write_epochs.retain(|&epoch, _| epoch >= keep_epoch);
        self.read_epochs.retain(|&epoch, _| epoch >= keep_epoch);
    }
}

impl Default for DtlsRecordProtection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::CipherSuite;
    use hptls_crypto_hpcrypt::HpcryptProvider;

    #[test]
    fn test_dtls_nonce_computation() {
        let provider = HpcryptProvider::new();
        let traffic_secret = vec![0u8; 32];
        let protection = DtlsEpochProtection::new(
            &provider,
            Epoch(1),
            CipherSuite::Aes128GcmSha256,
            &traffic_secret,
        )
        .unwrap();

        let nonce1 = protection.compute_nonce(SequenceNumber::new(0));
        let nonce2 = protection.compute_nonce(SequenceNumber::new(1));

        // Nonces should be different for different sequence numbers
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_dtls_encrypt_decrypt_roundtrip() {
        let provider = HpcryptProvider::new();
        let traffic_secret = vec![1u8; 32];

        let encryptor = DtlsEpochProtection::new(
            &provider,
            Epoch(1),
            CipherSuite::Aes128GcmSha256,
            &traffic_secret,
        )
        .unwrap();

        let decryptor = DtlsEpochProtection::new(
            &provider,
            Epoch(1),
            CipherSuite::Aes128GcmSha256,
            &traffic_secret,
        )
        .unwrap();

        let plaintext = b"Hello, DTLS 1.3!";
        let content_type = ContentType::ApplicationData;
        let seq = SequenceNumber::new(42);

        // Encrypt
        let ciphertext = encryptor
            .encrypt(&provider, content_type, plaintext, seq)
            .unwrap();

        // Verify epoch and sequence are in header
        assert_eq!(ciphertext.header.epoch, Epoch(1));
        assert_eq!(ciphertext.header.sequence_number, seq);

        // Decrypt
        let decrypted = decryptor.decrypt(&provider, &ciphertext).unwrap();

        // Verify
        assert_eq!(decrypted.content_type, content_type);
        assert_eq!(decrypted.fragment.as_slice(), plaintext);
    }

    #[test]
    fn test_dtls_ciphertext_encode_decode() {
        let header = DtlsRecordHeader {
            content_type: ContentType::ApplicationData,
            legacy_version: 0xFEFD,
            epoch: Epoch(1),
            sequence_number: SequenceNumber::new(100),
            length: 5,
        };

        let encrypted_data = vec![1, 2, 3, 4, 5];
        let ciphertext = DtlsCiphertext::new(header, encrypted_data.clone());

        let encoded = ciphertext.encode();
        let decoded = DtlsCiphertext::decode(&encoded).unwrap();

        assert_eq!(decoded.header.epoch, Epoch(1));
        assert_eq!(decoded.header.sequence_number.0, 100);
        assert_eq!(decoded.encrypted_record, encrypted_data);
    }

    #[test]
    fn test_dtls_record_protection_multi_epoch() {
        let provider = HpcryptProvider::new();
        let mut protection = DtlsRecordProtection::new();

        // Add epoch 0 (initial handshake)
        let secret0 = vec![1u8; 32];
        protection
            .add_epoch(&provider, Epoch(0), CipherSuite::Aes128GcmSha256, &secret0)
            .unwrap();

        // Add epoch 1 (application data)
        let secret1 = vec![2u8; 32];
        protection
            .add_epoch(&provider, Epoch(1), CipherSuite::Aes128GcmSha256, &secret1)
            .unwrap();

        // Set write epoch to 1
        protection.set_write_epoch(Epoch(1)).unwrap();

        // Encrypt with epoch 1
        let plaintext = b"test data";
        let ciphertext = protection
            .encrypt(
                &provider,
                ContentType::ApplicationData,
                plaintext,
                SequenceNumber::new(0),
            )
            .unwrap();

        assert_eq!(ciphertext.header.epoch, Epoch(1));

        // Should be able to decrypt with epoch 1
        let decrypted = protection.decrypt(&provider, &ciphertext).unwrap();
        assert_eq!(decrypted.fragment.as_slice(), plaintext);
    }

    #[test]
    fn test_dtls_wrong_epoch_fails() {
        let provider = HpcryptProvider::new();

        // Create encryptor with epoch 1
        let encryptor = DtlsEpochProtection::new(
            &provider,
            Epoch(1),
            CipherSuite::Aes128GcmSha256,
            &vec![1u8; 32],
        )
        .unwrap();

        // Create decryptor with epoch 2 (wrong epoch)
        let decryptor = DtlsEpochProtection::new(
            &provider,
            Epoch(2),
            CipherSuite::Aes128GcmSha256,
            &vec![2u8; 32],
        )
        .unwrap();

        let ciphertext = encryptor
            .encrypt(
                &provider,
                ContentType::ApplicationData,
                b"secret",
                SequenceNumber::new(0),
            )
            .unwrap();

        // Decryption should fail due to epoch mismatch
        let result = decryptor.decrypt(&provider, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_dtls_remove_old_epochs() {
        let provider = HpcryptProvider::new();
        let mut protection = DtlsRecordProtection::new();

        // Add multiple epochs
        for i in 0..5 {
            protection
                .add_epoch(
                    &provider,
                    Epoch(i),
                    CipherSuite::Aes128GcmSha256,
                    &vec![i as u8; 32],
                )
                .unwrap();
        }

        assert_eq!(protection.write_epochs.len(), 5);
        assert_eq!(protection.read_epochs.len(), 5);

        // Remove epochs older than epoch 3
        protection.remove_old_epochs(Epoch(3));

        assert_eq!(protection.write_epochs.len(), 2); // Should have epochs 3 and 4
        assert_eq!(protection.read_epochs.len(), 2);
        assert!(protection.write_epochs.contains_key(&Epoch(3)));
        assert!(protection.write_epochs.contains_key(&Epoch(4)));
        assert!(!protection.write_epochs.contains_key(&Epoch(2)));
        assert!(protection.read_epochs.contains_key(&Epoch(3)));
        assert!(protection.read_epochs.contains_key(&Epoch(4)));
        assert!(!protection.read_epochs.contains_key(&Epoch(2)));
    }
}
