//! Ticket Encryption for Session Resumption (RFC 8446 Section 4.6.1)
//!
//! This module implements secure encryption for NewSessionTicket messages.
//! Tickets contain sensitive session data (resumption master secret) and MUST
//! be encrypted to prevent information disclosure.
//!
//! # Security Requirements
//!
//! - Tickets MUST be encrypted with AES-256-GCM
//! - Encryption keys MUST be rotated regularly
//! - Tickets MUST include authentication
//! - Tickets MUST include version information for format evolution
//!
//! # Ticket Format
//!
//! ```text
//! struct EncryptedTicket {
//!     version: u8,              // Ticket format version (current: 1)
//!     key_id: u8,               // Key ID for rotation support
//!     nonce: [u8; 12],          // GCM nonce (96 bits)
//!     encrypted_data: Vec<u8>,  // AES-256-GCM encrypted payload
//!     tag: [u8; 16],            // GCM authentication tag
//! }
//!
//! Plaintext payload:
//! struct TicketPayload {
//!     resumption_master_secret: [u8; 32 or 48], // 32 for SHA-256, 48 for SHA-384
//!     cipher_suite: u16,                         // TLS cipher suite
//!     created_at: u64,                           // UNIX timestamp (seconds)
//!     server_name_len: u16,                      // Server name length
//!     server_name: Vec<u8>,                      // Server name (SNI)
//! }
//! ```

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};
use hptls_crypto::{AeadAlgorithm, CryptoProvider};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

/// Current ticket format version
pub const TICKET_VERSION: u8 = 1;

/// Ticket encryption key size (AES-256)
pub const TICKET_KEY_SIZE: usize = 32;

/// GCM nonce size
pub const GCM_NONCE_SIZE: usize = 12;

/// GCM tag size
pub const GCM_TAG_SIZE: usize = 16;

/// Ticket encryption key with metadata
#[derive(Clone)]
pub struct TicketKey {
    /// Key ID (for rotation)
    pub key_id: u8,

    /// AES-256 key
    pub key: Zeroizing<[u8; TICKET_KEY_SIZE]>,

    /// When this key was created (UNIX timestamp)
    pub created_at: u64,

    /// Key lifetime in seconds
    pub lifetime: u64,
}

impl TicketKey {
    /// Create a new ticket key with random material
    pub fn new(key_id: u8, lifetime: u64) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut key = [0u8; TICKET_KEY_SIZE];
        rng.fill(&mut key);

        let created_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        Self {
            key_id,
            key: Zeroizing::new(key),
            created_at,
            lifetime,
        }
    }

    /// Create a ticket key from existing key material (for testing)
    #[cfg(test)]
    pub fn from_bytes(key_id: u8, key: [u8; TICKET_KEY_SIZE], lifetime: u64) -> Self {
        let created_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        Self {
            key_id,
            key: Zeroizing::new(key),
            created_at,
            lifetime,
        }
    }

    /// Check if key is still valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        now < self.created_at + self.lifetime
    }

    /// Check if key should be rotated (past 75% of lifetime)
    pub fn should_rotate(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let age = now.saturating_sub(self.created_at);
        age >= (self.lifetime * 3) / 4
    }
}

impl Drop for TicketKey {
    fn drop(&mut self) {
        // Zeroizing will handle this, but explicit for clarity
        self.key.zeroize();
    }
}

/// Ticket encryption manager
///
/// Manages multiple ticket encryption keys for rotation support.
/// The server maintains 2-3 keys:
/// - Current key (for encrypting new tickets)
/// - Previous key(s) (for decrypting old tickets during rotation)
pub struct TicketEncryptor {
    /// Current key for encryption
    current_key: TicketKey,

    /// Previous keys for decryption (during rotation)
    previous_keys: Vec<TicketKey>,
}

impl TicketEncryptor {
    /// Create a new ticket encryptor with a random key
    ///
    /// # Arguments
    /// * `key_lifetime` - Key lifetime in seconds (recommended: 24 hours = 86400)
    pub fn new(key_lifetime: u64) -> Self {
        let current_key = TicketKey::new(0, key_lifetime);

        Self {
            current_key,
            previous_keys: Vec::new(),
        }
    }

    /// Create with a specific key (for testing)
    #[cfg(test)]
    pub fn with_key(key: TicketKey) -> Self {
        Self {
            current_key: key,
            previous_keys: Vec::new(),
        }
    }

    /// Rotate to a new encryption key
    ///
    /// The current key becomes a previous key (for decryption of old tickets).
    /// Previous keys are kept for 2x their lifetime to ensure old tickets can be decrypted.
    pub fn rotate_key(&mut self) {
        // Calculate next key ID and copy lifetime before moving
        let next_key_id = self.current_key.key_id.wrapping_add(1);
        let key_lifetime = self.current_key.lifetime;

        // Move current key to previous keys
        let old_key = std::mem::replace(
            &mut self.current_key,
            TicketKey::new(next_key_id, key_lifetime),
        );
        self.previous_keys.push(old_key);

        // Remove expired previous keys
        self.previous_keys.retain(|key| key.is_valid());

        // Keep at most 3 previous keys
        if self.previous_keys.len() > 3 {
            self.previous_keys.drain(0..self.previous_keys.len() - 3);
        }
    }

    /// Check if key rotation is needed and rotate if necessary
    pub fn maybe_rotate(&mut self) {
        if self.current_key.should_rotate() {
            self.rotate_key();
        }
    }

    /// Encrypt a ticket payload
    ///
    /// # Arguments
    /// * `provider` - Cryptographic provider
    /// * `resumption_master_secret` - The resumption master secret from the handshake
    /// * `cipher_suite` - The cipher suite used in the connection
    /// * `ticket_nonce` - The ticket nonce sent to the client (for PSK derivation)
    /// * `server_name` - Optional server name (SNI)
    ///
    /// # Returns
    /// Encrypted ticket bytes
    pub fn encrypt_ticket(
        &self,
        provider: &dyn CryptoProvider,
        resumption_master_secret: &[u8],
        cipher_suite: CipherSuite,
        ticket_nonce: &[u8],
        server_name: Option<&str>,
    ) -> Result<Vec<u8>> {
        // Construct plaintext payload
        let mut payload = BytesMut::new();

        // Resumption master secret length
        payload.put_u16(resumption_master_secret.len() as u16);
        payload.put_slice(resumption_master_secret);

        // Cipher suite
        payload.put_u16(cipher_suite as u16);

        // Created timestamp
        let created_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        payload.put_u64(created_at);

        // Ticket nonce length and data
        if ticket_nonce.len() > 255 {
            return Err(Error::InvalidMessage("Ticket nonce too long".into()));
        }
        payload.put_u8(ticket_nonce.len() as u8);
        payload.put_slice(ticket_nonce);

        // Server name
        let server_name_bytes = server_name.unwrap_or("").as_bytes();
        if server_name_bytes.len() > 65535 {
            return Err(Error::InvalidMessage("Server name too long".into()));
        }
        payload.put_u16(server_name_bytes.len() as u16);
        payload.put_slice(server_name_bytes);

        let plaintext = payload.freeze();

        // Generate random nonce
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; GCM_NONCE_SIZE];
        rng.fill(&mut nonce);

        // Encrypt with AES-256-GCM
        let aead = provider.aead(AeadAlgorithm::Aes256Gcm)?;

        // Additional authenticated data (AAD): version || key_id
        let mut aad = Vec::with_capacity(2);
        aad.push(TICKET_VERSION);
        aad.push(self.current_key.key_id);

        let ciphertext = aead.seal(&*self.current_key.key, &nonce, &aad, &plaintext)?;

        // Build encrypted ticket: version || key_id || nonce || ciphertext_with_tag
        let mut encrypted_ticket = Vec::with_capacity(2 + GCM_NONCE_SIZE + ciphertext.len());
        encrypted_ticket.push(TICKET_VERSION);
        encrypted_ticket.push(self.current_key.key_id);
        encrypted_ticket.extend_from_slice(&nonce);
        encrypted_ticket.extend_from_slice(&ciphertext);

        Ok(encrypted_ticket)
    }

    /// Decrypt a ticket
    ///
    /// # Arguments
    /// * `provider` - Cryptographic provider
    /// * `encrypted_ticket` - Encrypted ticket bytes
    ///
    /// # Returns
    /// Tuple of (resumption_master_secret, cipher_suite, created_at, ticket_nonce, server_name)
    pub fn decrypt_ticket(
        &self,
        provider: &dyn CryptoProvider,
        encrypted_ticket: &[u8],
    ) -> Result<(
        Zeroizing<Vec<u8>>,
        CipherSuite,
        u64,
        Vec<u8>,
        Option<String>,
    )> {
        // Minimum size: version(1) + key_id(1) + nonce(12) + tag(16) = 30 bytes
        if encrypted_ticket.len() < 30 {
            return Err(Error::InvalidMessage("Ticket too short".into()));
        }

        let mut data = encrypted_ticket;

        // Parse header
        let version = data.get_u8();
        if version != TICKET_VERSION {
            return Err(Error::InvalidMessage("Unsupported ticket version".into()));
        }

        let key_id = data.get_u8();

        // Find the right key
        let key = if key_id == self.current_key.key_id {
            &self.current_key
        } else {
            self.previous_keys
                .iter()
                .find(|k| k.key_id == key_id)
                .ok_or_else(|| Error::InvalidMessage("Unknown key ID".into()))?
        };

        // Check key is still valid
        if !key.is_valid() {
            return Err(Error::InvalidMessage("Ticket key expired".into()));
        }

        // Extract nonce
        let nonce = &data[..GCM_NONCE_SIZE];
        data.advance(GCM_NONCE_SIZE);

        // Remaining is ciphertext + tag
        let ciphertext_with_tag = data;

        // Decrypt with AES-256-GCM
        let aead = provider.aead(AeadAlgorithm::Aes256Gcm)?;

        // AAD: version || key_id
        let mut aad = Vec::with_capacity(2);
        aad.push(version);
        aad.push(key_id);

        let plaintext = aead
            .open(&*key.key, nonce, &aad, ciphertext_with_tag)
            .map_err(|_| Error::InvalidMessage("Ticket decryption failed".into()))?;

        // Parse plaintext payload
        let mut payload = &plaintext[..];

        if payload.len() < 2 {
            return Err(Error::InvalidMessage("Ticket payload too short".into()));
        }

        // Resumption master secret
        let secret_len = payload.get_u16() as usize;
        if payload.len() < secret_len {
            return Err(Error::InvalidMessage("Invalid secret length".into()));
        }
        let resumption_master_secret = Zeroizing::new(payload[..secret_len].to_vec());
        payload.advance(secret_len);

        if payload.len() < 2 {
            return Err(Error::InvalidMessage("Missing cipher suite".into()));
        }

        // Cipher suite
        let cipher_suite_u16 = payload.get_u16();
        let cipher_suite = CipherSuite::from_u16(cipher_suite_u16)
            .ok_or_else(|| Error::InvalidMessage("Unknown cipher suite".into()))?;

        if payload.len() < 8 {
            return Err(Error::InvalidMessage("Missing timestamp".into()));
        }

        // Created timestamp
        let created_at = payload.get_u64();

        if payload.is_empty() {
            return Err(Error::InvalidMessage("Missing ticket nonce length".into()));
        }

        // Ticket nonce
        let ticket_nonce_len = payload.get_u8() as usize;
        if payload.len() < ticket_nonce_len {
            return Err(Error::InvalidMessage("Invalid ticket nonce length".into()));
        }
        let ticket_nonce = payload[..ticket_nonce_len].to_vec();
        payload.advance(ticket_nonce_len);

        if payload.len() < 2 {
            return Err(Error::InvalidMessage("Missing server name length".into()));
        }

        // Server name
        let server_name_len = payload.get_u16() as usize;
        if payload.len() < server_name_len {
            return Err(Error::InvalidMessage("Invalid server name length".into()));
        }
        let server_name = if server_name_len > 0 {
            let name_bytes = &payload[..server_name_len];
            Some(
                String::from_utf8(name_bytes.to_vec())
                    .map_err(|_| Error::InvalidMessage("Invalid server name UTF-8".into()))?,
            )
        } else {
            None
        };

        Ok((
            resumption_master_secret,
            cipher_suite,
            created_at,
            ticket_nonce,
            server_name,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hptls_crypto_hpcrypt::HpcryptProvider;

    #[test]
    fn test_ticket_key_creation() {
        let key = TicketKey::new(0, 86400);
        assert_eq!(key.key_id, 0);
        assert_eq!(key.key.len(), TICKET_KEY_SIZE);
        assert!(key.is_valid());
        assert!(!key.should_rotate());
    }

    #[test]
    fn test_ticket_encryption_decryption() {
        let provider = HpcryptProvider::new();
        let encryptor = TicketEncryptor::new(86400);

        let resumption_secret = vec![0x42; 32];
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        let ticket_nonce = vec![0x12; 32];
        let server_name = Some("example.com");

        // Encrypt
        let encrypted = encryptor
            .encrypt_ticket(
                &provider,
                &resumption_secret,
                cipher_suite,
                &ticket_nonce,
                server_name,
            )
            .unwrap();

        // Verify format
        assert!(encrypted.len() > 30);
        assert_eq!(encrypted[0], TICKET_VERSION);

        // Decrypt
        let (decrypted_secret, decrypted_suite, _created_at, decrypted_nonce, decrypted_name) =
            encryptor.decrypt_ticket(&provider, &encrypted).unwrap();

        assert_eq!(&decrypted_secret[..], &resumption_secret[..]);
        assert_eq!(decrypted_suite, cipher_suite);
        assert_eq!(&decrypted_nonce, &ticket_nonce);
        assert_eq!(decrypted_name.as_deref(), server_name);
    }

    #[test]
    fn test_ticket_encryption_without_server_name() {
        let provider = HpcryptProvider::new();
        let encryptor = TicketEncryptor::new(86400);

        let resumption_secret = vec![0x42; 32];
        let cipher_suite = CipherSuite::Aes256GcmSha384;
        let ticket_nonce = vec![0x34; 32];

        // Encrypt without server name
        let encrypted = encryptor
            .encrypt_ticket(
                &provider,
                &resumption_secret,
                cipher_suite,
                &ticket_nonce,
                None,
            )
            .unwrap();

        // Decrypt
        let (decrypted_secret, decrypted_suite, _created_at, decrypted_nonce, decrypted_name) =
            encryptor.decrypt_ticket(&provider, &encrypted).unwrap();

        assert_eq!(&decrypted_secret[..], &resumption_secret[..]);
        assert_eq!(decrypted_suite, cipher_suite);
        assert_eq!(&decrypted_nonce, &ticket_nonce);
        assert_eq!(decrypted_name, None);
    }

    #[test]
    fn test_ticket_key_rotation() {
        let provider = HpcryptProvider::new();
        let mut encryptor = TicketEncryptor::new(86400);

        let resumption_secret = vec![0x42; 32];
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        let ticket_nonce = vec![0x56; 32];

        // Encrypt with key 0
        let encrypted_key0 = encryptor
            .encrypt_ticket(
                &provider,
                &resumption_secret,
                cipher_suite,
                &ticket_nonce,
                Some("example.com"),
            )
            .unwrap();

        assert_eq!(encrypted_key0[1], 0); // key_id = 0

        // Rotate key
        encryptor.rotate_key();
        assert_eq!(encryptor.current_key.key_id, 1);
        assert_eq!(encryptor.previous_keys.len(), 1);

        // Encrypt with key 1
        let encrypted_key1 = encryptor
            .encrypt_ticket(
                &provider,
                &resumption_secret,
                cipher_suite,
                &ticket_nonce,
                Some("example.com"),
            )
            .unwrap();

        assert_eq!(encrypted_key1[1], 1); // key_id = 1

        // Should still be able to decrypt ticket encrypted with key 0
        let (decrypted_secret, _, _, _, _) =
            encryptor.decrypt_ticket(&provider, &encrypted_key0).unwrap();
        assert_eq!(&decrypted_secret[..], &resumption_secret[..]);

        // Should be able to decrypt ticket encrypted with key 1
        let (decrypted_secret, _, _, _, _) =
            encryptor.decrypt_ticket(&provider, &encrypted_key1).unwrap();
        assert_eq!(&decrypted_secret[..], &resumption_secret[..]);
    }

    #[test]
    fn test_ticket_decryption_wrong_key() {
        let provider = HpcryptProvider::new();

        let encryptor1 = TicketEncryptor::new(86400);
        let encryptor2 = TicketEncryptor::new(86400);

        let resumption_secret = vec![0x42; 32];
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        let ticket_nonce = vec![0x78; 32];

        // Encrypt with encryptor1
        let encrypted = encryptor1
            .encrypt_ticket(
                &provider,
                &resumption_secret,
                cipher_suite,
                &ticket_nonce,
                Some("example.com"),
            )
            .unwrap();

        // Try to decrypt with encryptor2 (different key)
        let result = encryptor2.decrypt_ticket(&provider, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_decryption_corrupted() {
        let provider = HpcryptProvider::new();
        let encryptor = TicketEncryptor::new(86400);

        let resumption_secret = vec![0x42; 32];
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        let ticket_nonce = vec![0x9a; 32];

        // Encrypt
        let mut encrypted = encryptor
            .encrypt_ticket(
                &provider,
                &resumption_secret,
                cipher_suite,
                &ticket_nonce,
                Some("example.com"),
            )
            .unwrap();

        // Corrupt the ciphertext
        encrypted[20] ^= 0xFF;

        // Decryption should fail
        let result = encryptor.decrypt_ticket(&provider, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_decryption_invalid_version() {
        let provider = HpcryptProvider::new();
        let encryptor = TicketEncryptor::new(86400);

        let resumption_secret = vec![0x42; 32];
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        let ticket_nonce = vec![0xbc; 32];

        // Encrypt
        let mut encrypted = encryptor
            .encrypt_ticket(
                &provider,
                &resumption_secret,
                cipher_suite,
                &ticket_nonce,
                Some("example.com"),
            )
            .unwrap();

        // Change version
        encrypted[0] = 99;

        // Decryption should fail
        let result = encryptor.decrypt_ticket(&provider, &encrypted);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidMessage(_))));
    }

    #[test]
    fn test_multiple_key_rotations() {
        let provider = HpcryptProvider::new();
        let mut encryptor = TicketEncryptor::new(86400);

        let resumption_secret = vec![0x42; 32];
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        let ticket_nonce = vec![0xde; 32];

        // Create tickets with different keys
        let mut tickets = Vec::new();

        for _ in 0..5 {
            let ticket = encryptor
                .encrypt_ticket(
                    &provider,
                    &resumption_secret,
                    cipher_suite,
                    &ticket_nonce,
                    Some("example.com"),
                )
                .unwrap();
            tickets.push(ticket);
            encryptor.rotate_key();
        }

        // Should keep at most 3 previous keys + current = 4 keys total
        assert!(encryptor.previous_keys.len() <= 3);

        // Oldest tickets may not be decryptable (kept only 3 previous keys)
        // But recent tickets should be decryptable
        let recent_tickets = &tickets[tickets.len() - 3..];
        for ticket in recent_tickets {
            let result = encryptor.decrypt_ticket(&provider, ticket);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_ticket_with_sha384_cipher_suite() {
        let provider = HpcryptProvider::new();
        let encryptor = TicketEncryptor::new(86400);

        // SHA-384 uses 48-byte resumption secret
        let resumption_secret = vec![0x42; 48];
        let cipher_suite = CipherSuite::Aes256GcmSha384;
        let ticket_nonce = vec![0xef; 48];

        // Encrypt
        let encrypted = encryptor
            .encrypt_ticket(
                &provider,
                &resumption_secret,
                cipher_suite,
                &ticket_nonce,
                Some("example.com"),
            )
            .unwrap();

        // Decrypt
        let (decrypted_secret, decrypted_suite, _created_at, decrypted_nonce, _server_name) =
            encryptor.decrypt_ticket(&provider, &encrypted).unwrap();

        assert_eq!(&decrypted_secret[..], &resumption_secret[..]);
        assert_eq!(decrypted_suite, cipher_suite);
        assert_eq!(&decrypted_nonce, &ticket_nonce);
    }
}
