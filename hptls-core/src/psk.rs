//! Pre-Shared Key (PSK) Session Resumption (RFC 8446 Section 4.2.11, 4.6.1)
//!
//! This module implements PSK-based session resumption for TLS 1.3, which enables:
//! - Session resumption without full handshake
//! - 0-RTT early data in resumed connections
//! - Forward secrecy with (EC)DHE key exchange
//! # Protocol Flow
//! ```text
//! Initial Connection:
//!   Client                                      Server
//!   ClientHello           -------->
//!                         <--------       ServerHello
//!                                   EncryptedExtensions
//!                                            Certificate
//!                                      CertificateVerify
//!                         <--------            Finished
//!   Finished              -------->
//!                         <--------  [NewSessionTicket]  // PSK ticket
//! Resumed Connection (with PSK):
//!   ClientHello
//!     + pre_shared_key
//!     + psk_key_exchange_modes
//!     + early_data (optional)
//!   (Application Data*)   -------->
//!                                        + pre_shared_key
//!   (Application Data)    <------->  (Application Data)
//! ```
//! # Security
//! - PSKs are bound to the original connection's cipher suite and hash algorithm
//! - PSK binders provide cryptographic binding to the handshake
//! - ticket_age_add provides obfuscation of ticket age
//! - Tickets should have limited lifetime

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};
use crate::messages::NewSessionTicket;
use hptls_crypto::HashAlgorithm;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;
/// Default ticket lifetime (7 days in seconds)
pub const DEFAULT_TICKET_LIFETIME: u32 = 7 * 24 * 60 * 60;
/// Maximum ticket lifetime (7 days as per RFC 8446)
pub const MAX_TICKET_LIFETIME: u32 = 7 * 24 * 60 * 60;
/// PSK key exchange mode (RFC 8446 Section 4.2.9)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PskKeyExchangeMode {
    /// PSK-only key exchange (no (EC)DHE)
    PskKe = 0,
    /// PSK with (EC)DHE key exchange (recommended for forward secrecy)
    PskDheKe = 1,
}
impl PskKeyExchangeMode {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PskKeyExchangeMode::PskKe),
            1 => Some(PskKeyExchangeMode::PskDheKe),
            _ => None,
        }
    }
    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}
/// PSK identity sent by client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskIdentity {
    /// Opaque identity value
    pub identity: Vec<u8>,
    /// Obfuscated ticket age
    pub obfuscated_ticket_age: u32,
}
impl PskIdentity {
    /// Create a new PSK identity
    pub fn new(identity: Vec<u8>, obfuscated_ticket_age: u32) -> Self {
        Self {
            identity,
            obfuscated_ticket_age,
        }
    }
    /// Encode to wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(6 + self.identity.len());
        // Identity length (2 bytes)
        buf.extend_from_slice(&(self.identity.len() as u16).to_be_bytes());
        // Identity
        buf.extend_from_slice(&self.identity);
        // Obfuscated ticket age (4 bytes)
        buf.extend_from_slice(&self.obfuscated_ticket_age.to_be_bytes());
        buf
    }
    /// Decode from wire format
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 6 {
            return Err(Error::InvalidMessage("PSK identity too short".into()));
        }
        let identity_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 6 + identity_len {
            return Err(Error::InvalidMessage("Incomplete PSK identity".into()));
        }
        let identity = data[2..2 + identity_len].to_vec();
        let obfuscated_ticket_age = u32::from_be_bytes([
            data[2 + identity_len],
            data[3 + identity_len],
            data[4 + identity_len],
            data[5 + identity_len],
        ]);
        Ok((
            Self {
                identity,
                obfuscated_ticket_age,
            },
            6 + identity_len,
        ))
    }
}
/// PSK binder value
#[derive(Debug, Clone)]
pub struct PskBinder {
    /// HMAC of handshake transcript
    pub binder: Vec<u8>,
}

impl PskBinder {
    /// Compute PSK binder for ClientHello.
    ///
    /// RFC 8446 Section 4.2.11.2:
    /// ```text
    /// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    /// binder = HMAC(finished_key, Transcript-Hash(ClientHello[truncated]))
    /// ```
    /// Where BaseKey is the binder_key derived from early secret with the PSK.
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `psk` - Pre-shared key
    /// * `cipher_suite` - Cipher suite for the handshake
    /// * `client_hello_partial` - ClientHello encoded up to (but not including) the binders
    pub fn compute(
        provider: &dyn hptls_crypto::CryptoProvider,
        psk: &[u8],
        cipher_suite: CipherSuite,
        client_hello_partial: &[u8],
    ) -> Result<Self> {
        use crate::transcript::{hkdf_expand_label, TranscriptHash};
        let hash_algorithm = cipher_suite.hash_algorithm();
        // 1. Derive early secret from PSK
        // early_secret = HKDF-Extract(0, PSK)
        let kdf = provider.kdf(hash_algorithm.to_kdf_algorithm())?;
        let hash_len = match hash_algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            _ => {
                return Err(Error::InternalError(
                    "Unsupported hash algorithm".to_string(),
                ))
            },
        };
        let salt = vec![0u8; hash_len];
        let early_secret = kdf.extract(&salt, psk);
        // 2. Derive binder_key from early secret
        // binder_key = Derive-Secret(early_secret, "ext binder", "")
        let empty_hash = {
            let mut transcript = TranscriptHash::new(hash_algorithm);
            transcript.current_hash(provider)?
        };
        let binder_key = hkdf_expand_label(
            provider,
            hash_algorithm,
            &early_secret,
            b"ext binder",
            &empty_hash,
            hash_len,
        )?;
        // 3. Derive finished_key from binder_key
        // finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
        let finished_key = hkdf_expand_label(
            provider,
            hash_algorithm,
            &binder_key,
            b"finished",
            b"",
            hash_len,
        )?;
        // 4. Compute transcript hash of partial ClientHello
        let mut transcript = TranscriptHash::new(hash_algorithm);
        transcript.update(client_hello_partial);
        let transcript_hash = transcript.current_hash(provider)?;
        // 5. Compute binder = HMAC(finished_key, transcript_hash)
        let mut hmac_impl = provider.hmac(hash_algorithm, &finished_key)?;
        hmac_impl.update(&transcript_hash);
        let binder = hmac_impl.finalize();
        Ok(Self { binder })
    }
    /// Verify PSK binder.
    /// Returns true if the binder is valid for the given PSK and ClientHello.
    pub fn verify(
        &self,
        provider: &dyn hptls_crypto::CryptoProvider,
        psk: &[u8],
        cipher_suite: CipherSuite,
        client_hello_partial: &[u8],
    ) -> Result<bool> {
        let expected = Self::compute(provider, psk, cipher_suite, client_hello_partial)?;
        Ok(self.binder == expected.binder)
    }
    /// Encode binder to wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.binder.len());
        buf.push(self.binder.len() as u8);
        buf.extend_from_slice(&self.binder);
        buf
    }
    /// Decode binder from wire format
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::InvalidMessage("Binder data is empty".into()));
        }
        let binder_len = data[0] as usize;
        if data.len() < 1 + binder_len {
            return Err(Error::InvalidMessage("Incomplete binder data".into()));
        }
        let binder = data[1..1 + binder_len].to_vec();
        Ok((Self { binder }, 1 + binder_len))
    }
}
/// Pre-Shared Key extension for ClientHello (RFC 8446 Section 4.2.11)
///
/// This extension contains PSK identities and binders. It MUST be the last extension in ClientHello.
#[derive(Debug, Clone)]
pub struct PreSharedKeyExtension {
    /// PSK identities offered by the client
    pub identities: Vec<PskIdentity>,
    /// PSK binders (one per identity)
    pub binders: Vec<PskBinder>,
}
impl PreSharedKeyExtension {
    /// Create a new PreSharedKey extension
    pub fn new(identities: Vec<PskIdentity>, binders: Vec<PskBinder>) -> Result<Self> {
        if identities.len() != binders.len() {
            return Err(Error::InternalError(
                "Number of identities must match number of binders".to_string(),
            ));
        }
        if identities.is_empty() {
            return Err(Error::InternalError(
                "PreSharedKey extension must have at least one identity".to_string(),
            ));
        }
        Ok(Self {
            identities,
            binders,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Encode identities
        let mut identities_buf = Vec::new();
        for identity in &self.identities {
            identities_buf.extend_from_slice(&identity.encode());
        }
        // Identities length (2 bytes)
        buf.extend_from_slice(&(identities_buf.len() as u16).to_be_bytes());
        buf.extend_from_slice(&identities_buf);
        // Encode binders
        let mut binders_buf = Vec::new();
        for binder in &self.binders {
            binders_buf.extend_from_slice(&binder.encode());
        }
        // Binders length (2 bytes)
        buf.extend_from_slice(&(binders_buf.len() as u16).to_be_bytes());
        buf.extend_from_slice(&binders_buf);
        buf
    }
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidMessage(
                "PreSharedKey extension too short".into(),
            ));
        }
        let mut offset = 0;
        // Decode identities
        let identities_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if data.len() < offset + identities_len {
            return Err(Error::InvalidMessage("Incomplete identities data".into()));
        }
        let mut identities = Vec::new();
        let identities_end = offset + identities_len;
        while offset < identities_end {
            let (identity, bytes_read) = PskIdentity::decode(&data[offset..])?;
            identities.push(identity);
            offset += bytes_read;
        }
        // Decode binders
        if data.len() < offset + 2 {
            return Err(Error::InvalidMessage("Missing binders length".into()));
        }
        let binders_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if data.len() < offset + binders_len {
            return Err(Error::InvalidMessage("Incomplete binders data".into()));
        }
        let mut binders = Vec::new();
        let binders_end = offset + binders_len;
        while offset < binders_end {
            let (binder, bytes_read) = PskBinder::decode(&data[offset..])?;
            binders.push(binder);
            offset += bytes_read;
        }
        Self::new(identities, binders)
    }
    /// Get the size of the extension data without binders
    /// This is used when computing PSK binders, as the binder computation
    /// must include the ClientHello up to (but not including) the binders.
    pub fn size_without_binders(&self) -> usize {
        let mut size = 2; // identities length field
        for identity in &self.identities {
            size += identity.encode().len();
        }
        size += 2; // binders length field (but not the binders themselves)
        size
    }
}
/// Pre-Shared Key extension for ServerHello (RFC 8446 Section 4.2.11)
/// The server responds with the index of the selected PSK identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreSharedKeyServerExtension {
    /// Index of the selected PSK identity (0-based)
    pub selected_identity: u16,
}
impl PreSharedKeyServerExtension {
    /// Create a new server PreSharedKey extension
    pub fn new(selected_identity: u16) -> Self {
        Self { selected_identity }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.selected_identity.to_be_bytes().to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != 2 {
            return Err(Error::InvalidMessage(
                "Server PreSharedKey extension must be 2 bytes".into(),
            ));
        }
        let selected_identity = u16::from_be_bytes([data[0], data[1]]);
        Ok(Self { selected_identity })
    }
}
/// PSK Key Exchange Modes extension (RFC 8446 Section 4.2.9)
#[derive(Debug, Clone)]
pub struct PskKeyExchangeModesExtension {
    /// Supported PSK key exchange modes
    pub modes: Vec<PskKeyExchangeMode>,
}
impl PskKeyExchangeModesExtension {
    /// Create a new PskKeyExchangeModes extension
    pub fn new(modes: Vec<PskKeyExchangeMode>) -> Result<Self> {
        if modes.is_empty() {
            return Err(Error::InternalError(
                "PskKeyExchangeModes must have at least one mode".to_string(),
            ));
        }
        Ok(Self { modes })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.modes.len());
        // Length (1 byte)
        buf.push(self.modes.len() as u8);
        // Modes
        for mode in &self.modes {
            buf.push(mode.to_u8());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidMessage(
                "PskKeyExchangeModes extension is empty".into(),
            ));
        }
        let modes_len = data[0] as usize;
        if data.len() != 1 + modes_len {
            return Err(Error::InvalidMessage(
                "Invalid PskKeyExchangeModes length".into(),
            ));
        }
        let mut modes = Vec::new();
        for i in 0..modes_len {
            if let Some(mode) = PskKeyExchangeMode::from_u8(data[1 + i]) {
                modes.push(mode);
            }
            // Unknown modes are ignored per RFC 8446
        }
        if modes.is_empty() {
            return Err(Error::InvalidMessage(
                "No recognized PSK key exchange modes".into(),
            ));
        }
        Self::new(modes)
    }
}
/// Stored session ticket with associated data
#[derive(Debug, Clone)]
pub struct StoredTicket {
    /// The ticket value (opaque from client perspective)
    pub ticket: Vec<u8>,
    /// Resumption master secret
    pub resumption_master_secret: Zeroizing<Vec<u8>>,
    /// Cipher suite used in original connection
    pub cipher_suite: CipherSuite,
    /// Timestamp when ticket was received (seconds since UNIX epoch)
    pub received_at: u64,
    /// Ticket lifetime in seconds
    pub lifetime: u32,
    /// Ticket age add value (for obfuscation)
    pub age_add: u32,
    /// Ticket nonce (for PSK derivation)
    pub nonce: Vec<u8>,
    /// Server name (SNI) the ticket is bound to
    pub server_name: Option<String>,
}
impl StoredTicket {
    /// Create a new stored ticket from NewSessionTicket message
    pub fn from_new_session_ticket(
        ticket_msg: &NewSessionTicket,
        resumption_master_secret: Zeroizing<Vec<u8>>,
        cipher_suite: CipherSuite,
        server_name: Option<String>,
    ) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Self {
            ticket: ticket_msg.ticket.clone(),
            resumption_master_secret,
            cipher_suite,
            received_at: now,
            lifetime: ticket_msg.ticket_lifetime,
            age_add: ticket_msg.ticket_age_add,
            nonce: ticket_msg.ticket_nonce.clone(),
            server_name,
        }
    }
    /// Check if ticket is still valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let age = now.saturating_sub(self.received_at);
        age < self.lifetime as u64
    }
    /// Get ticket age in milliseconds
    pub fn get_ticket_age_ms(&self) -> u32 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let age_secs = now.saturating_sub(self.received_at);
        (age_secs * 1000) as u32
    }
    /// Get obfuscated ticket age (for ClientHello)
    pub fn get_obfuscated_ticket_age(&self) -> u32 {
        let age_ms = self.get_ticket_age_ms();
        age_ms.wrapping_add(self.age_add)
    }
    /// Get hash algorithm for this ticket's cipher suite
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.cipher_suite.hash_algorithm()
    }
    /// Derive PSK from resumption master secret and ticket nonce.
    /// This is used by the client when offering a PSK in ClientHello.
    /// PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
    pub fn derive_psk(
        &self,
        provider: &dyn hptls_crypto::CryptoProvider,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let hash_algorithm = self.hash_algorithm();
        let hash_len = match hash_algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            _ => {
                return Err(Error::InternalError(
                    "Unsupported hash algorithm".to_string(),
                ))
            },
        };
        let psk = crate::transcript::hkdf_expand_label(
            provider,
            hash_algorithm,
            &self.resumption_master_secret,
            b"resumption",
            &self.nonce,
            hash_len,
        )?;
        Ok(Zeroizing::new(psk))
    }
}
/// PSK session ticket store
/// Stores session tickets for resumption. In a real implementation,
/// this should persist tickets to disk and handle rotation.
#[derive(Debug, Default)]
pub struct PskStore {
    /// Tickets indexed by server name
    tickets: HashMap<String, Vec<StoredTicket>>,
}
impl PskStore {
    /// Create a new PSK store
    pub fn new() -> Self {
        Self {
            tickets: HashMap::new(),
        }
    }
    /// Store a ticket for a server
    pub fn store_ticket(&mut self, ticket: StoredTicket) {
        let server_name = ticket.server_name.clone().unwrap_or_else(|| "".to_string());
        // Get or create ticket list for this server
        let tickets = self.tickets.entry(server_name).or_insert_with(Vec::new);
        // Add new ticket
        tickets.push(ticket);
        // Clean up expired tickets
        tickets.retain(|t| t.is_valid());
        // Limit to 10 tickets per server (most recent)
        if tickets.len() > 10 {
            tickets.drain(0..tickets.len() - 10);
        }
    }
    /// Get a valid ticket for a server
    pub fn get_ticket(&self, server_name: Option<&str>) -> Option<&StoredTicket> {
        let key = server_name.unwrap_or("");
        self.tickets.get(key)?.iter().filter(|t| t.is_valid()).last() // Return most recent valid ticket
    }
    /// Get all valid tickets for a server
    pub fn get_tickets(&self, server_name: Option<&str>) -> Vec<&StoredTicket> {
        let key = server_name.unwrap_or("");
        self.tickets
            .get(key)
            .map(|tickets| tickets.iter().filter(|t| t.is_valid()).collect())
            .unwrap_or_default()
    }
    /// Clear all tickets
    pub fn clear(&mut self) {
        self.tickets.clear();
    }
    /// Clear tickets for a specific server
    pub fn clear_server(&mut self, server_name: Option<&str>) {
        let key = server_name.unwrap_or("");
        self.tickets.remove(key);
    }
    /// Remove expired tickets
    pub fn prune_expired(&mut self) {
        for tickets in self.tickets.values_mut() {
            tickets.retain(|t| t.is_valid());
        }
        // Remove servers with no tickets
        self.tickets.retain(|_, tickets| !tickets.is_empty());
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hptls_crypto::CryptoProvider;
    use hptls_crypto_hpcrypt::HpcryptProvider;
    #[test]
    fn test_psk_identity_encode_decode() {
        let identity = PskIdentity::new(vec![1, 2, 3, 4], 12345678);
        let encoded = identity.encode();
        let (decoded, bytes_read) = PskIdentity::decode(&encoded).unwrap();
        assert_eq!(identity, decoded);
        assert_eq!(bytes_read, encoded.len());
    }

    #[test]
    fn test_stored_ticket_validity() {
        let ticket_msg = NewSessionTicket {
            ticket_lifetime: 3600, // 1 hour
            ticket_age_add: 12345,
            ticket_nonce: vec![1, 2, 3],
            ticket: vec![4, 5, 6],
            extensions: crate::extensions::Extensions::new(),
        };
        let secret = Zeroizing::new(vec![1; 32]);
        let stored = StoredTicket::from_new_session_ticket(
            &ticket_msg,
            secret,
            CipherSuite::Aes128GcmSha256,
            Some("example.com".to_string()),
        );
        // Should be valid immediately
        assert!(stored.is_valid());
    }

    #[test]
    fn test_psk_store_operations() {
        let mut store = PskStore::new();
        let ticket_msg = NewSessionTicket {
            ticket_lifetime: 3600,
            ticket_age_add: 12345,
            ticket_nonce: vec![1, 2, 3],
            ticket: vec![4, 5, 6],
            extensions: crate::extensions::Extensions::new(),
        };
        let secret = Zeroizing::new(vec![1; 32]);
        let stored = StoredTicket::from_new_session_ticket(
            &ticket_msg,
            secret,
            CipherSuite::Aes128GcmSha256,
            Some("example.com".to_string()),
        );
        // Store ticket
        store.store_ticket(stored);
        // Retrieve ticket
        let retrieved = store.get_ticket(Some("example.com"));
        assert!(retrieved.is_some());
        // Clear server tickets
        store.clear_server(Some("example.com"));
        assert!(store.get_ticket(Some("example.com")).is_none());
    }

    #[test]
    fn test_obfuscated_ticket_age() {
        let ticket_msg = NewSessionTicket {
            ticket_lifetime: 3600,
            ticket_age_add: 1000,
            ticket_nonce: vec![1, 2, 3],
            ticket: vec![4, 5, 6],
            extensions: crate::extensions::Extensions::new(),
        };
        let secret = Zeroizing::new(vec![1; 32]);
        let stored = StoredTicket::from_new_session_ticket(
            &ticket_msg,
            secret,
            CipherSuite::Aes128GcmSha256,
            None,
        );
        let obfuscated = stored.get_obfuscated_ticket_age();
        let age_ms = stored.get_ticket_age_ms();
        // Obfuscated age should be age_ms + age_add
        assert_eq!(obfuscated, age_ms.wrapping_add(1000));
    }

    #[test]
    fn test_psk_store_limits_tickets_per_server() {
        let mut store = PskStore::new();
        // Add 15 tickets
        for i in 0..15 {
            let ticket_msg = NewSessionTicket {
                ticket_lifetime: 3600,
                ticket_age_add: i as u32,
                ticket_nonce: vec![i as u8],
                ticket: vec![i as u8],
                extensions: crate::extensions::Extensions::new(),
            };
            let secret = Zeroizing::new(vec![i as u8; 32]);
            let stored = StoredTicket::from_new_session_ticket(
                &ticket_msg,
                secret,
                CipherSuite::Aes128GcmSha256,
                Some("example.com".to_string()),
            );
            store.store_ticket(stored);
        }
        // Should only keep 10 most recent
        let tickets = store.get_tickets(Some("example.com"));
        assert_eq!(tickets.len(), 10);
    }

    #[test]
    fn test_stored_ticket_derive_psk() {
        use hptls_crypto_hpcrypt::HpcryptProvider;
        let provider = HpcryptProvider::new();
        let ticket_msg = NewSessionTicket {
            ticket_lifetime: 3600,
            ticket_age_add: 12345,
            ticket_nonce: vec![1, 2, 3, 4, 5],
            ticket: vec![9, 8, 7, 6],
            extensions: crate::extensions::Extensions::new(),
        };
        let resumption_secret = Zeroizing::new(vec![0x42; 32]);
        let stored = StoredTicket::from_new_session_ticket(
            &ticket_msg,
            resumption_secret,
            CipherSuite::Aes128GcmSha256,
            Some("example.com".to_string()),
        );
        // Derive PSK
        let psk = stored.derive_psk(&provider).unwrap();
        // PSK should be 32 bytes for SHA-256
        assert_eq!(psk.len(), 32);
        // Derive again - should get same result
        let psk2 = stored.derive_psk(&provider).unwrap();
        assert_eq!(&psk[..], &psk2[..]);
    }

    #[test]
    fn test_psk_binder_encode_decode() {
        let binder = PskBinder {
            binder: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let encoded = binder.encode();
        let (decoded, bytes_read) = PskBinder::decode(&encoded).unwrap();
        assert_eq!(binder.binder, decoded.binder);
        assert_eq!(bytes_read, 1 + 8); // 1 byte length + 8 bytes data
    }

    #[test]
    fn test_psk_binder_computation() {
        let provider = HpcryptProvider::new();
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        let psk = vec![0x42; 32];
        // Simulate a partial ClientHello (without binders)
        let client_hello_partial = vec![1, 0, 0, 100]; // Fake ClientHello
                                                       // Compute binder
        let binder =
            PskBinder::compute(&provider, &psk, cipher_suite, &client_hello_partial).unwrap();
        // Binder should be 32 bytes for SHA-256
        assert_eq!(binder.binder.len(), 32);
        // Verify the binder
        let is_valid = binder.verify(&provider, &psk, cipher_suite, &client_hello_partial).unwrap();
        assert!(is_valid);
        // Wrong PSK should fail verification
        let wrong_psk = vec![0x99; 32];
        let is_valid = binder
            .verify(&provider, &wrong_psk, cipher_suite, &client_hello_partial)
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_psk_binder_with_different_cipher_suites() {
        let provider = HpcryptProvider::new();
        let psk = vec![0x42; 32];
        let client_hello_partial = vec![1, 0, 0, 100];
        // Compute binder with SHA-256 cipher suite
        let binder_sha256 = PskBinder::compute(
            &provider,
            &psk,
            CipherSuite::Aes128GcmSha256,
            &client_hello_partial,
        )
        .unwrap();
        // Compute binder with different SHA-256 cipher suite
        let binder_chacha = PskBinder::compute(
            &provider,
            &psk,
            CipherSuite::ChaCha20Poly1305Sha256,
            &client_hello_partial,
        )
        .unwrap();
        // Same hash algorithm (SHA-256) should produce same binder
        assert_eq!(binder_sha256.binder, binder_chacha.binder);
    }

    #[test]
    fn test_pre_shared_key_extension_encode_decode() {
        let identity = PskIdentity::new(vec![1, 2, 3], 12345);
        let binder = PskBinder {
            binder: vec![4, 5, 6, 7],
        };
        let psk_ext =
            PreSharedKeyExtension::new(vec![identity.clone()], vec![binder.clone()]).unwrap();
        let encoded = psk_ext.encode();
        let decoded = PreSharedKeyExtension::decode(&encoded).unwrap();
        assert_eq!(decoded.identities.len(), 1);
        assert_eq!(decoded.identities[0], identity);
        assert_eq!(decoded.binders.len(), 1);
        assert_eq!(decoded.binders[0].binder, binder.binder);
    }

    #[test]
    fn test_pre_shared_key_extension_multiple_psks() {
        let identity1 = PskIdentity::new(vec![1, 2, 3], 100);
        let identity2 = PskIdentity::new(vec![4, 5, 6, 7, 8], 200);
        let binder1 = PskBinder {
            binder: vec![10, 11, 12],
        };
        let binder2 = PskBinder {
            binder: vec![20, 21, 22, 23, 24],
        };
        let psk_ext = PreSharedKeyExtension::new(
            vec![identity1.clone(), identity2.clone()],
            vec![binder1.clone(), binder2.clone()],
        )
        .unwrap();
        let encoded = psk_ext.encode();
        let decoded = PreSharedKeyExtension::decode(&encoded).unwrap();
        assert_eq!(decoded.identities.len(), 2);
        assert_eq!(decoded.identities[0], identity1);
        assert_eq!(decoded.identities[1], identity2);
        assert_eq!(decoded.binders.len(), 2);
        assert_eq!(decoded.binders[0].binder, binder1.binder);
        assert_eq!(decoded.binders[1].binder, binder2.binder);
    }

    #[test]
    fn test_pre_shared_key_extension_mismatched_counts() {
        let identity = PskIdentity::new(vec![1, 2, 3], 100);
        let binder1 = PskBinder {
            binder: vec![4, 5, 6],
        };
        let binder2 = PskBinder {
            binder: vec![7, 8, 9],
        };
        // Should fail - 1 identity but 2 binders
        let result = PreSharedKeyExtension::new(vec![identity], vec![binder1, binder2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pre_shared_key_server_extension_encode_decode() {
        let server_ext = PreSharedKeyServerExtension::new(5);
        let encoded = server_ext.encode();
        let decoded = PreSharedKeyServerExtension::decode(&encoded).unwrap();
        assert_eq!(decoded.selected_identity, 5);
    }

    #[test]
    fn test_psk_key_exchange_modes_extension() {
        let modes_ext = PskKeyExchangeModesExtension::new(vec![
            PskKeyExchangeMode::PskDheKe,
            PskKeyExchangeMode::PskKe,
        ])
        .unwrap();
        let encoded = modes_ext.encode();
        let decoded = PskKeyExchangeModesExtension::decode(&encoded).unwrap();
        assert_eq!(decoded.modes.len(), 2);
        assert_eq!(decoded.modes[0], PskKeyExchangeMode::PskDheKe);
        assert_eq!(decoded.modes[1], PskKeyExchangeMode::PskKe);
    }

    #[test]
    fn test_psk_key_exchange_mode_conversion() {
        assert_eq!(PskKeyExchangeMode::PskKe.to_u8(), 0);
        assert_eq!(PskKeyExchangeMode::PskDheKe.to_u8(), 1);
        assert_eq!(
            PskKeyExchangeMode::from_u8(0),
            Some(PskKeyExchangeMode::PskKe)
        );
        assert_eq!(
            PskKeyExchangeMode::from_u8(1),
            Some(PskKeyExchangeMode::PskDheKe)
        );
        assert_eq!(PskKeyExchangeMode::from_u8(99), None);
    }

    #[test]
    fn test_pre_shared_key_extension_size_without_binders() {
        let identity = PskIdentity::new(vec![1, 2, 3, 4, 5], 12345);
        let binder = PskBinder {
            binder: vec![0; 32], // 32-byte binder
        };
        let psk_ext = PreSharedKeyExtension::new(vec![identity.clone()], vec![binder]).unwrap();
        // Size should be: 2 (identities length) + identity encoded + 2 (binders length)
        let identity_encoded_size = identity.encode().len(); // 2 (len) + 5 (identity) + 4 (age) = 11
        let expected_size = 2 + identity_encoded_size + 2; // 2 + 11 + 2 = 15
        assert_eq!(psk_ext.size_without_binders(), expected_size);
    }
}
/// External PSK (out-of-band pre-shared key)
/// External PSKs are established through mechanisms outside of TLS,
/// such as manual configuration, HSMs, or key agreement protocols.
#[derive(Debug)]
pub struct ExternalPsk {
    /// PSK identity
    pub identity: Vec<u8>,
    /// PSK value (secret)
    pub psk: Zeroizing<Vec<u8>>,
    /// Cipher suite to use with this PSK
    pub cipher_suite: CipherSuite,
    /// Hash algorithm (derived from cipher suite)
    pub hash_algorithm: HashAlgorithm,
    /// Maximum early data size (0 = no early data)
    pub max_early_data_size: u32,
}

impl ExternalPsk {
    /// Create a new external PSK
    pub fn new(
        identity: Vec<u8>,
        psk: Vec<u8>,
        cipher_suite: CipherSuite,
        max_early_data_size: u32,
    ) -> Self {
        Self {
            identity,
            psk: Zeroizing::new(psk),
            cipher_suite,
            hash_algorithm: cipher_suite.hash_algorithm(),
            max_early_data_size,
        }
    }
    /// Get PSK value
    pub fn psk_value(&self) -> &[u8] {
        &self.psk
    }
    /// Check if early data is allowed
    pub fn allows_early_data(&self) -> bool {
        self.max_early_data_size > 0
    }
}
/// External PSK store
/// Manages out-of-band PSKs established through external mechanisms
#[derive(Debug, Default)]
pub struct ExternalPskStore {
    /// PSKs indexed by identity
    psks: HashMap<Vec<u8>, ExternalPsk>,
}
impl ExternalPskStore {
    /// Create a new external PSK store
    pub fn new() -> Self {
        Self {
            psks: HashMap::new(),
        }
    }
    /// Add an external PSK
    pub fn add_psk(&mut self, psk: ExternalPsk) {
        self.psks.insert(psk.identity.clone(), psk);
    }
    /// Get a PSK by identity
    pub fn get_psk(&self, identity: &[u8]) -> Option<&ExternalPsk> {
        self.psks.get(identity)
    }
    /// Remove a PSK
    pub fn remove_psk(&mut self, identity: &[u8]) -> Option<ExternalPsk> {
        self.psks.remove(identity)
    }
    /// Clear all PSKs
    pub fn clear(&mut self) {
        self.psks.clear();
    }
    /// Get all PSK identities
    pub fn identities(&self) -> Vec<&[u8]> {
        self.psks.keys().map(|k| k.as_slice()).collect()
    }
    /// Check if a PSK exists
    pub fn has_psk(&self, identity: &[u8]) -> bool {
        self.psks.contains_key(identity)
    }
}
#[cfg(test)]
mod external_psk_tests {
    use super::*;

    #[test]
    fn test_external_psk_creation() {
        let psk = ExternalPsk::new(
            b"test-identity".to_vec(),
            vec![0x01; 32],
            CipherSuite::Aes128GcmSha256,
            16384,
        );
        assert_eq!(psk.identity, b"test-identity");
        assert_eq!(psk.psk_value(), &vec![0x01; 32]);
        assert!(psk.allows_early_data());
    }

    #[test]
    fn test_external_psk_no_early_data() {
        let psk = ExternalPsk::new(
            b"test-identity".to_vec(),
            vec![0x01; 32],
            CipherSuite::Aes128GcmSha256,
            0, // No early data
        );
        assert!(!psk.allows_early_data());
    }

    #[test]
    fn test_external_psk_store_operations() {
        let mut store = ExternalPskStore::new();
        let psk = ExternalPsk::new(
            b"identity-1".to_vec(),
            vec![0x01; 32],
            CipherSuite::Aes128GcmSha256,
            16384,
        );
        // Add PSK
        store.add_psk(psk);
        // Get PSK
        let retrieved = store.get_psk(b"identity-1");
        assert_eq!(retrieved.unwrap().identity, b"identity-1");
        // Check if exists
        assert!(store.has_psk(b"identity-1"));
        // Remove PSK
        let removed = store.remove_psk(b"identity-1");
        assert!(removed.is_some());
        assert!(!store.has_psk(b"identity-1"));
    }

    #[test]
    fn test_external_psk_store_multiple() {
        let mut store = ExternalPskStore::new();
        // Add multiple PSKs
        for i in 0..5 {
            let identity = format!("identity-{}", i);
            let psk = ExternalPsk::new(
                identity.as_bytes().to_vec(),
                vec![i as u8; 32],
                CipherSuite::Aes128GcmSha256,
                16384,
            );
            store.add_psk(psk);
        }
        // Check count
        let identities = store.identities();
        assert_eq!(identities.len(), 5);
        // Clear all
        store.clear();
        assert_eq!(store.identities().len(), 0);
    }

    #[test]
    fn test_external_psk_hash_algorithm() {
        let psk = ExternalPsk::new(
            b"test".to_vec(),
            vec![0x01; 32],
            CipherSuite::Aes128GcmSha256,
            0,
        );
        assert_eq!(psk.hash_algorithm, HashAlgorithm::Sha256);
    }
}
