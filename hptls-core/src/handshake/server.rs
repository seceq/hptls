//! TLS 1.3 Server Handshake State Machine (RFC 8446 Section 4).
//!
//! This module implements the server-side TLS 1.3 handshake state machine.
//! The server processes the ClientHello, selects cipher suite and parameters,
//! generates the ServerHello and subsequent messages, and verifies the client's
//! Finished message.
//! # State Transition Diagram
//! ```text
//! START
//!   |
//!   | (receive ClientHello)
//!   v
//! NEGOTIATE
//!   | (send ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished)
//! WAIT_FINISHED
//!   | (receive client Finished)
//! CONNECTED
//! ```

use crate::cipher::CipherSuite;
use crate::early_data::{AntiReplayCache, EarlyDataContext};
use crate::error::{Error, Result};
use crate::extension_types::{KeyShareEntry, SignatureScheme, TypedExtension};
use crate::extensions::Extensions;
use crate::key_schedule::KeySchedule;
use crate::messages::*;
use crate::protocol::ProtocolVersion;
use crate::psk::{PreSharedKeyExtension, PreSharedKeyServerExtension, PskBinder};
use crate::ticket_encryption::TicketEncryptor;
use crate::transcript::{compute_verify_data, TranscriptHash};
use hptls_crypto::key_exchange::PrivateKey;
use hptls_crypto::{CryptoProvider, KeyExchangeAlgorithm, SignatureAlgorithm};
use std::collections::HashMap;
use zeroize::Zeroizing;
/// Server-side ticket information for PSK resumption.
///
/// Simplified version for testing - in production, tickets would be encrypted
/// and this information would be derived from decrypting the ticket blob.
#[derive(Debug, Clone)]
pub struct ServerTicket {
    /// The ticket blob (opaque identifier)
    pub ticket: Vec<u8>,
    /// PSK derived from resumption master secret
    pub psk: Zeroizing<Vec<u8>>,
    /// Cipher suite this ticket is valid for
    pub cipher_suite: CipherSuite,
    /// When this ticket was issued (seconds since UNIX epoch)
    pub issued_at: u64,
    /// Ticket lifetime in seconds
    pub lifetime: u32,
    /// Ticket age add (for age validation)
    pub ticket_age_add: u32,
}
impl ServerTicket {
    /// Check if ticket is still valid
    pub fn is_valid(&self, current_time: u64) -> bool {
        let age = current_time.saturating_sub(self.issued_at);
        age < self.lifetime as u64
    }
}
/// Server handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Initial state, waiting for ClientHello
    Start,
    /// Received ClientHello, ready to send ServerHello
    Negotiate,
    /// Sent HelloRetryRequest, waiting for updated ClientHello
    WaitClientHello,
    /// Sent ServerHello and subsequent messages, waiting for client Finished
    WaitFinished,
    /// Handshake complete, ready for application data
    Connected,
    /// Connection is closing (close_notify sent or received)
    Closing,
    /// Connection is closed
    Closed,
    /// Error state
    Failed,
}
/// Server handshake context.
/// Manages the server-side TLS 1.3 handshake state machine.
pub struct ServerHandshake {
    /// Current handshake state
    state: ServerState,
    /// Negotiated cipher suite
    cipher_suite: Option<CipherSuite>,
    /// Key schedule for deriving secrets
    key_schedule: Option<KeySchedule>,
    /// Transcript hash for all handshake messages
    transcript: Option<TranscriptHash>,
    /// Server random (32 bytes)
    server_random: [u8; 32],
    /// Client random (extracted from ClientHello)
    client_random: Option<[u8; 32]>,
    /// Selected key exchange algorithm
    key_exchange_algorithm: Option<KeyExchangeAlgorithm>,
    /// Server's private key for key exchange
    key_exchange_private: Option<Vec<u8>>,
    /// Server's public key for key exchange
    key_exchange_public: Option<Vec<u8>>,
    /// Client's public key (extracted from ClientHello)
    client_key_exchange: Option<Vec<u8>>,
    /// Session ID (from ClientHello, for compatibility)
    session_id: Vec<u8>,
    /// Supported cipher suites (server configuration)
    supported_cipher_suites: Vec<CipherSuite>,
    /// Supported key exchange groups (server preferences, in order)
    supported_groups: Vec<KeyExchangeAlgorithm>,
    /// Server name (extracted from SNI)
    server_name: Option<String>,
    /// Ticket store (maps ticket blob to ticket info)
    /// In production, this would be replaced with encrypted tickets
    ticket_store: HashMap<Vec<u8>, ServerTicket>,
    /// Selected PSK index (if client offered PSK and server accepted)
    selected_psk_index: Option<u16>,
    /// Selected PSK (if PSK resumption is being used)
    selected_psk: Option<Zeroizing<Vec<u8>>>,
    /// Whether we've sent a HelloRetryRequest (can only send once per connection)
    hello_retry_sent: bool,
    /// Original ClientHello (before HRR) for transcript hash computation
    original_client_hello: Option<Vec<u8>>,
    /// Negotiated ALPN protocol
    negotiated_alpn: Option<String>,
    /// Client certificate chain (received during mTLS)
    client_cert_chain: Option<Vec<Vec<u8>>>,
    /// Ticket encryptor for secure session ticket encryption/decryption
    ticket_encryptor: TicketEncryptor,
    /// Early data (0-RTT) context
    early_data: Option<EarlyDataContext>,
    /// Anti-replay cache for 0-RTT protection
    anti_replay_cache: AntiReplayCache,
}
impl ServerHandshake {
    /// Create a new server handshake state machine.
    ///
    /// # Arguments
    /// * `supported_cipher_suites` - List of cipher suites the server supports (in preference order)
    pub fn new(supported_cipher_suites: Vec<CipherSuite>) -> Self {
        // Default key exchange group preferences (most secure first)
        let supported_groups = vec![
            KeyExchangeAlgorithm::X25519,    // Preferred: Fast, secure curve25519
            KeyExchangeAlgorithm::Secp256r1, // NIST P-256 for compatibility
            KeyExchangeAlgorithm::Secp384r1, // NIST P-384 for high security
        ];

        // Create ticket encryptor with 24-hour key lifetime (recommended)
        let ticket_encryptor = TicketEncryptor::new(86400);

        // Create anti-replay cache with 10-second window (recommended for 0-RTT)
        let anti_replay_cache = AntiReplayCache::new(10);

        Self {
            state: ServerState::Start,
            cipher_suite: None,
            key_schedule: None,
            transcript: None,
            server_random: [0u8; 32],
            client_random: None,
            key_exchange_algorithm: None,
            key_exchange_private: None,
            key_exchange_public: None,
            client_key_exchange: None,
            session_id: Vec::new(),
            supported_cipher_suites,
            supported_groups,
            server_name: None,
            ticket_store: HashMap::new(),
            selected_psk_index: None,
            selected_psk: None,
            hello_retry_sent: false,
            original_client_hello: None,
            negotiated_alpn: None,
            client_cert_chain: None,
            ticket_encryptor,
            early_data: None,
            anti_replay_cache,
        }
    }

    /// Get the current handshake state.
    pub fn state(&self) -> ServerState {
        self.state
    }

    /// Set supported key exchange groups (in preference order).
    ///
    /// # Arguments
    /// * `groups` - List of supported key exchange algorithms, most preferred first
    ///
    /// # Example
    /// ```rust
    /// use hptls_core::handshake::ServerHandshake;
    /// use hptls_core::cipher::CipherSuite;
    /// use hptls_crypto::KeyExchangeAlgorithm;
    ///
    /// let mut server = ServerHandshake::new(vec![CipherSuite::Aes128GcmSha256]);
    /// // Prefer X25519, fallback to P-256
    /// server.set_supported_groups(vec![
    ///     KeyExchangeAlgorithm::X25519,
    ///     KeyExchangeAlgorithm::Secp256r1,
    /// ]);
    /// ```
    pub fn set_supported_groups(&mut self, groups: Vec<KeyExchangeAlgorithm>) {
        self.supported_groups = groups;
    }

    /// Get the negotiated cipher suite.
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.cipher_suite
    }

    /// Get the selected key exchange algorithm.
    pub fn key_exchange_algorithm(&self) -> Option<KeyExchangeAlgorithm> {
        self.key_exchange_algorithm
    }

    /// Get the server name (SNI) from the ClientHello.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Check if the handshake is in the negotiation phase.
    pub fn is_negotiating(&self) -> bool {
        matches!(self.state, ServerState::Negotiate)
    }

    /// Check if the server is waiting for client's Finished message.
    pub fn is_waiting_finished(&self) -> bool {
        matches!(self.state, ServerState::WaitFinished)
    }

    /// Check if the server is waiting for updated ClientHello (after HRR).
    pub fn is_waiting_client_hello(&self) -> bool {
        matches!(self.state, ServerState::WaitClientHello)
    }

    /// Get handshake progress as a percentage (0-100).
    ///
    /// # Returns
    /// Approximate completion percentage:
    /// - Start: 0%
    /// - Negotiate: 25%
    /// - WaitClientHello: 30% (HRR scenario)
    /// - WaitFinished: 75%
    /// - Connected: 100%
    pub fn handshake_progress(&self) -> u8 {
        match self.state {
            ServerState::Start => 0,
            ServerState::Negotiate => 25,
            ServerState::WaitClientHello => 30,
            ServerState::WaitFinished => 75,
            ServerState::Connected => 100,
            ServerState::Closing | ServerState::Closed => 100,
            ServerState::Failed => 0,
        }
    }

    /// Get a summary of the current handshake state for debugging/logging.
    ///
    /// Returns a human-readable string describing the handshake state and negotiated parameters.
    ///
    /// # Example
    /// ```rust
    /// use hptls_core::handshake::ServerHandshake;
    /// use hptls_core::cipher::CipherSuite;
    ///
    /// let server = ServerHandshake::new(vec![CipherSuite::Aes128GcmSha256]);
    /// println!("{}", server.handshake_summary());
    /// // Output: "State: Start, Progress: 0%, Cipher: None, KEX: None"
    /// ```
    pub fn handshake_summary(&self) -> String {
        format!(
            "State: {:?}, Progress: {}%, Cipher: {:?}, KEX: {:?}, SNI: {:?}, ALPN: {:?}, HRR: {}",
            self.state,
            self.handshake_progress(),
            self.cipher_suite,
            self.key_exchange_algorithm,
            self.server_name,
            self.negotiated_alpn,
            if self.hello_retry_sent {
                "sent"
            } else {
                "not sent"
            }
        )
    }

    /// Rotate the ticket encryption key.
    ///
    /// Should be called periodically (e.g., every 12-24 hours) to ensure ticket encryption
    /// key security. Old keys are retained temporarily to allow decryption of recently
    /// issued tickets.
    ///
    /// The encryptor automatically checks if rotation is needed (past 75% of key lifetime).
    /// You can call this method proactively or use the automatic check.
    ///
    /// # Example
    /// ```rust,no_run
    /// use hptls_core::handshake::ServerHandshake;
    /// use hptls_core::cipher::CipherSuite;
    ///
    /// let mut server = ServerHandshake::new(vec![CipherSuite::Aes128GcmSha256]);
    ///
    /// // Rotate key manually
    /// server.rotate_ticket_key();
    ///
    /// // Or check and rotate if needed
    /// server.maybe_rotate_ticket_key();
    /// # Ok::<(), hptls_core::Error>(())
    /// ```
    pub fn rotate_ticket_key(&mut self) {
        self.ticket_encryptor.rotate_key();
        tracing::info!("Rotated ticket encryption key");
    }

    /// Check if ticket key rotation is needed and rotate if necessary.
    ///
    /// This checks if the current ticket encryption key has passed 75% of its lifetime.
    /// If so, it automatically rotates to a new key while keeping the old key for
    /// decrypting recently issued tickets.
    pub fn maybe_rotate_ticket_key(&mut self) {
        self.ticket_encryptor.maybe_rotate();
    }
    /// Store a ticket for PSK resumption.
    ///
    /// **DEPRECATED** (Session 42): Tickets are now encrypted and stored in the ticket_encryptor.
    /// This method is kept for backward compatibility with tests but should not be used in new code.
    /// The server now automatically encrypts/decrypts tickets using the TicketEncryptor.
    ///
    /// * `ticket` - Server ticket to store
    #[deprecated(
        since = "0.2.0",
        note = "Tickets are now encrypted automatically - this method is for legacy test compatibility only"
    )]
    pub fn store_ticket(&mut self, ticket: ServerTicket) {
        self.ticket_store.insert(ticket.ticket.clone(), ticket);
    }

    /// Get a stored ticket by its blob.
    ///
    /// **DEPRECATED** (Session 42): Tickets are now encrypted.
    /// This method only works with the legacy ticket_store HashMap, not encrypted tickets.
    ///
    /// Returns None if ticket not found.
    #[deprecated(
        since = "0.2.0",
        note = "Tickets are now encrypted - use encrypted ticket flow instead"
    )]
    pub fn get_ticket(&self, ticket_blob: &[u8]) -> Option<&ServerTicket> {
        self.ticket_store.get(ticket_blob)
    }
    /// Check if server accepted PSK resumption.
    /// Returns true if a PSK was selected during ClientHello processing.
    pub fn is_psk_resumption(&self) -> bool {
        self.selected_psk.is_some()
    }

    /// Get the negotiated ALPN protocol, if any.
    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.negotiated_alpn.as_deref()
    }

    /// Get the client certificate chain received during mTLS, if any.
    pub fn client_cert_chain(&self) -> Option<&[Vec<u8>]> {
        self.client_cert_chain.as_deref()
    }

    /// Check if a HelloRetryRequest has been sent.
    pub fn hello_retry_sent(&self) -> bool {
        self.hello_retry_sent
    }

    /// Enable 0-RTT early data support.
    ///
    /// Must be called before processing the first ClientHello.
    /// Once enabled, the server will accept early data from clients offering PSK resumption.
    ///
    /// # Arguments
    /// * `config` - Early data configuration (max size, anti-replay window, etc.)
    ///
    /// # Security Considerations
    /// - Early data is NOT forward secret
    /// - Early data can be replayed by network attackers
    /// - Applications MUST ensure early data operations are idempotent
    /// - Use strict configuration for production (small max size, short replay window)
    ///
    /// # Example
    /// ```rust,no_run
    /// use hptls_core::handshake::ServerHandshake;
    /// use hptls_core::cipher::CipherSuite;
    /// use hptls_core::early_data::EarlyDataConfig;
    ///
    /// let mut server = ServerHandshake::new(vec![CipherSuite::Aes128GcmSha256]);
    ///
    /// // Enable with strict configuration for production
    /// server.enable_early_data(EarlyDataConfig::strict())?;
    ///
    /// // Or use permissive configuration for testing
    /// // server.enable_early_data(EarlyDataConfig::permissive())?;
    /// # Ok::<(), hptls_core::Error>(())
    /// ```
    pub fn enable_early_data(&mut self, config: crate::early_data::EarlyDataConfig) -> Result<()> {
        if self.state != ServerState::Start {
            return Err(Error::InvalidConfig(
                "Early data must be enabled before handshake starts".into(),
            ));
        }
        self.early_data = Some(EarlyDataContext::new(config));
        Ok(())
    }

    /// Check if early data (0-RTT) is enabled on this server.
    pub fn is_early_data_enabled(&self) -> bool {
        self.early_data.as_ref().map(|ed| ed.is_enabled()).unwrap_or(false)
    }

    /// Check if early data was accepted for the current connection.
    ///
    /// Returns true if the server accepted the client's early data offer.
    /// This can be checked after processing ClientHello.
    pub fn is_early_data_accepted(&self) -> bool {
        self.early_data.as_ref().map(|ed| ed.is_accepted()).unwrap_or(false)
    }

    /// Get early data context (for advanced use cases).
    ///
    /// Provides access to early data state and configuration.
    pub fn early_data_context(&self) -> Option<&EarlyDataContext> {
        self.early_data.as_ref()
    }

    /// Get mutable early data context (for advanced use cases).
    pub fn early_data_context_mut(&mut self) -> Option<&mut EarlyDataContext> {
        self.early_data.as_mut()
    }

    /// Get anti-replay cache statistics.
    ///
    /// Useful for monitoring and debugging 0-RTT replay protection.
    pub fn anti_replay_stats(&self) -> crate::early_data::AntiReplayCacheStats {
        self.anti_replay_cache.stats()
    }

    /// Check if client's key shares are acceptable, or if HelloRetryRequest is needed.
    ///
    /// This can be called before `process_client_hello()` to determine if HRR should be sent.
    ///
    /// # Returns
    /// - `Ok(None)` - Client offered an acceptable key share
    /// - `Ok(Some(group))` - HRR needed, server should request this group
    /// - `Err(_)` - No supported groups at all (fatal error)
    ///
    /// # Example
    /// ```rust
    /// use hptls_core::handshake::ServerHandshake;
    /// use hptls_core::cipher::CipherSuite;
    /// use hptls_core::messages::ClientHello;
    /// use hptls_crypto::KeyExchangeAlgorithm;
    ///
    /// let server = ServerHandshake::new(vec![CipherSuite::Aes128GcmSha256]);
    ///
    /// // Example: client hello with no key shares
    /// let client_hello = ClientHello::new([0u8; 32], vec![]);
    ///
    /// if let Ok(Some(preferred_group)) = server.check_key_share_acceptable(&client_hello) {
    ///     // HRR needed - client should retry with preferred_group
    ///     assert_eq!(preferred_group, KeyExchangeAlgorithm::X25519);
    /// }
    /// ```
    pub fn check_key_share_acceptable(
        &self,
        client_hello: &ClientHello,
    ) -> Result<Option<KeyExchangeAlgorithm>> {
        // Get client's key shares
        let client_key_shares = match client_hello.extensions.get_key_share()? {
            Some(shares) if !shares.is_empty() => shares,
            _ => {
                // No key shares offered - definitely need HRR
                return Ok(Some(self.supported_groups[0]));
            },
        };

        // Check if any server-preferred group is offered by client
        let has_acceptable_share = self
            .supported_groups
            .iter()
            .any(|&server_group| client_key_shares.iter().any(|ks| ks.group == server_group));

        if has_acceptable_share {
            Ok(None) // Acceptable key share found
        } else {
            // No acceptable share, return most preferred group for HRR
            Ok(Some(self.supported_groups[0]))
        }
    }

    /// Process ClientHello and prepare ServerHello response.
    /// This method:
    /// 1. Validates the ClientHello
    /// 2. Selects a cipher suite
    /// 3. Selects a key exchange group
    /// 4. Extracts the client's key share
    /// 5. Generates server's key exchange key pair
    /// 6. Updates the transcript hash
    /// 7. Transitions to Negotiate state
    /// * `provider` - Crypto provider for random generation and key exchange
    /// * `client_hello` - ClientHello message from client
    /// # Returns
    /// Ok(()) on success, transitions to Negotiate state.
    pub fn process_client_hello(
        &mut self,
        provider: &dyn CryptoProvider,
        client_hello: &ClientHello,
    ) -> Result<()> {
        // ClientHello can be received in Start state (initial) or WaitClientHello state (after HRR)
        if self.state != ServerState::Start && self.state != ServerState::WaitClientHello {
            return Err(Error::UnexpectedMessage(format!(
                "ClientHello can only be processed in Start or WaitClientHello state, got {:?}",
                self.state
            )));
        }

        let is_retry = self.state == ServerState::WaitClientHello;

        // Store original ClientHello if this is the first one (for HRR transcript)
        if !is_retry {
            self.original_client_hello = Some(client_hello.encode()?);
        }

        // Validate TLS 1.3 support
        if !client_hello.extensions.contains_supported_versions() {
            return Err(Error::ProtocolError(
                crate::error::ProtocolError::ProtocolVersion,
            ));
        }

        // Extract client random
        self.client_random = Some(client_hello.random);
        // Store session ID for compatibility
        self.session_id = client_hello.legacy_session_id.clone();
        // Extract server name (SNI)
        self.server_name = client_hello.extensions.get_server_name()?;

        // ALPN negotiation (if client offered protocols)
        if let Some(client_alpn) = client_hello.extensions.get_alpn()? {
            // For now, accept the first protocol the client offers
            // In production, server would have a list of supported protocols and select the first match
            if let Some(protocol) = client_alpn.first() {
                self.negotiated_alpn = Some(protocol.clone());
                tracing::debug!("Negotiated ALPN protocol: {}", protocol);
            }
        }

        // Select cipher suite (first match from client's list that we support)
        let selected_cipher = client_hello
            .cipher_suites
            .iter()
            .find(|cs| self.supported_cipher_suites.contains(cs))
            .ok_or_else(|| Error::ProtocolError(crate::error::ProtocolError::HandshakeFailure))?;
        self.cipher_suite = Some(*selected_cipher);
        // Extract client's key share
        let client_key_shares = client_hello
            .extensions
            .get_key_share()?
            .ok_or_else(|| Error::ProtocolError(crate::error::ProtocolError::MissingExtension))?;
        if client_key_shares.is_empty() {
            return Err(Error::ProtocolError(
                crate::error::ProtocolError::IllegalParameter,
            ));
        }

        // Select key exchange group based on server preferences
        // Find first server-preferred group that client offered
        let selected_key_share = self
            .supported_groups
            .iter()
            .find_map(|&server_group| client_key_shares.iter().find(|ks| ks.group == server_group))
            .ok_or_else(|| {
                // No common group found - client should send HRR with preferred group
                tracing::warn!(
                    "No acceptable key share found. Client offered: {:?}, Server supports: {:?}",
                    client_key_shares.iter().map(|ks| ks.group).collect::<Vec<_>>(),
                    self.supported_groups
                );
                Error::ProtocolError(crate::error::ProtocolError::HandshakeFailure)
            })?;

        tracing::debug!(
            "Selected key exchange group: {:?} from client offers: {:?}",
            selected_key_share.group,
            client_key_shares.iter().map(|ks| ks.group).collect::<Vec<_>>()
        );

        self.key_exchange_algorithm = Some(selected_key_share.group);
        self.client_key_exchange = Some(selected_key_share.key_exchange.clone());
        // Generate server's key exchange key pair
        let kex = provider.key_exchange(selected_key_share.group)?;
        let (private_key, public_key) = kex.generate_keypair()?;
        self.key_exchange_private = Some(private_key.as_bytes().to_vec());
        self.key_exchange_public = Some(public_key.as_bytes().to_vec());
        // Generate server random
        provider.random().fill(&mut self.server_random)?;
        // Check for PSK extension and validate if present
        if let Some(psk_ext) = client_hello.extensions.get_pre_shared_key()? {
            self.process_psk_offer(provider, client_hello, &psk_ext, *selected_cipher)?;
        }

        // Check for early_data extension (0-RTT)
        if client_hello.extensions.has_early_data() {
            self.process_early_data_offer(client_hello)?;
        }

        // Initialize transcript hash
        let hash_algorithm = selected_cipher.hash_algorithm();
        let mut transcript = TranscriptHash::new(hash_algorithm);
        // Add ClientHello to transcript
        let encoded = client_hello.encode()?;
        transcript.update(&encoded);

        // Derive early traffic secret if 0-RTT was accepted
        if self.is_early_data_accepted() {
            let transcript_hash = transcript.current_hash(provider)?;
            if let Some(ref mut key_schedule) = self.key_schedule {
                key_schedule.derive_client_early_traffic_secret(provider, &transcript_hash)?;
                tracing::info!("Derived client early traffic secret for 0-RTT");
            }
        }

        self.transcript = Some(transcript);
        self.state = ServerState::Negotiate;
        Ok(())
    }

    /// Process PSK offer from ClientHello.
    /// 1. Extracts PSK identities from the extension
    /// 2. Looks up tickets in the ticket store
    /// 3. Validates PSK binders
    /// 4. Selects a PSK (currently just picks the first valid one)
    /// * `provider` - Crypto provider for binder validation
    /// * `client_hello` - ClientHello message (for binder validation)
    /// * `psk_ext` - PreSharedKey extension from ClientHello
    /// * `cipher_suite` - Selected cipher suite
    /// Ok(()) on success. Sets self.selected_psk and self.selected_psk_index.
    /// Returns Ok(()) even if no valid PSK found (PSK is optional).
    fn process_psk_offer(
        &mut self,
        provider: &dyn CryptoProvider,
        client_hello: &ClientHello,
        psk_ext: &PreSharedKeyExtension,
        cipher_suite: CipherSuite,
    ) -> Result<()> {
        // Verify we have at least one identity and one binder
        if psk_ext.identities.is_empty() || psk_ext.binders.is_empty() {
            // Invalid PSK extension - ignore it (don't fail handshake)
            return Ok(());
        }

        if psk_ext.identities.len() != psk_ext.binders.len() {
            // Mismatched identities/binders - ignore (don't fail handshake)
            return Ok(());
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Try each PSK identity in order
        for (index, (identity, binder)) in
            psk_ext.identities.iter().zip(&psk_ext.binders).enumerate()
        {
            // First, try encrypted ticket flow (new way)
            if let Ok((
                resumption_master_secret,
                ticket_cipher_suite,
                ticket_created_at,
                ticket_nonce,
                ticket_server_name,
            )) = self.ticket_encryptor.decrypt_ticket(provider, &identity.identity)
            {
                // Validate ticket hasn't expired (check age from ticket_created_at)
                let ticket_age = current_time.saturating_sub(ticket_created_at);
                // Default ticket lifetime is 7 days
                if ticket_age > 604800 {
                    tracing::debug!("Ticket expired (age: {} seconds)", ticket_age);
                    continue; // Expired ticket, try next
                }

                // Validate cipher suite matches
                if ticket_cipher_suite != cipher_suite {
                    tracing::debug!(
                        "Ticket cipher suite mismatch: {:?} != {:?}",
                        ticket_cipher_suite,
                        cipher_suite
                    );
                    continue; // Cipher suite mismatch, try next
                }

                // Validate server name matches (if present)
                if let Some(ref ticket_sni) = ticket_server_name {
                    if let Some(ref current_sni) = self.server_name {
                        if ticket_sni != current_sni {
                            tracing::debug!(
                                "Ticket SNI mismatch: {} != {}",
                                ticket_sni,
                                current_sni
                            );
                            continue; // SNI mismatch, try next
                        }
                    }
                }

                // Derive PSK from resumption_master_secret and ticket nonce
                // PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
                let hash_algorithm = cipher_suite.hash_algorithm();
                let hash_len = match hash_algorithm {
                    hptls_crypto::HashAlgorithm::Sha256 => 32,
                    hptls_crypto::HashAlgorithm::Sha384 => 48,
                    _ => continue, // Unsupported hash, try next
                };

                let psk = crate::transcript::hkdf_expand_label(
                    provider,
                    hash_algorithm,
                    &resumption_master_secret,
                    b"resumption",
                    &ticket_nonce,
                    hash_len,
                )?;

                // Validate PSK binder
                // The binder is computed over the ClientHello truncated at the binders
                if !self.validate_psk_binder(provider, client_hello, &psk, binder, cipher_suite)? {
                    tracing::debug!("Invalid PSK binder");
                    continue; // Invalid binder, try next
                }

                // Valid PSK found! Select it.
                self.selected_psk_index = Some(index as u16);
                self.selected_psk = Some(Zeroizing::new(psk));
                tracing::info!(
                    "Server selected PSK index {} (encrypted ticket resumption)",
                    index
                );
                return Ok(());
            }

            // Fallback: try legacy ticket_store (for backward compatibility with tests)
            #[allow(deprecated)]
            if let Some(ticket) = self.ticket_store.get(&identity.identity) {
                // Validate ticket hasn't expired
                if !ticket.is_valid(current_time) {
                    tracing::debug!("Legacy ticket expired");
                    continue;
                }
                // Validate cipher suite matches
                if ticket.cipher_suite != cipher_suite {
                    tracing::debug!("Legacy ticket cipher suite mismatch");
                    continue;
                }

                // Validate PSK binder
                if !self.validate_psk_binder(
                    provider,
                    client_hello,
                    &ticket.psk,
                    binder,
                    cipher_suite,
                )? {
                    tracing::debug!("Legacy ticket invalid binder");
                    continue;
                }

                // Valid legacy PSK found
                self.selected_psk_index = Some(index as u16);
                self.selected_psk = Some(ticket.psk.clone());
                tracing::info!(
                    "Server selected PSK index {} (legacy ticket resumption)",
                    index
                );
                return Ok(());
            }

            tracing::debug!("No ticket found (encrypted or legacy)");
        }

        // No valid PSK found - that's OK, we'll do a full handshake
        Ok(())
    }

    /// Process early data offer from client.
    ///
    /// Determines whether to accept or reject 0-RTT early data based on:
    /// - Whether early data is enabled on the server
    /// - Whether PSK resumption was accepted
    /// - Anti-replay protection (ticket not seen before)
    ///
    /// If accepted, the early_data context transitions to Accepted state.
    /// If rejected or not enabled, the context transitions to Rejected state.
    fn process_early_data_offer(&mut self, client_hello: &ClientHello) -> Result<()> {
        // Early data requires PSK resumption
        if self.selected_psk.is_none() {
            tracing::debug!("Early data offered but no PSK selected - rejecting");
            if let Some(ref mut ed) = self.early_data {
                ed.offer()?;
                ed.reject()?;
            }
            return Ok(());
        }

        // Check if early data is enabled on server
        let early_data_ctx = match self.early_data.as_mut() {
            Some(ctx) if ctx.is_enabled() => ctx,
            Some(ctx) => {
                // Early data disabled on server
                tracing::debug!("Early data offered but server has it disabled - rejecting");
                ctx.offer()?;
                ctx.reject()?;
                return Ok(());
            },
            None => {
                tracing::debug!("Early data offered but server not configured - rejecting");
                return Ok(());
            },
        };

        // Mark as offered
        early_data_ctx.offer()?;

        // Anti-replay check: verify ticket hasn't been used before
        // Extract ticket from PSK identity for replay check
        if let Some(psk_ext) = client_hello.extensions.get_pre_shared_key()? {
            if let Some(selected_index) = self.selected_psk_index {
                if let Some(identity) = psk_ext.identities.get(selected_index as usize) {
                    // Use ticket as replay token (with obfuscated ticket age as timestamp)
                    let ticket = &identity.identity;
                    let timestamp = identity.obfuscated_ticket_age as u64;

                    if !self.anti_replay_cache.check_and_mark(ticket, timestamp) {
                        tracing::warn!(
                            "Early data rejected: replay detected or timestamp out of window"
                        );
                        early_data_ctx.reject()?;
                        return Ok(());
                    }
                }
            }
        }

        // All checks passed - accept early data
        early_data_ctx.accept()?;
        tracing::info!("Early data (0-RTT) accepted");

        Ok(())
    }

    /// Validate PSK binder.
    /// Computes the expected binder and compares it with the client's binder.
    /// * `provider` - Crypto provider
    /// * `client_hello` - ClientHello message
    /// * `psk` - Pre-shared key
    /// * `client_binder` - Binder from client
    /// * `cipher_suite` - Cipher suite
    /// Ok(true) if binder is valid, Ok(false) if invalid.
    fn validate_psk_binder(
        &self,
        provider: &dyn CryptoProvider,
        client_hello: &ClientHello,
        psk: &[u8],
        client_binder: &PskBinder,
        cipher_suite: CipherSuite,
    ) -> Result<bool> {
        // Encode ClientHello and truncate at binders
        let full_encoded = client_hello.encode()?;
        // Calculate where binders start
        // We need the size of the binders in the encoding
        let hash_len = cipher_suite.hash_algorithm().output_size();
        // Get PSK extension to calculate binders size
        let psk_ext = client_hello
            .extensions
            .get_pre_shared_key()?
            .ok_or_else(|| Error::InternalError("PSK extension disappeared".to_string()))?;
        // Calculate total binders size
        let mut binders_size = 2; // binders length field (2 bytes)
        for binder in &psk_ext.binders {
            binders_size += 1 + binder.binder.len(); // length(1) + binder data
        }

        let truncated_len = full_encoded.len() - binders_size;
        let client_hello_partial = &full_encoded[..truncated_len];
        // Verify the binder
        client_binder.verify(provider, psk, cipher_suite, client_hello_partial)
    }

    /// Generate HelloRetryRequest message when client's key shares are not acceptable.
    ///
    /// This should be called instead of `generate_server_hello()` when the server
    /// needs the client to retry the handshake with a different key share group.
    ///
    /// # Arguments
    /// * `selected_group` - The key exchange group the server wants the client to use
    /// * `cookie` - Optional cookie for stateless operation (None for stateful)
    ///
    /// # Returns
    /// HelloRetryRequest message to send to the client
    ///
    /// # RFC 8446 Section 4.1.4
    /// The server sends HelloRetryRequest when it can negotiate an acceptable set of handshake
    /// parameters but the client's ClientHello doesn't contain sufficient information.
    pub fn generate_hello_retry_request(
        &mut self,
        selected_group: KeyExchangeAlgorithm,
        cookie: Option<Vec<u8>>,
    ) -> Result<HelloRetryRequest> {
        if self.state != ServerState::Negotiate {
            return Err(Error::UnexpectedMessage(
                "HelloRetryRequest can only be generated in Negotiate state".to_string(),
            ));
        }

        if self.hello_retry_sent {
            return Err(Error::InternalError(
                "HelloRetryRequest already sent - can only send once per connection".to_string(),
            ));
        }

        let cipher_suite = self
            .cipher_suite
            .ok_or_else(|| Error::InternalError("Cipher suite not selected".to_string()))?;

        // Build extensions
        let mut extensions = Extensions::new();

        // Supported versions (TLS 1.3 only)
        extensions.add_typed(TypedExtension::SupportedVersions(vec![
            ProtocolVersion::Tls13,
        ]))?;

        // Selected group (key_share extension in HRR context)
        extensions.add_typed(TypedExtension::KeyShare(vec![KeyShareEntry {
            group: selected_group,
            key_exchange: vec![], // Empty in HRR - just indicates the group
        }]))?;

        // Cookie extension (optional)
        // Note: Cookie extension support in TypedExtension is pending implementation
        if let Some(_cookie_data) = cookie {
            tracing::warn!("Cookie extension requested but not yet implemented in TypedExtension");
            // Future: extensions.add_typed(TypedExtension::Cookie(cookie_data))?;
        }

        let hrr = HelloRetryRequest::new(cipher_suite, extensions);

        // Store original ClientHello for transcript update
        // (already stored in process_client_hello)

        // Update transcript with HelloRetryRequest
        let encoded = hrr.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        // Mark that we've sent HRR
        self.hello_retry_sent = true;

        // Transition to WaitClientHello state
        self.state = ServerState::WaitClientHello;

        tracing::info!(
            "Generated HelloRetryRequest requesting group {:?}",
            selected_group
        );

        Ok(hrr)
    }

    /// Generate ServerHello message.
    /// Must be called after `process_client_hello()`.
    /// * `provider` - Crypto provider for key derivation
    /// ServerHello message to send to the client.
    pub fn generate_server_hello(&mut self, provider: &dyn CryptoProvider) -> Result<ServerHello> {
        if self.state != ServerState::Negotiate {
            return Err(Error::UnexpectedMessage(
                "ServerHello can only be generated in Negotiate state".to_string(),
            ));
        }

        let cipher_suite = self
            .cipher_suite
            .ok_or_else(|| Error::InternalError("Cipher suite not selected".to_string()))?;

        let key_exchange_algorithm = self.key_exchange_algorithm.ok_or_else(|| {
            Error::InternalError("Key exchange algorithm not selected".to_string())
        })?;

        let public_key = self
            .key_exchange_public
            .as_ref()
            .ok_or_else(|| Error::InternalError("Server public key not generated".to_string()))?;
        // Build extensions
        let mut extensions = Extensions::new();
        // Supported versions (TLS 1.3 only)
        extensions.add_typed(TypedExtension::SupportedVersions(vec![
            ProtocolVersion::Tls13,
        ]))?;
        // Key share
        extensions.add_typed(TypedExtension::KeyShare(vec![KeyShareEntry {
            group: key_exchange_algorithm,
            key_exchange: public_key.clone(),
        }]))?;
        // Pre-Shared Key (if PSK resumption is being used)
        if let Some(selected_index) = self.selected_psk_index {
            let psk_server_ext = PreSharedKeyServerExtension::new(selected_index);
            extensions.add_pre_shared_key_server(psk_server_ext);
        }

        let server_hello = ServerHello {
            legacy_version: ProtocolVersion::Tls12, // Always 0x0303 for TLS 1.3
            random: self.server_random,
            legacy_session_id_echo: self.session_id.clone(),
            cipher_suite,
            legacy_compression_method: 0, // null compression
            extensions,
        };
        // Update transcript with ServerHello
        let encoded = server_hello.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        // Compute shared secret and derive handshake keys
        self.derive_handshake_keys(provider)?;
        Ok(server_hello)
    }
    /// Derive handshake traffic secrets.
    /// Internal method called after ServerHello is generated.
    fn derive_handshake_keys(&mut self, provider: &dyn CryptoProvider) -> Result<()> {
        let cipher_suite = self
            .cipher_suite
            .ok_or_else(|| Error::InternalError("Cipher suite not selected".to_string()))?;

        // Compute shared secret via ECDH
        let shared_secret = self.compute_shared_secret(provider)?;
        // Initialize key schedule
        let mut key_schedule = KeySchedule::new(cipher_suite);
        // Initialize early secret with PSK if present, otherwise with zeros
        if let Some(ref psk) = self.selected_psk {
            key_schedule.init_early_secret(provider, psk)?;
        } else {
            key_schedule.init_early_secret(provider, &[])?;
        }

        key_schedule.derive_handshake_secret(provider, &shared_secret)?;
        // Derive client and server handshake traffic secrets
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".to_string()))?
            .current_hash(provider)?;
        key_schedule.derive_client_handshake_traffic_secret(provider, &transcript_hash)?;
        key_schedule.derive_server_handshake_traffic_secret(provider, &transcript_hash)?;
        self.key_schedule = Some(key_schedule);
        Ok(())
    }
    /// Compute shared secret using ECDH.
    fn compute_shared_secret(&self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        let algorithm = self
            .key_exchange_algorithm
            .ok_or_else(|| Error::InternalError("Key exchange algorithm not set".to_string()))?;

        let private_key_bytes = self
            .key_exchange_private
            .as_ref()
            .ok_or_else(|| Error::InternalError("Server private key not set".to_string()))?;

        let client_public_key = self
            .client_key_exchange
            .as_ref()
            .ok_or_else(|| Error::InternalError("Client public key not set".to_string()))?;
        let kex = provider.key_exchange(algorithm)?;
        let private_key = PrivateKey::from_bytes(private_key_bytes.clone());
        let shared_secret = kex.exchange(&private_key, client_public_key)?;
        Ok(shared_secret.as_bytes().to_vec())
    }
    /// Generate EncryptedExtensions message.
    /// Must be called after `generate_server_hello()`.
    /// * `additional_extensions` - Optional additional extensions to include
    /// EncryptedExtensions message to send to the client.
    pub fn generate_encrypted_extensions(
        &mut self,
        additional_extensions: Option<Extensions>,
    ) -> Result<EncryptedExtensions> {
        if self.state != ServerState::Negotiate {
            return Err(Error::UnexpectedMessage(
                "EncryptedExtensions can only be generated in Negotiate state".to_string(),
            ));
        }

        let mut extensions = additional_extensions.unwrap_or_else(Extensions::new);

        // Add ALPN extension if protocol was negotiated
        if let Some(ref protocol) = self.negotiated_alpn {
            extensions.add_alpn(vec![protocol.clone()])?;
            tracing::debug!("Adding ALPN extension to EncryptedExtensions: {}", protocol);
        }

        // Add early_data extension if 0-RTT was accepted
        if self.is_early_data_accepted() {
            extensions.add_early_data()?;
            tracing::info!("Adding early_data extension to EncryptedExtensions (0-RTT accepted)");
        }

        let encrypted_extensions = EncryptedExtensions { extensions };

        // Update transcript
        let encoded = encrypted_extensions.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        Ok(encrypted_extensions)
    }

    /// Generate CertificateRequest message for client authentication (mTLS).
    /// Must be called after `generate_encrypted_extensions()`.
    /// * `signature_algorithms` - List of signature algorithms the server accepts
    /// CertificateRequest message to send to the client.
    ///
    /// # TLS 1.3 Specification (RFC 8446 Section 4.3.2)
    /// The CertificateRequest message is sent by servers who desire client
    /// authentication. A server which is authenticating with a certificate
    /// MAY optionally request a certificate from the client.
    ///
    /// The message contains:
    /// - `certificate_request_context`: An opaque string which identifies the
    ///   certificate request (usually empty in TLS 1.3)
    /// - Extensions:
    ///   - `signature_algorithms` (REQUIRED): Signature algorithms the server accepts
    ///   - `certificate_authorities` (OPTIONAL): List of acceptable CAs
    ///
    /// # Example
    /// ```ignore
    /// let sig_algs = vec![
    ///     SignatureScheme::EcdsaSecp256r1Sha256,
    ///     SignatureScheme::RsaPssRsaeSha256,
    ///     SignatureScheme::Ed25519,
    /// ];
    /// let cert_req = server.generate_certificate_request(sig_algs)?;
    /// ```
    pub fn generate_certificate_request(
        &mut self,
        signature_algorithms: Vec<SignatureScheme>,
    ) -> Result<CertificateRequest> {
        if self.state != ServerState::Negotiate {
            return Err(Error::UnexpectedMessage(
                "CertificateRequest can only be generated in Negotiate state".to_string(),
            ));
        }

        // Validate that at least one signature algorithm is provided
        if signature_algorithms.is_empty() {
            return Err(Error::InvalidMessage(
                "CertificateRequest must include at least one signature algorithm".into(),
            ));
        }

        // Build extensions with signature_algorithms
        let mut extensions = Extensions::new();
        extensions.add_typed(TypedExtension::SignatureAlgorithms(signature_algorithms))?;

        // Certificate request context is empty for TLS 1.3 client auth
        let certificate_request = CertificateRequest::new(vec![], extensions);

        // Update transcript
        let encoded = certificate_request.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        Ok(certificate_request)
    }

    /// Generate Certificate message.
    /// Must be called after `generate_encrypted_extensions()`.
    /// * `certificate_chain` - Server's certificate chain (leaf first)
    /// Certificate message to send to the client.
    pub fn generate_certificate(&mut self, certificate_chain: Vec<Vec<u8>>) -> Result<Certificate> {
        if self.state != ServerState::Negotiate {
            return Err(Error::UnexpectedMessage(
                "Certificate can only be generated in Negotiate state".to_string(),
            ));
        }
        let certificate = Certificate {
            certificate_request_context: Vec::new(), // Empty for server auth
            certificate_list: certificate_chain
                .into_iter()
                .map(|cert_data| CertificateEntry {
                    cert_data,
                    extensions: Extensions::new(),
                })
                .collect(),
        };
        let encoded = certificate.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }
        Ok(certificate)
    }
    /// Generate CertificateVerify message.
    /// Must be called after `generate_certificate()`.
    /// * `provider` - Crypto provider for signature generation
    /// * `signing_key` - Server's private signing key
    /// CertificateVerify message to send to the client.
    /// # Note
    /// This is currently a stub. Full implementation requires signature generation.
    pub fn generate_certificate_verify(
        &mut self,
        provider: &dyn CryptoProvider,
        _signing_key: &[u8],
    ) -> Result<CertificateVerify> {
        if self.state != ServerState::Negotiate {
            return Err(Error::UnexpectedMessage(
                "CertificateVerify can only be generated in Negotiate state".to_string(),
            ));
        }

        // Get transcript hash up to this point
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".to_string()))?
            .current_hash(provider)?;
        // Build the data to sign per RFC 8446 Section 4.4.3:
        // String that consists of 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
        let mut message_to_sign = Vec::with_capacity(64 + 33 + 1 + transcript_hash.len());
        message_to_sign.extend_from_slice(&[0x20u8; 64]); // 64 spaces
        message_to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        message_to_sign.push(0x00);
        message_to_sign.extend_from_slice(&transcript_hash);
        // Determine signature algorithm from signing key format and length
        // Ed25519: 32 bytes (raw), ECDSA P-256: 32 bytes (raw), ECDSA P-384: 48 bytes (raw)
        // RSA: PKCS#8 DER format (starts with 0x30 0x82)
        let sig_algorithm = match _signing_key.len() {
            32 => {
                // Could be Ed25519 or ECDSA P-256
                // Try Ed25519 first (most common for 32-byte keys in TLS 1.3)
                SignatureAlgorithm::Ed25519
            },
            48 => SignatureAlgorithm::EcdsaSecp384r1Sha384,
            _ => {
                // Check if it's PKCS#8 DER format (RSA key)
                // PKCS#8 starts with SEQUENCE tag (0x30) followed by length
                if _signing_key.len() > 2 && _signing_key[0] == 0x30 {
                    // Use RSA-PSS-SHA256 as default (most common)
                    // The signature implementation will parse the PKCS#8 DER
                    SignatureAlgorithm::RsaPssRsaeSha256
                } else {
                    return Err(Error::InternalError(format!(
                        "Unsupported signing key length: {}",
                        _signing_key.len()
                    )))
                }
            },
        };

        // Generate real signature
        let signature_impl = provider.signature(sig_algorithm)?;
        let signature = signature_impl.sign(_signing_key, &message_to_sign)?;
        let cert_verify = CertificateVerify {
            algorithm: sig_algorithm,
            signature,
        };
        let encoded = cert_verify.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }
        Ok(cert_verify)
    }
    /// Generate server Finished message.
    /// Must be called after `generate_certificate_verify()`.
    /// * `provider` - Crypto provider for HMAC computation
    /// Finished message to send to the client.
    pub fn generate_server_finished(&mut self, provider: &dyn CryptoProvider) -> Result<Finished> {
        if self.state != ServerState::Negotiate {
            return Err(Error::UnexpectedMessage(
                "Finished can only be generated in Negotiate state".to_string(),
            ));
        }

        let cipher_suite = self
            .cipher_suite
            .ok_or_else(|| Error::InternalError("Cipher suite not selected".to_string()))?;

        let hash_algorithm = cipher_suite.hash_algorithm();
        // Get transcript hash
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".to_string()))?
            .current_hash(provider)?;

        // Get server handshake traffic secret
        let key_schedule = self
            .key_schedule
            .as_ref()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".to_string()))?;
        let server_hs_secret =
            key_schedule.get_server_handshake_traffic_secret().ok_or_else(|| {
                Error::InternalError("Server handshake secret not available".to_string())
            })?;
        // Compute verify data
        let verify_data =
            compute_verify_data(provider, hash_algorithm, server_hs_secret, &transcript_hash)?;
        let finished = Finished { verify_data };
        // Update transcript with Finished
        let encoded = finished.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        // Derive master secret and application traffic secrets
        let key_schedule = self
            .key_schedule
            .as_mut()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".to_string()))?;

        key_schedule.derive_master_secret(provider)?;
        // Get updated transcript hash (including server Finished)
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".to_string()))?
            .current_hash(provider)?;

        key_schedule.derive_client_application_traffic_secret(provider, &transcript_hash)?;
        key_schedule.derive_server_application_traffic_secret(provider, &transcript_hash)?;
        // Transition to WaitFinished state
        self.state = ServerState::WaitFinished;
        Ok(finished)
    }
    /// Process client Certificate message (mTLS).
    /// Must be called after sending CertificateRequest.
    /// * `certificate` - Client's Certificate message
    /// Ok(()) on success, updates transcript.
    ///
    /// # TLS 1.3 Specification (RFC 8446 Section 4.4.2)
    /// This message conveys the client's certificate chain to the server.
    /// The client MUST send a Certificate message if the server has sent a
    /// CertificateRequest. If the client does not have a suitable certificate,
    /// it MUST send a Certificate message containing no certificates (i.e.,
    /// with the certificate_list field having length 0).
    ///
    /// # Note
    /// This implementation stores the client certificate for later verification
    /// but does not perform certificate validation (chain validation, revocation
    /// checking, etc.). Production implementations MUST validate the certificate
    /// chain against trusted CAs.
    pub fn process_client_certificate(&mut self, certificate: &Certificate) -> Result<()> {
        if self.state != ServerState::WaitFinished {
            return Err(Error::UnexpectedMessage(
                "Client Certificate can only be processed in WaitFinished state".to_string(),
            ));
        }

        // Update transcript
        let encoded = certificate.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        // Store client certificate for verification (if present)
        // Empty certificate list is valid in TLS 1.3 (client has no cert)
        if !certificate.certificate_list.is_empty() {
            tracing::debug!(
                "Client sent certificate chain with {} certificates",
                certificate.certificate_list.len()
            );
            // Store the certificate chain
            self.client_cert_chain = Some(
                certificate
                    .certificate_list
                    .iter()
                    .map(|entry| entry.cert_data.clone())
                    .collect(),
            );
        } else {
            tracing::debug!("Client sent empty certificate (no client cert available)");
            self.client_cert_chain = None;
        }

        Ok(())
    }

    /// Verify and process client CertificateVerify message (mTLS).
    /// Must be called after `process_client_certificate()`.
    /// * `provider` - Crypto provider for signature verification
    /// * `certificate_verify` - Client's CertificateVerify message
    /// * `client_public_key` - Client's public key from the certificate
    /// Ok(()) on success, updates transcript.
    ///
    /// # TLS 1.3 Specification (RFC 8446 Section 4.4.3)
    /// This message is used to provide explicit proof that the client possesses
    /// the private key corresponding to its certificate.
    ///
    /// The signature is computed over:
    /// - 64 spaces (0x20)
    /// - "TLS 1.3, client CertificateVerify"
    /// - A single 0x00 byte
    /// - The transcript hash up to this point
    ///
    /// # Note
    /// The `client_public_key` parameter must be extracted from the client's
    /// certificate by the caller. This implementation only verifies the signature.
    pub fn verify_client_certificate_signature(
        &mut self,
        provider: &dyn CryptoProvider,
        certificate_verify: &CertificateVerify,
        client_public_key: &[u8],
    ) -> Result<()> {
        if self.state != ServerState::WaitFinished {
            return Err(Error::UnexpectedMessage(
                "Client CertificateVerify can only be processed in WaitFinished state".to_string(),
            ));
        }

        // Get transcript hash up to this point (before CertificateVerify)
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".to_string()))?
            .current_hash(provider)?;

        // Build the signed content per RFC 8446 Section 4.4.3
        let mut content_to_verify = Vec::new();
        content_to_verify.extend_from_slice(&[0x20u8; 64]); // 64 spaces
        content_to_verify.extend_from_slice(b"TLS 1.3, client CertificateVerify");
        content_to_verify.push(0x00);
        content_to_verify.extend_from_slice(&transcript_hash);

        // Verify signature
        let signature_impl = provider.signature(certificate_verify.algorithm)?;
        signature_impl.verify(
            client_public_key,
            &content_to_verify,
            &certificate_verify.signature,
        )?;

        // Update transcript with CertificateVerify
        let encoded = certificate_verify.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        tracing::debug!(
            "Client certificate signature verified successfully with {:?}",
            certificate_verify.algorithm
        );

        Ok(())
    }

    /// Process client Finished message.
    /// Must be called after sending server Finished.
    /// * `provider` - Crypto provider for HMAC verification
    /// * `finished` - Client's Finished message
    /// Ok(()) on success, transitions to Connected state.
    pub fn process_client_finished(
        &mut self,
        provider: &dyn CryptoProvider,
        finished: &Finished,
    ) -> Result<()> {
        if self.state != ServerState::WaitFinished {
            return Err(Error::UnexpectedMessage(
                "Client Finished can only be processed in WaitFinished state".to_string(),
            ));
        }

        let cipher_suite = self
            .cipher_suite
            .ok_or_else(|| Error::InternalError("Cipher suite not selected".to_string()))?;

        let hash_algorithm = cipher_suite.hash_algorithm();

        // Get transcript hash (up to server Finished, not including client Finished)
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".to_string()))?
            .current_hash(provider)?;

        // Get client handshake traffic secret
        let key_schedule = self
            .key_schedule
            .as_ref()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".to_string()))?;

        let client_hs_secret =
            key_schedule.get_client_handshake_traffic_secret().ok_or_else(|| {
                Error::InternalError("Client handshake secret not available".to_string())
            })?;
        // Compute expected verify data
        let expected_verify_data =
            compute_verify_data(provider, hash_algorithm, client_hs_secret, &transcript_hash)?;
        // Verify client's Finished message
        if finished.verify_data != expected_verify_data {
            return Err(Error::DecryptionFailed);
        }

        // Update transcript with client Finished
        let encoded = finished.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        // Transition to Connected state
        self.state = ServerState::Connected;
        Ok(())
    }
    /// Check if the handshake is complete.
    pub fn is_connected(&self) -> bool {
        self.state == ServerState::Connected
    }

    /// Get the server handshake traffic secret.
    /// Available after ServerHello is sent.
    pub fn get_server_handshake_traffic_secret(&self) -> Option<&[u8]> {
        self.key_schedule
            .as_ref()
            .and_then(|ks| ks.get_server_handshake_traffic_secret())
    }

    /// Get the client handshake traffic secret.
    pub fn get_client_handshake_traffic_secret(&self) -> Option<&[u8]> {
        self.key_schedule
            .as_ref()
            .and_then(|ks| ks.get_client_handshake_traffic_secret())
    }

    /// Get the server application traffic secret.
    /// Available after server Finished is sent.
    pub fn get_server_application_traffic_secret(&self) -> Option<&[u8]> {
        self.key_schedule
            .as_ref()
            .and_then(|ks| ks.get_server_application_traffic_secret())
    }

    /// Get the client application traffic secret.
    pub fn get_client_application_traffic_secret(&self) -> Option<&[u8]> {
        self.key_schedule
            .as_ref()
            .and_then(|ks| ks.get_client_application_traffic_secret())
    }
    /// Send a KeyUpdate message.
    /// This initiates a key update by generating a new server application traffic secret
    /// and returning a KeyUpdate message to send to the client.
    /// * `request_update` - Whether to request the peer to also update their keys
    /// Returns the KeyUpdate message to send, and the new server application traffic secret
    /// that should be used to update the record protection layer.
    /// # RFC 8446 Section 4.6.3
    /// The KeyUpdate handshake message is used to indicate that the sender is updating
    /// its sending cryptographic keys. The KeyUpdate message can be sent by either peer
    /// after the connection is established.
    pub fn send_key_update(
        &mut self,
        provider: &dyn CryptoProvider,
        request_update: key_update::KeyUpdateRequest,
    ) -> Result<KeyUpdate> {
        // Must be in connected state
        if !matches!(self.state, ServerState::Connected) {
            return Err(Error::HandshakeFailure(
                "Cannot send KeyUpdate before connection is established".into(),
            ));
        }

        // Update server application traffic secret
        let key_schedule = self
            .key_schedule
            .as_mut()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".into()))?;
        key_schedule.update_server_application_traffic_secret(provider)?;
        Ok(KeyUpdate::new(request_update))
    }
    /// Process a received KeyUpdate message.
    /// This updates the client application traffic secret in response to a KeyUpdate
    /// message received from the client.
    /// * `key_update` - The KeyUpdate message received from the client
    /// Returns the new client application traffic secret and optionally a KeyUpdate message
    /// if the client requested an update (tuple of (new_secret, Option<KeyUpdate>)).
    pub fn process_key_update(
        &mut self,
        provider: &dyn CryptoProvider,
        key_update: &KeyUpdate,
    ) -> Result<(Vec<u8>, Option<KeyUpdate>)> {
        if !matches!(self.state, ServerState::Connected) {
            return Err(Error::HandshakeFailure(
                "Cannot process KeyUpdate before connection is established".into(),
            ));
        }

        // Update client application traffic secret
        let key_schedule = self
            .key_schedule
            .as_mut()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".into()))?;

        key_schedule.update_client_application_traffic_secret(provider)?;
        let new_secret = key_schedule
            .get_client_application_traffic_secret()
            .ok_or_else(|| {
                Error::InternalError("Client application traffic secret not available".into())
            })?
            .to_vec();
        // If client requested update, prepare KeyUpdate response
        let response = if key_update.request_update == key_update::KeyUpdateRequest::UpdateRequested
        {
            // Update our own sending keys too
            key_schedule.update_server_application_traffic_secret(provider)?;
            Some(KeyUpdate::new(
                key_update::KeyUpdateRequest::UpdateNotRequested,
            ))
        } else {
            None
        };

        Ok((new_secret, response))
    }
    /// Generate a NewSessionTicket message for session resumption.
    /// This should be called after the handshake is complete (Connected state).
    /// The ticket contains a PSK derived from the resumption master secret that
    /// allows the client to resume the session later.
    /// * `provider` - Crypto provider for secret derivation
    /// * `ticket_lifetime` - Optional lifetime in seconds (default: 7 days)
    /// Returns a NewSessionTicket message to send to the client.
    /// # Example
    /// ```rust,no_run
    /// use hptls_core::handshake::ServerHandshake;
    /// use hptls_crypto_hpcrypt::HpcryptProvider;
    /// use hptls_crypto::CryptoProvider;
    /// let mut server = ServerHandshake::new(vec![]);
    /// let provider = HpcryptProvider::new();
    /// // ... complete handshake ...
    /// let ticket = server.generate_new_session_ticket(&provider, None)?;
    /// // Send ticket to client
    /// # Ok::<(), hptls_core::Error>(())
    /// ```
    pub fn generate_new_session_ticket(
        &mut self,
        provider: &dyn CryptoProvider,
        ticket_lifetime: Option<u32>,
    ) -> Result<NewSessionTicket> {
        use crate::psk::DEFAULT_TICKET_LIFETIME;
        if self.state != ServerState::Connected {
            return Err(Error::UnexpectedMessage(
                "NewSessionTicket can only be generated after handshake is complete".to_string(),
            ));
        }

        let cipher_suite = self
            .cipher_suite
            .ok_or_else(|| Error::InternalError("Cipher suite not selected".to_string()))?;

        // Get final transcript hash (includes all handshake messages through client Finished)
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".to_string()))?
            .current_hash(provider)?;

        let key_schedule = self
            .key_schedule
            .as_mut()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".to_string()))?;
        // Derive resumption master secret
        let resumption_master_secret =
            key_schedule.derive_resumption_master_secret(provider, &transcript_hash)?;

        // Generate random ticket nonce (32 bytes)
        // The client will use this nonce to derive the PSK from its copy of the resumption_master_secret
        let ticket_nonce = provider.random().generate(32)?;

        // Encrypt ticket with ticket encryptor
        // The ticket contains the resumption_master_secret, cipher_suite, timestamp, ticket_nonce, and SNI
        // This allows the server to decrypt and resume the session later
        let ticket_data = self.ticket_encryptor.encrypt_ticket(
            provider,
            &resumption_master_secret,
            cipher_suite,
            &ticket_nonce,
            self.server_name.as_deref(),
        )?;
        // Generate random ticket_age_add for obfuscation
        let ticket_age_add_bytes = provider.random().generate(4)?;
        let ticket_age_add = u32::from_be_bytes([
            ticket_age_add_bytes[0],
            ticket_age_add_bytes[1],
            ticket_age_add_bytes[2],
            ticket_age_add_bytes[3],
        ]);
        // Use provided lifetime or default
        let lifetime = ticket_lifetime.unwrap_or(DEFAULT_TICKET_LIFETIME);
        Ok(NewSessionTicket {
            ticket_lifetime: lifetime,
            ticket_age_add,
            ticket_nonce,
            ticket: ticket_data,
            extensions: Extensions::new(),
        })
    }

    /// Send a close_notify alert to gracefully close the TLS connection.
    ///
    /// # RFC 8446 Section 6.1
    /// Either party may initiate a close by sending a close_notify alert. Any data
    /// received after a close_notify alert has been received MUST be ignored.
    ///
    /// This method transitions the connection to the Closing state.
    ///
    /// # Returns
    /// An Alert message to be sent to the peer.
    ///
    /// # Example
    /// ```ignore
    /// let close_notify = server.send_close_notify();
    /// // Encode and send the alert to the client
    /// ```
    pub fn send_close_notify(&mut self) -> crate::alert::Alert {
        use crate::alert::Alert;

        tracing::info!("Sending close_notify alert - transitioning to Closing state");
        self.state = ServerState::Closing;
        Alert::close_notify()
    }

    /// Process a received close_notify alert from the peer.
    ///
    /// # RFC 8446 Section 6.1
    /// When the peer sends a close_notify alert, the local side should respond
    /// with its own close_notify and close the connection. Any data received
    /// after close_notify MUST be ignored.
    ///
    /// This method transitions the connection state based on current state:
    /// - If Connected → Closing (peer initiated close)
    /// - If Closing → Closed (completing mutual close)
    ///
    /// # Arguments
    /// * `alert` - The received alert message
    ///
    /// # Returns
    /// Ok(()) if the alert was close_notify, Err otherwise
    ///
    /// # Example
    /// ```ignore
    /// let alert = Alert::decode(&alert_bytes)?;
    /// server.process_close_notify(&alert)?;
    /// // Send our own close_notify if not already sent
    /// ```
    pub fn process_close_notify(&mut self, alert: &crate::alert::Alert) -> Result<()> {
        use crate::error::AlertDescription;

        if alert.description != AlertDescription::CloseNotify {
            return Err(Error::ProtocolError(
                crate::error::ProtocolError::UnexpectedMessage,
            ));
        }

        match self.state {
            ServerState::Connected => {
                tracing::info!("Received close_notify alert - transitioning to Closing state");
                self.state = ServerState::Closing;
            },
            ServerState::Closing => {
                tracing::info!("Received close_notify alert - completing mutual close, transitioning to Closed");
                self.state = ServerState::Closed;
            },
            _ => {
                tracing::warn!("Received close_notify in state {:?}", self.state);
            },
        }

        Ok(())
    }

    /// Process a received alert and determine if the connection should close.
    ///
    /// # RFC 8446 Section 6
    /// Fatal alerts always terminate the connection immediately. Close_notify
    /// is a warning alert that initiates graceful connection shutdown.
    ///
    /// # Arguments
    /// * `alert` - The received alert message
    ///
    /// # Returns
    /// Ok(true) if the connection should close, Ok(false) to continue
    ///
    /// # Errors
    /// Returns Error::AlertReceived for fatal alerts
    pub fn process_alert(&self, alert: &crate::alert::Alert) -> Result<bool> {
        use crate::error::AlertDescription;

        match alert.description {
            AlertDescription::CloseNotify => {
                tracing::info!("Received close_notify - connection closing gracefully");
                Ok(true)
            },
            _ if alert.is_fatal() => {
                tracing::error!("Received fatal alert: {:?}", alert.description);
                Err(Error::AlertReceived(alert.description))
            },
            _ => {
                tracing::warn!("Received warning alert: {:?}", alert.description);
                Ok(false)
            },
        }
    }

    /// Check if the connection is in the closing state.
    ///
    /// # Returns
    /// true if close_notify has been sent or received
    pub fn is_closing(&self) -> bool {
        matches!(self.state, ServerState::Closing)
    }

    /// Check if the connection is closed.
    ///
    /// # Returns
    /// true if the connection is fully closed (mutual close_notify exchange complete)
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ServerState::Closed)
    }

    /// Complete the connection close after sending response close_notify.
    ///
    /// Should be called after:
    /// 1. Receiving close_notify from peer (state → Closing)
    /// 2. Sending our own close_notify in response
    ///
    /// This transitions the state to Closed.
    pub fn complete_close(&mut self) {
        if self.state == ServerState::Closing {
            tracing::info!("Completing connection close - transitioning to Closed state");
            self.state = ServerState::Closed;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hptls_crypto_hpcrypt::HpcryptProvider;
    #[test]
    fn test_server_handshake_initial_state() {
        let cipher_suites = vec![CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384];
        let handshake = ServerHandshake::new(cipher_suites);
        assert_eq!(handshake.state(), ServerState::Start);
        assert!(handshake.cipher_suite().is_none());
        assert!(!handshake.is_connected());
    }

    #[test]
    fn test_server_process_client_hello() {
        let provider = HpcryptProvider::new();
        let cipher_suites = vec![CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384];
        let mut server = ServerHandshake::new(cipher_suites.clone());
        // Create a ClientHello
        let mut client = crate::handshake::client::ClientHandshake::new();
        let client_hello = client
            .client_hello(&provider, &cipher_suites, Some("example.com"), None)
            .unwrap();
        // Process ClientHello
        let result = server.process_client_hello(&provider, &client_hello);
        assert!(result.is_ok());
        assert_eq!(server.state(), ServerState::Negotiate);
        assert!(server.cipher_suite().is_some());
        assert_eq!(server.server_name, Some("example.com".to_string()));
    }

    #[test]
    fn test_server_generate_server_hello() {
        let provider = HpcryptProvider::new();
        let cipher_suites = vec![CipherSuite::Aes128GcmSha256];
        let mut server = ServerHandshake::new(cipher_suites.clone());
        // Create and process ClientHello
        let mut client = crate::handshake::client::ClientHandshake::new();
        let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();
        server.process_client_hello(&provider, &client_hello).unwrap();
        // Generate ServerHello
        let server_hello = server.generate_server_hello(&provider).unwrap();
        assert_eq!(server_hello.legacy_version, ProtocolVersion::Tls12);
        assert_eq!(server_hello.cipher_suite, CipherSuite::Aes128GcmSha256);
        assert!(server_hello.extensions.contains_supported_versions());
        assert!(server_hello.extensions.get_key_share().unwrap().is_some());
    }
}
