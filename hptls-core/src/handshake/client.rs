//! TLS 1.3 Client Handshake State Machine.
//!
//! Implements the client-side handshake flow per RFC 8446.
//! ## State Transitions
//! ```text
//! START
//!   |
//!   | send ClientHello
//!   v
//! WAIT_SERVER_HELLO
//!   | recv ServerHello
//! WAIT_ENCRYPTED_EXTENSIONS
//!   | recv EncryptedExtensions
//! WAIT_CERT_CR (if server auth required)
//!   | recv Certificate (optional)
//!   | recv CertificateRequest (optional)
//! WAIT_CERT (if server auth required)
//!   | recv CertificateVerify
//! WAIT_FINISHED
//!   | recv Finished
//!   | send Certificate (if requested)
//!   | send CertificateVerify (if requested)
//!   | send Finished
//! CONNECTED
//! ```

use crate::cipher::CipherSuite;
use crate::early_data::EarlyDataContext;
use crate::error::{Error, Result};
use crate::extension_types::{KeyShareEntry, SignatureScheme, TypedExtension};
use crate::extensions::Extensions;
use crate::key_schedule::KeySchedule;
use crate::messages::*;
use crate::protocol::ProtocolVersion;
use crate::psk::{
    PreSharedKeyExtension, PskBinder, PskIdentity, PskKeyExchangeMode, PskKeyExchangeModesExtension,
};
use crate::transcript::{compute_verify_data, TranscriptHash};
use hptls_crypto::{CryptoProvider, HashAlgorithm, KeyExchange, KeyExchangeAlgorithm};
use zeroize::Zeroizing;
/// Stored session ticket for resumption.
///
/// Contains all information needed to resume a TLS session using PSK.
#[derive(Debug, Clone)]
pub struct StoredTicket {
    /// The opaque ticket blob from the server
    pub ticket: Vec<u8>,
    /// The derived PSK for this ticket
    pub psk: Zeroizing<Vec<u8>>,
    /// Cipher suite this ticket is valid for
    pub cipher_suite: CipherSuite,
    /// Obfuscation value for ticket age
    pub ticket_age_add: u32,
    /// When this ticket was received (seconds since UNIX epoch)
    pub received_at: u64,
    /// Ticket lifetime in seconds
    pub lifetime: u32,
}
impl StoredTicket {
    /// Check if this ticket is still valid (not expired).
    pub fn is_valid(&self, current_time: u64) -> bool {
        let age = current_time.saturating_sub(self.received_at);
        age < self.lifetime as u64
    }
    /// Get the obfuscated ticket age for use in PSK extension.
    pub fn obfuscated_age(&self, current_time: u64) -> u32 {
        let age = current_time.saturating_sub(self.received_at) as u32;
        age.wrapping_add(self.ticket_age_add)
    }
}

/// Client handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Initial state, ready to send ClientHello
    Start,
    /// Waiting for ServerHello
    WaitServerHello,
    /// HelloRetryRequest received, need to send updated ClientHello
    HelloRetryReceived,
    /// Waiting for EncryptedExtensions
    WaitEncryptedExtensions,
    /// Waiting for Certificate or CertificateRequest
    WaitCertCr,
    /// Waiting for CertificateVerify
    WaitCertVerify,
    /// Waiting for server Finished
    WaitFinished,
    /// Handshake complete, connection established
    Connected,
    /// Connection is closing (close_notify sent or received)
    Closing,
    /// Connection is closed
    Closed,
    /// Error state
    Failed,
}

/// Client handshake context.
/// Manages the client-side TLS 1.3 handshake process.
pub struct ClientHandshake {
    /// Current state
    state: ClientState,
    /// Cipher suite to use
    cipher_suite: Option<CipherSuite>,
    /// Key schedule
    key_schedule: Option<KeySchedule>,
    /// Transcript hash
    transcript: Option<TranscriptHash>,
    /// Client random (32 bytes)
    client_random: [u8; 32],
    /// Server random (32 bytes)
    server_random: Option<[u8; 32]>,
    /// Selected key exchange algorithm
    key_exchange_algorithm: Option<KeyExchangeAlgorithm>,
    /// Client's key exchange private key
    key_exchange_private: Option<Vec<u8>>,
    /// Client's key exchange public key
    key_exchange_public: Option<Vec<u8>>,
    /// Server's key exchange public key
    server_key_exchange: Option<Vec<u8>>,
    /// Whether server requested client certificate
    cert_requested: bool,
    /// Session ID (for compatibility)
    session_id: Vec<u8>,
    /// Server certificate chain (received during handshake)
    server_cert_chain: Option<Vec<Vec<u8>>>,
    /// Expected server hostname (for SNI and certificate validation)
    server_hostname: Option<String>,
    /// Negotiated ALPN protocol
    negotiated_alpn: Option<String>,
    /// Whether we've received a HelloRetryRequest (can only receive once)
    hello_retry_received: bool,
    /// Original ClientHello for HelloRetryRequest transcript update
    original_client_hello: Option<Vec<u8>>,
    /// Early data (0-RTT) context
    early_data: Option<EarlyDataContext>,
    /// Stored session tickets for resumption
    stored_tickets: Vec<StoredTicket>,
    /// Offered PSK (when using client_hello_with_psk)
    /// Stored so we can use it if server accepts PSK
    offered_psk: Option<Zeroizing<Vec<u8>>>,
    /// Client key shares (algorithm -> (private_key, public_key))
    client_shares: std::collections::HashMap<KeyExchangeAlgorithm, (Vec<u8>, Vec<u8>)>,
    /// Selected algorithm after HRR
    selected_algorithm: Option<KeyExchangeAlgorithm>,
    /// Cookie from HelloRetryRequest
    hrr_cookie: Option<Vec<u8>>,
    /// ECH configuration (if ECH should be used)
    ech_config: Option<crate::ech::EchConfig>,
    /// ECH retry configurations (received from server if ECH failed)
    ech_retry_configs: Option<Vec<crate::ech::EchConfig>>,
}

impl ClientHandshake {
    /// Create a new client handshake.
    pub fn new() -> Self {
        Self {
            state: ClientState::Start,
            cipher_suite: None,
            key_schedule: None,
            transcript: None,
            client_random: [0u8; 32],
            server_random: None,
            key_exchange_algorithm: None,
            key_exchange_private: None,
            key_exchange_public: None,
            server_key_exchange: None,
            cert_requested: false,
            session_id: Vec::new(),
            server_cert_chain: None,
            server_hostname: None,
            negotiated_alpn: None,
            hello_retry_received: false,
            original_client_hello: None,
            early_data: None,
            stored_tickets: Vec::new(),
            offered_psk: None,
            client_shares: std::collections::HashMap::new(),
            selected_algorithm: None,
            hrr_cookie: None,
            ech_config: None,
            ech_retry_configs: None,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Check if handshake is complete.
    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected
    }

    /// Get the negotiated cipher suite.
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.cipher_suite
    }

    /// Get the negotiated ALPN protocol.
    ///
    /// Available after EncryptedExtensions is processed (server selected protocol).
    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.negotiated_alpn.as_deref()
    }

    /// Get the client handshake traffic secret.
    /// Available after ServerHello is processed.
    pub fn get_client_handshake_traffic_secret(&self) -> Option<&[u8]> {
        self.key_schedule
            .as_ref()
            .and_then(|ks| ks.get_client_handshake_traffic_secret())
    }

    /// Get the server handshake traffic secret.
    pub fn get_server_handshake_traffic_secret(&self) -> Option<&[u8]> {
        self.key_schedule
            .as_ref()
            .and_then(|ks| ks.get_server_handshake_traffic_secret())
    }

    /// Get the client application traffic secret.
    /// Available after server Finished is processed.
    pub fn get_client_application_traffic_secret(&self) -> Option<&[u8]> {
        self.key_schedule
            .as_ref()
            .and_then(|ks| ks.get_client_application_traffic_secret())
    }

    /// Get the server application traffic secret.
    pub fn get_server_application_traffic_secret(&self) -> Option<&[u8]> {
        self.key_schedule
            .as_ref()
            .and_then(|ks| ks.get_server_application_traffic_secret())
    }

    /// Get mutable reference to the key schedule.
    ///
    /// Used for post-handshake operations like KeyUpdate that need to derive
    /// new application traffic secrets.
    ///
    /// # Returns
    /// `Some(&mut KeySchedule)` if handshake has progressed past ServerHello, `None` otherwise.
    pub fn key_schedule_mut(&mut self) -> Option<&mut KeySchedule> {
        self.key_schedule.as_mut()
    }

    /// Set the ECH configuration for this handshake.
    ///
    /// Must be called before `client_hello()` to enable ECH encryption.
    ///
    /// # Arguments
    ///
    /// * `config` - The ECH configuration (typically obtained from DNS HTTPS records)
    pub fn set_ech_config(&mut self, config: crate::ech::EchConfig) {
        self.ech_config = Some(config);
    }

    /// Get ECH retry configurations if the server provided them.
    ///
    /// After a failed ECH attempt, the server may provide retry configurations
    /// that the client should use for a new connection attempt.
    pub fn get_ech_retry_configs(&self) -> Option<&[crate::ech::EchConfig]> {
        self.ech_retry_configs.as_deref()
    }

    /// Manually update the transcript hash with raw handshake message bytes.
    /// This is useful for interoperability testing where you need precise control
    /// over the transcript to match wire-format bytes from a real TLS server.
    /// # Arguments
    /// * `handshake_msg_bytes` - Complete handshake message including type and length
    /// # Important
    /// The bytes must be a complete handshake message in the format:
    /// - 1 byte: HandshakeType
    /// - 3 bytes: length (24-bit big-endian)
    /// - N bytes: message payload
    /// After calling this, you should call the corresponding process_* method
    /// with `skip_transcript_update` parameter (if available) to avoid double-updating.
    pub fn update_transcript(&mut self, handshake_msg_bytes: &[u8]) -> Result<()> {
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(handshake_msg_bytes);
            Ok(())
        } else {
            Err(Error::InternalError(
                "Transcript not initialized".to_string(),
            ))
        }
    }

    /// Get the current transcript hash.
    /// This is useful for debugging and testing signature verification.
    pub fn get_transcript_hash(&mut self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        if let Some(ref mut transcript) = self.transcript {
            transcript.current_hash(provider)
        } else {
            Err(Error::InternalError(
                "Transcript not initialized".to_string(),
            ))
        }
    }

    /// Replace the entire transcript with raw handshake message bytes.
    /// This clears the existing transcript and initializes it with the provided messages.
    /// Useful for interoperability testing where you need to reconstruct the transcript
    /// from actual wire-format bytes.
    /// * `hash_algorithm` - Hash algorithm for the transcript
    /// * `messages` - Vector of complete handshake messages (each with type + length + payload)
    /// # Example
    /// ```ignore
    /// // Reconstruct transcript from actual ClientHello and ServerHello bytes
    /// handshake.replace_transcript(
    ///     HashAlgorithm::Sha256,
    ///     vec![client_hello_handshake_bytes, server_hello_handshake_bytes],
    /// )?;
    /// ```
    pub fn replace_transcript(
        &mut self,
        hash_algorithm: HashAlgorithm,
        messages: Vec<Vec<u8>>,
    ) -> Result<()> {
        let mut transcript = TranscriptHash::new(hash_algorithm);
        for msg in messages {
            transcript.update(&msg);
        }
        self.transcript = Some(transcript);
        Ok(())
    }

    /// Re-derive handshake traffic secrets with current transcript.
    /// This is useful after manually correcting the transcript (e.g., for interop testing).
    /// It re-computes the handshake traffic secrets using the current transcript hash.
    /// # Requirements
    /// - Must be called after `process_server_hello()` (so server key share is available)
    /// - Transcript must be initialized
    /// - Key schedule must be initialized
    /// * `provider` - Crypto provider for key derivation
    pub fn rederive_handshake_secrets(&mut self, provider: &dyn CryptoProvider) -> Result<()> {
        // Get current transcript hash
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".to_string()))?
            .current_hash(provider)?;
        // Re-derive handshake traffic secrets
        let key_schedule = self
            .key_schedule
            .as_mut()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".to_string()))?;
        key_schedule.derive_client_handshake_traffic_secret(provider, &transcript_hash)?;
        key_schedule.derive_server_handshake_traffic_secret(provider, &transcript_hash)?;

        Ok(())
    }

    /// Get the ECDH shared secret for debugging.
    /// This is only available after process_server_hello() has been called.
    /// * `provider` - Crypto provider for key exchange
    pub fn debug_get_shared_secret(&self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        self.compute_shared_secret(provider)
    }

    /// Get the stored client public key (the one we sent in ClientHello).
    /// This can be used to verify key exchange consistency.
    pub fn debug_get_client_public_key(&self) -> Result<Vec<u8>> {
        self.key_exchange_public
            .clone()
            .ok_or_else(|| Error::InternalError("Client public key not available".to_string()))
    }

    /// Generate and return ClientHello message.
    /// * `provider` - Crypto provider for random generation and key exchange
    /// * `cipher_suites` - List of supported cipher suites (in preference order)
    /// * `server_name` - Optional server name for SNI extension
    /// * `alpn_protocols` - Optional list of ALPN protocols (e.g., ["h2", "http/1.1"])
    /// * `override_legacy_version` - Optional override for legacy_version field (e.g., for DTLS)
    pub fn client_hello(
        &mut self,
        provider: &dyn CryptoProvider,
        cipher_suites: &[CipherSuite],
        server_name: Option<&str>,
        alpn_protocols: Option<&[&str]>,
        override_legacy_version: Option<ProtocolVersion>,
    ) -> Result<ClientHello> {
        if self.state != ClientState::Start {
            return Err(Error::UnexpectedMessage(
                "ClientHello can only be sent in Start state".to_string(),
            ));
        }

        if cipher_suites.is_empty() {
            return Err(Error::InvalidConfig(
                "At least one cipher suite must be provided".to_string(),
            ));
        }

        // Generate client random
        provider.random().fill(&mut self.client_random)?;
        // Generate session ID for compatibility (legacy_session_id)
        self.session_id = provider.random().generate(32)?;
        // Generate key exchange key pair (X25519 for now)
        let key_exchange_algorithm = KeyExchangeAlgorithm::X25519;
        let kex = provider.key_exchange(key_exchange_algorithm)?;
        let (private_key, public_key) = kex.generate_keypair()?;
        self.key_exchange_algorithm = Some(key_exchange_algorithm);
        self.key_exchange_private = Some(private_key.as_bytes().to_vec());
        self.key_exchange_public = Some(public_key.as_bytes().to_vec());
        // Build extensions
        let mut extensions = Extensions::new();
        // Supported versions (TLS 1.3 only)
        extensions.add_typed(TypedExtension::SupportedVersions(vec![
            ProtocolVersion::Tls13,
        ]))?;
        // Key share
        extensions.add_typed(TypedExtension::KeyShare(vec![KeyShareEntry {
            group: key_exchange_algorithm,
            key_exchange: public_key.as_bytes().to_vec(),
        }]))?;
        // Supported groups
        extensions.add_typed(TypedExtension::SupportedGroups(vec![
            KeyExchangeAlgorithm::X25519,
            KeyExchangeAlgorithm::Secp256r1,
        ]))?;

        // Signature algorithms
        extensions.add_typed(TypedExtension::SignatureAlgorithms(vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::Ed25519,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
        ]))?;

        // Server name (SNI)
        if let Some(name) = server_name {
            extensions.add_typed(TypedExtension::ServerName(name.to_string()))?;
        }

        // ALPN (Application-Layer Protocol Negotiation)
        if let Some(protocols) = alpn_protocols {
            let alpn_vec: Vec<String> = protocols.iter().map(|s| s.to_string()).collect();
            extensions.add_typed(TypedExtension::Alpn(alpn_vec))?;
        }

        // Early data (0-RTT) - add extension if enabled
        if self.is_early_data_enabled() {
            extensions.add_early_data()?;
            // Mark early data as offered
            if let Some(ref mut early_data) = self.early_data {
                early_data.offer()?;
            }
        }

        // Build ClientHello
        let mut client_hello = ClientHello {
            legacy_version: override_legacy_version.unwrap_or(ProtocolVersion::Tls12), // TLS 1.2 for TLS 1.3, or DTLS 1.2 for DTLS
            random: self.client_random,
            legacy_session_id: self.session_id.clone(),
            cipher_suites: cipher_suites.to_vec(),
            legacy_compression_methods: vec![0], // null compression
            extensions,
        };

        // Apply ECH encryption if configured
        if let Some(ref ech_config) = self.ech_config {
            // Determine real and public server names
            let real_sni = server_name.ok_or_else(|| {
                Error::InvalidConfig("ECH requires a server name (SNI)".to_string())
            })?;
            let public_name = &ech_config.public_name;

            // Split ClientHello into Inner (real SNI) and Outer (public name)
            let split = crate::ech::ClientHelloSplit::create_for_ech(
                real_sni,
                public_name,
                &client_hello,
            )?;

            // Encrypt ClientHelloInner
            let client_hello_inner_bytes = split.inner.encode()?;
            let cipher_suite = ech_config.cipher_suites.first().ok_or_else(|| {
                Error::InvalidConfig("ECH config has no cipher suites".to_string())
            })?;

            let (enc, ciphertext) = crate::ech::encrypt_client_hello_inner(
                ech_config,
                cipher_suite,
                &client_hello_inner_bytes,
                provider,
            )?;

            // Use the Outer ClientHello and add ECH extension
            client_hello = split.outer;
            client_hello.extensions.add_ech(
                *cipher_suite,
                ech_config.config_id,
                enc,
                ciphertext,
            )?;
        }

        // Initialize transcript hash with first cipher suite's hash algorithm
        let hash_algorithm = cipher_suites[0].hash_algorithm();
        let mut transcript = TranscriptHash::new(hash_algorithm);

        // Add ClientHello to transcript
        let encoded = client_hello.encode()?;
        transcript.update(&encoded);

        self.transcript = Some(transcript);
        self.server_hostname = server_name.map(|s| s.to_string());
        self.state = ClientState::WaitServerHello;

        Ok(client_hello)
    }
    /// Generate ClientHello with PSK extension for session resumption.
    /// This method generates a ClientHello that includes a Pre-Shared Key extension,
    /// allowing the client to offer a previously received session ticket for resumption.
    /// * `provider` - Crypto provider
    /// * `cipher_suites` - List of cipher suites (ticket's cipher suite should be first)
    /// * `server_name` - Server name (SNI)
    /// * `alpn_protocols` - ALPN protocols
    /// * `ticket` - Stored ticket to offer
    /// * `override_legacy_version` - Optional override for legacy_version field (e.g., for DTLS)
    /// # Returns
    /// ClientHello message with PSK extension
    /// Per RFC 8446, the PreSharedKey extension MUST be the last extension in ClientHello.
    /// This method ensures proper ordering and computes the PSK binder correctly.
    pub fn client_hello_with_psk(
        &mut self,
        provider: &dyn CryptoProvider,
        cipher_suites: &[CipherSuite],
        server_name: Option<&str>,
        alpn_protocols: Option<&[&str]>,
        ticket: &StoredTicket,
        override_legacy_version: Option<ProtocolVersion>,
    ) -> Result<ClientHello> {
        // Verify ticket is still valid
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if !ticket.is_valid(current_time) {
            return Err(Error::InvalidConfig("Ticket has expired".to_string()));
        }

        // First generate a regular ClientHello (without PSK)
        let mut client_hello =
            self.client_hello(provider, cipher_suites, server_name, alpn_protocols, override_legacy_version)?;

        // Build extensions (WITHOUT PSK extension first)
        // PSK Key Exchange Modes (MUST be present when offering PSK)
        let psk_modes = PskKeyExchangeModesExtension::new(vec![
            PskKeyExchangeMode::PskDheKe, // PSK with (EC)DHE key exchange
        ])?;
        client_hello.extensions.add_psk_key_exchange_modes(psk_modes);

        // Build PSK identity from ticket
        let psk_identity = PskIdentity {
            identity: ticket.ticket.clone(),
            obfuscated_ticket_age: ticket.obfuscated_age(current_time),
        };

        // Create a placeholder PSK extension (binder will be computed later)
        // We need a placeholder binder to calculate the correct size
        let hash_len = ticket.cipher_suite.hash_algorithm().output_size();
        let placeholder_binder = PskBinder {
            binder: vec![0; hash_len],
        };
        let psk_ext =
            PreSharedKeyExtension::new(vec![psk_identity.clone()], vec![placeholder_binder])?;
        // Add PSK extension (this MUST be last per RFC 8446)
        client_hello.extensions.add_pre_shared_key(psk_ext.clone());
        // Encode ClientHello and truncate at binders for PSK binder computation
        let full_encoded = client_hello.encode()?;
        // Calculate where binders start in the encoding
        // We need to truncate the ClientHello encoding just before the binders
        let binders_size = hash_len + 1 + 2; // binder_len(1) + binder(hash_len) + binders_length(2)
        let truncated_len = full_encoded.len() - binders_size;
        let client_hello_partial = &full_encoded[..truncated_len];
        // Get PSK from ticket (already derived during ticket processing)
        let psk = &ticket.psk;
        // Store PSK for use in key derivation if server accepts it
        self.offered_psk = Some(psk.clone());
        // Compute actual PSK binder
        let binder = PskBinder::compute(provider, &psk, ticket.cipher_suite, client_hello_partial)?;

        // Rebuild PSK extension with correct binder
        let psk_ext = PreSharedKeyExtension::new(vec![psk_identity], vec![binder])?;

        // Replace the PSK extension in ClientHello with the one with correct binder
        // We need to replace just the PSK extension, keeping all other extensions
        client_hello.extensions.remove_pre_shared_key();
        client_hello.extensions.add_pre_shared_key(psk_ext);

        // Re-encode the ClientHello with correct binder and update transcript
        let final_encoded = client_hello.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            // Clear and re-initialize transcript with corrected ClientHello
            let hash_algorithm = ticket.cipher_suite.hash_algorithm();
            *transcript = TranscriptHash::new(hash_algorithm);
            transcript.update(&final_encoded);
        }

        Ok(client_hello)
    }
    /// Process ServerHello message.
    /// * `server_hello` - ServerHello message from server
    pub fn process_server_hello(
        &mut self,
        provider: &dyn CryptoProvider,
        server_hello: &ServerHello,
    ) -> Result<()> {
        if self.state != ClientState::WaitServerHello {
            return Err(Error::UnexpectedMessage(format!(
                "ServerHello received in unexpected state: {:?}",
                self.state
            )));
        }

        // Check for HelloRetryRequest
        if server_hello.is_hello_retry_request() {
            return self.process_hello_retry_request(provider, server_hello);
        }

        // Validate protocol version
        if !server_hello.extensions.contains_supported_versions() {
            return Err(Error::ProtocolError(
                crate::error::ProtocolError::MissingExtension,
            ));
        }

        // Store server random
        self.server_random = Some(server_hello.random);
        // Validate selected cipher suite
        self.cipher_suite = Some(server_hello.cipher_suite);
        // Extract server key share
        if let Some(key_shares) = server_hello.extensions.get_key_share()? {
            if key_shares.len() != 1 {
                return Err(Error::ProtocolError(
                    crate::error::ProtocolError::IllegalParameter,
                ));
            }
            let entry = &key_shares[0];
            if Some(entry.group) != self.key_exchange_algorithm {
                return Err(Error::ProtocolError(
                    crate::error::ProtocolError::IllegalParameter,
                ));
            }
            self.server_key_exchange = Some(entry.key_exchange.clone());
        } else {
            return Err(Error::ProtocolError(
                crate::error::ProtocolError::MissingExtension,
            ));
        }

        // Add ServerHello to transcript
        let encoded = server_hello.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        // Compute shared secret
        let shared_secret = self.compute_shared_secret(provider)?;
        // Initialize key schedule
        let mut key_schedule = KeySchedule::new(server_hello.cipher_suite);
        // Check if server accepted PSK resumption
        let psk_accepted = server_hello.extensions.get_pre_shared_key_server()?.is_some();
        if psk_accepted {
            // Server accepted PSK - use offered PSK for key derivation
            if let Some(ref psk) = self.offered_psk {
                key_schedule.init_early_secret(provider, psk)?;
            } else {
                // Server accepted PSK but we don't have one - protocol error
                return Err(Error::ProtocolError(
                    crate::error::ProtocolError::IllegalParameter,
                ));
            }
        } else {
            // Normal handshake without PSK
            key_schedule.init_early_secret(provider, &[])?;
        }
        key_schedule.derive_handshake_secret(provider, &shared_secret)?;
        // Derive handshake traffic secrets
        let transcript_hash = self.transcript.as_mut().unwrap().current_hash(provider)?;
        let _client_hs_secret =
            key_schedule.derive_client_handshake_traffic_secret(provider, &transcript_hash)?;
        let _server_hs_secret =
            key_schedule.derive_server_handshake_traffic_secret(provider, &transcript_hash)?;
        self.key_schedule = Some(key_schedule);
        self.state = ClientState::WaitEncryptedExtensions;

        Ok(())
    }

    /// Process EncryptedExtensions message.
    pub fn process_encrypted_extensions(
        &mut self,
        encrypted_extensions: &EncryptedExtensions,
    ) -> Result<()> {
        if self.state != ClientState::WaitEncryptedExtensions {
            return Err(Error::UnexpectedMessage(format!(
                "EncryptedExtensions received in unexpected state: {:?}",
                self.state
            )));
        }

        // Add to transcript
        let encoded = encrypted_extensions.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        // Process extensions (ALPN, etc.)
        // Extract and store negotiated ALPN protocol
        if let Some(alpn_protocols) = encrypted_extensions.extensions.get_alpn()? {
            // Server must select exactly one protocol from client's list
            if alpn_protocols.len() == 1 {
                self.negotiated_alpn = Some(alpn_protocols[0].clone());
            } else if alpn_protocols.len() > 1 {
                return Err(Error::ProtocolError(
                    crate::error::ProtocolError::IllegalParameter,
                ));
            }
            // If empty, no ALPN negotiation occurred (optional extension)
        }

        // Handle early_data extension (0-RTT)
        if encrypted_extensions.extensions.has_early_data() {
            // Server accepted early data
            if let Some(ref mut early_data) = self.early_data {
                early_data.accept()?;
            }
        } else if let Some(ref mut early_data) = self.early_data {
            // Early data extension not present means server rejected it
            if matches!(early_data.state, crate::early_data::EarlyDataState::Offered) {
                early_data.reject()?;
            }
        }

        // Handle ECH retry_configs (sent when ECH decryption failed)
        if let Some(retry_configs_bytes) = encrypted_extensions.extensions.get_ech_retry_configs() {
            // Decode ECHConfigList
            match crate::ech::EchConfigList::decode(&retry_configs_bytes) {
                Ok(config_list) => {
                    // Store retry configs for application to use
                    self.ech_retry_configs = Some(config_list.configs.clone());
                    tracing::info!("Received {} ECH retry config(s) from server", config_list.configs.len());
                }
                Err(e) => {
                    tracing::warn!("Failed to decode ECH retry_configs: {:?}", e);
                }
            }
        }

        self.state = ClientState::WaitCertCr;

        Ok(())
    }

    /// Process CertificateRequest message from server (mTLS).
    ///
    /// When a server requests client authentication, it sends a CertificateRequest
    /// message. The client must respond with:
    /// 1. Certificate message (possibly empty if no suitable cert)
    /// 2. CertificateVerify message (if certificate was sent)
    /// 3. Finished message
    ///
    /// # Arguments
    /// * `certificate_request` - The CertificateRequest message from the server
    ///
    /// # State
    /// Must be called in `WaitCertCr` state.
    ///
    /// # RFC 8446 Section 4.3.2
    /// The CertificateRequest message signals that the server wishes to authenticate
    /// the client. This message will be sent following EncryptedExtensions.
    pub fn process_certificate_request(
        &mut self,
        certificate_request: &CertificateRequest,
    ) -> Result<()> {
        if self.state != ClientState::WaitCertCr {
            return Err(Error::UnexpectedMessage(format!(
                "CertificateRequest received in unexpected state: {:?}",
                self.state
            )));
        }

        // Update transcript with CertificateRequest
        let encoded = certificate_request.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        // Mark that client authentication was requested
        self.cert_requested = true;

        // Extract signature algorithms that server will accept
        // The client will use this when generating CertificateVerify
        if let Some(sig_algs) = certificate_request.signature_algorithms()? {
            tracing::debug!(
                "Server requested client authentication with {} supported signature algorithms",
                sig_algs.len()
            );
        }

        // State remains WaitCertCr - client still needs to receive server's Certificate
        // The client will send its own Certificate/CertificateVerify after receiving
        // the server's Finished message

        Ok(())
    }

    /// Process Certificate message.
    pub fn process_certificate(&mut self, certificate: &Certificate) -> Result<()> {
        if self.state != ClientState::WaitCertCr {
            return Err(Error::UnexpectedMessage(format!(
                "Certificate received in unexpected state: {:?}",
                self.state
            )));
        }

        let encoded = certificate.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        // Store certificate chain for later validation
        let cert_chain: Vec<Vec<u8>> = certificate
            .certificate_list
            .iter()
            .map(|entry| entry.cert_data.clone())
            .collect();
        self.server_cert_chain = Some(cert_chain);
        self.state = ClientState::WaitCertVerify;

        Ok(())
    }
    /// Validate the server certificate chain using the provided validator.
    /// This should be called after `process_certificate()` to validate the certificate chain.
    /// The validation is separated from processing to allow flexible validation policies.
    /// * `validator` - Certificate validator with configured trust anchors and policy
    /// ```rust,no_run
    /// use hptls_core::{handshake::ClientHandshake, certificate_validator::CertificateValidator};
    /// use hptls_crypto::CryptoProvider;
    /// use hptls_crypto_hpcrypt::HpcryptProvider;
    /// # fn main() -> Result<(), hptls_core::Error> {
    /// let mut client = ClientHandshake::new();
    /// let provider = HpcryptProvider::new();
    /// // ... perform handshake ...
    /// // After processing the certificate message:
    /// let validator = CertificateValidator::permissive();
    /// client.validate_server_certificate(&validator, &provider)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate_server_certificate(
        &self,
        validator: &crate::certificate_validator::CertificateValidator,
        crypto_provider: &dyn CryptoProvider,
    ) -> Result<()> {
        let cert_chain = self
            .server_cert_chain
            .as_ref()
            .ok_or_else(|| Error::InternalError("No certificate chain received".into()))?;
        validator.validate_chain(cert_chain, self.server_hostname.as_deref(), crypto_provider)
    }
    /// Process CertificateVerify message.
    pub fn process_certificate_verify(&mut self, cert_verify: &CertificateVerify) -> Result<()> {
        if self.state != ClientState::WaitCertVerify {
            return Err(Error::UnexpectedMessage(format!(
                "CertificateVerify received in unexpected state: {:?}",
                self.state
            )));
        }

        // Note: Signature verification should be done BEFORE calling this method
        // using verify_server_certificate_signature(), because the signature is
        // computed over the transcript hash that does NOT include CertificateVerify itself.
        let encoded = cert_verify.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        self.state = ClientState::WaitFinished;

        Ok(())
    }
    /// Verify the server's CertificateVerify signature.
    /// This verifies that the server possesses the private key corresponding to its certificate.
    /// **IMPORTANT**: This method must be called BEFORE `process_certificate_verify()`, because
    /// the signature is computed over the transcript hash that does NOT include the CertificateVerify
    /// message itself (RFC 8446 Section 4.4.3).
    /// * `provider` - Crypto provider for signature verification
    /// * `cert_verify` - The CertificateVerify message to verify
    /// # Signature Verification Process
    /// 1. Extracts the public key from the server's leaf certificate
    /// 2. Computes the current transcript hash (excluding CertificateVerify)
    /// 3. Verifies the signature according to RFC 8446 Section 4.4.3
    ///
    /// # Example
    /// ```rust,no_run
    /// use hptls_core::{handshake::ClientHandshake, messages::certificate_verify::CertificateVerify};
    /// use hptls_crypto_hpcrypt::HpcryptProvider;
    /// use hptls_crypto::CryptoProvider;
    /// # fn main() -> Result<(), hptls_core::Error> {
    /// let mut client = ClientHandshake::new();
    /// let provider = HpcryptProvider::new();
    /// # let cert_verify = CertificateVerify::new(
    /// #     hptls_crypto::SignatureAlgorithm::EcdsaSecp256r1Sha256,
    /// #     vec![0u8; 64]
    /// # );
    /// // ... perform handshake up to CertificateVerify ...
    /// // Verify signature BEFORE processing the message
    /// client.verify_server_certificate_signature(&provider, &cert_verify)?;
    /// // Then process the message (updates transcript)
    /// client.process_certificate_verify(&cert_verify)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_server_certificate_signature(
        &mut self,
        provider: &dyn CryptoProvider,
        cert_verify: &CertificateVerify,
    ) -> Result<()> {
        // Get the server's leaf certificate
        let cert_chain = self
            .server_cert_chain
            .as_ref()
            .ok_or_else(|| Error::InternalError("No certificate chain available".into()))?;
        if cert_chain.is_empty() {
            return Err(Error::InternalError("Certificate chain is empty".into()));
        }
        let leaf_cert_der = &cert_chain[0];
        // Parse the certificate to extract the public key
        let cert = crate::certificate_validator::X509Certificate::parse_der(leaf_cert_der)?;
        // Get the transcript hash (up to but NOT including CertificateVerify)
        // The transcript at this point should include: ClientHello, ServerHello, EncryptedExtensions, Certificate
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".into()))?
            .current_hash(provider)?;

        // Verify the signature
        crate::signature_verify::verify_certificate_verify_signature(
            provider,
            cert_verify.algorithm,
            &cert.public_key,
            &cert_verify.signature,
            &transcript_hash,
            true, // is_server = true
        )
    }
    /// Process server Finished message and generate client Finished.
    pub fn process_server_finished(
        &mut self,
        provider: &dyn CryptoProvider,
        finished: &Finished,
    ) -> Result<Finished> {
        if self.state != ClientState::WaitFinished {
            return Err(Error::UnexpectedMessage(format!(
                "Finished received in unexpected state: {:?}",
                self.state
            )));
        }

        // Verify server Finished
        let hash_algorithm = self.cipher_suite.unwrap().hash_algorithm();
        let transcript_hash = self.transcript.as_mut().unwrap().current_hash(provider)?;
        let key_schedule = self.key_schedule.as_ref().unwrap();
        let server_hs_secret =
            key_schedule.get_server_handshake_traffic_secret().ok_or_else(|| {
                Error::InternalError("Server handshake secret not available".to_string())
            })?;
        let expected_verify_data =
            compute_verify_data(provider, hash_algorithm, server_hs_secret, &transcript_hash)?;
        if finished.verify_data != expected_verify_data {
            return Err(Error::DecryptionFailed);
        }

        // Add server Finished to transcript
        let encoded = finished.encode()?;
        self.transcript.as_mut().unwrap().update(&encoded);
        // Derive application traffic secrets NOW (after server Finished, before client Finished)
        // Per RFC 8446 Section 7.1: application secrets use transcript through server Finished
        let transcript_hash = self.transcript.as_mut().unwrap().current_hash(provider)?;
        let key_schedule = self.key_schedule.as_mut().unwrap();
        key_schedule.derive_master_secret(provider)?;
        key_schedule.derive_client_application_traffic_secret(provider, &transcript_hash)?;
        key_schedule.derive_server_application_traffic_secret(provider, &transcript_hash)?;

        // NOW generate client Finished (uses same transcript hash as server Finished verification)
        let client_hs_secret =
            key_schedule.get_client_handshake_traffic_secret().ok_or_else(|| {
                Error::InternalError("Client handshake secret not available".to_string())
            })?;
        let client_verify_data =
            compute_verify_data(provider, hash_algorithm, client_hs_secret, &transcript_hash)?;
        let client_finished = Finished::new(client_verify_data);

        // Add client Finished to transcript (for resumption/exporter secrets, not for app secrets)
        let encoded = client_finished.encode()?;
        self.transcript.as_mut().unwrap().update(&encoded);

        self.state = ClientState::Connected;

        Ok(client_finished)
    }

    /// Generate client Certificate message for mutual TLS authentication.
    ///
    /// This should only be called if the server requested client authentication
    /// via CertificateRequest. The client can send an empty certificate list if
    /// it has no suitable certificate.
    ///
    /// # Arguments
    /// * `certificate_chain` - The client's certificate chain (leaf first, root last).
    ///                         Pass empty vec if no suitable certificate is available.
    ///
    /// # Returns
    /// A Certificate message ready to send to the server.
    ///
    /// # RFC 8446 Section 4.4.2
    /// This message conveys the client's certificate chain to the server.
    /// The certificate_request_context field MUST be set to the value from
    /// the CertificateRequest message.
    pub fn generate_client_certificate(
        &mut self,
        certificate_chain: Vec<Vec<u8>>,
    ) -> Result<Certificate> {
        if !self.cert_requested {
            return Err(Error::InternalError(
                "Cannot generate client certificate: server did not request client auth".into(),
            ));
        }

        // Create Certificate message
        // In TLS 1.3, certificate_request_context is typically empty for normal handshakes
        let certificate = Certificate::new(certificate_chain);

        // Update transcript
        let encoded = certificate.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        Ok(certificate)
    }

    /// Generate client CertificateVerify message for mutual TLS authentication.
    ///
    /// This proves possession of the private key corresponding to the certificate
    /// sent in the client Certificate message.
    ///
    /// # Arguments
    /// * `provider` - Cryptographic provider for signing operations
    /// * `signing_key` - The client's private key (must match the certificate)
    /// * `signature_algorithm` - The signature algorithm to use (must be one that
    ///                          the server indicated support for in CertificateRequest)
    ///
    /// # Returns
    /// A CertificateVerify message with the signature.
    ///
    /// # RFC 8446 Section 4.4.3
    /// The signature covers the transcript hash with a context string prefix.
    /// The context string for client authentication is:
    /// "TLS 1.3, client CertificateVerify" (with 64 spaces)
    pub fn generate_client_certificate_verify(
        &mut self,
        provider: &dyn CryptoProvider,
        signing_key: &[u8],
        signature_algorithm: hptls_crypto::SignatureAlgorithm,
    ) -> Result<CertificateVerify> {
        if !self.cert_requested {
            return Err(Error::InternalError(
                "Cannot generate CertificateVerify: server did not request client auth".into(),
            ));
        }

        // Get current transcript hash
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".into()))?
            .current_hash(provider)?;

        // Build the content to be signed (RFC 8446 Section 4.4.3)
        // 64 spaces + context string + 0x00 + transcript hash
        let mut content_to_sign = Vec::new();
        content_to_sign.extend_from_slice(&[0x20u8; 64]); // 64 spaces
        content_to_sign.extend_from_slice(b"TLS 1.3, client CertificateVerify");
        content_to_sign.push(0x00);
        content_to_sign.extend_from_slice(&transcript_hash);

        // Sign the content
        let sig_impl = provider.signature(signature_algorithm)?;
        let signature = sig_impl.sign(signing_key, &content_to_sign)?;

        // Create CertificateVerify with the signature
        let cert_verify = CertificateVerify::new(signature_algorithm, signature);

        // Update transcript with CertificateVerify
        let encoded = cert_verify.encode()?;
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&encoded);
        }

        Ok(cert_verify)
    }

    /// Compute the shared secret from key exchange.
    fn compute_shared_secret(&self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        let algorithm = self
            .key_exchange_algorithm
            .ok_or_else(|| Error::InternalError("Key exchange algorithm not set".to_string()))?;
        let private_key = self
            .key_exchange_private
            .as_ref()
            .ok_or_else(|| Error::InternalError("Private key not available".to_string()))?;
        let server_public = self
            .server_key_exchange
            .as_ref()
            .ok_or_else(|| Error::InternalError("Server public key not available".to_string()))?;
        let kex = provider.key_exchange(algorithm)?;
        let private = hptls_crypto::key_exchange::PrivateKey::from_bytes(private_key.clone());
        let shared = kex.exchange(&private, server_public)?;
        Ok(shared.as_bytes().to_vec())
    }

    /// Process HelloRetryRequest.
    ///
    /// RFC 8446 Section 4.1.4:
    /// The server sends HelloRetryRequest when:
    /// - It doesn't support any of the client's key share groups
    /// - It wants to use a cookie for stateless operation
    /// - It wants to negotiate different parameters
    ///
    /// The client MUST respond with an updated ClientHello.
    fn process_hello_retry_request(
        &mut self,
        provider: &dyn CryptoProvider,
        hrr: &ServerHello,
    ) -> Result<()> {
        tracing::info!("Processing HelloRetryRequest");

        // Verify state - should be waiting for ServerHello
        if !matches!(self.state, ClientState::WaitServerHello) {
            return Err(Error::UnexpectedMessage(
                "HelloRetryRequest received in wrong state".into(),
            ));
        }

        // Check if we already received HRR (can only receive once)
        if self.hello_retry_received {
            return Err(Error::UnexpectedMessage(
                "Received multiple HelloRetryRequests".into(),
            ));
        }

        // Store selected cipher suite
        self.cipher_suite = Some(hrr.cipher_suite);
        self.hello_retry_received = true;

        // Update transcript with special HRR handling (RFC 8446 Section 4.4.1)
        // For HRR, we need to:
        // 1. Hash the original ClientHello
        // 2. Create a message_hash wrapper
        // 3. Reset transcript with message_hash
        // 4. Add HRR to new transcript

        use crate::protocol::ExtensionType;

        // Check for selected_group in key_share extension
        let selected_algorithm_u16 = if let Some(ext) = hrr.extensions.get(ExtensionType::KeyShare)
        {
            // In HRR, key_share contains only selected_group (2 bytes)
            if ext.data.len() < 2 {
                return Err(Error::InvalidMessage("Invalid key_share in HRR".into()));
            }
            Some(u16::from_be_bytes([ext.data[0], ext.data[1]]))
        } else {
            None
        };

        // Check for cookie extension
        let cookie = hrr.extensions.get(ExtensionType::Cookie).map(|e| e.data.clone());

        // Validate that HRR contains at least one actionable extension
        if selected_algorithm_u16.is_none() && cookie.is_none() {
            return Err(Error::ProtocolError(
                crate::error::ProtocolError::IllegalParameter,
            ));
        }

        // Store selected algorithm for retry
        if let Some(alg_u16) = selected_algorithm_u16 {
            // Convert u16 to KeyExchangeAlgorithm
            let algorithm = match alg_u16 {
                0x001D => KeyExchangeAlgorithm::X25519,
                0x001E => KeyExchangeAlgorithm::X448,
                0x0017 => KeyExchangeAlgorithm::Secp256r1,
                0x0018 => KeyExchangeAlgorithm::Secp384r1,
                0x0019 => KeyExchangeAlgorithm::Secp521r1,
                _ => {
                    return Err(Error::InvalidMessage(
                        "Unsupported selected group in HRR".into(),
                    ))
                },
            };

            self.selected_algorithm = Some(algorithm);
            tracing::debug!("Server selected key exchange algorithm: {:?}", algorithm);
        }

        // Store cookie if present
        if let Some(cookie_data) = cookie {
            tracing::debug!("Received cookie in HRR ({} bytes)", cookie_data.len());
            self.hrr_cookie = Some(cookie_data);
        }

        // Transition to HRR state - application should send updated ClientHello
        self.state = ClientState::HelloRetryReceived;

        tracing::info!("HelloRetryRequest processed - client needs to retry handshake");
        Ok(())
    }
    /// Send a KeyUpdate message.
    /// This initiates a key update by generating a new client application traffic secret
    /// and returning a KeyUpdate message to send to the server.
    /// * `request_update` - Whether to request the peer to also update their keys
    /// Returns the KeyUpdate message to send, and the new client application traffic secret
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
        if !matches!(self.state, ClientState::Connected) {
            return Err(Error::HandshakeFailure(
                "Cannot send KeyUpdate before connection is established".into(),
            ));
        }

        // Update client application traffic secret
        let key_schedule = self
            .key_schedule
            .as_mut()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".into()))?;
        key_schedule.update_client_application_traffic_secret(provider)?;

        Ok(KeyUpdate::new(request_update))
    }
    /// Process a received KeyUpdate message.
    /// This updates the server application traffic secret in response to a KeyUpdate
    /// message received from the server.
    /// * `key_update` - The KeyUpdate message received from the server
    /// Returns the new server application traffic secret and optionally a KeyUpdate message
    /// if the server requested an update (tuple of (new_secret, Option<KeyUpdate>)).
    pub fn process_key_update(
        &mut self,
        provider: &dyn CryptoProvider,
        key_update: &KeyUpdate,
    ) -> Result<(Vec<u8>, Option<KeyUpdate>)> {
        // Must be in connected state
        if !matches!(self.state, ClientState::Connected) {
            return Err(Error::HandshakeFailure(
                "Cannot process KeyUpdate before connection is established".into(),
            ));
        }

        // Update server application traffic secret
        let key_schedule = self
            .key_schedule
            .as_mut()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".into()))?;
        key_schedule.update_server_application_traffic_secret(provider)?;
        let new_secret = key_schedule
            .get_server_application_traffic_secret()
            .ok_or_else(|| {
                Error::InternalError("Server application traffic secret not available".into())
            })?
            .to_vec();

        // If server requested update, prepare KeyUpdate response
        let response = if key_update.request_update == key_update::KeyUpdateRequest::UpdateRequested
        {
            // Update our own sending keys too
            key_schedule.update_client_application_traffic_secret(provider)?;
            Some(KeyUpdate::new(
                key_update::KeyUpdateRequest::UpdateNotRequested,
            ))
        } else {
            None
        };

        Ok((new_secret, response))
    }
    /// Enable early data (0-RTT) with the given configuration.
    /// Must be called before sending ClientHello.
    /// * `config` - Early data configuration
    /// Returns `Ok(())` if early data is enabled, error if called in wrong state.
    pub fn enable_early_data(&mut self, config: crate::early_data::EarlyDataConfig) -> Result<()> {
        if self.state != ClientState::Start {
            return Err(Error::HandshakeFailure(
                "Early data can only be enabled before sending ClientHello".into(),
            ));
        }
        self.early_data = Some(EarlyDataContext::new(config));
        Ok(())
    }
    /// Check if early data is enabled.
    pub fn is_early_data_enabled(&self) -> bool {
        self.early_data.as_ref().map(|ed| ed.is_enabled()).unwrap_or(false)
    }

    /// Check if early data was accepted by the server.
    /// Available after processing EncryptedExtensions.
    pub fn is_early_data_accepted(&self) -> bool {
        self.early_data.as_ref().map(|ed| ed.is_accepted()).unwrap_or(false)
    }

    /// Get early data context (for sending 0-RTT data).
    pub fn early_data_context(&mut self) -> Option<&mut EarlyDataContext> {
        self.early_data.as_mut()
    }
    /// Create EndOfEarlyData message.
    /// This should be called after all early data has been sent and before
    /// sending the client Finished message.
    /// Returns the EndOfEarlyData message if early data was accepted, None otherwise.
    pub fn create_end_of_early_data(&mut self) -> Result<Option<EndOfEarlyData>> {
        if let Some(ref mut early_data) = self.early_data {
            if early_data.is_accepted() {
                // Mark early data as complete
                early_data.mark_complete()?;
                return Ok(Some(EndOfEarlyData::new()));
            }
        }
        Ok(None)
    }
    /// Process a NewSessionTicket message received after handshake completion.
    /// This method derives the PSK from the ticket and returns a StoredTicket for future session resumption.
    /// The ticket is automatically stored internally and can be retrieved with `get_stored_tickets()`.
    /// NewSessionTicket messages can only be processed after the handshake is complete (Connected state).
    /// * `provider` - Crypto provider for PSK derivation
    /// * `ticket` - The NewSessionTicket message from the server
    /// Returns the StoredTicket containing the PSK and all necessary metadata.
    /// use hptls_core::handshake::ClientHandshake;
    /// use hptls_core::messages::NewSessionTicket;
    /// // ... complete handshake ...
    /// // Receive NewSessionTicket from server
    /// let ticket = NewSessionTicket { /* ... */ };
    /// let stored_ticket = client.process_new_session_ticket(&provider, &ticket)?;
    /// // Ticket is automatically stored; can retrieve later with get_stored_tickets()
    pub fn process_new_session_ticket(
        &mut self,
        provider: &dyn CryptoProvider,
        ticket: &NewSessionTicket,
    ) -> Result<StoredTicket> {
        if self.state != ClientState::Connected {
            return Err(Error::UnexpectedMessage(
                "NewSessionTicket can only be processed after handshake is complete".to_string(),
            ));
        }

        let cipher_suite = self
            .cipher_suite
            .ok_or_else(|| Error::InternalError("Cipher suite not selected".to_string()))?;

        // Get final transcript hash (same as server used)
        let transcript_hash = self
            .transcript
            .as_mut()
            .ok_or_else(|| Error::InternalError("Transcript not initialized".to_string()))?
            .current_hash(provider)?;

        // Derive resumption master secret (same process as server)
        let key_schedule = self
            .key_schedule
            .as_ref()
            .ok_or_else(|| Error::InternalError("Key schedule not initialized".to_string()))?;
        let resumption_master_secret =
            key_schedule.derive_resumption_master_secret(provider, &transcript_hash)?;
        // Derive PSK from resumption secret using the ticket nonce
        // PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
        let hash_algorithm = cipher_suite.hash_algorithm();
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
            &resumption_master_secret,
            b"resumption",
            &ticket.ticket_nonce,
            hash_len,
        )?;

        // Get current time (seconds since UNIX epoch)
        let received_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create StoredTicket
        let stored_ticket = StoredTicket {
            ticket: ticket.ticket.clone(),
            psk: Zeroizing::new(psk),
            cipher_suite,
            ticket_age_add: ticket.ticket_age_add,
            received_at,
            lifetime: ticket.ticket_lifetime,
        };

        // Store the ticket internally
        self.stored_tickets.push(stored_ticket.clone());

        Ok(stored_ticket)
    }
    /// Get all stored session tickets.
    /// Returns a slice of all stored tickets that have been received via NewSessionTicket messages.
    /// The caller should check ticket validity using `StoredTicket::is_valid()` before use.
    pub fn get_stored_tickets(&self) -> &[StoredTicket] {
        &self.stored_tickets
    }

    /// Clear all stored session tickets.
    /// This removes all stored tickets from memory. Useful for testing or when
    /// you want to prevent session resumption.
    pub fn clear_stored_tickets(&mut self) {
        self.stored_tickets.clear();
    }

    /// Remove expired tickets from storage.
    /// This method removes all tickets that have exceeded their lifetime.
    /// Should be called periodically to prevent memory buildup.
    pub fn prune_expired_tickets(&mut self) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.stored_tickets.retain(|ticket| ticket.is_valid(current_time));
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
    /// let close_notify = client.send_close_notify();
    /// // Encode and send the alert to the server
    /// ```
    pub fn send_close_notify(&mut self) -> crate::alert::Alert {
        use crate::alert::Alert;

        tracing::info!("Sending close_notify alert - transitioning to Closing state");
        self.state = ClientState::Closing;
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
    /// client.process_close_notify(&alert)?;
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
            ClientState::Connected => {
                tracing::info!("Received close_notify alert - transitioning to Closing state");
                self.state = ClientState::Closing;
            },
            ClientState::Closing => {
                tracing::info!("Received close_notify alert - completing mutual close, transitioning to Closed");
                self.state = ClientState::Closed;
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
        matches!(self.state, ClientState::Closing)
    }

    /// Check if the connection is closed.
    ///
    /// # Returns
    /// true if the connection is fully closed (mutual close_notify exchange complete)
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ClientState::Closed)
    }

    /// Complete the connection close after sending response close_notify.
    ///
    /// Should be called after:
    /// 1. Receiving close_notify from peer (state → Closing)
    /// 2. Sending our own close_notify in response
    ///
    /// This transitions the state to Closed.
    pub fn complete_close(&mut self) {
        if self.state == ClientState::Closing {
            tracing::info!("Completing connection close - transitioning to Closed state");
            self.state = ClientState::Closed;
        }
    }
}

impl Default for ClientHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hptls_crypto_hpcrypt::HpcryptProvider;
    #[test]
    fn test_client_handshake_initial_state() {
        let handshake = ClientHandshake::new();
        assert_eq!(handshake.state(), ClientState::Start);
        assert!(!handshake.is_connected());
    }

    #[test]
    fn test_client_hello_generation() {
        let provider = HpcryptProvider::new();
        let mut handshake = ClientHandshake::new();
        let cipher_suites = vec![CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384];
        let client_hello = handshake
            .client_hello(&provider, &cipher_suites, Some("example.com"), None, None)
            .unwrap();
        assert_eq!(client_hello.legacy_version, ProtocolVersion::Tls12);
        assert_eq!(client_hello.cipher_suites, cipher_suites);
        assert_eq!(handshake.state(), ClientState::WaitServerHello);
        // Verify extensions
        assert!(client_hello.extensions.contains_supported_versions());
        assert!(client_hello.extensions.get_key_share().unwrap().is_some());
    }

    #[test]
    fn test_client_hello_requires_cipher_suites() {
        let provider = HpcryptProvider::new();
        let mut handshake = ClientHandshake::new();
        let result = handshake.client_hello(&provider, &[], None, None, None);
        assert!(result.is_err());
    }
}
