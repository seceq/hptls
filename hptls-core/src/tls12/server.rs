//! TLS 1.2 Server Handshake State Machine
//!
//! Implements the server-side TLS 1.2 handshake per RFC 5246.
//!
//! ## State Transitions
//! ```text
//! START
//!   |
//!   | recv ClientHello
//!   v
//! WAIT_CLIENT_KEY_EXCHANGE
//!   | send ServerHello
//!   | send Certificate
//!   | send ServerKeyExchange
//!   | send ServerHelloDone
//!   | recv ClientKeyExchange
//!   v
//! WAIT_CHANGE_CIPHER_SPEC
//!   | recv ChangeCipherSpec
//!   v
//! WAIT_FINISHED
//!   | recv Finished
//!   | send ChangeCipherSpec
//!   | send Finished
//!   v
//! CONNECTED
//! ```

use crate::error::{Error, Result};
use crate::extensions::Extensions;
use crate::messages::{ClientHello, ServerHello};
use crate::tls12::cipher_suites::Tls12CipherSuite;
use crate::tls12::key_exchange::{compute_premaster_secret, generate_key_pair};
use crate::tls12::messages::{ClientKeyExchange, ServerHelloDone, ServerKeyExchange, Tls12Certificate};
use crate::tls12::{compute_key_block, compute_master_secret, compute_verify_data};
use hptls_crypto::{CryptoProvider, KeyExchangeAlgorithm, SignatureAlgorithm};
use zeroize::Zeroizing;

/// TLS 1.2 server handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12ServerState {
    /// Initial state, ready to receive ClientHello
    Start,
    /// Waiting for ClientKeyExchange
    WaitClientKeyExchange,
    /// Waiting for ChangeCipherSpec
    WaitChangeCipherSpec,
    /// Waiting for Finished
    WaitFinished,
    /// Handshake complete, connection established
    Connected,
    /// Error state
    Failed,
}

/// TLS 1.2 server handshake context.
///
/// Manages the server-side TLS 1.2 handshake process.
pub struct Tls12ServerHandshake {
    /// Current state
    state: Tls12ServerState,
    /// Selected cipher suite
    cipher_suite: Option<Tls12CipherSuite>,
    /// Server random (32 bytes)
    server_random: [u8; 32],
    /// Client random (32 bytes)
    client_random: Option<[u8; 32]>,
    /// Selected key exchange algorithm
    key_exchange_algorithm: Option<KeyExchangeAlgorithm>,
    /// Server's ephemeral private key
    server_private_key: Option<Zeroizing<Vec<u8>>>,
    /// Server's ephemeral public key
    server_public_key: Option<Vec<u8>>,
    /// Client's ephemeral public key (from ClientKeyExchange)
    client_public_key: Option<Vec<u8>>,
    /// Premaster secret (from ECDHE)
    premaster_secret: Option<Zeroizing<Vec<u8>>>,
    /// Master secret (derived from premaster secret)
    master_secret: Option<Zeroizing<Vec<u8>>>,
    /// Key block (for encryption keys and IVs)
    key_block: Option<Zeroizing<Vec<u8>>>,
    /// Server certificate chain (DER-encoded)
    server_cert_chain: Option<Vec<Vec<u8>>>,
    /// Server's private signing key (for ServerKeyExchange signature)
    server_signing_key: Option<Vec<u8>>,
    /// Signature algorithm to use
    signature_algorithm: Option<SignatureAlgorithm>,
    /// Session ID
    session_id: Vec<u8>,
    /// Handshake messages hash (for verify_data computation)
    handshake_messages: Vec<Vec<u8>>,
    /// Whether ChangeCipherSpec has been received
    change_cipher_spec_received: bool,
}

impl Tls12ServerHandshake {
    /// Create a new TLS 1.2 server handshake.
    pub fn new() -> Self {
        Self {
            state: Tls12ServerState::Start,
            cipher_suite: None,
            server_random: [0u8; 32],
            client_random: None,
            key_exchange_algorithm: None,
            server_private_key: None,
            server_public_key: None,
            client_public_key: None,
            premaster_secret: None,
            master_secret: None,
            key_block: None,
            server_cert_chain: None,
            server_signing_key: None,
            signature_algorithm: None,
            session_id: Vec::new(),
            handshake_messages: Vec::new(),
            change_cipher_spec_received: false,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> Tls12ServerState {
        self.state
    }

    /// Set server certificate chain.
    ///
    /// # Arguments
    /// * `cert_chain` - DER-encoded certificate chain (leaf first)
    pub fn set_certificate_chain(&mut self, cert_chain: Vec<Vec<u8>>) {
        self.server_cert_chain = Some(cert_chain);
    }

    /// Set server's private signing key.
    ///
    /// # Arguments
    /// * `signing_key` - Private key bytes (format depends on signature algorithm)
    /// * `signature_algorithm` - Signature algorithm to use
    pub fn set_signing_key(&mut self, signing_key: Vec<u8>, signature_algorithm: SignatureAlgorithm) {
        self.server_signing_key = Some(signing_key);
        self.signature_algorithm = Some(signature_algorithm);
    }

    /// Process ClientHello and generate server handshake messages.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `client_hello` - ClientHello message bytes
    /// * `supported_cipher_suites` - Server's supported cipher suites
    ///
    /// # Returns
    /// Tuple of (ServerHello, Certificate, ServerKeyExchange, ServerHelloDone) message bytes
    pub fn process_client_hello(
        &mut self,
        provider: &dyn CryptoProvider,
        client_hello_bytes: &[u8],
        supported_cipher_suites: &[Tls12CipherSuite],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        if self.state != Tls12ServerState::Start {
            return Err(Error::InternalError(format!(
                "Cannot process ClientHello in state {:?}",
                self.state
            )));
        }

        // Parse ClientHello
        let client_hello = ClientHello::decode(client_hello_bytes)?;

        // Extract client random
        self.client_random = Some(client_hello.random);

        // Store ClientHello for handshake hash
        self.handshake_messages.push(client_hello_bytes.to_vec());

        // Select cipher suite from client's offered suites
        let mut selected_cipher_suite = None;
        for offered in &client_hello.cipher_suites {
            if let Some(tls12_suite) = Tls12CipherSuite::from_cipher_suite(*offered) {
                if supported_cipher_suites.contains(&tls12_suite) {
                    selected_cipher_suite = Some(tls12_suite);
                    break;
                }
            }
        }

        let cipher_suite = selected_cipher_suite.ok_or_else(|| {
            Error::HandshakeFailure("No mutually supported cipher suite found".into())
        })?;
        self.cipher_suite = Some(cipher_suite);

        // Generate server random
        provider
            .random()
            .fill(&mut self.server_random)
            .map_err(|e| Error::CryptoError(format!("Failed to generate random: {}", e)))?;

        // Generate session ID (echo client's session ID or generate new one)
        self.session_id = client_hello.legacy_session_id.clone();
        if self.session_id.is_empty() {
            let mut new_session_id = vec![0u8; 32];
            provider
                .random()
                .fill(&mut new_session_id[..])
                .map_err(|e| Error::CryptoError(format!("Failed to generate session ID: {}", e)))?;
            self.session_id = new_session_id;
        }

        // Parse client extensions
        use crate::protocol::ExtensionType;
        use crate::tls12::extensions::{
            ec_point_formats_extension, extended_master_secret_extension,
            parse_supported_groups,
        };

        let mut client_supported_groups = Vec::new();
        let mut client_supports_extended_master_secret = false;

        // Extract supported_groups from client
        if let Some(ext) = client_hello.extensions.get(ExtensionType::SupportedGroups) {
            client_supported_groups = parse_supported_groups(&ext.data)?;
        }

        // Check for extended_master_secret
        if client_hello.extensions.has(ExtensionType::ExtendedMasterSecret) {
            client_supports_extended_master_secret = true;
        }

        // Select key exchange algorithm from client's supported groups
        // Prefer X25519, fall back to secp256r1
        let selected_group = if client_supported_groups.contains(&KeyExchangeAlgorithm::X25519) {
            KeyExchangeAlgorithm::X25519
        } else if client_supported_groups.contains(&KeyExchangeAlgorithm::Secp256r1) {
            KeyExchangeAlgorithm::Secp256r1
        } else if client_supported_groups.contains(&KeyExchangeAlgorithm::Secp384r1) {
            KeyExchangeAlgorithm::Secp384r1
        } else {
            // If client didn't send supported_groups or sent incompatible ones,
            // default to X25519 (most widely supported)
            KeyExchangeAlgorithm::X25519
        };
        self.key_exchange_algorithm = Some(selected_group);

        // Generate server's ephemeral key pair
        let (private_key, public_key) = generate_key_pair(
            provider,
            self.key_exchange_algorithm.unwrap(),
        )?;
        self.server_private_key = Some(Zeroizing::new(private_key));
        self.server_public_key = Some(public_key.clone());

        // Generate ServerHello with extensions
        let mut server_extensions = Extensions::new();

        // Add ec_point_formats - required for ECDHE
        server_extensions.add(ec_point_formats_extension());

        // Echo extended_master_secret if client supports it
        if client_supports_extended_master_secret {
            server_extensions.add(extended_master_secret_extension());
        }

        let server_hello_msg = ServerHello::new(self.server_random, cipher_suite.to_cipher_suite())
            .with_session_id_echo(self.session_id.clone())
            .with_extensions(server_extensions);

        let server_hello = server_hello_msg.encode()?;

        // Store ServerHello for handshake hash
        self.handshake_messages.push(server_hello.clone());

        // Generate Certificate message
        let certificate = if let Some(cert_chain) = &self.server_cert_chain {
            let cert_msg = Tls12Certificate::new(cert_chain.clone());
            let encoded = cert_msg.encode()?;
            self.handshake_messages.push(encoded.clone());
            encoded
        } else {
            // No certificate configured - return empty certificate (will fail validation)
            let cert_msg = Tls12Certificate::new(vec![]);
            let encoded = cert_msg.encode()?;
            self.handshake_messages.push(encoded.clone());
            encoded
        };

        // Generate ServerKeyExchange
        let server_key_exchange = self.generate_server_key_exchange(provider)?;

        // Store ServerKeyExchange for handshake hash
        self.handshake_messages.push(server_key_exchange.clone());

        // Generate ServerHelloDone
        let server_hello_done = ServerHelloDone::new().encode()?;

        // Store ServerHelloDone for handshake hash
        self.handshake_messages.push(server_hello_done.clone());

        self.state = Tls12ServerState::WaitClientKeyExchange;

        Ok((server_hello, certificate, server_key_exchange, server_hello_done))
    }

    /// Generate ServerKeyExchange message.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    ///
    /// # Returns
    /// ServerKeyExchange message bytes
    fn generate_server_key_exchange(&self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        let algorithm = self
            .key_exchange_algorithm
            .ok_or(Error::InternalError("No key exchange algorithm".into()))?;

        let public_key = self
            .server_public_key
            .as_ref()
            .ok_or(Error::InternalError("No server public key".into()))?;

        let signature_algorithm = self
            .signature_algorithm
            .ok_or(Error::InternalError("No signature algorithm".into()))?;

        let client_random = self
            .client_random
            .as_ref()
            .ok_or(Error::InternalError("No client random".into()))?;

        // Create temporary ServerKeyExchange to compute signed data
        let temp_ske = ServerKeyExchange::new(
            algorithm,
            public_key.clone(),
            signature_algorithm,
            vec![], // Empty signature for now
        );

        // Get the data that needs to be signed
        let signed_data = temp_ske.get_signed_data(client_random, &self.server_random)?;

        // Generate signature
        let signature = if let Some(signing_key_bytes) = &self.server_signing_key {
            // Sign the data using the crypto provider
            use hptls_crypto::HashAlgorithm;

            // Determine hash algorithm from signature algorithm
            let hash_algorithm = match signature_algorithm {
                SignatureAlgorithm::EcdsaSecp256r1Sha256 => HashAlgorithm::Sha256,
                SignatureAlgorithm::EcdsaSecp384r1Sha384 => HashAlgorithm::Sha384,
                SignatureAlgorithm::RsaPssRsaeSha256 => HashAlgorithm::Sha256,
                SignatureAlgorithm::RsaPssRsaeSha384 => HashAlgorithm::Sha384,
                SignatureAlgorithm::RsaPssRsaeSha512 => HashAlgorithm::Sha512,
                _ => {
                    return Err(Error::UnsupportedFeature(format!(
                        "Unsupported signature algorithm: {:?}",
                        signature_algorithm
                    )))
                }
            };

            // Hash the data
            let mut hasher = provider.hash(hash_algorithm)?;
            hasher.update(&signed_data);
            let hash = hasher.finalize();

            // Sign the hash
            let signer = provider.signature(signature_algorithm)?;
            signer.sign(signing_key_bytes, &hash)?
        } else {
            // No signing key configured - use dummy signature for testing
            vec![0u8; 64]
        };

        // Create final ServerKeyExchange with signature
        let ske = ServerKeyExchange::new(
            algorithm,
            public_key.clone(),
            signature_algorithm,
            signature,
        );

        ske.encode()
    }

    /// Process ClientKeyExchange and compute secrets.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `client_key_exchange_data` - ClientKeyExchange message bytes
    ///
    /// # Returns
    /// Unit on success
    pub fn process_client_key_exchange(
        &mut self,
        provider: &dyn CryptoProvider,
        client_key_exchange_data: &[u8],
    ) -> Result<()> {
        if self.state != Tls12ServerState::WaitClientKeyExchange {
            return Err(Error::InternalError(format!(
                "Cannot process ClientKeyExchange in state {:?}",
                self.state
            )));
        }

        // Parse ClientKeyExchange
        let cke = ClientKeyExchange::decode(client_key_exchange_data)?;
        self.client_public_key = Some(cke.public_key.clone());

        // Compute premaster secret
        let algorithm = self
            .key_exchange_algorithm
            .ok_or(Error::InternalError("No key exchange algorithm".into()))?;

        let private_key = self
            .server_private_key
            .as_ref()
            .ok_or(Error::InternalError("No server private key".into()))?;

        let premaster = compute_premaster_secret(provider, algorithm, private_key, &cke.public_key)?;
        self.premaster_secret = Some(Zeroizing::new(premaster));

        // Compute master secret
        let cipher_suite = self
            .cipher_suite
            .ok_or(Error::InternalError("No cipher suite".into()))?;

        let client_random = self
            .client_random
            .as_ref()
            .ok_or(Error::InternalError("No client random".into()))?;

        let master = compute_master_secret(
            provider,
            cipher_suite.hash_algorithm(),
            self.premaster_secret.as_ref().unwrap(),
            client_random,
            &self.server_random,
        )?;
        self.master_secret = Some(Zeroizing::new(master));

        // Compute key block
        let key_block_len = cipher_suite.key_block_length();
        let key_block = compute_key_block(
            provider,
            cipher_suite.hash_algorithm(),
            self.master_secret.as_ref().unwrap(),
            &self.server_random,
            client_random,
            key_block_len,
        )?;
        self.key_block = Some(Zeroizing::new(key_block));

        self.state = Tls12ServerState::WaitChangeCipherSpec;
        Ok(())
    }

    /// Process ChangeCipherSpec message.
    pub fn process_change_cipher_spec(&mut self, data: &[u8]) -> Result<()> {
        if self.state != Tls12ServerState::WaitChangeCipherSpec {
            return Err(Error::InternalError(format!(
                "Cannot process ChangeCipherSpec in state {:?}",
                self.state
            )));
        }

        if data.len() != 1 || data[0] != 0x01 {
            return Err(Error::InvalidMessage(
                "Invalid ChangeCipherSpec message".into(),
            ));
        }

        self.change_cipher_spec_received = true;
        self.state = Tls12ServerState::WaitFinished;
        Ok(())
    }

    /// Process client Finished message.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `finished_data` - Finished message payload (verify_data)
    pub fn process_finished(
        &mut self,
        provider: &dyn CryptoProvider,
        finished_data: &[u8],
    ) -> Result<()> {
        if self.state != Tls12ServerState::WaitFinished {
            return Err(Error::InternalError(format!(
                "Cannot process Finished in state {:?}",
                self.state
            )));
        }

        if finished_data.len() != 12 {
            return Err(Error::InvalidMessage(format!(
                "Finished verify_data must be 12 bytes, got {}",
                finished_data.len()
            )));
        }

        let cipher_suite = self
            .cipher_suite
            .ok_or(Error::InternalError("No cipher suite".into()))?;

        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or(Error::InternalError("No master secret".into()))?;

        // Compute expected verify_data
        // Note: This is a placeholder. Full implementation would compute hash of all handshake messages.
        let handshake_hash = vec![0u8; 32]; // Placeholder

        let expected_verify_data = compute_verify_data(
            provider,
            cipher_suite.hash_algorithm(),
            master_secret,
            b"client finished",
            &handshake_hash,
        )?;

        // Verify
        if finished_data != expected_verify_data {
            return Err(Error::HandshakeFailure(
                "Client Finished verify_data mismatch".into(),
            ));
        }

        self.state = Tls12ServerState::Connected;
        Ok(())
    }

    /// Generate ChangeCipherSpec message.
    pub fn change_cipher_spec(&self) -> Vec<u8> {
        vec![0x01]
    }

    /// Generate server Finished message.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    ///
    /// # Returns
    /// Finished message payload (verify_data, 12 bytes)
    pub fn finished(&self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        let cipher_suite = self
            .cipher_suite
            .ok_or(Error::InternalError("No cipher suite".into()))?;

        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or(Error::InternalError("No master secret".into()))?;

        // Compute handshake hash
        // Note: This is a placeholder. Full implementation would compute hash of all handshake messages.
        let handshake_hash = vec![0u8; 32]; // Placeholder

        let verify_data = compute_verify_data(
            provider,
            cipher_suite.hash_algorithm(),
            master_secret,
            b"server finished",
            &handshake_hash,
        )?;

        Ok(verify_data)
    }

    /// Get the master secret (for key derivation).
    pub fn master_secret(&self) -> Option<&[u8]> {
        self.master_secret.as_ref().map(|z| z.as_slice())
    }

    /// Get the key block.
    pub fn key_block(&self) -> Option<&[u8]> {
        self.key_block.as_ref().map(|z| z.as_slice())
    }

    /// Get the negotiated cipher suite.
    pub fn cipher_suite(&self) -> Option<Tls12CipherSuite> {
        self.cipher_suite
    }
}

impl Default for Tls12ServerHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls12::cipher_suites::default_cipher_suites;
    use hptls_crypto_hpcrypt::HpcryptProvider;

    #[test]
    fn test_server_initial_state() {
        let server = Tls12ServerHandshake::new();
        assert_eq!(server.state(), Tls12ServerState::Start);
        assert!(server.cipher_suite().is_none());
        assert!(server.master_secret().is_none());
    }

    #[test]
    fn test_server_change_cipher_spec() {
        let server = Tls12ServerHandshake::new();
        let ccs = server.change_cipher_spec();
        assert_eq!(ccs, vec![0x01]);
    }

    #[test]
    fn test_server_set_certificate() {
        let mut server = Tls12ServerHandshake::new();
        let cert_chain = vec![vec![0x30, 0x82], vec![0x30, 0x81]];
        server.set_certificate_chain(cert_chain.clone());
        assert!(server.server_cert_chain.is_some());
    }

    #[test]
    fn test_server_invalid_state_transition() {
        let mut server = Tls12ServerHandshake::new();

        // Try to process ClientKeyExchange without ClientHello
        let result = server.process_client_key_exchange(&HpcryptProvider::new(), &[]);
        assert!(result.is_err());
    }
}
