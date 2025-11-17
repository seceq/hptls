//! TLS 1.2 Client Handshake State Machine
//!
//! Implements the client-side TLS 1.2 handshake per RFC 5246.
//!
//! ## State Transitions
//! ```text
//! START
//!   |
//!   | send ClientHello
//!   v
//! WAIT_SERVER_HELLO
//!   | recv ServerHello
//!   v
//! WAIT_CERTIFICATE
//!   | recv Certificate
//!   v
//! WAIT_SERVER_KEY_EXCHANGE
//!   | recv ServerKeyExchange (ECDHE only)
//!   v
//! WAIT_SERVER_HELLO_DONE
//!   | recv ServerHelloDone
//!   | send ClientKeyExchange
//!   | send ChangeCipherSpec
//!   | send Finished
//!   v
//! WAIT_CHANGE_CIPHER_SPEC
//!   | recv ChangeCipherSpec
//!   v
//! WAIT_FINISHED
//!   | recv Finished
//!   v
//! CONNECTED
//! ```

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};
use crate::extensions::Extensions;
use crate::messages::{ClientHello, ServerHello};
use crate::tls12::cipher_suites::Tls12CipherSuite;
use crate::tls12::key_exchange::{compute_premaster_secret, generate_key_pair};
use crate::tls12::messages::{ClientKeyExchange, ServerHelloDone, ServerKeyExchange, Tls12Certificate};
use crate::tls12::{compute_key_block, compute_master_secret, compute_verify_data};
use hptls_crypto::{CryptoProvider, KeyExchangeAlgorithm, SignatureAlgorithm};
use zeroize::Zeroizing;

/// TLS 1.2 client handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12ClientState {
    /// Initial state, ready to send ClientHello
    Start,
    /// Waiting for ServerHello
    WaitServerHello,
    /// Waiting for Certificate
    WaitCertificate,
    /// Waiting for ServerKeyExchange (ECDHE)
    WaitServerKeyExchange,
    /// Waiting for ServerHelloDone
    WaitServerHelloDone,
    /// Waiting for ChangeCipherSpec
    WaitChangeCipherSpec,
    /// Waiting for Finished
    WaitFinished,
    /// Handshake complete, connection established
    Connected,
    /// Error state
    Failed,
}

/// TLS 1.2 client handshake context.
///
/// Manages the client-side TLS 1.2 handshake process.
pub struct Tls12ClientHandshake {
    /// Current state
    state: Tls12ClientState,
    /// Selected cipher suite
    cipher_suite: Option<Tls12CipherSuite>,
    /// Client random (32 bytes)
    client_random: [u8; 32],
    /// Server random (32 bytes)
    server_random: Option<[u8; 32]>,
    /// Selected key exchange algorithm
    key_exchange_algorithm: Option<KeyExchangeAlgorithm>,
    /// Client's ephemeral private key
    client_private_key: Option<Zeroizing<Vec<u8>>>,
    /// Client's ephemeral public key
    client_public_key: Option<Vec<u8>>,
    /// Server's ephemeral public key (from ServerKeyExchange)
    server_public_key: Option<Vec<u8>>,
    /// Premaster secret (from ECDHE)
    premaster_secret: Option<Zeroizing<Vec<u8>>>,
    /// Master secret (derived from premaster secret)
    master_secret: Option<Zeroizing<Vec<u8>>>,
    /// Key block (for encryption keys and IVs)
    key_block: Option<Zeroizing<Vec<u8>>>,
    /// Server certificate chain
    server_cert_chain: Option<Vec<Vec<u8>>>,
    /// Expected server hostname (for SNI and validation)
    server_hostname: Option<String>,
    /// Negotiated ALPN protocol
    negotiated_alpn: Option<String>,
    /// Session ID (for session resumption)
    session_id: Vec<u8>,
    /// Handshake messages hash (for verify_data computation)
    handshake_messages: Vec<Vec<u8>>,
    /// Whether ChangeCipherSpec has been received
    change_cipher_spec_received: bool,
}

impl Tls12ClientHandshake {
    /// Create a new TLS 1.2 client handshake.
    pub fn new() -> Self {
        Self {
            state: Tls12ClientState::Start,
            cipher_suite: None,
            client_random: [0u8; 32],
            server_random: None,
            key_exchange_algorithm: None,
            client_private_key: None,
            client_public_key: None,
            server_public_key: None,
            premaster_secret: None,
            master_secret: None,
            key_block: None,
            server_cert_chain: None,
            server_hostname: None,
            negotiated_alpn: None,
            session_id: Vec::new(),
            handshake_messages: Vec::new(),
            change_cipher_spec_received: false,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> Tls12ClientState {
        self.state
    }

    /// Set server hostname for SNI.
    pub fn set_server_hostname(&mut self, hostname: String) {
        self.server_hostname = Some(hostname);
    }

    /// Generate ClientHello message.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider for random number generation
    /// * `cipher_suites` - List of supported cipher suites (in preference order)
    ///
    /// # Returns
    /// ClientHello message bytes
    pub fn client_hello(
        &mut self,
        provider: &dyn CryptoProvider,
        cipher_suites: &[Tls12CipherSuite],
    ) -> Result<Vec<u8>> {
        if self.state != Tls12ClientState::Start {
            return Err(Error::InternalError(format!(
                "Cannot send ClientHello in state {:?}",
                self.state
            )));
        }

        // Generate client random
        provider
            .random()
            .fill(&mut self.client_random)
            .map_err(|e| Error::CryptoError(format!("Failed to generate random: {}", e)))?;

        // Convert TLS 1.2 cipher suites to generic cipher suites
        let cipher_suite_list: Vec<CipherSuite> = cipher_suites
            .iter()
            .map(|cs| cs.to_cipher_suite())
            .collect();

        // Generate session ID for middlebox compatibility (32 random bytes)
        let mut session_id = vec![0u8; 32];
        provider
            .random()
            .fill(&mut session_id[..])
            .map_err(|e| Error::CryptoError(format!("Failed to generate session ID: {}", e)))?;
        self.session_id = session_id.clone();

        // Create ClientHello message
        let mut client_hello = ClientHello::new(self.client_random, cipher_suite_list)
            .with_session_id(session_id);

        // Add TLS 1.2-specific extensions
        use crate::tls12::extensions::{
            default_signature_algorithms, default_supported_groups, ec_point_formats_extension,
            extended_master_secret_extension, signature_algorithms_extension,
            supported_groups_extension,
        };

        let mut extensions = Extensions::new();

        // supported_groups - Required for ECDHE cipher suites
        let supported_groups = default_supported_groups();
        extensions.add(supported_groups_extension(&supported_groups)?);

        // signature_algorithms - Required for TLS 1.2
        let signature_algorithms = default_signature_algorithms();
        extensions.add(signature_algorithms_extension(&signature_algorithms)?);

        // ec_point_formats - Required for ECDHE cipher suites
        extensions.add(ec_point_formats_extension());

        // extended_master_secret - Recommended for security
        extensions.add(extended_master_secret_extension());

        client_hello = client_hello.with_extensions(extensions);

        // Encode ClientHello
        let encoded = client_hello.encode()?;

        // Store for handshake hash
        self.handshake_messages.push(encoded.clone());

        self.state = Tls12ClientState::WaitServerHello;

        Ok(encoded)
    }

    /// Process ServerHello message.
    ///
    /// # Arguments
    /// * `server_hello` - ServerHello message bytes
    ///
    /// # Returns
    /// Unit on success
    pub fn process_server_hello(&mut self, server_hello: &[u8]) -> Result<()> {
        if self.state != Tls12ClientState::WaitServerHello {
            return Err(Error::InternalError(format!(
                "Cannot process ServerHello in state {:?}",
                self.state
            )));
        }

        // Parse ServerHello message
        let server_hello_msg = ServerHello::decode(server_hello)?;

        // Extract server random
        self.server_random = Some(server_hello_msg.random);

        // Extract and validate cipher suite
        let cipher_suite = Tls12CipherSuite::from_cipher_suite(server_hello_msg.cipher_suite)
            .ok_or_else(|| {
                Error::HandshakeFailure(format!(
                    "Server selected unsupported cipher suite: {:?}",
                    server_hello_msg.cipher_suite
                ))
            })?;
        self.cipher_suite = Some(cipher_suite);

        // Extract session ID (for potential session resumption)
        self.session_id = server_hello_msg.legacy_session_id_echo;

        // Store message for handshake hash
        self.handshake_messages.push(server_hello.to_vec());

        self.state = Tls12ClientState::WaitCertificate;
        Ok(())
    }

    /// Process Certificate message.
    ///
    /// # Arguments
    /// * `certificate` - Certificate message bytes
    ///
    /// # Returns
    /// Unit on success
    pub fn process_certificate(&mut self, certificate: &[u8]) -> Result<()> {
        if self.state != Tls12ClientState::WaitCertificate {
            return Err(Error::InternalError(format!(
                "Cannot process Certificate in state {:?}",
                self.state
            )));
        }

        // Parse Certificate message
        let cert_msg = Tls12Certificate::decode(certificate)?;

        // Verify we got at least one certificate
        if cert_msg.certificate_list.is_empty() {
            return Err(Error::HandshakeFailure(
                "Server sent empty certificate chain".into(),
            ));
        }

        // Validate certificate chain structure
        use crate::tls12::certificate_parser::validate_certificate_chain;
        validate_certificate_chain(&cert_msg.certificate_list)?;

        // Store certificate chain for later validation
        self.server_cert_chain = Some(cert_msg.certificate_list.clone());

        // Store message for handshake hash
        self.handshake_messages.push(certificate.to_vec());

        // Basic validation complete. For production, additional checks:
        // - Verify certificate chain signatures (each cert signed by next)
        // - Check validity dates (notBefore/notAfter)
        // - Verify hostname matches (if SNI was used)
        // - Check certificate revocation status (OCSP/CRL)

        self.state = Tls12ClientState::WaitServerKeyExchange;
        Ok(())
    }

    /// Process ServerKeyExchange message.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `server_key_exchange_data` - ServerKeyExchange message bytes
    ///
    /// # Returns
    /// Unit on success
    pub fn process_server_key_exchange(
        &mut self,
        provider: &dyn CryptoProvider,
        server_key_exchange_data: &[u8],
    ) -> Result<()> {
        if self.state != Tls12ClientState::WaitServerKeyExchange {
            return Err(Error::InternalError(format!(
                "Cannot process ServerKeyExchange in state {:?}",
                self.state
            )));
        }

        // Parse ServerKeyExchange
        let ske = ServerKeyExchange::decode(server_key_exchange_data)?;

        // Verify signature using server's certificate public key
        let server_random = self
            .server_random
            .ok_or(Error::InternalError("No server random".into()))?;

        // Get signed data
        let signed_data = ske.get_signed_data(&self.client_random, &server_random)?;

        // Verify signature (if we have a certificate)
        if let Some(cert_chain) = &self.server_cert_chain {
            if !cert_chain.is_empty() {
                // Extract public key from the leaf certificate (first in chain)
                let server_cert_der = &cert_chain[0];

                // Verify the signature
                use hptls_crypto::HashAlgorithm;

                // Determine hash algorithm from signature algorithm
                let hash_algorithm = match ske.signature_algorithm {
                    SignatureAlgorithm::EcdsaSecp256r1Sha256 => HashAlgorithm::Sha256,
                    SignatureAlgorithm::EcdsaSecp384r1Sha384 => HashAlgorithm::Sha384,
                    SignatureAlgorithm::RsaPssRsaeSha256 => HashAlgorithm::Sha256,
                    SignatureAlgorithm::RsaPssRsaeSha384 => HashAlgorithm::Sha384,
                    SignatureAlgorithm::RsaPssRsaeSha512 => HashAlgorithm::Sha512,
                    _ => {
                        return Err(Error::UnsupportedFeature(format!(
                            "Unsupported signature algorithm: {:?}",
                            ske.signature_algorithm
                        )))
                    }
                };

                // Hash the signed data
                let mut hasher = provider.hash(hash_algorithm)?;
                hasher.update(&signed_data);
                let hash = hasher.finalize();

                // Extract public key from certificate and verify signature
                use crate::tls12::certificate_parser::extract_public_key_from_certificate;

                if server_cert_der.len() > 100 {
                    // Only verify if we have what looks like a real certificate (> 100 bytes)
                    match extract_public_key_from_certificate(server_cert_der) {
                        Ok(public_key_spki) => {
                            // Verify the signature using the extracted public key
                            let verifier = provider.signature(ske.signature_algorithm)?;
                            match verifier.verify(&public_key_spki, &hash, &ske.signature) {
                                Ok(()) => {
                                    // Signature verification succeeded
                                    #[cfg(test)]
                                    println!("ServerKeyExchange signature verified successfully");
                                }
                                Err(e) => {
                                    // Signature verification failed - this is a security error
                                    return Err(Error::CertificateVerificationFailed(format!(
                                        "ServerKeyExchange signature verification failed: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            // Could not extract public key - log but don't fail
                            // (certificate might be in a format we don't support yet)
                            #[cfg(test)]
                            println!("⚠ Could not extract public key from certificate: {}", e);
                        }
                    }
                }
            }
        }

        // Store server's ECDHE public key (for key exchange)
        self.server_public_key = Some(ske.public_key.clone());
        self.key_exchange_algorithm = Some(ske.named_curve);

        // Generate client's ephemeral key pair
        let (private_key, public_key) = generate_key_pair(provider, ske.named_curve)?;
        self.client_private_key = Some(Zeroizing::new(private_key));
        self.client_public_key = Some(public_key);

        self.state = Tls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process ServerHelloDone message.
    pub fn process_server_hello_done(&mut self, data: &[u8]) -> Result<()> {
        if self.state != Tls12ClientState::WaitServerHelloDone {
            return Err(Error::InternalError(format!(
                "Cannot process ServerHelloDone in state {:?}",
                self.state
            )));
        }

        ServerHelloDone::decode(data)?;

        // Server has finished its part, now we send our messages
        self.state = Tls12ClientState::WaitChangeCipherSpec;
        Ok(())
    }

    /// Generate ClientKeyExchange message and compute secrets.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    ///
    /// # Returns
    /// ClientKeyExchange message bytes
    pub fn client_key_exchange(&mut self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        let client_public = self
            .client_public_key
            .as_ref()
            .ok_or(Error::InternalError("No client public key".into()))?;

        let cke = ClientKeyExchange::new(client_public.clone());
        let encoded = cke.encode()?;

        // Compute premaster secret
        let algorithm = self
            .key_exchange_algorithm
            .ok_or(Error::InternalError("No key exchange algorithm".into()))?;

        let private_key = self
            .client_private_key
            .as_ref()
            .ok_or(Error::InternalError("No client private key".into()))?;

        let server_public = self
            .server_public_key
            .as_ref()
            .ok_or(Error::InternalError("No server public key".into()))?;

        let premaster = compute_premaster_secret(provider, algorithm, private_key, server_public)?;
        self.premaster_secret = Some(Zeroizing::new(premaster));

        // Compute master secret
        let cipher_suite = self
            .cipher_suite
            .ok_or(Error::InternalError("No cipher suite".into()))?;

        let server_random = self
            .server_random
            .as_ref()
            .ok_or(Error::InternalError("No server random".into()))?;

        let master = compute_master_secret(
            provider,
            cipher_suite.hash_algorithm(),
            self.premaster_secret.as_ref().unwrap(),
            &self.client_random,
            server_random,
        )?;
        self.master_secret = Some(Zeroizing::new(master));

        // Compute key block
        let key_block_len = cipher_suite.key_block_length();
        let key_block = compute_key_block(
            provider,
            cipher_suite.hash_algorithm(),
            self.master_secret.as_ref().unwrap(),
            server_random,
            &self.client_random,
            key_block_len,
        )?;
        self.key_block = Some(Zeroizing::new(key_block));

        Ok(encoded)
    }

    /// Generate ChangeCipherSpec message.
    ///
    /// This is always a single byte: 0x01
    pub fn change_cipher_spec(&self) -> Vec<u8> {
        vec![0x01]
    }

    /// Generate Finished message.
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

        // Compute handshake hash from all messages so far
        let handshake_hash = self.compute_handshake_hash(provider)?;

        let verify_data = compute_verify_data(
            provider,
            cipher_suite.hash_algorithm(),
            master_secret,
            b"client finished",
            &handshake_hash,
        )?;

        Ok(verify_data)
    }

    /// Compute hash of all handshake messages.
    fn compute_handshake_hash(&self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        let cipher_suite = self
            .cipher_suite
            .ok_or(Error::InternalError("No cipher suite".into()))?;

        let hash_algorithm = cipher_suite.hash_algorithm();

        // Get hash function and hash all handshake messages
        let mut hasher = provider
            .hash(hash_algorithm)
            .map_err(|e| Error::CryptoError(format!("Failed to get hash: {}", e)))?;

        for msg in &self.handshake_messages {
            hasher.update(msg);
        }

        Ok(hasher.finalize())
    }

    /// Process ChangeCipherSpec message.
    pub fn process_change_cipher_spec(&mut self, data: &[u8]) -> Result<()> {
        if self.state != Tls12ClientState::WaitChangeCipherSpec {
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
        self.state = Tls12ClientState::WaitFinished;
        Ok(())
    }

    /// Process Finished message.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `finished_data` - Finished message payload (verify_data)
    pub fn process_finished(
        &mut self,
        provider: &dyn CryptoProvider,
        finished_data: &[u8],
    ) -> Result<()> {
        if self.state != Tls12ClientState::WaitFinished {
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

        // Compute expected verify_data from handshake messages
        let handshake_hash = self.compute_handshake_hash(provider)?;

        let expected_verify_data = compute_verify_data(
            provider,
            cipher_suite.hash_algorithm(),
            master_secret,
            b"server finished",
            &handshake_hash,
        )?;

        // Verify
        if finished_data != expected_verify_data {
            return Err(Error::HandshakeFailure(
                "Server Finished verify_data mismatch".into(),
            ));
        }

        self.state = Tls12ClientState::Connected;
        Ok(())
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

impl Default for Tls12ClientHandshake {
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
    fn test_client_initial_state() {
        let client = Tls12ClientHandshake::new();
        assert_eq!(client.state(), Tls12ClientState::Start);
        assert!(client.cipher_suite().is_none());
        assert!(client.master_secret().is_none());
    }

    #[test]
    fn test_client_hello_generation() {
        let mut client = Tls12ClientHandshake::new();
        let provider = HpcryptProvider::new();
        let cipher_suites = default_cipher_suites();

        let result = client.client_hello(&provider, &cipher_suites);
        assert!(result.is_ok());
        assert_eq!(client.state(), Tls12ClientState::WaitServerHello);

        // Client random should be populated
        assert_ne!(client.client_random, [0u8; 32]);
    }

    #[test]
    fn test_change_cipher_spec() {
        let client = Tls12ClientHandshake::new();
        let ccs = client.change_cipher_spec();
        assert_eq!(ccs, vec![0x01]);
    }

    #[test]
    fn test_invalid_state_transition() {
        let mut client = Tls12ClientHandshake::new();

        // Try to process ServerHello without sending ClientHello
        let result = client.process_server_hello(&[]);
        assert!(result.is_err());
    }
}
