//! DTLS 1.3 Client and Server APIs
//!
//! This module provides high-level APIs for DTLS 1.3 client and server functionality.
//!
//! # Example - DTLS Client
//!
//! ```rust,no_run
//! use hptls::dtls::{DtlsClientConfig, DtlsClient};
//! use std::net::UdpSocket;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create DTLS client configuration
//! let config = DtlsClientConfig::builder()
//!     .with_server_name("example.com".to_string())
//!     .build()?;
//!
//! // Create UDP socket
//! let socket = UdpSocket::bind("0.0.0.0:0")?;
//! socket.connect("example.com:4433")?;
//!
//! // Create DTLS client
//! let mut client = DtlsClient::new(config, socket)?;
//!
//! // Perform handshake
//! client.connect()?;
//!
//! // Send/receive data
//! client.write(b"Hello, DTLS!")?;
//! let mut buf = [0u8; 1024];
//! let n = client.read(&mut buf)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Example - DTLS Server
//!
//! ```rust,no_run
//! use hptls::dtls::{DtlsServerConfig, DtlsServer};
//! use std::net::UdpSocket;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create DTLS server configuration
//! let config = DtlsServerConfig::builder()
//!     .with_certificate_chain(vec![/* ... */])
//!     .with_private_key(vec![/* ... */])
//!     .build()?;
//!
//! // Create UDP socket
//! let socket = UdpSocket::bind("0.0.0.0:4433")?;
//!
//! // Create DTLS server
//! let mut server = DtlsServer::new(config, socket)?;
//!
//! // Accept connection and handle handshake
//! server.accept()?;
//!
//! // Send/receive data
//! let mut buf = [0u8; 1024];
//! let n = server.read(&mut buf)?;
//! server.write(b"Hello from DTLS server!")?;
//! # Ok(())
//! # }
//! ```

use hptls_core::alert::Alert;
use hptls_core::cipher::CipherSuite;
use hptls_core::dtls::{
    DtlsRecordHeader, DtlsState, Epoch, DTLS_13_VERSION,
    DtlsClientHandshake, DtlsServerHandshake,
    record_protection::{DtlsCiphertext, DtlsRecordProtection},
};
use hptls_core::error::{Error, Result};
use hptls_core::messages::key_update::{KeyUpdate, KeyUpdateRequest};
use hptls_core::extension_types::TypedExtension;
use hptls_core::extensions::Extensions;
use hptls_core::handshake::client::ClientHandshake;
use hptls_core::handshake::server::ServerHandshake;
use hptls_core::messages::{
    Certificate, CertificateVerify, ClientHello, EncryptedExtensions, Finished, HelloRetryRequest,
    ServerHello,
};
use hptls_core::protocol::ContentType;
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;
use std::net::UdpSocket;
use std::time::Duration;

/// DTLS client configuration
#[derive(Debug, Clone)]
pub struct DtlsClientConfig {
    /// Server name for SNI
    pub server_name: Option<String>,
    /// Supported cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Maximum transmission unit (MTU)
    pub mtu: usize,
    /// Initial retransmit timeout
    pub retransmit_timeout: Duration,
}

impl DtlsClientConfig {
    /// Create a new configuration builder
    pub fn builder() -> DtlsClientConfigBuilder {
        DtlsClientConfigBuilder::default()
    }
}

/// Builder for DTLS client configuration
#[derive(Debug, Default)]
pub struct DtlsClientConfigBuilder {
    server_name: Option<String>,
    cipher_suites: Option<Vec<CipherSuite>>,
    mtu: Option<usize>,
    retransmit_timeout: Option<Duration>,
}

impl DtlsClientConfigBuilder {
    /// Set the server name for SNI
    ///
    /// # Arguments
    /// * `name` - Server name for SNI extension
    pub fn with_server_name(mut self, name: String) -> Self {
        self.server_name = Some(name);
        self
    }

    /// Set supported cipher suites
    ///
    /// # Arguments
    /// * `suites` - List of cipher suites to support
    pub fn with_cipher_suites(mut self, suites: Vec<CipherSuite>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    /// Set the MTU (Maximum Transmission Unit)
    ///
    /// # Arguments
    /// * `mtu` - Maximum packet size in bytes (default: 1200)
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the retransmit timeout
    ///
    /// # Arguments
    /// * `timeout` - Initial retransmit timeout duration
    pub fn with_retransmit_timeout(mut self, timeout: Duration) -> Self {
        self.retransmit_timeout = Some(timeout);
        self
    }

    /// Build the configuration
    ///
    /// # Returns
    /// A configured `DtlsClientConfig`
    pub fn build(self) -> Result<DtlsClientConfig> {
        Ok(DtlsClientConfig {
            server_name: self.server_name,
            cipher_suites: self.cipher_suites.unwrap_or_else(|| {
                vec![
                    CipherSuite::Aes128GcmSha256,
                    CipherSuite::Aes256GcmSha384,
                    CipherSuite::ChaCha20Poly1305Sha256,
                ]
            }),
            mtu: self.mtu.unwrap_or(1200), // Default DTLS MTU
            retransmit_timeout: self.retransmit_timeout.unwrap_or(Duration::from_secs(1)),
        })
    }
}

/// DTLS client
pub struct DtlsClient {
    /// Configuration
    config: DtlsClientConfig,
    /// UDP socket
    socket: UdpSocket,
    /// Crypto provider
    provider: HpcryptProvider,
    /// DTLS handshake wrapper
    handshake: Option<DtlsClientHandshake>,
    /// DTLS state (epochs, sequence numbers, replay protection)
    dtls_state: DtlsState,
    /// Record protection (per-epoch encryption)
    record_protection: DtlsRecordProtection,
    /// Whether the handshake is complete
    handshake_complete: bool,
}

impl DtlsClient {
    /// Create a new DTLS client
    ///
    /// # Arguments
    /// * `config` - Client configuration
    /// * `socket` - UDP socket (should be connected to the server)
    pub fn new(config: DtlsClientConfig, socket: UdpSocket) -> Result<Self> {
        let provider = HpcryptProvider::new();
        let dtls_state = DtlsState::new();
        let record_protection = DtlsRecordProtection::new();

        Ok(Self {
            config,
            socket,
            provider,
            handshake: None,
            dtls_state,
            record_protection,
            handshake_complete: false,
        })
    }

    /// Perform the DTLS handshake
    ///
    /// Initiates the DTLS 1.3 handshake with the server, including:
    /// - Sending ClientHello with retry protection
    /// - Processing ServerHello and encrypted extensions
    /// - Verifying server certificate
    /// - Sending client Finished message
    ///
    /// # Returns
    /// `Ok(())` on successful handshake completion
    ///
    /// # Errors
    /// - `Error::HandshakeFailure` - Handshake protocol error
    /// - `Error::CertificateVerificationFailed` - Invalid server certificate
    /// - `Error::IoError` - Network communication failure
    pub fn connect(&mut self) -> Result<()> {
        // Create TLS 1.3 handshake
        let mut tls_handshake = ClientHandshake::new();

        // Step 1: Generate ClientHello using TLS 1.3 handshake logic
        // For DTLS, use DTLS 1.2 version (0xFEFD) instead of TLS 1.2 (0x0303)
        use hptls_core::protocol::ProtocolVersion;
        let client_hello = tls_handshake.client_hello(
            &self.provider,
            &self.config.cipher_suites,
            self.config.server_name.as_deref(),
            None, // No ALPN for now
            Some(ProtocolVersion::Dtls12), // Override for DTLS
        )?;

        // Step 2: Encode ClientHello as a handshake message
        let client_hello_bytes = client_hello.encode()?;

        if client_hello_bytes.len() >= 4 {
            let byte0 = client_hello_bytes[0];
            let length = u32::from_be_bytes([0, client_hello_bytes[1], client_hello_bytes[2], client_hello_bytes[3]]);
        }

        // Step 3: Create DTLS handshake wrapper and send first flight
        let mut dtls_handshake = DtlsClientHandshake::new(tls_handshake);

        // Add ClientHello to flight 1 (epoch 0)
        // msg_type = 1 (ClientHello), payload = client_hello_bytes
        dtls_handshake.add_message_to_flight(1, client_hello_bytes.clone());

        // Send flight 1
        let flight_messages = dtls_handshake.transmit_flight()?;
        for msg_bytes in &flight_messages {
            // Wrap in DTLS record and send (epoch 0 for ClientHello)
            self.send_handshake_message(msg_bytes, Epoch::INITIAL)?;
        }

        // Step 4: Receive ServerHello or HelloRetryRequest
        let mut receive_buffer = vec![0u8; self.config.mtu];

        // Receive response from server
        let n = self.socket.recv(&mut receive_buffer)
            .map_err(|e| Error::IoError(e.to_string()))?;


        let server_response_record = DtlsCiphertext::decode(&receive_buffer[..n])?;
        let dtls_handshake_bytes = &server_response_record.encrypted_record; // Unencrypted in epoch 0


        // Convert DTLS handshake message (12-byte header) to TLS format (4-byte header)
        let tls_handshake_bytes = hptls_core::dtls::handshake::decode_dtls_handshake_message(dtls_handshake_bytes)?;

        // Extract payload from TLS message (skip 4-byte header)
        if tls_handshake_bytes.len() < 4 {
            return Err(Error::InvalidMessage("TLS handshake message too short".into()));
        }
        let payload = &tls_handshake_bytes[4..];

        // Try to decode as ServerHello first
        let server_hello = match ServerHello::decode(payload) {
            Ok(sh) => {
                // Check if this is actually a HelloRetryRequest
                use hptls_core::messages::hello_retry_request::HelloRetryRequest;
                if HelloRetryRequest::is_hello_retry_request(&sh.random) {
                    // This is a HelloRetryRequest - decode it properly
                    let hrr = HelloRetryRequest::decode(payload)?;

                    // Extract cookie from HelloRetryRequest
                    let cookie = hrr.extensions.get_cookie()?
                        .ok_or_else(|| Error::InvalidMessage("HelloRetryRequest must contain cookie".into()))?;

                    // Step 4a: Send second ClientHello with cookie
                    // Generate new ClientHello with cookie extension
                    let mut client_hello2 = dtls_handshake.tls_handshake_mut().client_hello(
                        &self.provider,
                        &self.config.cipher_suites,
                        self.config.server_name.as_deref(),
                        None,
                        Some(ProtocolVersion::Dtls12), // Override for DTLS
                    )?;

                    // Add cookie to extensions
                    client_hello2.extensions.add_cookie(cookie)?;

                    let client_hello2_bytes = client_hello2.encode()?;

                    // Send second ClientHello
                    self.send_handshake_message(&client_hello2_bytes, Epoch::INITIAL)?;

                    // Step 4b: Receive ServerHello after HelloRetryRequest
                    let n = self.socket.recv(&mut receive_buffer)
                        .map_err(|e| Error::IoError(e.to_string()))?;
                    receive_buffer.truncate(n);

                    let server_hello_record2 = DtlsCiphertext::decode(&receive_buffer)?;
                    let dtls_handshake_bytes2 = &server_hello_record2.encrypted_record;
                    let tls_handshake_bytes2 = hptls_core::dtls::handshake::decode_dtls_handshake_message(dtls_handshake_bytes2)?;
                    // Skip the 4-byte TLS handshake header (msg_type + 3-byte length)
                    ServerHello::decode(&tls_handshake_bytes2[4..])?
                } else {
                    // Normal ServerHello
                    sh
                }
            }
            Err(e) => return Err(e),
        };

        // Process ServerHello in TLS handshake
        dtls_handshake.tls_handshake_mut().process_server_hello(&self.provider, &server_hello)?;

        // Acknowledge flight 1 (ServerHello received)
        dtls_handshake.acknowledge_flight(1);

        // Step 5: Derive handshake keys and advance to epoch 1
        let client_hs_secret = dtls_handshake.tls_handshake()
            .get_client_handshake_traffic_secret()
            .ok_or_else(|| Error::InternalError("Client handshake secret not available".to_string()))?;
        let server_hs_secret = dtls_handshake.tls_handshake()
            .get_server_handshake_traffic_secret()
            .ok_or_else(|| Error::InternalError("Server handshake secret not available".to_string()))?;


        let cipher_suite = dtls_handshake.tls_handshake()
            .cipher_suite()
            .ok_or_else(|| Error::InternalError("Cipher suite not negotiated".to_string()))?;

        // Set up handshake epoch encryption (epoch 1)
        // In TLS 1.3, client uses client_hs_secret for sending and server_hs_secret for receiving
        self.record_protection.add_epoch_bidirectional(
            &self.provider,
            Epoch::HANDSHAKE,
            cipher_suite,
            client_hs_secret,  // Write with client secret
            server_hs_secret,  // Read with server secret
        )?;
        self.record_protection.set_write_epoch(Epoch::HANDSHAKE)?;
        self.record_protection.set_read_epoch(Epoch::HANDSHAKE)?;

        // Advance DTLS state to epoch 1
        self.dtls_state.next_epoch()?;
        dtls_handshake.advance_epoch()?;

        // Step 6: Receive encrypted messages (EncryptedExtensions, Certificate, CertificateVerify, Finished)
        // These are all encrypted with handshake keys

        // Receive EncryptedExtensions
        let n = self.socket.recv(&mut receive_buffer)
            .map_err(|e| Error::IoError(e.to_string()))?;
        let enc_ext_record = DtlsCiphertext::decode(&receive_buffer[..n])?;
        let enc_ext_plaintext = self.record_protection.decrypt(&self.provider, &enc_ext_record)?;
        // Convert DTLS handshake message (12-byte header) to TLS format (4-byte header)
        let tls_handshake_bytes = hptls_core::dtls::handshake::decode_dtls_handshake_message(&enc_ext_plaintext.fragment)?;
        // Skip 4-byte TLS handshake header (msg_type + 3-byte length)
        if tls_handshake_bytes.len() < 4 {
            return Err(Error::InvalidMessage("EncryptedExtensions message too short".into()));
        }
        let encrypted_extensions = EncryptedExtensions::decode(&tls_handshake_bytes[4..])?;
        dtls_handshake.tls_handshake_mut().process_encrypted_extensions(&encrypted_extensions)?;

        // Receive Certificate
        let n = self.socket.recv(&mut receive_buffer)
            .map_err(|e| Error::IoError(e.to_string()))?;
        let cert_record = DtlsCiphertext::decode(&receive_buffer[..n])?;
        let cert_plaintext = self.record_protection.decrypt(&self.provider, &cert_record)?;
        // Convert DTLS handshake message (12-byte header) to TLS format (4-byte header)
        let tls_handshake_bytes = hptls_core::dtls::handshake::decode_dtls_handshake_message(&cert_plaintext.fragment)?;
        // Skip 4-byte TLS handshake header (msg_type + 3-byte length)
        if tls_handshake_bytes.len() < 4 {
            return Err(Error::InvalidMessage("Certificate message too short".into()));
        }
        let certificate = Certificate::decode(&tls_handshake_bytes[4..])?;
        dtls_handshake.tls_handshake_mut().process_certificate(&certificate)?;

        // Receive CertificateVerify
        let n = self.socket.recv(&mut receive_buffer)
            .map_err(|e| Error::IoError(e.to_string()))?;
        let cert_verify_record = DtlsCiphertext::decode(&receive_buffer[..n])?;
        let cert_verify_plaintext = self.record_protection.decrypt(&self.provider, &cert_verify_record)?;
        // Convert DTLS handshake message (12-byte header) to TLS format (4-byte header)
        let tls_handshake_bytes = hptls_core::dtls::handshake::decode_dtls_handshake_message(&cert_verify_plaintext.fragment)?;
        // Skip 4-byte TLS handshake header (msg_type + 3-byte length)
        if tls_handshake_bytes.len() < 4 {
            return Err(Error::InvalidMessage("CertificateVerify message too short".into()));
        }
        let cert_verify = CertificateVerify::decode(&tls_handshake_bytes[4..])?;

        // Verify signature before processing
        dtls_handshake.tls_handshake_mut().verify_server_certificate_signature(&self.provider, &cert_verify)?;
        dtls_handshake.tls_handshake_mut().process_certificate_verify(&cert_verify)?;

        // Receive server Finished
        let n = self.socket.recv(&mut receive_buffer)
            .map_err(|e| Error::IoError(e.to_string()))?;
        let finished_record = DtlsCiphertext::decode(&receive_buffer[..n])?;
        let finished_plaintext = self.record_protection.decrypt(&self.provider, &finished_record)?;
        // Convert DTLS handshake message (12-byte header) to TLS format (4-byte header)
        let tls_handshake_bytes = hptls_core::dtls::handshake::decode_dtls_handshake_message(&finished_plaintext.fragment)?;
        // Skip 4-byte TLS handshake header (msg_type + 3-byte length)
        if tls_handshake_bytes.len() < 4 {
            return Err(Error::InvalidMessage("Finished message too short".into()));
        }
        let server_finished = Finished::decode(&tls_handshake_bytes[4..])?;

        // Process server Finished and generate client Finished
        let client_finished = dtls_handshake.tls_handshake_mut()
            .process_server_finished(&self.provider, &server_finished)?;

        // Derive application keys BEFORE sending Finished (they're needed after)
        let client_app_secret = dtls_handshake.tls_handshake()
            .get_client_application_traffic_secret()
            .ok_or_else(|| Error::InternalError("Client app secret not available".to_string()))?;
        let server_app_secret = dtls_handshake.tls_handshake()
            .get_server_application_traffic_secret()
            .ok_or_else(|| Error::InternalError("Server app secret not available".to_string()))?;

        // Set up application data epoch (epoch 2) but DON'T activate it yet
        // We need to send Finished with epoch 1 (handshake) keys first
        self.record_protection.add_epoch_bidirectional(
            &self.provider,
            Epoch::APPLICATION,
            cipher_suite,
            client_app_secret,  // Write with client secret
            server_app_secret,  // Read with server secret
        )?;

        // Step 7: Send client Finished (encrypted with handshake keys, epoch 1)
        let client_finished_payload = client_finished.encode()?;

        // Wrap in DTLS handshake format (12-byte header)
        let payload_len = client_finished_payload.len();
        let mut client_finished_dtls = Vec::with_capacity(12 + payload_len);
        client_finished_dtls.push(20); // Finished message type
        client_finished_dtls.extend_from_slice(&[
            ((payload_len >> 16) & 0xFF) as u8,
            ((payload_len >> 8) & 0xFF) as u8,
            (payload_len & 0xFF) as u8,
        ]);
        client_finished_dtls.extend_from_slice(&0u16.to_be_bytes()); // message_seq = 0
        client_finished_dtls.extend_from_slice(&[0, 0, 0]); // fragment_offset = 0
        client_finished_dtls.extend_from_slice(&[
            ((payload_len >> 16) & 0xFF) as u8,
            ((payload_len >> 8) & 0xFF) as u8,
            (payload_len & 0xFF) as u8,
        ]);
        client_finished_dtls.extend_from_slice(&client_finished_payload);

        // Encrypt with epoch 1 (handshake keys) - current write epoch is still 1
        let client_finished_seq = self.dtls_state.next_send_sequence()?;

        let client_finished_ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::Handshake,
            &client_finished_dtls,
            client_finished_seq,
        )?;
        let client_finished_encoded = client_finished_ciphertext.encode();

        // Add small delay to prevent UDP packet mixing
        std::thread::sleep(std::time::Duration::from_millis(10));

        self.socket.send(&client_finished_encoded)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Acknowledge all server flights
        dtls_handshake.acknowledge_all_flights();

        // Step 8: NOW advance to epoch 2 for application data
        self.record_protection.set_write_epoch(Epoch::APPLICATION)?;
        self.record_protection.set_read_epoch(Epoch::APPLICATION)?;

        self.dtls_state.next_epoch()?;

        // Handshake complete!
        self.handshake = Some(dtls_handshake);
        self.handshake_complete = true;

        Ok(())
    }

    /// Helper: Send a handshake message wrapped in DTLS record
    fn send_handshake_message(&mut self, message: &[u8], epoch: Epoch) -> Result<()> {
        let seq = self.dtls_state.send_sequence;

        let header = DtlsRecordHeader {
            content_type: ContentType::Handshake,
            legacy_version: DTLS_13_VERSION,
            epoch,
            sequence_number: seq,
            length: message.len() as u16,
        };

        let mut record_bytes = Vec::from(header.encode());
        record_bytes.extend_from_slice(message);

        self.socket.send(&record_bytes)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Increment sequence number
        self.dtls_state.send_sequence.0 = self.dtls_state.send_sequence.0.wrapping_add(1);

        Ok(())
    }

    /// Send application data to the server
    ///
    /// Encrypts and sends data over the established DTLS connection.
    ///
    /// # Arguments
    /// * `data` - Application data to send
    ///
    /// # Returns
    /// Number of bytes sent
    ///
    /// # Errors
    /// - `Error::InternalError` - Handshake not complete
    /// - `Error::IoError` - Network send failure
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Handshake not complete".to_string(),
            ));
        }

        // Get next sequence number
        let seq = self.dtls_state.next_send_sequence()?;

        // Encrypt the data
        let ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::ApplicationData,
            data,
            seq,
        )?;

        // Send over UDP
        let encoded = ciphertext.encode();
        self.socket.send(&encoded).map_err(|e| Error::IoError(e.to_string()))?;

        Ok(data.len())
    }

    /// Receive application data from the server
    ///
    /// Receives and decrypts data from the established DTLS connection.
    ///
    /// # Arguments
    /// * `buf` - Buffer to store received data
    ///
    /// # Returns
    /// Number of bytes read into the buffer
    ///
    /// # Errors
    /// - `Error::InternalError` - Handshake not complete
    /// - `Error::InvalidMessage` - Replay attack detected or invalid record
    /// - `Error::DecryptionFailed` - AEAD decryption failure
    /// - `Error::IoError` - Network receive failure
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Handshake not complete".to_string(),
            ));
        }

        // Receive UDP datagram
        let mut recv_buf = vec![0u8; self.config.mtu];
        let n = self.socket.recv(&mut recv_buf).map_err(|e| Error::IoError(e.to_string()))?;
        recv_buf.truncate(n);

        // Decode DTLS record
        let ciphertext = DtlsCiphertext::decode(&recv_buf)?;

        // Check replay protection
        if !self
            .dtls_state
            .check_replay(ciphertext.header.epoch, ciphertext.header.sequence_number)
        {
            return Err(Error::InvalidMessage("Replay detected".to_string()));
        }

        // Decrypt
        let plaintext = self.record_protection.decrypt(&self.provider, &ciphertext)?;

        // Handle different content types
        match plaintext.content_type {
            ContentType::ApplicationData => {
                // Copy application data to output buffer
                let len = plaintext.fragment.len().min(buf.len());
                buf[..len].copy_from_slice(&plaintext.fragment[..len]);
                Ok(len)
            }
            ContentType::Alert => {
                // Decode and handle alert
                let alert = Alert::decode(&plaintext.fragment)?;

                if alert.description == hptls_core::error::AlertDescription::CloseNotify {
                    self.handshake_complete = false;
                    return Err(Error::AlertReceived(alert.description));
                }

                if alert.is_fatal() {
                    self.handshake_complete = false;
                    return Err(Error::AlertReceived(alert.description));
                }

                // For non-fatal alerts, try to read again
                self.read(buf)
            }
            _ => {
                Err(Error::InvalidMessage(format!(
                    "Unexpected content type: {:?}",
                    plaintext.content_type
                )))
            }
        }
    }

    /// Check if retransmission is needed and perform it
    ///
    /// This should be called periodically during the handshake to handle
    /// packet loss. It checks if the retransmission timer has expired and
    /// retransmits the last flight if necessary.
    ///
    /// # Returns
    /// - `Ok(true)` if a retransmission was performed
    /// - `Ok(false)` if no retransmission was needed
    /// - `Err` if retransmission failed or max retries exceeded
    ///
    /// # Example
    /// ```no_run
    /// # use hptls::dtls::*;
    /// # use std::net::UdpSocket;
    /// # use std::time::Duration;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = DtlsClientConfig::builder().build()?;
    /// # let socket = UdpSocket::bind("0.0.0.0:0")?;
    /// # let mut client = DtlsClient::new(config, socket)?;
    /// loop {
    ///     // Check for retransmission
    ///     if client.poll_retransmit()? {
    ///         println!("Retransmitted flight");
    ///     }
    ///
    ///     // Try to receive data with timeout
    ///     // (implementation specific)
    ///
    ///     std::thread::sleep(Duration::from_millis(100));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn poll_retransmit(&mut self) -> Result<bool> {
        // Only retransmit during handshake
        if self.handshake_complete {
            return Ok(false);
        }

        // Check if retransmission is needed
        if !self.dtls_state.retransmit_timer.should_retransmit() {
            return Ok(false);
        }

        // Get handshake wrapper
        let handshake = self
            .handshake
            .as_mut()
            .ok_or_else(|| Error::InternalError("No handshake in progress".into()))?;

        // Check if there's a flight to retransmit
        if !handshake.has_flight_to_retransmit() {
            return Ok(false);
        }

        // Perform retransmission with exponential backoff
        self.dtls_state.retransmit_timer.retransmit()?;

        // Determine epoch before borrowing for retransmission
        let is_encrypted = handshake.is_encrypted();

        // Get the flight to retransmit
        let flight_messages = handshake.retransmit_current_flight()?;

        // Drop the mutable borrow before sending messages
        drop(handshake);

        // Retransmit all messages in the flight
        for msg_bytes in &flight_messages {
            // Determine epoch based on handshake state
            let epoch = if is_encrypted {
                Epoch(1) // Encrypted handshake messages
            } else {
                Epoch::INITIAL // Initial ClientHello
            };

            self.send_handshake_message(msg_bytes, epoch)?;
        }

        Ok(true)
    }

    /// Get the current retransmission timeout
    ///
    /// Returns the current timeout value, which increases with each retransmission
    /// using exponential backoff.
    pub fn retransmit_timeout(&self) -> Duration {
        self.dtls_state.retransmit_timer.current_timeout()
    }

    /// Get the number of retransmissions performed
    ///
    /// Useful for monitoring handshake reliability
    pub fn retransmit_count(&self) -> u32 {
        self.dtls_state.retransmit_timer.retransmit_count()
    }

    /// Close the DTLS connection gracefully by sending close_notify alert
    pub fn close(&mut self) -> Result<()> {
        if !self.handshake_complete {
            // Nothing to close
            return Ok(());
        }

        // Create close_notify alert
        let alert = Alert::close_notify();
        let alert_bytes = alert.encode();

        // Encrypt and send the close_notify alert with application epoch
        let seq = self.dtls_state.next_send_sequence()?;
        let alert_ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::Alert,
            &alert_bytes,
            seq,
        )?;

        let encoded = alert_ciphertext.encode();
        self.socket.send(&encoded)
            .map_err(|e| Error::IoError(e.to_string()))?;

        self.handshake_complete = false;
        Ok(())
    }

    /// Send a TLS alert to the server
    ///
    /// This is a lower-level method for sending arbitrary alerts.
    /// Most users should use `close()` for graceful shutdown instead.
    pub fn send_alert(&mut self, alert: Alert) -> Result<()> {
        let alert_bytes = alert.encode();

        // Determine which epoch to use based on handshake state
        let seq = if self.handshake_complete {
            // Use application epoch for post-handshake alerts
            self.dtls_state.next_send_sequence()?
        } else {
            // Use handshake epoch or initial epoch for handshake alerts
            self.dtls_state.next_send_sequence()?
        };

        let alert_ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::Alert,
            &alert_bytes,
            seq,
        )?;

        let encoded = alert_ciphertext.encode();
        self.socket.send(&encoded)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Fatal alerts should terminate the connection
        if alert.is_fatal() {
            self.handshake_complete = false;
        }

        Ok(())
    }

    /// Send an unexpected_message alert (fatal)
    pub fn send_unexpected_message_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::UnexpectedMessage))
    }

    /// Send a decode_error alert (fatal)
    pub fn send_decode_error_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::DecodeError))
    }

    /// Send a handshake_failure alert (fatal)
    pub fn send_handshake_failure_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::HandshakeFailure))
    }

    /// Send a bad_record_mac alert (fatal)
    pub fn send_bad_record_mac_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::BadRecordMac))
    }

    /// Send an internal_error alert (fatal)
    pub fn send_internal_error_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::InternalError))
    }

    /// Request a key update from the server (RFC 8446 Section 4.6.3)
    ///
    /// Initiates post-handshake rekeying to update traffic secrets, enhancing
    /// forward secrecy. This sends a KeyUpdate message with `update_requested` flag,
    /// requiring the server to respond with its own KeyUpdate message.
    ///
    /// # Protocol Behavior
    /// - Client sends KeyUpdate(update_requested=1)
    /// - Server must respond with KeyUpdate
    /// - Both parties update their traffic keys
    ///
    /// # Errors
    /// Returns error if called before handshake completion or if send fails.
    ///
    /// # Note
    /// Current implementation sends the message but does not yet update local keys.
    /// Key derivation integration with KeySchedule is pending.
    pub fn request_key_update(&mut self) -> Result<()> {
        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Cannot update keys before handshake completion".into(),
            ));
        }

        // Create KeyUpdate message requesting update from peer
        let key_update = KeyUpdate::new(KeyUpdateRequest::UpdateRequested);
        let payload = key_update.encode()?;

        // Send as handshake message
        let seq = self.dtls_state.next_send_sequence()?;
        let ciphertext = self.record_protection.encrypt(
            &self.provider,
            hptls_core::protocol::ContentType::Handshake,
            &payload,
            seq,
        )?;

        let encoded = ciphertext.encode();
        self.socket
            .send(&encoded)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Update our sending keys (client application traffic secret)
        if let Some(handshake) = &mut self.handshake {
            let tls_handshake = handshake.tls_handshake_mut();

            // Update client application traffic secret to generation N+1
            if let Some(key_schedule) = tls_handshake.key_schedule_mut() {
                key_schedule.update_client_application_traffic_secret(&self.provider)?;

                // Get the new secrets and cipher suite
                let client_secret = tls_handshake
                    .get_client_application_traffic_secret()
                    .ok_or_else(|| Error::InternalError("Client app secret missing".into()))?;
                let server_secret = tls_handshake
                    .get_server_application_traffic_secret()
                    .ok_or_else(|| Error::InternalError("Server app secret missing".into()))?;
                let cipher_suite = tls_handshake
                    .cipher_suite()
                    .ok_or_else(|| Error::InternalError("Cipher suite not set".into()))?;

                // Update the APPLICATION epoch with new client write key
                self.record_protection.add_epoch_bidirectional(
                    &self.provider,
                    hptls_core::dtls::Epoch::APPLICATION,
                    cipher_suite,
                    client_secret,  // Updated write key
                    server_secret,  // Unchanged read key (until server updates)
                )?;
            }
        }

        Ok(())
    }

    /// Perform unilateral key update (RFC 8446 Section 4.6.3)
    ///
    /// Updates only the client's sending keys without requesting the server to
    /// update its keys. This sends a KeyUpdate message with `update_requested=0`.
    ///
    /// # Protocol Behavior
    /// - Client sends KeyUpdate(update_requested=0)
    /// - Server is NOT required to respond
    /// - Only client updates its sending keys
    ///
    /// # Use Cases
    /// Use this when you want to rotate your own keys without forcing the peer
    /// to do the same. For mutual key rotation, use [`request_key_update()`] instead.
    ///
    /// # Errors
    /// Returns error if called before handshake completion or if send fails.
    ///
    /// # Note
    /// Current implementation sends the message but does not yet update local keys.
    /// Key derivation integration with KeySchedule is pending.
    pub fn update_keys(&mut self) -> Result<()> {
        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Cannot update keys before handshake completion".into(),
            ));
        }

        // Create KeyUpdate message without requesting update from peer
        let key_update = KeyUpdate::new(KeyUpdateRequest::UpdateNotRequested);
        let payload = key_update.encode()?;

        // Send as handshake message
        let seq = self.dtls_state.next_send_sequence()?;
        let ciphertext = self.record_protection.encrypt(
            &self.provider,
            hptls_core::protocol::ContentType::Handshake,
            &payload,
            seq,
        )?;

        let encoded = ciphertext.encode();
        self.socket
            .send(&encoded)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Update our sending keys (client application traffic secret)
        if let Some(handshake) = &mut self.handshake {
            let tls_handshake = handshake.tls_handshake_mut();

            // Update client application traffic secret to generation N+1
            if let Some(key_schedule) = tls_handshake.key_schedule_mut() {
                key_schedule.update_client_application_traffic_secret(&self.provider)?;

                // Get the new secrets and cipher suite
                let client_secret = tls_handshake
                    .get_client_application_traffic_secret()
                    .ok_or_else(|| Error::InternalError("Client app secret missing".into()))?;
                let server_secret = tls_handshake
                    .get_server_application_traffic_secret()
                    .ok_or_else(|| Error::InternalError("Server app secret missing".into()))?;
                let cipher_suite = tls_handshake
                    .cipher_suite()
                    .ok_or_else(|| Error::InternalError("Cipher suite not set".into()))?;

                // Update the APPLICATION epoch with new client write key
                self.record_protection.add_epoch_bidirectional(
                    &self.provider,
                    hptls_core::dtls::Epoch::APPLICATION,
                    cipher_suite,
                    client_secret,  // Updated write key
                    server_secret,  // Unchanged read key
                )?;
            }
        }

        Ok(())
    }

    /// Send an ACK message to acknowledge received records (RFC 9147 Section 7).
    ///
    /// ACK messages allow explicit acknowledgment of successfully received records,
    /// enabling the peer to stop retransmitting acknowledged data and improving
    /// retransmission efficiency.
    ///
    /// # Arguments
    /// * `record_numbers` - List of record sequence numbers to acknowledge
    ///
    /// # Errors
    /// Returns error if encoding or sending fails.
    pub fn send_ack(&mut self, record_numbers: Vec<u64>) -> Result<()> {
        use hptls_core::messages::Ack;

        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Cannot send ACK before handshake completion".into(),
            ));
        }

        // Create ACK message
        let ack = Ack::new(record_numbers.clone());
        let payload = ack.encode()?;

        // Send as ACK content type
        let seq = self.dtls_state.next_send_sequence()?;
        let ciphertext = self.record_protection.encrypt(
            &self.provider,
            hptls_core::protocol::ContentType::Ack,
            &payload,
            seq,
        )?;

        let encoded = ciphertext.encode();
        self.socket
            .send(&encoded)
            .map_err(|e| Error::IoError(e.to_string()))?;

        Ok(())
    }
}

/// Cookie policy for DTLS DoS protection
///
/// Determines when the server should require clients to prove reachability
/// via the cookie exchange mechanism (HelloRetryRequest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookiePolicy {
    /// Always require cookie exchange for all ClientHello messages
    ///
    /// Maximum security but adds 1-RTT to all handshakes.
    /// Recommended for servers under constant attack or with very limited resources.
    Always,

    /// Require cookie exchange only when server load is high
    ///
    /// Balanced approach: normal operation has no extra RTT,
    /// cookie exchange activated when connection rate exceeds threshold.
    /// Uses a 60-second sliding window to measure connection rate.
    OnHighLoad {
        /// Connection rate threshold (connections/second) to trigger cookie exchange
        threshold: u32,
    },

    /// Never require cookie exchange (disable DoS protection)
    ///
    /// Lowest latency but vulnerable to connection exhaustion attacks.
    /// Only recommended for testing or trusted networks.
    Never,
}

impl Default for CookiePolicy {
    fn default() -> Self {
        // Default to OnHighLoad with reasonable threshold
        Self::OnHighLoad { threshold: 100 }
    }
}

/// Cookie configuration for DTLS DoS protection
///
/// Controls all aspects of cookie-based DoS protection including
/// the cookie policy, secret rotation, and operational parameters.
#[derive(Debug, Clone)]
pub struct DtlsCookieConfig {
    /// Cookie exchange policy
    pub policy: CookiePolicy,

    /// Cookie secret rotation interval
    ///
    /// How often to rotate the HMAC secret used for cookie generation.
    /// Shorter intervals improve security but increase rotation overhead.
    ///
    /// Default: 3600 seconds (1 hour)
    pub rotation_interval: Duration,

    /// Maximum cookie age
    ///
    /// How long a cookie remains valid after generation.
    /// Should be longer than expected RTT but short enough to prevent replay.
    ///
    /// Default: 60 seconds
    pub max_cookie_age: Duration,

    /// Enable cookie metrics collection
    ///
    /// When enabled, tracks cookie generation/verification statistics.
    /// **Not yet implemented** - reserved for future use.
    ///
    /// Default: false
    pub enable_metrics: bool,
}

impl Default for DtlsCookieConfig {
    fn default() -> Self {
        Self {
            policy: CookiePolicy::default(),
            rotation_interval: Duration::from_secs(3600), // 1 hour
            max_cookie_age: Duration::from_secs(60),      // 1 minute
            enable_metrics: false,
        }
    }
}

impl DtlsCookieConfig {
    /// Create a new cookie configuration builder
    pub fn builder() -> DtlsCookieConfigBuilder {
        DtlsCookieConfigBuilder::default()
    }

    /// Create configuration with "Always" policy (maximum security)
    pub fn always() -> Self {
        Self {
            policy: CookiePolicy::Always,
            ..Default::default()
        }
    }

    /// Create configuration with "Never" policy (no DoS protection)
    pub fn never() -> Self {
        Self {
            policy: CookiePolicy::Never,
            ..Default::default()
        }
    }

    /// Create configuration with "OnHighLoad" policy
    pub fn on_high_load(threshold: u32) -> Self {
        Self {
            policy: CookiePolicy::OnHighLoad { threshold },
            ..Default::default()
        }
    }

    /// Check if cookie exchange is enabled for this configuration
    pub fn is_enabled(&self) -> bool {
        !matches!(self.policy, CookiePolicy::Never)
    }
}

/// Builder for cookie configuration
#[derive(Debug, Default)]
pub struct DtlsCookieConfigBuilder {
    policy: Option<CookiePolicy>,
    rotation_interval: Option<Duration>,
    max_cookie_age: Option<Duration>,
    enable_metrics: Option<bool>,
}

impl DtlsCookieConfigBuilder {
    /// Set the cookie policy
    pub fn with_policy(mut self, policy: CookiePolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set cookie secret rotation interval
    pub fn with_rotation_interval(mut self, interval: Duration) -> Self {
        self.rotation_interval = Some(interval);
        self
    }

    /// Set maximum cookie age
    pub fn with_max_cookie_age(mut self, age: Duration) -> Self {
        self.max_cookie_age = Some(age);
        self
    }

    /// Enable metrics collection
    pub fn with_metrics(mut self, enable: bool) -> Self {
        self.enable_metrics = Some(enable);
        self
    }

    /// Build the cookie configuration
    pub fn build(self) -> DtlsCookieConfig {
        DtlsCookieConfig {
            policy: self.policy.unwrap_or_default(),
            rotation_interval: self.rotation_interval.unwrap_or(Duration::from_secs(3600)),
            max_cookie_age: self.max_cookie_age.unwrap_or(Duration::from_secs(60)),
            enable_metrics: self.enable_metrics.unwrap_or(false),
        }
    }
}

/// DTLS server configuration
#[derive(Debug, Clone)]
pub struct DtlsServerConfig {
    /// Server certificate chain (DER-encoded)
    pub certificate_chain: Vec<Vec<u8>>,
    /// Private key (DER-encoded)
    pub private_key: Vec<u8>,
    /// Supported cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Maximum transmission unit (MTU)
    pub mtu: usize,
    /// Cookie configuration for DoS protection
    pub cookie_config: DtlsCookieConfig,
}

impl DtlsServerConfig {
    /// Create a new configuration builder
    pub fn builder() -> DtlsServerConfigBuilder {
        DtlsServerConfigBuilder::default()
    }
}

/// Builder for DTLS server configuration
#[derive(Debug, Default)]
pub struct DtlsServerConfigBuilder {
    certificate_chain: Option<Vec<Vec<u8>>>,
    private_key: Option<Vec<u8>>,
    cipher_suites: Option<Vec<CipherSuite>>,
    mtu: Option<usize>,
    cookie_config: Option<DtlsCookieConfig>,
}

impl DtlsServerConfigBuilder {
    /// Set the certificate chain
    pub fn with_certificate_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.certificate_chain = Some(chain);
        self
    }

    /// Set the private key
    pub fn with_private_key(mut self, key: Vec<u8>) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Set supported cipher suites
    pub fn with_cipher_suites(mut self, suites: Vec<CipherSuite>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    /// Set the MTU
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Enable cookie-based DoS protection (deprecated - use with_cookie_config)
    ///
    /// This method is kept for backward compatibility.
    /// For new code, use `with_cookie_config()` for more control.
    #[deprecated(since = "0.2.0", note = "use with_cookie_config() instead")]
    pub fn with_cookie_exchange(mut self, enable: bool) -> Self {
        let policy = if enable {
            CookiePolicy::default()
        } else {
            CookiePolicy::Never
        };
        self.cookie_config = Some(DtlsCookieConfig {
            policy,
            ..Default::default()
        });
        self
    }

    /// Set cookie secret rotation interval (deprecated - use with_cookie_config)
    ///
    /// This method is kept for backward compatibility.
    /// For new code, use `with_cookie_config()` for more control.
    #[deprecated(since = "0.2.0", note = "use with_cookie_config() instead")]
    pub fn with_cookie_rotation_interval(mut self, interval: Duration) -> Self {
        let mut config = self.cookie_config.unwrap_or_default();
        config.rotation_interval = interval;
        self.cookie_config = Some(config);
        self
    }

    /// Set cookie configuration for DoS protection
    ///
    /// # Arguments
    /// * `config` - Complete cookie configuration including policy and rotation settings
    ///
    /// # Example
    /// ```rust,no_run
    /// use hptls::dtls::{DtlsServerConfig, DtlsCookieConfig};
    /// use std::time::Duration;
    ///
    /// let cookie_config = DtlsCookieConfig::builder()
    ///     .with_rotation_interval(Duration::from_secs(7200)) // 2 hours
    ///     .build();
    ///
    /// let config = DtlsServerConfig::builder()
    ///     .with_certificate_chain(vec![/* ... */])
    ///     .with_private_key(vec![/* ... */])
    ///     .with_cookie_config(cookie_config)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn with_cookie_config(mut self, config: DtlsCookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<DtlsServerConfig> {
        let certificate_chain = self
            .certificate_chain
            .ok_or_else(|| Error::InvalidConfig("Certificate chain required".to_string()))?;
        let private_key = self
            .private_key
            .ok_or_else(|| Error::InvalidConfig("Private key required".to_string()))?;

        Ok(DtlsServerConfig {
            certificate_chain,
            private_key,
            cipher_suites: self.cipher_suites.unwrap_or_else(|| {
                vec![
                    CipherSuite::Aes128GcmSha256,
                    CipherSuite::Aes256GcmSha384,
                    CipherSuite::ChaCha20Poly1305Sha256,
                ]
            }),
            mtu: self.mtu.unwrap_or(1200),
            cookie_config: self.cookie_config.unwrap_or_default(),
        })
    }
}

/// DTLS server
pub struct DtlsServer {
    /// Configuration
    config: DtlsServerConfig,
    /// UDP socket
    socket: UdpSocket,
    /// Crypto provider
    provider: HpcryptProvider,
    /// DTLS handshake wrapper
    handshake: Option<DtlsServerHandshake>,
    /// DTLS state
    dtls_state: DtlsState,
    /// Record protection
    record_protection: DtlsRecordProtection,
    /// Whether the handshake is complete
    handshake_complete: bool,
    /// Client address
    client_addr: Option<std::net::SocketAddr>,
    /// Cookie secret manager for DoS protection with automatic rotation
    cookie_manager: Option<hptls_core::cookie_manager::CookieSecretManager>,
    /// Connection rate tracker for OnHighLoad policy
    rate_tracker: hptls_core::connection_rate_tracker::ConnectionRateTracker,
}

impl DtlsServer {
    /// Create a new DTLS server
    ///
    /// # Arguments
    /// * `config` - Server configuration
    /// * `socket` - UDP socket (should be bound to listen address)
    pub fn new(config: DtlsServerConfig, socket: UdpSocket) -> Result<Self> {
        let provider = HpcryptProvider::new();
        let dtls_state = DtlsState::new();
        let record_protection = DtlsRecordProtection::new();

        // Create cookie manager if cookie exchange is enabled
        let cookie_manager = if config.cookie_config.is_enabled() {
            Some(hptls_core::cookie_manager::CookieSecretManager::new(
                &provider,
                config.cookie_config.rotation_interval,
            )?)
        } else {
            None
        };

        Ok(Self {
            config,
            socket,
            provider,
            handshake: None,
            dtls_state,
            record_protection,
            handshake_complete: false,
            client_addr: None,
            cookie_manager,
            rate_tracker: hptls_core::connection_rate_tracker::ConnectionRateTracker::default(),
        })
    }

    /// Accept a DTLS connection and perform handshake
    pub fn accept(&mut self) -> Result<()> {
        // Create TLS 1.3 handshake
        let tls_handshake = ServerHandshake::new(self.config.cipher_suites.clone());
        let mut dtls_handshake = DtlsServerHandshake::new(tls_handshake);

        let mut receive_buffer = vec![0u8; self.config.mtu];

        // Step 1: Receive ClientHello
        let (n, client_addr) = self.socket.recv_from(&mut receive_buffer)
            .map_err(|e| Error::IoError(e.to_string()))?;
        receive_buffer.truncate(n);
        self.client_addr = Some(client_addr);

        let client_hello_record = DtlsCiphertext::decode(&receive_buffer)?;
        let dtls_handshake_bytes = &client_hello_record.encrypted_record; // Unencrypted in epoch 0

        // Extract DTLS handshake header (12 bytes) to get payload
        if dtls_handshake_bytes.len() < 12 {
            return Err(Error::InvalidMessage("DTLS handshake message too short".into()));
        }
        let payload_len = u32::from_be_bytes([
            0,
            dtls_handshake_bytes[1],
            dtls_handshake_bytes[2],
            dtls_handshake_bytes[3],
        ]) as usize;
        let client_hello_payload = &dtls_handshake_bytes[12..12 + payload_len];

        let mut client_hello = ClientHello::decode(client_hello_payload)?;

        // Record connection attempt for rate tracking
        self.rate_tracker.record_connection();

        // Check if cookie exchange is enabled and if client sent a cookie
        if self.config.cookie_config.is_enabled() {
            let has_cookie = client_hello.extensions.get_cookie()?.is_some();

            // Determine if we should require a cookie based on policy
            let should_require_cookie = match self.config.cookie_config.policy {
                CookiePolicy::Always => true,
                CookiePolicy::OnHighLoad { threshold } => {
                    // Check if current connection rate exceeds threshold
                    self.rate_tracker.exceeds_threshold(threshold)
                }
                CookiePolicy::Never => false,
            };

            if should_require_cookie && !has_cookie {
                // Step 1a: Send HelloRetryRequest with cookie
                // Generate cookie based on client address and ClientHello
                let client_addr_bytes = client_addr.to_string().into_bytes();

                // Get cookie manager and generate cookie
                let cookie_manager = self.cookie_manager.as_ref()
                    .ok_or_else(|| Error::InternalError("Cookie manager not initialized".into()))?;
                let cookie = cookie_manager.generate_cookie(
                    &self.provider,
                    client_hello_payload,
                    &client_addr_bytes,
                )?;

                // Create HelloRetryRequest with cookie extension
                let mut hrr_extensions = Extensions::new();
                hrr_extensions.add_cookie(cookie)?;

                // Add supported_versions extension (required)
                use hptls_core::protocol::ProtocolVersion;
                hrr_extensions.add_typed(TypedExtension::SupportedVersions(vec![ProtocolVersion::Tls13]))?;

                let cipher_suite = *self.config.cipher_suites.first()
                    .ok_or_else(|| Error::InternalError("No cipher suites configured".to_string()))?;

                let hello_retry_request = HelloRetryRequest::new(cipher_suite, hrr_extensions);
                let hrr_bytes = hello_retry_request.encode()?;

                // Send HelloRetryRequest (epoch 0, unencrypted)
                self.send_handshake_message_to(&hrr_bytes, Epoch::INITIAL, client_addr)?;

                // Step 1b: Receive second ClientHello with cookie
                let n = self.socket.recv(&mut receive_buffer)
                    .map_err(|e| Error::IoError(e.to_string()))?;
                receive_buffer.truncate(n);

                let client_hello_record2 = DtlsCiphertext::decode(&receive_buffer)?;
                let client_hello_bytes2 = &client_hello_record2.encrypted_record;
                client_hello = ClientHello::decode(client_hello_bytes2)?;

                // Verify cookie in second ClientHello
                let received_cookie = client_hello.extensions.get_cookie()?
                    .ok_or_else(|| Error::InvalidMessage("Second ClientHello must contain cookie".into()))?;

                // Get cookie manager and verify cookie
                let cookie_manager = self.cookie_manager.as_ref()
                    .ok_or_else(|| Error::InternalError("Cookie manager not initialized".into()))?;
                let valid = cookie_manager.verify_cookie(
                    &self.provider,
                    &received_cookie,
                    client_hello_bytes2,
                    &client_addr_bytes,
                )?;

                if !valid {
                    return Err(Error::InvalidMessage("Cookie verification failed".into()));
                }
            }
        }

        // Process ClientHello in TLS handshake
        dtls_handshake.tls_handshake_mut().process_client_hello(&self.provider, &client_hello)?;

        // Step 2: Generate and send ServerHello
        // NOTE: The ServerHello wire format uses TLS 1.2 (0x0303), NOT DTLS 1.2 (0xFEFD)!
        // DTLS version numbers only appear in DTLS record headers, not in TLS handshake messages.
        let server_hello = dtls_handshake.tls_handshake_mut()
            .generate_server_hello(&self.provider, None)?;

        let server_hello_payload = server_hello.encode()?;

        // Build DTLS handshake message with 12-byte header
        let mut dtls_handshake_msg = Vec::with_capacity(12 + server_hello_payload.len());

        // Message type (1 byte) - ServerHello = 2
        dtls_handshake_msg.push(2);

        // Length (3 bytes, big-endian)
        let payload_len = server_hello_payload.len() as u32;
        dtls_handshake_msg.push(((payload_len >> 16) & 0xFF) as u8);
        dtls_handshake_msg.push(((payload_len >> 8) & 0xFF) as u8);
        dtls_handshake_msg.push((payload_len & 0xFF) as u8);

        // Message sequence (2 bytes) - 0 for ServerHello
        dtls_handshake_msg.extend_from_slice(&0u16.to_be_bytes());

        // Fragment offset (3 bytes) - 0 for unfragmented
        dtls_handshake_msg.extend_from_slice(&[0, 0, 0]);

        // Fragment length (3 bytes) - same as payload length for unfragmented
        dtls_handshake_msg.push(((payload_len >> 16) & 0xFF) as u8);
        dtls_handshake_msg.push(((payload_len >> 8) & 0xFF) as u8);
        dtls_handshake_msg.push((payload_len & 0xFF) as u8);

        // Payload
        dtls_handshake_msg.extend_from_slice(&server_hello_payload);

        self.send_handshake_message_to(&dtls_handshake_msg, Epoch::INITIAL, client_addr)?;

        // Step 3: Derive handshake keys and advance to epoch 1
        let client_hs_secret = dtls_handshake.tls_handshake()
            .get_client_handshake_traffic_secret()
            .ok_or_else(|| Error::InternalError("Client handshake secret not available".to_string()))?;
        let server_hs_secret = dtls_handshake.tls_handshake()
            .get_server_handshake_traffic_secret()
            .ok_or_else(|| Error::InternalError("Server handshake secret not available".to_string()))?;


        let cipher_suite = dtls_handshake.tls_handshake()
            .cipher_suite()
            .ok_or_else(|| Error::InternalError("Cipher suite not negotiated".to_string()))?;

        // Set up handshake epoch encryption (epoch 1)
        // Server uses server_hs_secret for writes, client_hs_secret for reads
        self.record_protection.add_epoch_bidirectional(
            &self.provider,
            Epoch::HANDSHAKE,
            cipher_suite,
            server_hs_secret,  // Write with server secret
            client_hs_secret,  // Read with client secret
        )?;
        self.record_protection.set_write_epoch(Epoch::HANDSHAKE)?;
        self.record_protection.set_read_epoch(Epoch::HANDSHAKE)?;

        // Advance DTLS state to epoch 1
        self.dtls_state.next_epoch()?;
        dtls_handshake.advance_epoch()?;

        // Step 4: Send encrypted handshake messages (EncryptedExtensions, Certificate, CertificateVerify, Finished)
        // NOTE: Each TLS handshake message must be wrapped in DTLS handshake format (12-byte header) before encryption

        // Helper to wrap TLS message in DTLS handshake format
        let wrap_dtls_handshake = |msg_type: u8, payload: &[u8], message_seq: u16| -> Vec<u8> {
            let payload_len = payload.len();
            let mut dtls_msg = Vec::with_capacity(12 + payload_len);

            // Build 12-byte DTLS handshake header
            dtls_msg.push(msg_type);
            dtls_msg.extend_from_slice(&[
                ((payload_len >> 16) & 0xFF) as u8,
                ((payload_len >> 8) & 0xFF) as u8,
                (payload_len & 0xFF) as u8,
            ]);
            dtls_msg.extend_from_slice(&message_seq.to_be_bytes());
            dtls_msg.extend_from_slice(&[0, 0, 0]); // fragment_offset = 0
            dtls_msg.extend_from_slice(&[
                ((payload_len >> 16) & 0xFF) as u8,
                ((payload_len >> 8) & 0xFF) as u8,
                (payload_len & 0xFF) as u8,
            ]);
            dtls_msg.extend_from_slice(payload);
            dtls_msg
        };

        // Generate and send EncryptedExtensions (message_seq = 1)
        let encrypted_extensions = dtls_handshake.tls_handshake_mut().generate_encrypted_extensions(None)?;
        let enc_ext_payload = encrypted_extensions.encode()?;
        let enc_ext_dtls = wrap_dtls_handshake(8, &enc_ext_payload, 1); // msg_type=8 for EncryptedExtensions
        let enc_ext_seq = self.dtls_state.next_send_sequence()?;
        let enc_ext_ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::Handshake,
            &enc_ext_dtls,
            enc_ext_seq,
        )?;
        let enc_ext_encoded = enc_ext_ciphertext.encode();
        self.socket.send_to(&enc_ext_encoded, client_addr)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Add small delay to prevent UDP packet mixing
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Generate and send Certificate (message_seq = 2)
        let certificate = dtls_handshake.tls_handshake_mut()
            .generate_certificate(self.config.certificate_chain.clone())?;
        let cert_payload = certificate.encode()?;
        let cert_dtls = wrap_dtls_handshake(11, &cert_payload, 2); // msg_type=11 for Certificate
        let cert_seq = self.dtls_state.next_send_sequence()?;
        let cert_ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::Handshake,
            &cert_dtls,
            cert_seq,
        )?;
        let cert_encoded = cert_ciphertext.encode();
        self.socket.send_to(&cert_encoded, client_addr)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Add small delay to prevent UDP packet mixing
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Generate and send CertificateVerify (message_seq = 3)
        let cert_verify = dtls_handshake.tls_handshake_mut()
            .generate_certificate_verify(&self.provider, &self.config.private_key)?;
        let cert_verify_payload = cert_verify.encode()?;

        // Update transcript with CertificateVerify AFTER generation
        // (the signature is computed over transcript EXCLUDING CertificateVerify itself)
        // NOTE: Just use the encoded payload, NOT the full TLS handshake message with 4-byte header
        dtls_handshake.tls_handshake_mut().update_transcript(&cert_verify_payload)?;

        let cert_verify_dtls = wrap_dtls_handshake(15, &cert_verify_payload, 3); // msg_type=15 for CertificateVerify
        let cert_verify_seq = self.dtls_state.next_send_sequence()?;
        let cert_verify_ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::Handshake,
            &cert_verify_dtls,
            cert_verify_seq,
        )?;
        let cert_verify_encoded = cert_verify_ciphertext.encode();
        self.socket.send_to(&cert_verify_encoded, client_addr)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Add small delay to prevent UDP packet mixing
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Generate and send server Finished (message_seq = 4)
        let server_finished = dtls_handshake.tls_handshake_mut().generate_server_finished(&self.provider)?;
        let finished_payload = server_finished.encode()?;
        let finished_dtls = wrap_dtls_handshake(20, &finished_payload, 4); // msg_type=20 for Finished
        let finished_seq = self.dtls_state.next_send_sequence()?;
        let finished_ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::Handshake,
            &finished_dtls,
            finished_seq,
        )?;
        let finished_encoded = finished_ciphertext.encode();
        self.socket.send_to(&finished_encoded, client_addr)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Step 5: Receive client Finished
        let n = self.socket.recv(&mut receive_buffer)
            .map_err(|e| Error::IoError(e.to_string()))?;
        receive_buffer.truncate(n);

        let client_finished_record = DtlsCiphertext::decode(&receive_buffer)?;

        let client_finished_plaintext = self.record_protection.decrypt(&self.provider, &client_finished_record)?;

        // Convert DTLS handshake message (12-byte header) to TLS format (4-byte header)
        let tls_handshake_bytes = hptls_core::dtls::handshake::decode_dtls_handshake_message(&client_finished_plaintext.fragment)?;
        // Skip 4-byte TLS handshake header (msg_type + 3-byte length)
        if tls_handshake_bytes.len() < 4 {
            return Err(Error::InvalidMessage("Client Finished message too short".into()));
        }
        let client_finished = Finished::decode(&tls_handshake_bytes[4..])?;

        // Process client Finished
        dtls_handshake.tls_handshake_mut().process_client_finished(&self.provider, &client_finished)?;

        // Step 6: Derive application keys and advance to epoch 2
        let client_app_secret = dtls_handshake.tls_handshake()
            .get_client_application_traffic_secret()
            .ok_or_else(|| Error::InternalError("Client app secret not available".to_string()))?;
        let server_app_secret = dtls_handshake.tls_handshake()
            .get_server_application_traffic_secret()
            .ok_or_else(|| Error::InternalError("Server app secret not available".to_string()))?;

        // Set up application data epoch (epoch 2)
        // Server uses server_app_secret for writes, client_app_secret for reads
        self.record_protection.add_epoch_bidirectional(
            &self.provider,
            Epoch::APPLICATION,
            cipher_suite,
            server_app_secret,  // Write with server secret
            client_app_secret,  // Read with client secret
        )?;

        self.record_protection.set_write_epoch(Epoch::APPLICATION)?;
        self.record_protection.set_read_epoch(Epoch::APPLICATION)?;

        self.dtls_state.next_epoch()?;

        // Handshake complete!
        self.handshake = Some(dtls_handshake);
        self.handshake_complete = true;

        Ok(())
    }

    /// Helper: Send a handshake message wrapped in DTLS record to specific address
    fn send_handshake_message_to(&mut self, message: &[u8], epoch: Epoch, addr: std::net::SocketAddr) -> Result<()> {
        let seq = self.dtls_state.send_sequence;

        let header = DtlsRecordHeader {
            content_type: ContentType::Handshake,
            legacy_version: DTLS_13_VERSION,
            epoch,
            sequence_number: seq,
            length: message.len() as u16,
        };

        let mut record_bytes = Vec::from(header.encode());
        record_bytes.extend_from_slice(message);

        self.socket.send_to(&record_bytes, addr)
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Increment sequence number
        self.dtls_state.send_sequence.0 = self.dtls_state.send_sequence.0.wrapping_add(1);

        Ok(())
    }

    /// Send application data to the connected client
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Handshake not complete".to_string(),
            ));
        }

        let client_addr = self
            .client_addr
            .ok_or_else(|| Error::InternalError("No client connected".to_string()))?;

        // Get next sequence number
        let seq = self.dtls_state.next_send_sequence()?;

        // Encrypt the data
        let ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::ApplicationData,
            data,
            seq,
        )?;

        // Send to client
        let encoded = ciphertext.encode();
        self.socket.send_to(&encoded, client_addr).map_err(|e| Error::IoError(e.to_string()))?;

        Ok(data.len())
    }

    /// Receive application data from the client
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Handshake not complete".to_string(),
            ));
        }

        // Receive UDP datagram
        let mut recv_buf = vec![0u8; self.config.mtu];
        let (n, addr) = self.socket.recv_from(&mut recv_buf).map_err(|e| Error::IoError(e.to_string()))?;
        recv_buf.truncate(n);

        // Verify it's from our client
        if let Some(client_addr) = self.client_addr {
            if addr != client_addr {
                return Err(Error::InvalidMessage(
                    "Packet from unexpected address".to_string(),
                ));
            }
        }

        // Decode DTLS record
        let ciphertext = DtlsCiphertext::decode(&recv_buf)?;

        // Check replay protection
        if !self
            .dtls_state
            .check_replay(ciphertext.header.epoch, ciphertext.header.sequence_number)
        {
            return Err(Error::InvalidMessage("Replay detected".to_string()));
        }

        // Decrypt
        let plaintext = self.record_protection.decrypt(&self.provider, &ciphertext)?;

        // Handle different content types
        match plaintext.content_type {
            ContentType::ApplicationData => {
                // Copy application data to output buffer
                let len = plaintext.fragment.len().min(buf.len());
                buf[..len].copy_from_slice(&plaintext.fragment[..len]);
                Ok(len)
            }
            ContentType::Alert => {
                // Decode and handle alert
                let alert = Alert::decode(&plaintext.fragment)?;

                if alert.description == hptls_core::error::AlertDescription::CloseNotify {
                    self.handshake_complete = false;
                    self.client_addr = None;
                    return Err(Error::AlertReceived(alert.description));
                }

                if alert.is_fatal() {
                    self.handshake_complete = false;
                    self.client_addr = None;
                    return Err(Error::AlertReceived(alert.description));
                }

                // For non-fatal alerts, try to read again
                self.read(buf)
            }
            _ => {
                Err(Error::InvalidMessage(format!(
                    "Unexpected content type: {:?}",
                    plaintext.content_type
                )))
            }
        }
    }

    /// Check if retransmission is needed and perform it
    ///
    /// This should be called periodically during the handshake to handle
    /// packet loss. It checks if the retransmission timer has expired and
    /// retransmits the last flight if necessary.
    ///
    /// # Returns
    /// - `Ok(true)` if a retransmission was performed
    /// - `Ok(false)` if no retransmission was needed
    /// - `Err` if retransmission failed or max retries exceeded
    pub fn poll_retransmit(&mut self) -> Result<bool> {
        // Only retransmit during handshake
        if self.handshake_complete {
            return Ok(false);
        }

        // Check if retransmission is needed
        if !self.dtls_state.retransmit_timer.should_retransmit() {
            return Ok(false);
        }

        // Get handshake wrapper
        let handshake = self
            .handshake
            .as_mut()
            .ok_or_else(|| Error::InternalError("No handshake in progress".into()))?;

        // Check if there's a flight to retransmit
        if !handshake.has_flight_to_retransmit() {
            return Ok(false);
        }

        // Perform retransmission with exponential backoff
        self.dtls_state.retransmit_timer.retransmit()?;

        // Determine epoch before borrowing for retransmission
        let is_encrypted = handshake.is_encrypted();

        // Get the flight to retransmit
        let flight_messages = handshake.retransmit_current_flight()?;

        // Drop the mutable borrow before sending messages
        drop(handshake);

        // Get client address
        let client_addr = self
            .client_addr
            .ok_or_else(|| Error::InternalError("No client address".into()))?;

        // Retransmit all messages in the flight
        for msg_bytes in &flight_messages {
            // Determine epoch based on handshake state
            let epoch = if is_encrypted {
                Epoch(1) // Encrypted handshake messages
            } else {
                Epoch::INITIAL // Initial ServerHello
            };

            self.send_handshake_message_to(msg_bytes, epoch, client_addr)?;
        }

        Ok(true)
    }

    /// Get the current retransmission timeout
    ///
    /// Returns the current timeout value, which increases with each retransmission
    /// using exponential backoff.
    pub fn retransmit_timeout(&self) -> Duration {
        self.dtls_state.retransmit_timer.current_timeout()
    }

    /// Get the number of retransmissions performed
    ///
    /// Useful for monitoring handshake reliability
    pub fn retransmit_count(&self) -> u32 {
        self.dtls_state.retransmit_timer.retransmit_count()
    }

    /// Manually rotate the cookie secret
    ///
    /// Forces immediate rotation of the cookie secret, moving the current secret
    /// to the previous slot (for grace period) and generating a new current secret.
    ///
    /// This is useful for:
    /// - Scheduled key rotation policies
    /// - Security event responses
    /// - Testing rotation logic
    ///
    /// # Returns
    /// `Ok(())` on successful rotation
    ///
    /// # Errors
    /// - `Error::InvalidConfig` - Cookie exchange is not enabled
    /// - `Error::CryptoError` - Failed to generate new secret
    pub fn rotate_cookie_secret(&mut self) -> Result<()> {
        let cookie_manager = self.cookie_manager.as_ref()
            .ok_or_else(|| Error::InvalidConfig("Cookie exchange is not enabled".into()))?;
        cookie_manager.rotate(&self.provider)?;
        Ok(())
    }

    /// Check if cookie secret rotation is needed
    ///
    /// Returns true if the current secret has exceeded the configured rotation interval.
    /// Applications can use this to implement periodic rotation checks.
    ///
    /// # Returns
    /// - `Some(true)` - Rotation is recommended
    /// - `Some(false)` - Rotation is not needed yet
    /// - `None` - Cookie exchange is not enabled
    pub fn should_rotate_cookie_secret(&self) -> Option<bool> {
        self.cookie_manager.as_ref().map(|cm| cm.needs_rotation())
    }

    /// Get cookie secret rotation statistics
    ///
    /// Returns information about cookie secret rotation:
    /// - Number of rotations performed
    /// - Age of current secret
    ///
    /// # Returns
    /// - `Some((rotation_count, current_age))` - Statistics
    /// - `None` - Cookie exchange is not enabled
    pub fn cookie_rotation_stats(&self) -> Option<(u64, Duration)> {
        self.cookie_manager.as_ref().map(|cm| {
            (cm.rotation_count(), cm.current_secret_age())
        })
    }

    /// Get current connection rate (connections per second)
    ///
    /// Returns the current connection rate based on a 60-second sliding window.
    /// This is used by the OnHighLoad cookie policy to determine when to
    /// require cookie exchange.
    ///
    /// # Returns
    /// Current connection rate in connections/second
    ///
    /// # Example
    /// ```rust,no_run
    /// # use hptls::dtls::DtlsServer;
    /// # let mut server: DtlsServer = unimplemented!();
    /// let rate = server.connection_rate();
    /// if rate > 100 {
    ///     println!("High load detected: {} conn/sec", rate);
    /// }
    /// ```
    pub fn connection_rate(&mut self) -> u32 {
        self.rate_tracker.current_rate()
    }

    /// Get connection tracking statistics
    ///
    /// Returns detailed information about connection tracking:
    /// - Current connection rate (connections/second)
    /// - Total connections recorded
    /// - Connections in current window
    ///
    /// # Returns
    /// `(rate, total, in_window)` tuple
    ///
    /// # Example
    /// ```rust,no_run
    /// # use hptls::dtls::DtlsServer;
    /// # let mut server: DtlsServer = unimplemented!();
    /// let (rate, total, in_window) = server.connection_stats();
    /// println!("Rate: {} conn/sec, Total: {}, In window: {}",
    ///          rate, total, in_window);
    /// ```
    pub fn connection_stats(&mut self) -> (u32, u64, usize) {
        let rate = self.rate_tracker.current_rate();
        let total = self.rate_tracker.total_connections();
        let in_window = self.rate_tracker.connections_in_window();
        (rate, total, in_window)
    }

    /// Check if current connection rate exceeds a threshold
    ///
    /// Useful for manual load monitoring or custom policies.
    ///
    /// # Arguments
    /// * `threshold` - Maximum acceptable connections per second
    ///
    /// # Returns
    /// `true` if current rate exceeds threshold
    ///
    /// # Example
    /// ```rust,no_run
    /// # use hptls::dtls::DtlsServer;
    /// # let mut server: DtlsServer = unimplemented!();
    /// if server.is_high_load(150) {
    ///     println!("Load is high, consider rate limiting");
    /// }
    /// ```
    pub fn is_high_load(&mut self, threshold: u32) -> bool {
        self.rate_tracker.exceeds_threshold(threshold)
    }

    /// Close the DTLS connection gracefully by sending close_notify alert
    pub fn close(&mut self) -> Result<()> {
        if !self.handshake_complete || self.client_addr.is_none() {
            // Nothing to close
            self.handshake_complete = false;
            self.client_addr = None;
            return Ok(());
        }

        // Create close_notify alert
        let alert = Alert::close_notify();
        let alert_bytes = alert.encode();

        // Encrypt and send the close_notify alert with application epoch
        let seq = self.dtls_state.next_send_sequence()?;
        let alert_ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::Alert,
            &alert_bytes,
            seq,
        )?;

        let encoded = alert_ciphertext.encode();
        if let Some(client_addr) = self.client_addr {
            self.socket.send_to(&encoded, client_addr)
                .map_err(|e| Error::IoError(e.to_string()))?;
        }

        self.handshake_complete = false;
        self.client_addr = None;
        Ok(())
    }

    /// Send a TLS alert to the client
    ///
    /// This is a lower-level method for sending arbitrary alerts.
    /// Most users should use `close()` for graceful shutdown instead.
    pub fn send_alert(&mut self, alert: Alert) -> Result<()> {
        if self.client_addr.is_none() {
            return Err(Error::InternalError("No client connected".into()));
        }

        let alert_bytes = alert.encode();

        // Determine which epoch to use based on handshake state
        let seq = if self.handshake_complete {
            // Use application epoch for post-handshake alerts
            self.dtls_state.next_send_sequence()?
        } else {
            // Use handshake epoch or initial epoch for handshake alerts
            self.dtls_state.next_send_sequence()?
        };

        let alert_ciphertext = self.record_protection.encrypt(
            &self.provider,
            ContentType::Alert,
            &alert_bytes,
            seq,
        )?;

        let encoded = alert_ciphertext.encode();
        if let Some(client_addr) = self.client_addr {
            self.socket.send_to(&encoded, client_addr)
                .map_err(|e| Error::IoError(e.to_string()))?;
        }

        // Fatal alerts should terminate the connection
        if alert.is_fatal() {
            self.handshake_complete = false;
            self.client_addr = None;
        }

        Ok(())
    }

    /// Send an unexpected_message alert (fatal)
    pub fn send_unexpected_message_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::UnexpectedMessage))
    }

    /// Send a decode_error alert (fatal)
    pub fn send_decode_error_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::DecodeError))
    }

    /// Send a handshake_failure alert (fatal)
    pub fn send_handshake_failure_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::HandshakeFailure))
    }

    /// Send a bad_record_mac alert (fatal)
    pub fn send_bad_record_mac_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::BadRecordMac))
    }

    /// Send an internal_error alert (fatal)
    pub fn send_internal_error_alert(&mut self) -> Result<()> {
        use hptls_core::error::AlertDescription;
        self.send_alert(Alert::fatal(AlertDescription::InternalError))
    }

    /// Request a key update from the client (RFC 8446 Section 4.6.3)
    ///
    /// Initiates post-handshake rekeying to update traffic secrets, enhancing
    /// forward secrecy. This sends a KeyUpdate message with `update_requested` flag,
    /// requiring the client to respond with its own KeyUpdate message.
    ///
    /// # Protocol Behavior
    /// - Server sends KeyUpdate(update_requested=1)
    /// - Client must respond with KeyUpdate
    /// - Both parties update their traffic keys
    ///
    /// # Errors
    /// Returns error if:
    /// - Called before handshake completion
    /// - No client is connected
    /// - Send operation fails
    ///
    /// # Note
    /// Current implementation sends the message but does not yet update local keys.
    /// Key derivation integration with KeySchedule is pending.
    pub fn request_key_update(&mut self) -> Result<()> {
        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Cannot update keys before handshake completion".into(),
            ));
        }

        if self.client_addr.is_none() {
            return Err(Error::InternalError("No client connected".into()));
        }

        // Create KeyUpdate message requesting update from peer
        let key_update = KeyUpdate::new(KeyUpdateRequest::UpdateRequested);
        let payload = key_update.encode()?;

        // Send as handshake message
        let seq = self.dtls_state.next_send_sequence()?;
        let ciphertext = self.record_protection.encrypt(
            &self.provider,
            hptls_core::protocol::ContentType::Handshake,
            &payload,
            seq,
        )?;

        let encoded = ciphertext.encode();
        if let Some(client_addr) = self.client_addr {
            self.socket
                .send_to(&encoded, client_addr)
                .map_err(|e| Error::IoError(e.to_string()))?;
        }

        // Update our sending keys (server application traffic secret)
        if let Some(handshake) = &mut self.handshake {
            let tls_handshake = handshake.tls_handshake_mut();

            // Update server application traffic secret to generation N+1
            if let Some(key_schedule) = tls_handshake.key_schedule_mut() {
                key_schedule.update_server_application_traffic_secret(&self.provider)?;

                // Get the new secrets and cipher suite
                let client_secret = tls_handshake
                    .get_client_application_traffic_secret()
                    .ok_or_else(|| Error::InternalError("Client app secret missing".into()))?;
                let server_secret = tls_handshake
                    .get_server_application_traffic_secret()
                    .ok_or_else(|| Error::InternalError("Server app secret missing".into()))?;
                let cipher_suite = tls_handshake
                    .cipher_suite()
                    .ok_or_else(|| Error::InternalError("Cipher suite not set".into()))?;

                // Update the APPLICATION epoch with new server write key
                self.record_protection.add_epoch_bidirectional(
                    &self.provider,
                    hptls_core::dtls::Epoch::APPLICATION,
                    cipher_suite,
                    server_secret,  // Updated write key
                    client_secret,  // Unchanged read key (until client updates)
                )?;
            }
        }

        Ok(())
    }

    /// Perform unilateral key update (RFC 8446 Section 4.6.3)
    ///
    /// Updates only the server's sending keys without requesting the client to
    /// update its keys. This sends a KeyUpdate message with `update_requested=0`.
    ///
    /// # Protocol Behavior
    /// - Server sends KeyUpdate(update_requested=0)
    /// - Client is NOT required to respond
    /// - Only server updates its sending keys
    ///
    /// # Use Cases
    /// Use this when you want to rotate your own keys without forcing the peer
    /// to do the same. For mutual key rotation, use [`request_key_update()`] instead.
    ///
    /// # Errors
    /// Returns error if:
    /// - Called before handshake completion
    /// - No client is connected
    /// - Send operation fails
    ///
    /// # Note
    /// Current implementation sends the message but does not yet update local keys.
    /// Key derivation integration with KeySchedule is pending.
    pub fn update_keys(&mut self) -> Result<()> {
        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Cannot update keys before handshake completion".into(),
            ));
        }

        if self.client_addr.is_none() {
            return Err(Error::InternalError("No client connected".into()));
        }

        // Create KeyUpdate message without requesting update from peer
        let key_update = KeyUpdate::new(KeyUpdateRequest::UpdateNotRequested);
        let payload = key_update.encode()?;

        // Send as handshake message
        let seq = self.dtls_state.next_send_sequence()?;
        let ciphertext = self.record_protection.encrypt(
            &self.provider,
            hptls_core::protocol::ContentType::Handshake,
            &payload,
            seq,
        )?;

        let encoded = ciphertext.encode();
        if let Some(client_addr) = self.client_addr {
            self.socket
                .send_to(&encoded, client_addr)
                .map_err(|e| Error::IoError(e.to_string()))?;
        }

        // Update our sending keys (server application traffic secret)
        if let Some(handshake) = &mut self.handshake {
            let tls_handshake = handshake.tls_handshake_mut();

            // Update server application traffic secret to generation N+1
            if let Some(key_schedule) = tls_handshake.key_schedule_mut() {
                key_schedule.update_server_application_traffic_secret(&self.provider)?;

                // Get the new secrets and cipher suite
                let client_secret = tls_handshake
                    .get_client_application_traffic_secret()
                    .ok_or_else(|| Error::InternalError("Client app secret missing".into()))?;
                let server_secret = tls_handshake
                    .get_server_application_traffic_secret()
                    .ok_or_else(|| Error::InternalError("Server app secret missing".into()))?;
                let cipher_suite = tls_handshake
                    .cipher_suite()
                    .ok_or_else(|| Error::InternalError("Cipher suite not set".into()))?;

                // Update the APPLICATION epoch with new server write key
                self.record_protection.add_epoch_bidirectional(
                    &self.provider,
                    hptls_core::dtls::Epoch::APPLICATION,
                    cipher_suite,
                    server_secret,  // Updated write key
                    client_secret,  // Unchanged read key
                )?;
            }
        }

        Ok(())
    }

    /// Send an ACK message to acknowledge received records (RFC 9147 Section 7).
    ///
    /// ACK messages allow explicit acknowledgment of successfully received records,
    /// enabling the client to stop retransmitting acknowledged data and improving
    /// retransmission efficiency.
    ///
    /// # Arguments
    /// * `record_numbers` - List of record sequence numbers to acknowledge
    ///
    /// # Errors
    /// Returns error if encoding or sending fails, or if no client is connected.
    pub fn send_ack(&mut self, record_numbers: Vec<u64>) -> Result<()> {
        use hptls_core::messages::Ack;

        if !self.handshake_complete {
            return Err(Error::InternalError(
                "Cannot send ACK before handshake completion".into(),
            ));
        }

        if self.client_addr.is_none() {
            return Err(Error::InternalError("No client connected".into()));
        }

        // Create ACK message
        let ack = Ack::new(record_numbers.clone());
        let payload = ack.encode()?;

        // Send as ACK content type
        let seq = self.dtls_state.next_send_sequence()?;
        let ciphertext = self.record_protection.encrypt(
            &self.provider,
            hptls_core::protocol::ContentType::Ack,
            &payload,
            seq,
        )?;

        let encoded = ciphertext.encode();
        if let Some(client_addr) = self.client_addr {
            self.socket
                .send_to(&encoded, client_addr)
                .map_err(|e| Error::IoError(e.to_string()))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_builder() {
        let config = DtlsClientConfig::builder()
            .with_server_name("example.com".to_string())
            .with_mtu(1400)
            .build()
            .unwrap();

        assert_eq!(config.server_name, Some("example.com".to_string()));
        assert_eq!(config.mtu, 1400);
        assert!(!config.cipher_suites.is_empty());
    }

    #[test]
    fn test_server_config_builder() {
        let result = DtlsServerConfig::builder().build();
        assert!(result.is_err()); // Should fail without cert/key

        let config = DtlsServerConfig::builder()
            .with_certificate_chain(vec![vec![1, 2, 3]])
            .with_private_key(vec![4, 5, 6])
            .with_cookie_exchange(true)
            .build()
            .unwrap();

        assert!(!config.certificate_chain.is_empty());
        assert!(!config.private_key.is_empty());
        assert!(config.cookie_config.is_enabled());
    }

    #[test]
    fn test_cookie_policy_default() {
        let policy = CookiePolicy::default();
        match policy {
            CookiePolicy::OnHighLoad { threshold } => assert_eq!(threshold, 100),
            _ => panic!("Default policy should be OnHighLoad with threshold 100"),
        }
    }

    #[test]
    fn test_cookie_config_default() {
        let config = DtlsCookieConfig::default();
        assert!(matches!(config.policy, CookiePolicy::OnHighLoad { .. }));
        assert_eq!(config.rotation_interval, Duration::from_secs(3600));
        assert_eq!(config.max_cookie_age, Duration::from_secs(60));
        assert!(!config.enable_metrics);
    }

    #[test]
    fn test_cookie_config_builder() {
        let config = DtlsCookieConfig::builder()
            .with_policy(CookiePolicy::Always)
            .with_rotation_interval(Duration::from_secs(7200))
            .with_max_cookie_age(Duration::from_secs(120))
            .with_metrics(true)
            .build();

        assert!(matches!(config.policy, CookiePolicy::Always));
        assert_eq!(config.rotation_interval, Duration::from_secs(7200));
        assert_eq!(config.max_cookie_age, Duration::from_secs(120));
        assert!(config.enable_metrics);
    }

    #[test]
    fn test_cookie_config_always() {
        let config = DtlsCookieConfig::always();
        assert!(matches!(config.policy, CookiePolicy::Always));
        assert!(config.is_enabled());
    }

    #[test]
    fn test_cookie_config_never() {
        let config = DtlsCookieConfig::never();
        assert!(matches!(config.policy, CookiePolicy::Never));
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_cookie_config_on_high_load() {
        let config = DtlsCookieConfig::on_high_load(200);
        match config.policy {
            CookiePolicy::OnHighLoad { threshold } => assert_eq!(threshold, 200),
            _ => panic!("Expected OnHighLoad policy"),
        }
        assert!(config.is_enabled());
    }

    #[test]
    fn test_server_config_with_cookie_config() {
        let cookie_config = DtlsCookieConfig::builder()
            .with_policy(CookiePolicy::Always)
            .with_rotation_interval(Duration::from_secs(1800))
            .build();

        let config = DtlsServerConfig::builder()
            .with_certificate_chain(vec![vec![1, 2, 3]])
            .with_private_key(vec![4, 5, 6])
            .with_cookie_config(cookie_config)
            .build()
            .unwrap();

        assert!(matches!(config.cookie_config.policy, CookiePolicy::Always));
        assert_eq!(config.cookie_config.rotation_interval, Duration::from_secs(1800));
    }

    #[test]
    #[allow(deprecated)]
    fn test_backward_compatibility_with_cookie_exchange() {
        // Test deprecated method still works
        let config = DtlsServerConfig::builder()
            .with_certificate_chain(vec![vec![1, 2, 3]])
            .with_private_key(vec![4, 5, 6])
            .with_cookie_exchange(true)
            .build()
            .unwrap();

        assert!(config.cookie_config.is_enabled());
    }

    #[test]
    #[allow(deprecated)]
    fn test_backward_compatibility_with_rotation_interval() {
        // Test deprecated method still works
        let config = DtlsServerConfig::builder()
            .with_certificate_chain(vec![vec![1, 2, 3]])
            .with_private_key(vec![4, 5, 6])
            .with_cookie_rotation_interval(Duration::from_secs(900))
            .build()
            .unwrap();

        assert_eq!(config.cookie_config.rotation_interval, Duration::from_secs(900));
    }
}
