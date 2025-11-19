//! DTLS 1.3 Handshake with Retransmission Support
//!
//! This module extends TLS 1.3 handshake state machines with DTLS-specific
//! features:
//! - Handshake message retransmission on timeout
//! - Flight-based message grouping
//! - Stateless cookie exchange for DoS protection
//! - Out-of-order message buffering
//!
//! # DTLS Handshake Flight Model
//!
//! DTLS groups messages into "flights" which are retransmitted as a unit:
//!
//! ```text
//! Client                                Server
//!
//! Flight 1: ClientHello      -------->
//!                                      Flight 2: HelloRetryRequest (+ cookie)
//!                            <--------
//! Flight 3: ClientHello      -------->
//! (+ cookie)
//!                                      Flight 4: ServerHello
//!                                                EncryptedExtensions
//!                                                Certificate
//!                                                CertificateVerify
//!                                                Finished
//!                            <--------
//! Flight 5: Certificate      -------->
//!           CertificateVerify
//!           Finished
//! ```

use crate::dtls::{Epoch, RetransmitTimer};
use crate::error::{Error, Result};
use crate::handshake::client::ClientHandshake;
use crate::handshake::server::ServerHandshake;
use std::collections::VecDeque;
use std::time::Instant;

/// A single handshake message with its metadata
#[derive(Debug, Clone)]
pub struct DtlsHandshakeMessage {
    /// Message type and payload
    pub message: Vec<u8>,
    /// Epoch this message belongs to
    pub epoch: Epoch,
    /// Sequence number (within handshake)
    pub sequence: u16,
    /// When this message was last transmitted
    pub last_transmit: Option<Instant>,
}

/// A flight of handshake messages that are transmitted together
#[derive(Debug, Clone)]
pub struct HandshakeFlight {
    /// Messages in this flight
    pub messages: Vec<DtlsHandshakeMessage>,
    /// Retransmission timer for this flight
    pub timer: RetransmitTimer,
    /// Whether this flight has been acknowledged
    pub acknowledged: bool,
}

impl HandshakeFlight {
    /// Create a new empty flight
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            timer: RetransmitTimer::new(),
            acknowledged: false,
        }
    }

    /// Add a message to this flight
    pub fn add_message(&mut self, message: DtlsHandshakeMessage) {
        self.messages.push(message);
    }

    /// Check if this flight needs retransmission
    pub fn needs_retransmit(&self) -> bool {
        !self.acknowledged && self.timer.should_retransmit()
    }

    /// Mark flight as transmitted
    pub fn record_transmit(&mut self) {
        self.timer.record_transmit();
        let now = Some(Instant::now());
        for msg in &mut self.messages {
            msg.last_transmit = now;
        }
    }

    /// Perform retransmission (exponential backoff)
    pub fn retransmit(&mut self) -> Result<()> {
        self.timer.retransmit()?;
        let now = Some(Instant::now());
        for msg in &mut self.messages {
            msg.last_transmit = now;
        }
        Ok(())
    }

    /// Acknowledge this flight (stop retransmissions)
    pub fn acknowledge(&mut self) {
        self.acknowledged = true;
        self.timer.reset();
    }
}

impl Default for HandshakeFlight {
    fn default() -> Self {
        Self::new()
    }
}

/// DTLS Client Handshake wrapper
///
/// Wraps the TLS 1.3 client handshake with DTLS-specific retransmission logic
pub struct DtlsClientHandshake {
    /// Underlying TLS 1.3 handshake
    tls_handshake: ClientHandshake,
    /// Current flight being built/transmitted
    current_flight: Option<HandshakeFlight>,
    /// Previous flights (for potential retransmission)
    previous_flights: VecDeque<HandshakeFlight>,
    /// Maximum number of flights to retain
    max_flights_retained: usize,
    /// Handshake message sequence number
    message_sequence: u16,
    /// Current epoch
    current_epoch: Epoch,
    /// Cookie received from HelloRetryRequest
    cookie: Option<Vec<u8>>,
}

impl DtlsClientHandshake {
    /// Create a new DTLS client handshake
    pub fn new(tls_handshake: ClientHandshake) -> Self {
        Self {
            tls_handshake,
            current_flight: Some(HandshakeFlight::new()),
            previous_flights: VecDeque::new(),
            max_flights_retained: 3, // Keep last 3 flights for retransmission
            message_sequence: 0,
            current_epoch: Epoch::INITIAL,
            cookie: None,
        }
    }

    /// Add a handshake message to the current flight
    ///
    /// # Arguments
    /// * `message` - Encoded TLS handshake message (with 4-byte TLS header)
    ///
    /// This function creates a DTLS handshake message with a 12-byte header + payload
    pub fn add_message_to_flight(&mut self, msg_type: u8, payload: Vec<u8>) {
        // Create DTLS handshake message with 12-byte header
        let dtls_message = encode_dtls_handshake_message(msg_type, &payload, self.message_sequence);

        let dtls_msg = DtlsHandshakeMessage {
            message: dtls_message,
            epoch: self.current_epoch,
            sequence: self.message_sequence,
            last_transmit: None,
        };

        self.message_sequence += 1;

        if let Some(flight) = &mut self.current_flight {
            flight.add_message(dtls_msg);
        }
    }

    /// Finalize and transmit the current flight
    ///
    /// # Returns
    /// The messages to transmit (all messages in the flight)
    pub fn transmit_flight(&mut self) -> Result<Vec<Vec<u8>>> {
        if let Some(mut flight) = self.current_flight.take() {
            flight.record_transmit();

            let messages: Vec<Vec<u8>> = flight.messages.iter().map(|m| m.message.clone()).collect();

            // Store flight for potential retransmission
            self.previous_flights.push_back(flight);

            // Limit retained flights
            while self.previous_flights.len() > self.max_flights_retained {
                self.previous_flights.pop_front();
            }

            // Start new flight
            self.current_flight = Some(HandshakeFlight::new());

            Ok(messages)
        } else {
            Ok(Vec::new())
        }
    }

    /// Check if any previous flights need retransmission
    ///
    /// # Returns
    /// Messages to retransmit, if any
    pub fn check_retransmission(&mut self) -> Result<Option<Vec<Vec<u8>>>> {
        for flight in &mut self.previous_flights {
            if flight.needs_retransmit() {
                flight.retransmit()?;
                let messages: Vec<Vec<u8>> =
                    flight.messages.iter().map(|m| m.message.clone()).collect();
                return Ok(Some(messages));
            }
        }
        Ok(None)
    }

    /// Acknowledge a flight (stop retransmissions)
    ///
    /// This should be called when the peer responds, indicating they received the flight
    pub fn acknowledge_flight(&mut self, flight_index: usize) {
        if let Some(flight) = self.previous_flights.get_mut(flight_index) {
            flight.acknowledge();
        }
    }

    /// Acknowledge all flights (handshake completed)
    pub fn acknowledge_all_flights(&mut self) {
        for flight in &mut self.previous_flights {
            flight.acknowledge();
        }
    }

    /// Advance to the next epoch
    pub fn advance_epoch(&mut self) -> Result<()> {
        self.current_epoch = self.current_epoch.next()?;
        Ok(())
    }

    /// Set the cookie from HelloRetryRequest
    pub fn set_cookie(&mut self, cookie: Vec<u8>) {
        self.cookie = Some(cookie);
    }

    /// Get the cookie for inclusion in ClientHello
    pub fn get_cookie(&self) -> Option<&[u8]> {
        self.cookie.as_deref()
    }

    /// Get a reference to the underlying TLS handshake
    pub fn tls_handshake(&self) -> &ClientHandshake {
        &self.tls_handshake
    }

    /// Get a mutable reference to the underlying TLS handshake
    pub fn tls_handshake_mut(&mut self) -> &mut ClientHandshake {
        &mut self.tls_handshake
    }

    /// Check if there's a flight available for retransmission
    pub fn has_flight_to_retransmit(&self) -> bool {
        self.previous_flights
            .iter()
            .any(|f| f.needs_retransmit())
    }

    /// Retransmit the current flight that needs retransmission
    ///
    /// # Returns
    /// The messages to retransmit
    pub fn retransmit_current_flight(&mut self) -> Result<Vec<Vec<u8>>> {
        // Find the first flight that needs retransmission
        for flight in &mut self.previous_flights {
            if flight.needs_retransmit() {
                flight.retransmit()?;
                let messages: Vec<Vec<u8>> =
                    flight.messages.iter().map(|m| m.message.clone()).collect();
                return Ok(messages);
            }
        }
        Ok(Vec::new())
    }

    /// Check if the handshake is using encrypted messages
    pub fn is_encrypted(&self) -> bool {
        self.current_epoch.0 > 0
    }
}

/// DTLS Server Handshake wrapper
///
/// Wraps the TLS 1.3 server handshake with DTLS-specific features
pub struct DtlsServerHandshake {
    /// Underlying TLS 1.3 handshake
    tls_handshake: ServerHandshake,
    /// Current flight being built/transmitted
    current_flight: Option<HandshakeFlight>,
    /// Previous flights (for potential retransmission)
    previous_flights: VecDeque<HandshakeFlight>,
    /// Maximum number of flights to retain
    max_flights_retained: usize,
    /// Handshake message sequence number
    message_sequence: u16,
    /// Current epoch
    current_epoch: Epoch,
    /// Cookie to send in HelloRetryRequest (for DoS protection)
    cookie: Option<Vec<u8>>,
    /// Whether a cookie has been verified
    cookie_verified: bool,
}

impl DtlsServerHandshake {
    /// Create a new DTLS server handshake
    pub fn new(tls_handshake: ServerHandshake) -> Self {
        Self {
            tls_handshake,
            current_flight: Some(HandshakeFlight::new()),
            previous_flights: VecDeque::new(),
            max_flights_retained: 3,
            message_sequence: 0,
            current_epoch: Epoch::INITIAL,
            cookie: None,
            cookie_verified: false,
        }
    }

    /// Generate a cookie for DoS protection using HMAC-SHA256
    ///
    /// The cookie is computed as: HMAC-SHA256(secret, client_addr || client_hello_hash)
    /// This binds the cookie to both the client's network address and the ClientHello content.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider for HMAC
    /// * `secret` - Secret key for HMAC (should be rotated periodically)
    /// * `client_hello` - The ClientHello message bytes
    /// * `client_addr` - Client's network address as bytes (e.g., IP:port)
    ///
    /// # Returns
    /// The generated cookie (32 bytes for SHA256)
    pub fn generate_cookie(
        &mut self,
        provider: &dyn hptls_crypto::CryptoProvider,
        secret: &[u8],
        client_hello: &[u8],
        client_addr: &[u8],
    ) -> Result<Vec<u8>> {
        use hptls_crypto::HashAlgorithm;

        // Compute HMAC-SHA256(secret, client_addr || client_hello)
        let mut hmac = provider.hmac(HashAlgorithm::Sha256, secret)?;
        hmac.update(client_addr);
        hmac.update(client_hello);
        let cookie = hmac.finalize();

        self.cookie = Some(cookie.clone());
        Ok(cookie)
    }

    /// Verify a cookie from the client using constant-time comparison
    ///
    /// # Arguments
    /// * `provider` - Crypto provider for HMAC
    /// * `secret` - Secret key for HMAC (same as used for generation)
    /// * `cookie` - Cookie received in ClientHello
    /// * `client_hello` - The current ClientHello bytes
    /// * `client_addr` - Client's network address as bytes
    ///
    /// # Returns
    /// `Ok(true)` if cookie is valid, `Ok(false)` if invalid, `Err` on crypto error
    pub fn verify_cookie(
        &mut self,
        provider: &dyn hptls_crypto::CryptoProvider,
        secret: &[u8],
        cookie: &[u8],
        client_hello: &[u8],
        client_addr: &[u8],
    ) -> Result<bool> {
        use hptls_crypto::HashAlgorithm;

        // Compute expected cookie
        let mut hmac = provider.hmac(HashAlgorithm::Sha256, secret)?;
        hmac.update(client_addr);
        hmac.update(client_hello);

        // Use constant-time verification
        let valid = hmac.verify(cookie);
        if valid {
            self.cookie_verified = true;
        }
        Ok(valid)
    }

    /// Check if cookie has been verified
    pub fn is_cookie_verified(&self) -> bool {
        self.cookie_verified
    }

    /// Add a handshake message to the current flight
    ///
    /// # Arguments
    /// * `message` - Encoded TLS handshake message (with 4-byte TLS header)
    ///
    /// This function creates a DTLS handshake message with a 12-byte header + payload
    pub fn add_message_to_flight(&mut self, msg_type: u8, payload: Vec<u8>) {
        // Create DTLS handshake message with 12-byte header
        let dtls_message = encode_dtls_handshake_message(msg_type, &payload, self.message_sequence);

        let dtls_msg = DtlsHandshakeMessage {
            message: dtls_message,
            epoch: self.current_epoch,
            sequence: self.message_sequence,
            last_transmit: None,
        };

        self.message_sequence += 1;

        if let Some(flight) = &mut self.current_flight {
            flight.add_message(dtls_msg);
        }
    }

    /// Finalize and transmit the current flight
    pub fn transmit_flight(&mut self) -> Result<Vec<Vec<u8>>> {
        if let Some(mut flight) = self.current_flight.take() {
            flight.record_transmit();

            let messages: Vec<Vec<u8>> = flight.messages.iter().map(|m| m.message.clone()).collect();

            // Store flight for potential retransmission
            self.previous_flights.push_back(flight);

            // Limit retained flights
            while self.previous_flights.len() > self.max_flights_retained {
                self.previous_flights.pop_front();
            }

            // Start new flight
            self.current_flight = Some(HandshakeFlight::new());

            Ok(messages)
        } else {
            Ok(Vec::new())
        }
    }

    /// Check if any previous flights need retransmission
    pub fn check_retransmission(&mut self) -> Result<Option<Vec<Vec<u8>>>> {
        for flight in &mut self.previous_flights {
            if flight.needs_retransmit() {
                flight.retransmit()?;
                let messages: Vec<Vec<u8>> =
                    flight.messages.iter().map(|m| m.message.clone()).collect();
                return Ok(Some(messages));
            }
        }
        Ok(None)
    }

    /// Acknowledge a flight
    pub fn acknowledge_flight(&mut self, flight_index: usize) {
        if let Some(flight) = self.previous_flights.get_mut(flight_index) {
            flight.acknowledge();
        }
    }

    /// Acknowledge all flights
    pub fn acknowledge_all_flights(&mut self) {
        for flight in &mut self.previous_flights {
            flight.acknowledge();
        }
    }

    /// Advance to the next epoch
    pub fn advance_epoch(&mut self) -> Result<()> {
        self.current_epoch = self.current_epoch.next()?;
        Ok(())
    }

    /// Get a reference to the underlying TLS handshake
    pub fn tls_handshake(&self) -> &ServerHandshake {
        &self.tls_handshake
    }

    /// Get a mutable reference to the underlying TLS handshake
    pub fn tls_handshake_mut(&mut self) -> &mut ServerHandshake {
        &mut self.tls_handshake
    }

    /// Check if there's a flight available for retransmission
    pub fn has_flight_to_retransmit(&self) -> bool {
        self.previous_flights
            .iter()
            .any(|f| f.needs_retransmit())
    }

    /// Retransmit the current flight that needs retransmission
    ///
    /// # Returns
    /// The messages to retransmit
    pub fn retransmit_current_flight(&mut self) -> Result<Vec<Vec<u8>>> {
        // Find the first flight that needs retransmission
        for flight in &mut self.previous_flights {
            if flight.needs_retransmit() {
                flight.retransmit()?;
                let messages: Vec<Vec<u8>> =
                    flight.messages.iter().map(|m| m.message.clone()).collect();
                return Ok(messages);
            }
        }
        Ok(Vec::new())
    }

    /// Check if the handshake is using encrypted messages
    pub fn is_encrypted(&self) -> bool {
        self.current_epoch.0 > 0
    }
}

/// Out-of-order message buffer for DTLS
///
/// Buffers messages that arrive out of order until earlier messages arrive
pub struct MessageBuffer {
    /// Buffered messages (sequence -> message)
    buffer: std::collections::HashMap<u16, Vec<u8>>,
    /// Next expected sequence number
    next_expected: u16,
    /// Maximum buffer size
    max_size: usize,
}

impl MessageBuffer {
    /// Create a new message buffer
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: std::collections::HashMap::new(),
            next_expected: 0,
            max_size,
        }
    }

    /// Add a message to the buffer
    ///
    /// # Returns
    /// - Ok(None) if message is buffered
    /// - Ok(Some(messages)) if this message completes a sequence
    /// - Err if buffer is full or message is duplicate
    pub fn add_message(&mut self, sequence: u16, message: Vec<u8>) -> Result<Option<Vec<Vec<u8>>>> {
        // Reject old messages
        if sequence < self.next_expected {
            return Err(Error::InvalidMessage("Duplicate handshake message".into()));
        }

        // If this is the next expected message
        if sequence == self.next_expected {
            let mut messages = vec![message];
            self.next_expected += 1;

            // Drain buffer for consecutive messages
            while let Some(msg) = self.buffer.remove(&self.next_expected) {
                messages.push(msg);
                self.next_expected += 1;
            }

            return Ok(Some(messages));
        }

        // Future message - buffer it
        if self.buffer.len() >= self.max_size {
            return Err(Error::InternalError(
                "Handshake message buffer full".into(),
            ));
        }

        self.buffer.insert(sequence, message);
        Ok(None)
    }

    /// Reset the buffer
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.next_expected = 0;
    }

    /// Get the next expected sequence number
    pub fn next_expected(&self) -> u16 {
        self.next_expected
    }
}

/// Decode a DTLS handshake message (strip 12-byte header, convert to TLS format)
///
/// DTLS handshake messages have a 12-byte header, but TLS decoders expect a 4-byte header.
/// This function converts DTLS → TLS format by:
/// 1. Extracting msg_type and length from DTLS header
/// 2. Skipping the DTLS-specific fields (message_seq, fragment_offset, fragment_length)
/// 3. Rebuilding a TLS handshake message with 4-byte header
///
/// # Arguments
/// * `dtls_message` - DTLS handshake message (includes 12-byte header + payload)
///
/// # Returns
/// TLS handshake message with 4-byte header (msg_type + length + payload)
///
/// # Format
/// ```text
/// DTLS (12 bytes): [msg_type(1) | length(3) | message_seq(2) | fragment_offset(3) | fragment_length(3)]
/// TLS  (4 bytes):  [msg_type(1) | length(3)]
/// ```
pub fn decode_dtls_handshake_message(dtls_message: &[u8]) -> Result<Vec<u8>> {
    if dtls_message.len() < 12 {
        return Err(Error::InvalidMessage(format!(
            "DTLS handshake message too short: {} bytes (need at least 12)",
            dtls_message.len()
        )));
    }

    // Extract DTLS header fields
    let msg_type = dtls_message[0];
    let length_bytes = [dtls_message[1], dtls_message[2], dtls_message[3]];
    let length = u32::from_be_bytes([0, length_bytes[0], length_bytes[1], length_bytes[2]]) as usize;

    // DTLS-specific fields (we don't need these for TLS decoding)
    // let message_seq = u16::from_be_bytes([dtls_message[4], dtls_message[5]]);
    // let fragment_offset = u32::from_be_bytes([0, dtls_message[6], dtls_message[7], dtls_message[8]]);
    // let fragment_length = u32::from_be_bytes([0, dtls_message[9], dtls_message[10], dtls_message[11]]);

    // Payload starts at byte 12
    if dtls_message.len() < 12 + length {
        return Err(Error::InvalidMessage(format!(
            "DTLS handshake message incomplete: got {} bytes, expected {} (12 header + {} payload)",
            dtls_message.len(),
            12 + length,
            length
        )));
    }

    let payload = &dtls_message[12..12 + length];

    // Build TLS handshake message (4-byte header)
    let mut tls_message = Vec::with_capacity(4 + length);
    tls_message.push(msg_type);
    tls_message.extend_from_slice(&length_bytes);
    tls_message.extend_from_slice(payload);

    Ok(tls_message)
}

/// Encode a DTLS handshake message with proper 12-byte header
///
/// DTLS handshake messages have a different header than TLS:
/// - TLS: 4 bytes (msg_type + length)
/// - DTLS: 12 bytes (msg_type + length + message_seq + fragment_offset + fragment_length)
///
/// # Arguments
/// * `tls_message` - TLS handshake message (includes 4-byte TLS header + payload)
/// * `message_seq` - DTLS message sequence number
///
/// # Returns
/// DTLS handshake message with 12-byte header
///
/// # Format (RFC 9147 Section 5.2)
/// ```text
/// struct {
///     HandshakeType msg_type;       // 1 byte
///     uint24 length;                // 3 bytes - message length (excluding header)
///     uint16 message_seq;           // 2 bytes - DTLS-specific
///     uint24 fragment_offset;       // 3 bytes - DTLS-specific (0 for unfragmented)
///     uint24 fragment_length;       // 3 bytes - DTLS-specific (= length for unfragmented)
///     HandshakeMessage msg;         // variable
/// } Handshake;
/// ```
/// Encodes a DTLS handshake message from a handshake payload (without TLS header).
///
/// # Arguments
/// * `msg_type` - Handshake message type (1 = ClientHello, 2 = ServerHello, etc.)
/// * `payload` - The handshake message payload (without any header)
/// * `message_seq` - DTLS message sequence number
///
/// # Returns
/// DTLS handshake message with 12-byte header + payload
fn encode_dtls_handshake_message(msg_type: u8, payload: &[u8], message_seq: u16) -> Vec<u8> {
    let payload_len = payload.len();

    // Build DTLS handshake message with 12-byte header
    let mut dtls_message = Vec::with_capacity(12 + payload_len);

    // Byte 0: msg_type
    dtls_message.push(msg_type);

    // Bytes 1-3: length (24-bit, big-endian)
    let length_bytes = [
        ((payload_len >> 16) & 0xFF) as u8,
        ((payload_len >> 8) & 0xFF) as u8,
        (payload_len & 0xFF) as u8,
    ];
    dtls_message.extend_from_slice(&length_bytes);

    // Bytes 4-5: message_seq (16-bit, big-endian) - DTLS-specific
    dtls_message.extend_from_slice(&message_seq.to_be_bytes());

    // Bytes 6-8: fragment_offset (24-bit, big-endian) - 0 for unfragmented
    dtls_message.push(0);
    dtls_message.push(0);
    dtls_message.push(0);

    // Bytes 9-11: fragment_length (24-bit, big-endian) - same as length for unfragmented
    dtls_message.extend_from_slice(&length_bytes);

    // Payload
    dtls_message.extend_from_slice(payload);

    dtls_message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_flight() {
        let mut flight = HandshakeFlight::new();

        let msg = DtlsHandshakeMessage {
            message: vec![1, 2, 3],
            epoch: Epoch(0),
            sequence: 0,
            last_transmit: None,
        };

        flight.add_message(msg);
        assert_eq!(flight.messages.len(), 1);
        assert!(!flight.acknowledged);

        // Should need retransmit initially
        assert!(flight.needs_retransmit());

        flight.record_transmit();
        assert!(!flight.needs_retransmit()); // Not yet timed out

        flight.acknowledge();
        assert!(flight.acknowledged);
        assert!(!flight.needs_retransmit()); // Acknowledged
    }

    #[test]
    fn test_message_buffer_in_order() {
        let mut buffer = MessageBuffer::new(10);

        // Messages arrive in order
        let result = buffer.add_message(0, vec![1, 2, 3]).unwrap();
        assert_eq!(result.unwrap().len(), 1);

        let result = buffer.add_message(1, vec![4, 5, 6]).unwrap();
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_message_buffer_out_of_order() {
        let mut buffer = MessageBuffer::new(10);

        // Message 1 arrives first (out of order)
        let result = buffer.add_message(1, vec![4, 5, 6]).unwrap();
        assert!(result.is_none()); // Buffered

        // Message 0 arrives, should flush both
        let result = buffer.add_message(0, vec![1, 2, 3]).unwrap();
        let messages = result.unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], vec![1, 2, 3]);
        assert_eq!(messages[1], vec![4, 5, 6]);
    }

    #[test]
    fn test_message_buffer_duplicate() {
        let mut buffer = MessageBuffer::new(10);

        buffer.add_message(0, vec![1, 2, 3]).unwrap();
        assert_eq!(buffer.next_expected(), 1);

        // Duplicate should fail
        let result = buffer.add_message(0, vec![1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_buffer_overflow() {
        let mut buffer = MessageBuffer::new(2);

        buffer.add_message(1, vec![1]).unwrap();
        buffer.add_message(2, vec![2]).unwrap();

        // Buffer full
        let result = buffer.add_message(3, vec![3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dtls_client_handshake_flight() {
        let tls_handshake = ClientHandshake::new();
        let mut dtls_handshake = DtlsClientHandshake::new(tls_handshake);

        // Add messages to flight
        dtls_handshake.add_message_to_flight(1, vec![1, 2, 3]);
        dtls_handshake.add_message_to_flight(2, vec![4, 5, 6]);

        // Transmit flight
        let messages = dtls_handshake.transmit_flight().unwrap();
        assert_eq!(messages.len(), 2);

        // Check retransmission
        let retransmit = dtls_handshake.check_retransmission().unwrap();
        assert!(retransmit.is_none()); // Not yet timed out
    }

    #[test]
    fn test_cookie_generation_and_verification() {
        use crate::cipher::CipherSuite;
        use hptls_crypto::CryptoProvider;
        use hptls_crypto_hpcrypt::HpcryptProvider;

        // Use hpcrypt provider for testing
        let provider = HpcryptProvider::new();

        let tls_handshake = ServerHandshake::new(vec![CipherSuite::Aes128GcmSha256]);
        let mut dtls_handshake = DtlsServerHandshake::new(tls_handshake);

        let secret = b"test_secret_key_for_cookie_hmac";
        let client_hello = b"client_hello_data";
        let client_addr = b"192.168.1.1:12345";

        // Generate cookie
        let cookie = dtls_handshake
            .generate_cookie(&provider, secret, client_hello, client_addr)
            .unwrap();
        assert!(!cookie.is_empty());
        assert_eq!(cookie.len(), 32); // SHA256 produces 32 bytes

        // Verify cookie
        assert!(dtls_handshake
            .verify_cookie(&provider, secret, &cookie, client_hello, client_addr)
            .unwrap());
        assert!(dtls_handshake.is_cookie_verified());

        // Wrong cookie should fail
        let wrong_cookie = vec![0u8; cookie.len()];
        assert!(!dtls_handshake
            .verify_cookie(&provider, secret, &wrong_cookie, client_hello, client_addr)
            .unwrap());

        // Wrong secret should fail
        let wrong_secret = b"wrong_secret_key_for_cookie_hmac";
        dtls_handshake.cookie_verified = false; // Reset
        assert!(!dtls_handshake
            .verify_cookie(&provider, wrong_secret, &cookie, client_hello, client_addr)
            .unwrap());
    }
}
