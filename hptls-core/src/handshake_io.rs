//! Handshake message I/O utilities.
//!
//! This module provides utilities for reading and writing handshake messages
//! over a network stream, handling TLS record framing and handshake message framing.

use crate::error::{Error, Result};
use crate::protocol::{ContentType, HandshakeType, ProtocolVersion};
use crate::record::TlsPlaintext;
use bytes::{Buf, BufMut, BytesMut};

/// Handshake message wrapper.
///
/// ```text
/// struct {
///     HandshakeType msg_type;    /* handshake type */
///     uint24 length;             /* bytes in message */
///     select (Handshake.msg_type) {
///         case client_hello:          ClientHello;
///         case server_hello:          ServerHello;
///         case end_of_early_data:     EndOfEarlyData;
///         case encrypted_extensions:  EncryptedExtensions;
///         case certificate_request:   CertificateRequest;
///         case certificate:           Certificate;
///         case certificate_verify:    CertificateVerify;
///         case finished:              Finished;
///         case new_session_ticket:    NewSessionTicket;
///         case key_update:            KeyUpdate;
///     };
/// } Handshake;
/// ```
#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    pub msg_type: HandshakeType,
    pub payload: Vec<u8>,
}

impl HandshakeMessage {
    /// Create a new handshake message.
    pub fn new(msg_type: HandshakeType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Encode the handshake message.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Message type (1 byte)
        buf.put_u8(self.msg_type.to_u8());

        // Length (3 bytes, big-endian)
        let len = self.payload.len();
        if len > 0x00FFFFFF {
            return Err(Error::InvalidMessage("Handshake message too large".into()));
        }
        buf.put_u8(((len >> 16) & 0xFF) as u8);
        buf.put_u8(((len >> 8) & 0xFF) as u8);
        buf.put_u8((len & 0xFF) as u8);

        // Payload
        buf.put_slice(&self.payload);

        Ok(buf.to_vec())
    }

    /// Decode a handshake message from bytes.
    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidMessage("Handshake message too short".into()));
        }

        // Message type
        let msg_type_raw = data.get_u8();
        let msg_type = HandshakeType::from_u8(msg_type_raw).ok_or_else(|| {
            Error::InvalidMessage(format!("Unknown handshake type: {}", msg_type_raw))
        })?;

        // Length (3 bytes)
        let len_high = data.get_u8() as usize;
        let len_mid = data.get_u8() as usize;
        let len_low = data.get_u8() as usize;
        let length = (len_high << 16) | (len_mid << 8) | len_low;

        // Payload
        if data.len() < length {
            return Err(Error::InvalidMessage("Incomplete handshake message".into()));
        }
        let payload = data[..length].to_vec();

        Ok(Self { msg_type, payload })
    }

    /// Wrap the handshake message in a TLS record.
    pub fn to_record(&self) -> Result<TlsPlaintext> {
        let encoded = self.encode()?;
        Ok(TlsPlaintext::new(
            ContentType::Handshake,
            ProtocolVersion::Tls12, // Legacy version for compatibility
            encoded,
        ))
    }
}

/// Parse multiple handshake messages from a byte buffer.
///
/// Returns a vector of handshake messages and the number of bytes consumed.
pub fn parse_handshake_messages(mut data: &[u8]) -> Result<(Vec<HandshakeMessage>, usize)> {
    let original_len = data.len();
    let mut messages = Vec::new();

    while data.len() >= 4 {
        // Peek at the length to see if we have a complete message
        let len_high = data[1] as usize;
        let len_mid = data[2] as usize;
        let len_low = data[3] as usize;
        let length = (len_high << 16) | (len_mid << 8) | len_low;

        // Check if we have the full message
        if data.len() < 4 + length {
            break; // Incomplete message, wait for more data
        }

        // Parse the message
        let msg = HandshakeMessage::decode(data)?;
        let consumed = 4 + length;
        data = &data[consumed..];
        messages.push(msg);
    }

    let bytes_consumed = original_len - data.len();
    Ok((messages, bytes_consumed))
}

/// Parse TLS records from a byte buffer.
///
/// Returns a vector of records and the number of bytes consumed.
pub fn parse_tls_records(mut data: &[u8]) -> Result<(Vec<TlsPlaintext>, usize)> {
    let original_len = data.len();
    let mut records = Vec::new();

    while data.len() >= 5 {
        // Peek at the length to see if we have a complete record
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        // Check if we have the full record
        if data.len() < 5 + length {
            break; // Incomplete record, wait for more data
        }

        // Parse the record
        let record = TlsPlaintext::decode(data)?;
        let consumed = record.len();
        data = &data[consumed..];
        records.push(record);
    }

    let bytes_consumed = original_len - data.len();
    Ok((records, bytes_consumed))
}

/// Extract handshake messages from TLS records.
pub fn extract_handshake_messages(records: &[TlsPlaintext]) -> Result<Vec<HandshakeMessage>> {
    let mut all_handshake_data = Vec::new();

    // Collect all handshake data from records
    for record in records {
        if record.content_type == ContentType::Handshake {
            all_handshake_data.extend_from_slice(&record.fragment);
        }
    }

    // Parse handshake messages from the collected data
    let (messages, _) = parse_handshake_messages(&all_handshake_data)?;
    Ok(messages)
}

/// Handshake message parser for processing server messages.
pub struct HandshakeMessageParser {
    buffer: Vec<u8>,
}

impl HandshakeMessageParser {
    /// Create a new parser.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Add received data to the parser.
    pub fn add_data(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to parse complete TLS records from the buffer.
    pub fn parse_records(&mut self) -> Result<Vec<TlsPlaintext>> {
        let (records, consumed) = parse_tls_records(&self.buffer)?;
        self.buffer.drain(..consumed);
        Ok(records)
    }

    /// Try to parse complete handshake messages from the buffer.
    pub fn parse_messages(&mut self) -> Result<Vec<HandshakeMessage>> {
        let (messages, consumed) = parse_handshake_messages(&self.buffer)?;
        self.buffer.drain(..consumed);
        Ok(messages)
    }

    /// Get the number of buffered bytes.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for HandshakeMessageParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_message_encode_decode() {
        let payload = vec![1, 2, 3, 4, 5];
        let msg = HandshakeMessage::new(HandshakeType::ClientHello, payload.clone());

        let encoded = msg.encode().unwrap();
        let decoded = HandshakeMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.msg_type, HandshakeType::ClientHello);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_parse_multiple_handshake_messages() {
        let msg1 = HandshakeMessage::new(HandshakeType::ClientHello, vec![1, 2, 3]);
        let msg2 = HandshakeMessage::new(HandshakeType::ServerHello, vec![4, 5, 6]);

        let mut data = Vec::new();
        data.extend_from_slice(&msg1.encode().unwrap());
        data.extend_from_slice(&msg2.encode().unwrap());

        let (messages, consumed) = parse_handshake_messages(&data).unwrap();

        assert_eq!(messages.len(), 2);
        assert_eq!(consumed, data.len());
        assert_eq!(messages[0].msg_type, HandshakeType::ClientHello);
        assert_eq!(messages[1].msg_type, HandshakeType::ServerHello);
    }

    #[test]
    fn test_parse_partial_handshake_message() {
        let msg = HandshakeMessage::new(HandshakeType::ClientHello, vec![1, 2, 3, 4, 5]);
        let encoded = msg.encode().unwrap();

        // Only provide partial data
        let partial = &encoded[..encoded.len() - 2];
        let (messages, consumed) = parse_handshake_messages(partial).unwrap();

        assert_eq!(messages.len(), 0); // No complete messages
        assert_eq!(consumed, 0); // No bytes consumed
    }

    #[test]
    fn test_handshake_message_parser() {
        let mut parser = HandshakeMessageParser::new();

        let msg1 = HandshakeMessage::new(HandshakeType::ClientHello, vec![1, 2, 3]);
        let msg2 = HandshakeMessage::new(HandshakeType::ServerHello, vec![4, 5, 6]);

        let encoded1 = msg1.encode().unwrap();
        let encoded2 = msg2.encode().unwrap();

        // Add first message in two parts
        parser.add_data(&encoded1[..encoded1.len() / 2]);
        assert_eq!(parser.parse_messages().unwrap().len(), 0); // Incomplete

        parser.add_data(&encoded1[encoded1.len() / 2..]);
        let messages = parser.parse_messages().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].msg_type, HandshakeType::ClientHello);

        // Add second message complete
        parser.add_data(&encoded2);
        let messages = parser.parse_messages().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].msg_type, HandshakeType::ServerHello);
    }

    #[test]
    fn test_parse_tls_records() {
        let record1 = TlsPlaintext::new(
            ContentType::Handshake,
            ProtocolVersion::Tls12,
            vec![1, 2, 3],
        );
        let record2 = TlsPlaintext::new(
            ContentType::ApplicationData,
            ProtocolVersion::Tls12,
            vec![4, 5, 6],
        );

        let mut data = Vec::new();
        data.extend_from_slice(&record1.encode().unwrap());
        data.extend_from_slice(&record2.encode().unwrap());

        let (records, consumed) = parse_tls_records(&data).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(consumed, data.len());
        assert_eq!(records[0].content_type, ContentType::Handshake);
        assert_eq!(records[1].content_type, ContentType::ApplicationData);
    }
}
