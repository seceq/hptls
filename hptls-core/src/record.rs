//! TLS record layer implementation.
//!
//! The record layer provides:
//! - Fragmentation of messages into TLSPlaintext records
//! - Encryption/decryption of records (TLSCiphertext)
//! - Record validation and integrity checking
//!
//! # Record Structure (TLS 1.3)
//!
//! ```text
//! struct {
//!     ContentType type;
//!     ProtocolVersion legacy_record_version = 0x0303; // TLS 1.2 for compatibility
//!     uint16 length;
//!     opaque fragment[TLSPlaintext.length];
//! } TLSPlaintext;
//! ```

use crate::error::{Error, Result};
use crate::protocol::{ContentType, ProtocolVersion};

/// Maximum TLS record size (16 KB + headers).
pub const MAX_RECORD_SIZE: usize = 16384 + 256;

/// Maximum plaintext fragment size.
pub const MAX_FRAGMENT_SIZE: usize = 16384;

/// TLS record header size (5 bytes).
pub const RECORD_HEADER_SIZE: usize = 5;

/// TLS record (plaintext).
#[derive(Debug, Clone)]
pub struct TlsPlaintext {
    /// Content type
    pub content_type: ContentType,

    /// Protocol version (legacy field in TLS 1.3)
    pub version: ProtocolVersion,

    /// Fragment data
    pub fragment: Vec<u8>,
}

impl TlsPlaintext {
    /// Create a new plaintext record.
    pub fn new(content_type: ContentType, version: ProtocolVersion, fragment: Vec<u8>) -> Self {
        Self {
            content_type,
            version,
            fragment,
        }
    }

    /// Get the record length (including header).
    pub fn len(&self) -> usize {
        RECORD_HEADER_SIZE + self.fragment.len()
    }

    /// Check if the record is empty.
    pub fn is_empty(&self) -> bool {
        self.fragment.is_empty()
    }

    /// Encode the record to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.fragment.len() > MAX_FRAGMENT_SIZE {
            return Err(Error::InvalidMessage("Fragment too large".into()));
        }

        let mut buf = Vec::with_capacity(self.len());

        // Content type (1 byte)
        buf.push(self.content_type.to_u8());

        // Version (2 bytes)
        buf.extend_from_slice(&self.version.to_u16().to_be_bytes());

        // Length (2 bytes)
        buf.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());

        // Fragment
        buf.extend_from_slice(&self.fragment);

        Ok(buf)
    }

    /// Decode a record from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < RECORD_HEADER_SIZE {
            return Err(Error::InvalidMessage("Record too short".into()));
        }

        // Parse header
        let content_type = ContentType::from_u8(data[0])
            .ok_or_else(|| Error::InvalidMessage("Invalid content type".into()))?;

        let version_raw = u16::from_be_bytes([data[1], data[2]]);
        let version = ProtocolVersion::from_u16(version_raw)
            .ok_or_else(|| Error::InvalidMessage("Invalid protocol version".into()))?;

        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if length > MAX_FRAGMENT_SIZE {
            return Err(Error::ProtocolError(
                crate::error::ProtocolError::RecordOverflow,
            ));
        }

        if data.len() < RECORD_HEADER_SIZE + length {
            return Err(Error::InvalidMessage("Incomplete record".into()));
        }

        let fragment = data[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + length].to_vec();

        Ok(Self {
            content_type,
            version,
            fragment,
        })
    }
}

/// Record layer state machine.
#[derive(Debug)]
pub struct RecordLayer {
    /// Protocol version in use
    version: ProtocolVersion,

    /// Maximum fragment length
    max_fragment_length: u16,
}

impl RecordLayer {
    /// Create a new record layer.
    pub fn new(version: ProtocolVersion) -> Self {
        Self {
            version,
            max_fragment_length: MAX_FRAGMENT_SIZE as u16,
        }
    }

    /// Set the maximum fragment length.
    pub fn set_max_fragment_length(&mut self, length: u16) {
        self.max_fragment_length = length.min(MAX_FRAGMENT_SIZE as u16);
    }

    /// Fragment a message into multiple records if needed.
    pub fn fragment(&self, content_type: ContentType, data: &[u8]) -> Result<Vec<TlsPlaintext>> {
        let mut records = Vec::new();
        let max_len = self.max_fragment_length as usize;

        for chunk in data.chunks(max_len) {
            records.push(TlsPlaintext::new(
                content_type,
                self.version,
                chunk.to_vec(),
            ));
        }

        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_encode_decode() {
        let record = TlsPlaintext::new(
            ContentType::Handshake,
            ProtocolVersion::Tls13,
            vec![1, 2, 3, 4],
        );

        let encoded = record.encode().unwrap();
        assert_eq!(encoded.len(), RECORD_HEADER_SIZE + 4);

        let decoded = TlsPlaintext::decode(&encoded).unwrap();
        assert_eq!(decoded.content_type, ContentType::Handshake);
        assert_eq!(decoded.version, ProtocolVersion::Tls13);
        assert_eq!(decoded.fragment, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_record_fragmentation() {
        let layer = RecordLayer::new(ProtocolVersion::Tls13);
        let data = vec![0u8; 20000]; // Larger than max fragment

        let records = layer.fragment(ContentType::ApplicationData, &data).unwrap();
        assert!(records.len() > 1);

        let total_len: usize = records.iter().map(|r| r.fragment.len()).sum();
        assert_eq!(total_len, data.len());
    }

    #[test]
    fn test_invalid_record() {
        // Too short
        let result = TlsPlaintext::decode(&[1, 2, 3]);
        assert!(result.is_err());

        // Invalid content type
        let result = TlsPlaintext::decode(&[255, 3, 3, 0, 0]);
        assert!(result.is_err());
    }
}
