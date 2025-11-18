//! ACK message (RFC 9147 Section 7).
//!
//! ACK is a content type used to improve retransmission efficiency by
//! explicitly acknowledging received records, allowing the peer to stop
//! retransmitting acknowledged records.

use crate::error::{Error, Result};

/// ACK message for explicit record acknowledgment (RFC 9147 Section 7).
///
/// Format:
/// ```text
/// struct {
///     RecordNumber record_numbers<0..2^16-1>;
/// } ACK;
/// ```
///
/// RecordNumbers are encoded as a sequence of record numbers that have been
/// successfully received. This allows the peer to stop retransmitting these records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// List of acknowledged record numbers
    pub record_numbers: Vec<u64>,
}

impl Ack {
    /// Create a new ACK message.
    ///
    /// # Arguments
    /// * `record_numbers` - List of record numbers to acknowledge
    pub fn new(record_numbers: Vec<u64>) -> Self {
        Self { record_numbers }
    }

    /// Encode the ACK message to bytes.
    ///
    /// Format: 2-byte length + variable-length record numbers
    /// Each record number is encoded as a variable-length integer per RFC 9147.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Encode record numbers
        let mut records_buf = Vec::new();
        for &record_num in &self.record_numbers {
            // Encode as variable-length (we'll use simple 8-byte encoding for now)
            records_buf.extend_from_slice(&record_num.to_be_bytes());
        }

        // Length prefix (2 bytes)
        if records_buf.len() > 0xFFFF {
            return Err(Error::InvalidMessage("ACK message too large".into()));
        }
        buf.extend_from_slice(&(records_buf.len() as u16).to_be_bytes());
        buf.extend_from_slice(&records_buf);

        Ok(buf)
    }

    /// Decode an ACK message from bytes.
    ///
    /// # Arguments
    /// * `data` - Encoded ACK message
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::InvalidMessage("ACK message too short".into()));
        }

        let length = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + length {
            return Err(Error::InvalidMessage("ACK message truncated".into()));
        }

        // Decode record numbers (8 bytes each)
        let records_data = &data[2..2 + length];
        if records_data.len() % 8 != 0 {
            return Err(Error::InvalidMessage("Invalid ACK record numbers length".into()));
        }

        let mut record_numbers = Vec::new();
        for chunk in records_data.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            record_numbers.push(u64::from_be_bytes(bytes));
        }

        Ok(Self { record_numbers })
    }

    /// Check if this ACK acknowledges a specific record number.
    pub fn acknowledges(&self, record_num: u64) -> bool {
        self.record_numbers.contains(&record_num)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_encode_decode() {
        let ack = Ack::new(vec![100, 101, 102]);
        let encoded = ack.encode().unwrap();

        let decoded = Ack::decode(&encoded).unwrap();
        assert_eq!(decoded.record_numbers, vec![100, 101, 102]);
    }

    #[test]
    fn test_ack_empty() {
        let ack = Ack::new(vec![]);
        let encoded = ack.encode().unwrap();

        let decoded = Ack::decode(&encoded).unwrap();
        assert_eq!(decoded.record_numbers.len(), 0);
    }

    #[test]
    fn test_ack_acknowledges() {
        let ack = Ack::new(vec![100, 200, 300]);
        assert!(ack.acknowledges(100));
        assert!(ack.acknowledges(200));
        assert!(!ack.acknowledges(150));
    }
}
