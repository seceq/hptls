//! NewConnectionId message for runtime CID updates (RFC 9146 Section 6).

use crate::error::{Error, Result};

/// NewConnectionId message for updating Connection ID post-handshake.
///
/// Format (RFC 9146 Section 6):
/// ```text
/// struct {
///     opaque cid<0..255>;
///     uint64 sequence_number;
/// } NewConnectionId;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConnectionId {
    /// New Connection ID to use
    pub cid: Vec<u8>,
    /// Sequence number for this CID (monotonically increasing)
    pub sequence_number: u64,
}

impl NewConnectionId {
    /// Create a new NewConnectionId message.
    pub fn new(cid: Vec<u8>, sequence_number: u64) -> Self {
        Self { cid, sequence_number }
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.cid.len() > 255 {
            return Err(Error::InvalidMessage("Connection ID too long".into()));
        }

        let mut buf = Vec::new();
        buf.push(self.cid.len() as u8);
        buf.extend_from_slice(&self.cid);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        Ok(buf)
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidMessage("NewConnectionId too short".into()));
        }

        let cid_len = data[0] as usize;
        if data.len() < 1 + cid_len + 8 {
            return Err(Error::InvalidMessage("NewConnectionId truncated".into()));
        }

        let cid = data[1..1 + cid_len].to_vec();
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&data[1 + cid_len..1 + cid_len + 8]);
        let sequence_number = u64::from_be_bytes(seq_bytes);

        Ok(Self { cid, sequence_number })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_connection_id_encode_decode() {
        let msg = NewConnectionId::new(vec![1, 2, 3, 4], 42);
        let encoded = msg.encode().unwrap();
        let decoded = NewConnectionId::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }
}
