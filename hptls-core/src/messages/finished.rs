//! Finished message (RFC 8446 Section 4.4.4).

use crate::error::Result;

/// Finished message.
///
/// Contains verify_data which is an HMAC over the handshake transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// Verify data (HMAC output)
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn new(verify_data: Vec<u8>) -> Self {
        Self { verify_data }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(self.verify_data.clone())
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        Ok(Self {
            verify_data: data.to_vec(),
        })
    }
}
