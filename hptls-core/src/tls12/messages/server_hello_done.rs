//! ServerHelloDone Message (TLS 1.2 only)
//!
//! RFC 5246 Section 7.4.5
//!
//! The ServerHelloDone message is sent by the server to indicate that it has finished
//! sending messages to support the key exchange, and the client can proceed with
//! its phase of the key exchange.
//!
//! This is an empty message - it has no payload.
//!
//! Structure:
//! ```text
//! struct { } ServerHelloDone;
//! ```

use crate::error::{Error, Result};

/// ServerHelloDone message (empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHelloDone;

impl ServerHelloDone {
    /// Create a new ServerHelloDone message.
    pub fn new() -> Self {
        ServerHelloDone
    }

    /// Encode the ServerHelloDone message to bytes (empty).
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    /// Decode a ServerHelloDone message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if !data.is_empty() {
            return Err(Error::InvalidMessage(format!(
                "ServerHelloDone must be empty, got {} bytes",
                data.len()
            )));
        }
        Ok(ServerHelloDone)
    }
}

impl Default for ServerHelloDone {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_hello_done() {
        let shd = ServerHelloDone::new();
        let encoded = shd.encode().unwrap();
        assert_eq!(encoded.len(), 0);

        let decoded = ServerHelloDone::decode(&encoded).unwrap();
        assert_eq!(decoded, shd);
    }

    #[test]
    fn test_server_hello_done_non_empty_fails() {
        let result = ServerHelloDone::decode(&[0x00]);
        assert!(result.is_err());
    }
}
