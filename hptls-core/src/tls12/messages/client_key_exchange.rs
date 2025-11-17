//! ClientKeyExchange Message (TLS 1.2 only)
//!
//! RFC 5246 Section 7.4.7
//!
//! The ClientKeyExchange message is sent by the client after receiving ServerKeyExchange.
//! For ECDHE, it contains the client's ephemeral public key.
//!
//! Structure:
//! ```text
//! struct {
//!     select (KeyExchangeAlgorithm) {
//!         case ec_diffie_hellman:
//!             ECPoint ecdh_Yc;  // Client's ephemeral ECDH public key
//!     } exchange_keys;
//! } ClientKeyExchange;
//! ```

use crate::error::{Error, Result};

/// ClientKeyExchange message for ECDHE.
#[derive(Debug, Clone)]
pub struct ClientKeyExchange {
    /// Client's ephemeral ECDHE public key
    pub public_key: Vec<u8>,
}

impl ClientKeyExchange {
    /// Create a new ClientKeyExchange message.
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }

    /// Encode the ClientKeyExchange message to bytes.
    ///
    /// Format:
    /// - public_key_length: u8
    /// - public_key: [u8]
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Public key length (1 byte)
        if self.public_key.len() > 255 {
            return Err(Error::InvalidMessage(format!(
                "Public key too large: {} bytes",
                self.public_key.len()
            )));
        }
        bytes.push(self.public_key.len() as u8);

        // Public key
        bytes.extend_from_slice(&self.public_key);

        Ok(bytes)
    }

    /// Decode a ClientKeyExchange message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidMessage(
                "ClientKeyExchange is empty".to_string(),
            ));
        }

        // Public key length
        let pubkey_len = data[0] as usize;

        if data.len() != 1 + pubkey_len {
            return Err(Error::InvalidMessage(format!(
                "ClientKeyExchange length mismatch: expected {}, got {}",
                1 + pubkey_len,
                data.len()
            )));
        }

        // Public key
        let public_key = data[1..1 + pubkey_len].to_vec();

        Ok(ClientKeyExchange { public_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_key_exchange_encode_decode() {
        // X25519 public key (32 bytes)
        let cke = ClientKeyExchange::new(vec![0x42; 32]);

        let encoded = cke.encode().unwrap();
        assert_eq!(encoded.len(), 33); // 1 byte length + 32 bytes key

        let decoded = ClientKeyExchange::decode(&encoded).unwrap();
        assert_eq!(decoded.public_key, cke.public_key);
    }

    #[test]
    fn test_client_key_exchange_p256() {
        // Uncompressed P-256 public key (65 bytes: 0x04 || x || y)
        let cke = ClientKeyExchange::new(vec![0x04; 65]);

        let encoded = cke.encode().unwrap();
        assert_eq!(encoded.len(), 66); // 1 byte length + 65 bytes key

        let decoded = ClientKeyExchange::decode(&encoded).unwrap();
        assert_eq!(decoded.public_key.len(), 65);
        assert_eq!(decoded.public_key[0], 0x04);
    }
}
