//! ServerKeyExchange Message (TLS 1.2 only)
//!
//! RFC 5246 Section 7.4.3
//!
//! The ServerKeyExchange message is sent by the server when using ECDHE key exchange.
//! It contains:
//! - EC curve type (named_curve)
//! - Named curve ID (e.g., secp256r1)
//! - Server's ephemeral ECDHE public key
//! - Signature algorithm
//! - Signature over (ClientHello.random + ServerHello.random + ServerKeyExchange params)
//!
//! Structure:
//! ```text
//! struct {
//!     ECParameters curve_params;
//!     ECPoint public;
//! } ServerECDHParams;
//!
//! struct {
//!     select (KeyExchangeAlgorithm) {
//!         case ec_diffie_hellman:
//!             ServerECDHParams params;
//!             digitally-signed struct {
//!                 opaque client_random[32];
//!                 opaque server_random[32];
//!                 ServerECDHParams params;
//!             } signed_params;
//!     };
//! } ServerKeyExchange;
//! ```

use crate::error::{Error, Result};
use hptls_crypto::{KeyExchangeAlgorithm, SignatureAlgorithm};

/// ServerKeyExchange message for ECDHE.
#[derive(Debug, Clone)]
pub struct ServerKeyExchange {
    /// Named curve (e.g., secp256r1, X25519)
    pub named_curve: KeyExchangeAlgorithm,
    /// Server's ephemeral ECDHE public key
    pub public_key: Vec<u8>,
    /// Signature algorithm used
    pub signature_algorithm: SignatureAlgorithm,
    /// Signature over the key exchange parameters
    pub signature: Vec<u8>,
}

impl ServerKeyExchange {
    /// Create a new ServerKeyExchange message.
    pub fn new(
        named_curve: KeyExchangeAlgorithm,
        public_key: Vec<u8>,
        signature_algorithm: SignatureAlgorithm,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            named_curve,
            public_key,
            signature_algorithm,
            signature,
        }
    }

    /// Encode the ServerKeyExchange message to bytes.
    ///
    /// Format:
    /// - curve_type: u8 (3 = named_curve)
    /// - named_curve: u16
    /// - public_key_length: u8
    /// - public_key: [u8]
    /// - signature_algorithm: u16
    /// - signature_length: u16
    /// - signature: [u8]
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // ECCurveType: named_curve (3)
        bytes.push(3);

        // NamedCurve
        let curve_id = match self.named_curve {
            KeyExchangeAlgorithm::Secp256r1 => 23u16, // secp256r1
            KeyExchangeAlgorithm::Secp384r1 => 24u16, // secp384r1
            KeyExchangeAlgorithm::X25519 => 29u16,    // x25519
            KeyExchangeAlgorithm::X448 => 30u16,      // x448
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "Unsupported curve: {:?}",
                    self.named_curve
                )))
            }
        };
        bytes.extend_from_slice(&curve_id.to_be_bytes());

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

        // Signature algorithm (TLS 1.2 SignatureAndHashAlgorithm)
        bytes.extend_from_slice(&self.signature_algorithm.iana_codepoint().to_be_bytes());

        // Signature length (2 bytes)
        if self.signature.len() > 65535 {
            return Err(Error::InvalidMessage(format!(
                "Signature too large: {} bytes",
                self.signature.len()
            )));
        }
        bytes.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());

        // Signature
        bytes.extend_from_slice(&self.signature);

        Ok(bytes)
    }

    /// Decode a ServerKeyExchange message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::InvalidMessage(
                "ServerKeyExchange too short".to_string(),
            ));
        }

        let mut offset = 0;

        // ECCurveType
        let curve_type = data[offset];
        offset += 1;
        if curve_type != 3 {
            return Err(Error::UnsupportedFeature(format!(
                "Only named curves supported, got curve type {}",
                curve_type
            )));
        }

        // NamedCurve
        let curve_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let named_curve = match curve_id {
            23 => KeyExchangeAlgorithm::Secp256r1,
            24 => KeyExchangeAlgorithm::Secp384r1,
            29 => KeyExchangeAlgorithm::X25519,
            30 => KeyExchangeAlgorithm::X448,
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "Unsupported named curve: {}",
                    curve_id
                )))
            }
        };

        // Public key length
        let pubkey_len = data[offset] as usize;
        offset += 1;

        if offset + pubkey_len > data.len() {
            return Err(Error::InvalidMessage(
                "ServerKeyExchange public key truncated".to_string(),
            ));
        }

        // Public key
        let public_key = data[offset..offset + pubkey_len].to_vec();
        offset += pubkey_len;

        // Signature algorithm
        if offset + 2 > data.len() {
            return Err(Error::InvalidMessage(
                "ServerKeyExchange signature algorithm truncated".to_string(),
            ));
        }
        let sig_alg_value = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let signature_algorithm = SignatureAlgorithm::from_u16(sig_alg_value).ok_or_else(|| {
            Error::UnsupportedFeature(format!("Unknown signature algorithm: {}", sig_alg_value))
        })?;

        // Signature length
        if offset + 2 > data.len() {
            return Err(Error::InvalidMessage(
                "ServerKeyExchange signature length truncated".to_string(),
            ));
        }
        let sig_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + sig_len != data.len() {
            return Err(Error::InvalidMessage(format!(
                "ServerKeyExchange signature length mismatch: expected {}, got {}",
                sig_len,
                data.len() - offset
            )));
        }

        // Signature
        let signature = data[offset..offset + sig_len].to_vec();

        Ok(ServerKeyExchange {
            named_curve,
            public_key,
            signature_algorithm,
            signature,
        })
    }

    /// Get the data that should be signed (for verification).
    ///
    /// signed_params = ClientHello.random + ServerHello.random + ServerKeyExchange.params
    pub fn get_signed_data(
        &self,
        client_random: &[u8],
        server_random: &[u8],
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        // Client random (32 bytes)
        if client_random.len() != 32 {
            return Err(Error::InvalidMessage(format!(
                "Client random must be 32 bytes, got {}",
                client_random.len()
            )));
        }
        data.extend_from_slice(client_random);

        // Server random (32 bytes)
        if server_random.len() != 32 {
            return Err(Error::InvalidMessage(format!(
                "Server random must be 32 bytes, got {}",
                server_random.len()
            )));
        }
        data.extend_from_slice(server_random);

        // ServerECDHParams
        // curve_type (1 byte)
        data.push(3); // named_curve

        // named_curve (2 bytes)
        let curve_id = match self.named_curve {
            KeyExchangeAlgorithm::Secp256r1 => 23u16,
            KeyExchangeAlgorithm::Secp384r1 => 24u16,
            KeyExchangeAlgorithm::X25519 => 29u16,
            KeyExchangeAlgorithm::X448 => 30u16,
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "Unsupported curve: {:?}",
                    self.named_curve
                )))
            }
        };
        data.extend_from_slice(&curve_id.to_be_bytes());

        // public key length (1 byte)
        data.push(self.public_key.len() as u8);

        // public key
        data.extend_from_slice(&self.public_key);

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_key_exchange_encode_decode() {
        let ske = ServerKeyExchange::new(
            KeyExchangeAlgorithm::Secp256r1,
            vec![0x04; 65], // Uncompressed P-256 public key
            SignatureAlgorithm::EcdsaSecp256r1Sha256,
            vec![0xAB; 70], // ECDSA signature
        );

        let encoded = ske.encode().unwrap();
        let decoded = ServerKeyExchange::decode(&encoded).unwrap();

        assert_eq!(decoded.named_curve, ske.named_curve);
        assert_eq!(decoded.public_key, ske.public_key);
        assert_eq!(decoded.signature_algorithm, ske.signature_algorithm);
        assert_eq!(decoded.signature, ske.signature);
    }

    #[test]
    fn test_get_signed_data() {
        let ske = ServerKeyExchange::new(
            KeyExchangeAlgorithm::X25519,
            vec![0x12; 32], // X25519 public key
            SignatureAlgorithm::RsaPssRsaeSha256,
            vec![0xFF; 256], // RSA signature
        );

        let client_random = vec![0x01; 32];
        let server_random = vec![0x02; 32];

        let signed_data = ske.get_signed_data(&client_random, &server_random).unwrap();

        // Should be: client_random (32) + server_random (32) + curve_type (1) + curve_id (2) + pubkey_len (1) + pubkey (32)
        assert_eq!(signed_data.len(), 32 + 32 + 1 + 2 + 1 + 32);

        // Verify structure
        assert_eq!(&signed_data[0..32], client_random.as_slice());
        assert_eq!(&signed_data[32..64], server_random.as_slice());
        assert_eq!(signed_data[64], 3); // curve_type = named_curve
        assert_eq!(u16::from_be_bytes([signed_data[65], signed_data[66]]), 29); // X25519
        assert_eq!(signed_data[67], 32); // pubkey length
        assert_eq!(&signed_data[68..100], &vec![0x12; 32]);
    }
}
