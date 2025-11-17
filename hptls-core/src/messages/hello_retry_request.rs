//! HelloRetryRequest message (RFC 8446 Section 4.1.4).
//!
//! HelloRetryRequest is sent by the server when it needs the client to retry
//! the handshake with different parameters. It has the same structure as ServerHello
//! but uses a special random value to distinguish it.
//!
//! # Special Random Value
//!
//! ```text
//! CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
//! C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
//! ```

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};
use crate::extensions::Extensions;
use crate::protocol::ProtocolVersion;
use bytes::{Buf, BufMut, BytesMut};

/// Special random value that identifies a HelloRetryRequest.
///
/// This value is used in place of the server random to distinguish
/// HelloRetryRequest from ServerHello (RFC 8446 Section 4.1.3).
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// HelloRetryRequest message.
///
/// Sent by the server to request that the client retry the handshake with
/// different parameters. This is used when:
/// - The server doesn't support any of the client's key share groups
/// - The server wants to request a client certificate
/// - The server wants to use a cookie for stateless operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloRetryRequest {
    /// Protocol version (must be TLS 1.2 for compatibility)
    pub legacy_version: ProtocolVersion,

    /// Special random value (HELLO_RETRY_REQUEST_RANDOM)
    pub random: [u8; 32],

    /// Cipher suite selected by server
    pub cipher_suite: CipherSuite,

    /// Extensions (must include supported_versions)
    pub extensions: Extensions,
}

impl HelloRetryRequest {
    /// Create a new HelloRetryRequest.
    ///
    /// # Arguments
    ///
    /// * `cipher_suite` - The cipher suite selected by the server
    /// * `extensions` - Extensions (must include supported_versions and selected_group or cookie)
    pub fn new(cipher_suite: CipherSuite, extensions: Extensions) -> Self {
        Self {
            legacy_version: ProtocolVersion::Tls12, // Always 0x0303
            random: HELLO_RETRY_REQUEST_RANDOM,
            cipher_suite,
            extensions,
        }
    }

    /// Check if a random value indicates a HelloRetryRequest.
    pub fn is_hello_retry_request(random: &[u8; 32]) -> bool {
        random == &HELLO_RETRY_REQUEST_RANDOM
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Legacy version (2 bytes)
        buf.put_u16(self.legacy_version.to_u16());

        // Random (32 bytes) - special value
        buf.put_slice(&self.random);

        // Legacy session ID echo (1 byte length + 0 bytes)
        buf.put_u8(0);

        // Cipher suite (2 bytes)
        buf.put_u16(self.cipher_suite as u16);

        // Legacy compression method (1 byte, must be 0)
        buf.put_u8(0);

        // Extensions
        let ext_bytes = self.extensions.encode();
        buf.put_slice(&ext_bytes);

        Ok(buf.to_vec())
    }

    /// Decode from bytes.
    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.len() < 38 {
            // Minimum: 2 (version) + 32 (random) + 1 (session_id_len) + 2 (cipher) + 1 (compression)
            return Err(Error::InvalidMessage("HelloRetryRequest too short".into()));
        }

        // Legacy version
        let version_raw = data.get_u16();
        let legacy_version = ProtocolVersion::from_u16(version_raw)
            .ok_or_else(|| Error::InvalidMessage("Invalid protocol version".into()))?;

        // Random (must be special value)
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[0..32]);
        data.advance(32);

        if random != HELLO_RETRY_REQUEST_RANDOM {
            return Err(Error::InvalidMessage(
                "Invalid HelloRetryRequest random value".into(),
            ));
        }

        // Legacy session ID (should be 0 length)
        let session_id_len = data.get_u8() as usize;
        if session_id_len != 0 {
            return Err(Error::InvalidMessage(
                "HelloRetryRequest must have empty session ID".into(),
            ));
        }

        // Cipher suite
        let cipher_raw = data.get_u16();
        let cipher_suite = CipherSuite::from_u16(cipher_raw)
            .ok_or_else(|| Error::InvalidMessage("Invalid cipher suite".into()))?;

        // Legacy compression method (must be 0)
        let compression = data.get_u8();
        if compression != 0 {
            return Err(Error::InvalidMessage("Invalid compression method".into()));
        }

        // Extensions
        let extensions = Extensions::decode(data)?;

        Ok(Self {
            legacy_version,
            random,
            cipher_suite,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_retry_request_random() {
        assert!(HelloRetryRequest::is_hello_retry_request(
            &HELLO_RETRY_REQUEST_RANDOM
        ));

        let normal_random = [0u8; 32];
        assert!(!HelloRetryRequest::is_hello_retry_request(&normal_random));
    }

    #[test]
    fn test_hello_retry_request_encode_decode() {
        let extensions = Extensions::new();
        // In a real HelloRetryRequest, this would include supported_versions
        // and either key_share (selected_group) or cookie

        let hrr = HelloRetryRequest::new(CipherSuite::Aes128GcmSha256, extensions);

        let encoded = hrr.encode().unwrap();
        let decoded = HelloRetryRequest::decode(&encoded).unwrap();

        assert_eq!(hrr, decoded);
        assert_eq!(decoded.random, HELLO_RETRY_REQUEST_RANDOM);
    }

    #[test]
    fn test_hello_retry_request_rejects_invalid_random() {
        let extensions = Extensions::new();
        let mut hrr = HelloRetryRequest::new(CipherSuite::Aes128GcmSha256, extensions);

        // Change the random to a non-HRR value
        hrr.random = [0u8; 32];

        let encoded = hrr.encode().unwrap();
        let result = HelloRetryRequest::decode(&encoded);

        assert!(result.is_err());
    }
}
