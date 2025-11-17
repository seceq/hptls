//! ServerHello message (RFC 8446 Section 4.1.3).

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};
use crate::extensions::Extensions;
use crate::protocol::ProtocolVersion;
use bytes::{Buf, BufMut, BytesMut};

/// ServerHello message.
///
/// ```text
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id_echo<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Legacy version (always 0x0303 for TLS 1.3)
    pub legacy_version: ProtocolVersion,

    /// Random bytes (32 bytes)
    pub random: [u8; 32],

    /// Legacy session ID echo (echoes client's session ID)
    pub legacy_session_id_echo: Vec<u8>,

    /// Selected cipher suite
    pub cipher_suite: CipherSuite,

    /// Legacy compression method (must be 0 for TLS 1.3)
    pub legacy_compression_method: u8,

    /// Extensions
    pub extensions: Extensions,
}

/// HelloRetryRequest special random value (RFC 8446 Section 4.1.3)
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

impl ServerHello {
    /// Create a new ServerHello.
    pub fn new(random: [u8; 32], cipher_suite: CipherSuite) -> Self {
        Self {
            legacy_version: ProtocolVersion::Tls12, // Always 0x0303
            random,
            legacy_session_id_echo: Vec::new(),
            cipher_suite,
            legacy_compression_method: 0,
            extensions: Extensions::new(),
        }
    }

    /// Create a HelloRetryRequest.
    ///
    /// A HelloRetryRequest is a ServerHello with a special random value.
    pub fn hello_retry_request(cipher_suite: CipherSuite) -> Self {
        Self {
            legacy_version: ProtocolVersion::Tls12,
            random: HELLO_RETRY_REQUEST_RANDOM,
            legacy_session_id_echo: Vec::new(),
            cipher_suite,
            legacy_compression_method: 0,
            extensions: Extensions::new(),
        }
    }

    /// Check if this is a HelloRetryRequest.
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }

    /// Set the legacy session ID echo.
    pub fn with_session_id_echo(mut self, session_id: Vec<u8>) -> Self {
        self.legacy_session_id_echo = session_id;
        self
    }

    /// Add extensions.
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = extensions;
        self
    }

    /// Encode the ServerHello to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Legacy version (2 bytes)
        buf.put_u16(self.legacy_version.to_u16());

        // Random (32 bytes)
        buf.put_slice(&self.random);

        // Legacy session ID echo (length + data)
        if self.legacy_session_id_echo.len() > 32 {
            return Err(Error::InvalidMessage("Session ID too long".into()));
        }
        buf.put_u8(self.legacy_session_id_echo.len() as u8);
        buf.put_slice(&self.legacy_session_id_echo);

        // Cipher suite (2 bytes)
        buf.put_u16(self.cipher_suite.to_u16());

        // Legacy compression method (1 byte, must be 0)
        buf.put_u8(self.legacy_compression_method);

        // Extensions
        let ext_bytes = self.extensions.encode();
        buf.put_slice(&ext_bytes);

        Ok(buf.to_vec())
    }

    /// Decode a ServerHello from bytes.
    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.len() < 38 {
            // Min: 2 (version) + 32 (random) + 1 (sid_len) + 2 (cipher) + 1 (compression) + 2 (ext_len) - 2 (min sid)
            return Err(Error::InvalidMessage("ServerHello too short".into()));
        }

        // Legacy version
        let version_raw = data.get_u16();
        let legacy_version = ProtocolVersion::from_u16(version_raw)
            .ok_or_else(|| Error::InvalidMessage("Invalid legacy version".into()))?;

        // Random
        let mut random = [0u8; 32];
        data.copy_to_slice(&mut random);

        // Legacy session ID echo
        let session_id_len = data.get_u8() as usize;
        if session_id_len > 32 {
            return Err(Error::InvalidMessage("Session ID too long".into()));
        }
        if data.len() < session_id_len {
            return Err(Error::InvalidMessage("Incomplete session ID".into()));
        }
        let legacy_session_id_echo = data[..session_id_len].to_vec();
        data.advance(session_id_len);

        // Cipher suite
        if data.len() < 2 {
            return Err(Error::InvalidMessage("Missing cipher suite".into()));
        }
        let suite_raw = data.get_u16();
        let cipher_suite = CipherSuite::from_u16(suite_raw)
            .ok_or_else(|| Error::InvalidMessage("Unknown cipher suite".into()))?;

        // Legacy compression method
        if data.is_empty() {
            return Err(Error::InvalidMessage("Missing compression method".into()));
        }
        let legacy_compression_method = data.get_u8();
        if legacy_compression_method != 0 {
            return Err(Error::InvalidMessage(
                "Non-zero compression method in TLS 1.3".into(),
            ));
        }

        // Extensions
        let extensions = Extensions::decode(data)?;

        Ok(Self {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_hello_encode_decode() {
        let random = [0x42u8; 32];
        let hello = ServerHello::new(random, CipherSuite::Aes128GcmSha256)
            .with_session_id_echo(vec![0x01, 0x02, 0x03]);

        let encoded = hello.encode().unwrap();
        let decoded = ServerHello::decode(&encoded).unwrap();

        assert_eq!(decoded.legacy_version, ProtocolVersion::Tls12);
        assert_eq!(decoded.random, random);
        assert_eq!(decoded.legacy_session_id_echo, vec![0x01, 0x02, 0x03]);
        assert_eq!(decoded.cipher_suite, CipherSuite::Aes128GcmSha256);
        assert_eq!(decoded.legacy_compression_method, 0);
        assert!(!decoded.is_hello_retry_request());
    }

    #[test]
    fn test_hello_retry_request() {
        let hrr = ServerHello::hello_retry_request(CipherSuite::Aes128GcmSha256);

        assert!(hrr.is_hello_retry_request());
        assert_eq!(hrr.random, HELLO_RETRY_REQUEST_RANDOM);

        let encoded = hrr.encode().unwrap();
        let decoded = ServerHello::decode(&encoded).unwrap();

        assert!(decoded.is_hello_retry_request());
    }

    #[test]
    fn test_server_hello_invalid() {
        // Too short
        let result = ServerHello::decode(&[1, 2, 3]);
        assert!(result.is_err());

        // Non-zero compression
        let mut data = vec![0x03, 0x03]; // version
        data.extend_from_slice(&[0u8; 32]); // random
        data.push(0); // session ID length
        data.extend_from_slice(&[0x13, 0x01]); // cipher suite
        data.push(1); // non-zero compression
        data.extend_from_slice(&[0, 0]); // extensions length
        let result = ServerHello::decode(&data);
        assert!(result.is_err());
    }
}
