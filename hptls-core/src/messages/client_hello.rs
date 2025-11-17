//! ClientHello message (RFC 8446 Section 4.1.2).

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};
use crate::extensions::Extensions;
use crate::protocol::ProtocolVersion;
use bytes::{Buf, BufMut, BytesMut};

/// ClientHello message.
///
/// ```text
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id<0..32>;
///     CipherSuite cipher_suites<2..2^16-2>;
///     opaque legacy_compression_methods<1..2^8-1>;
///     Extension extensions<8..2^16-1>;
/// } ClientHello;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Legacy version (always 0x0303 for TLS 1.3)
    pub legacy_version: ProtocolVersion,

    /// Random bytes (32 bytes)
    pub random: [u8; 32],

    /// Legacy session ID (for middlebox compatibility)
    pub legacy_session_id: Vec<u8>,

    /// Cipher suites offered by client
    pub cipher_suites: Vec<CipherSuite>,

    /// Legacy compression methods (must be [0] for TLS 1.3)
    pub legacy_compression_methods: Vec<u8>,

    /// Extensions
    pub extensions: Extensions,
}

impl ClientHello {
    /// Create a new ClientHello.
    pub fn new(random: [u8; 32], cipher_suites: Vec<CipherSuite>) -> Self {
        Self {
            legacy_version: ProtocolVersion::Tls12, // Always 0x0303
            random,
            legacy_session_id: Vec::new(),
            cipher_suites,
            legacy_compression_methods: vec![0], // No compression
            extensions: Extensions::new(),
        }
    }

    /// Set the legacy session ID (for compatibility mode).
    pub fn with_session_id(mut self, session_id: Vec<u8>) -> Self {
        self.legacy_session_id = session_id;
        self
    }

    /// Add an extension.
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = extensions;
        self
    }

    /// Encode the ClientHello to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Legacy version (2 bytes)
        buf.put_u16(self.legacy_version.to_u16());

        // Random (32 bytes)
        buf.put_slice(&self.random);

        // Legacy session ID (length + data)
        if self.legacy_session_id.len() > 32 {
            return Err(Error::InvalidMessage("Session ID too long".into()));
        }
        buf.put_u8(self.legacy_session_id.len() as u8);
        buf.put_slice(&self.legacy_session_id);

        // Cipher suites (length + data)
        let cipher_suites_len = self.cipher_suites.len() * 2;
        if cipher_suites_len > 65534 {
            return Err(Error::InvalidMessage("Too many cipher suites".into()));
        }
        buf.put_u16(cipher_suites_len as u16);
        for suite in &self.cipher_suites {
            buf.put_u16(suite.to_u16());
        }

        // Legacy compression methods (length + data)
        if self.legacy_compression_methods.is_empty() || self.legacy_compression_methods.len() > 255
        {
            return Err(Error::InvalidMessage(
                "Invalid compression methods length".into(),
            ));
        }
        buf.put_u8(self.legacy_compression_methods.len() as u8);
        buf.put_slice(&self.legacy_compression_methods);

        // Extensions
        let ext_bytes = self.extensions.encode();
        buf.put_slice(&ext_bytes);

        Ok(buf.to_vec())
    }

    /// Decode a ClientHello from bytes.
    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.len() < 41 {
            // Min: 2 (version) + 32 (random) + 1 (sid_len) + 2 (cs_len) + 2 (cm_len) + 2 (ext_len)
            return Err(Error::InvalidMessage("ClientHello too short".into()));
        }

        // Legacy version
        let version_raw = data.get_u16();
        let legacy_version = ProtocolVersion::from_u16(version_raw)
            .ok_or_else(|| Error::InvalidMessage("Invalid legacy version".into()))?;

        // Random
        let mut random = [0u8; 32];
        data.copy_to_slice(&mut random);

        // Legacy session ID
        let session_id_len = data.get_u8() as usize;
        if session_id_len > 32 {
            return Err(Error::InvalidMessage("Session ID too long".into()));
        }
        if data.len() < session_id_len {
            return Err(Error::InvalidMessage("Incomplete session ID".into()));
        }
        let legacy_session_id = data[..session_id_len].to_vec();
        data.advance(session_id_len);

        // Cipher suites
        if data.len() < 2 {
            return Err(Error::InvalidMessage("Missing cipher suites length".into()));
        }
        let cipher_suites_len = data.get_u16() as usize;
        if cipher_suites_len % 2 != 0 || cipher_suites_len < 2 {
            return Err(Error::InvalidMessage("Invalid cipher suites length".into()));
        }
        if data.len() < cipher_suites_len {
            return Err(Error::InvalidMessage("Incomplete cipher suites".into()));
        }
        let mut cipher_suites = Vec::new();
        for _ in 0..(cipher_suites_len / 2) {
            let suite_raw = data.get_u16();
            if let Some(suite) = CipherSuite::from_u16(suite_raw) {
                cipher_suites.push(suite);
            }
            // Note: Unknown cipher suites are silently ignored per RFC
        }

        // Legacy compression methods
        if data.is_empty() {
            return Err(Error::InvalidMessage(
                "Missing compression methods length".into(),
            ));
        }
        let compression_len = data.get_u8() as usize;
        if compression_len == 0 || data.len() < compression_len {
            return Err(Error::InvalidMessage("Invalid compression methods".into()));
        }
        let legacy_compression_methods = data[..compression_len].to_vec();
        data.advance(compression_len);

        // Extensions
        let extensions = Extensions::decode(data)?;

        Ok(Self {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_encode_decode() {
        let random = [0x42u8; 32];
        let cipher_suites = vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::ChaCha20Poly1305Sha256,
        ];

        let hello =
            ClientHello::new(random, cipher_suites.clone()).with_session_id(vec![0x01, 0x02, 0x03]);

        let encoded = hello.encode().unwrap();
        let decoded = ClientHello::decode(&encoded).unwrap();

        assert_eq!(decoded.legacy_version, ProtocolVersion::Tls12);
        assert_eq!(decoded.random, random);
        assert_eq!(decoded.legacy_session_id, vec![0x01, 0x02, 0x03]);
        assert_eq!(decoded.cipher_suites.len(), 2);
        assert_eq!(decoded.legacy_compression_methods, vec![0]);
    }

    #[test]
    fn test_client_hello_minimum() {
        let random = [0u8; 32];
        let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

        let hello = ClientHello::new(random, cipher_suites);
        let encoded = hello.encode().unwrap();

        assert!(encoded.len() >= 41);

        let decoded = ClientHello::decode(&encoded).unwrap();
        assert_eq!(decoded.cipher_suites.len(), 1);
    }

    #[test]
    fn test_client_hello_invalid() {
        // Too short
        let result = ClientHello::decode(&[1, 2, 3]);
        assert!(result.is_err());

        // Invalid session ID length
        let mut data = vec![0x03, 0x03]; // version
        data.extend_from_slice(&[0u8; 32]); // random
        data.push(33); // session ID length > 32
        let result = ClientHello::decode(&data);
        assert!(result.is_err());
    }
}
