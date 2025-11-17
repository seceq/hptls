//! Encrypted Client Hello (ECH) Support (draft-ietf-tls-esni)
//!
//! ECH encrypts the ClientHello to prevent passive network observers from
//! learning the server name and other sensitive handshake parameters.
//!
//! # Architecture
//!
//! ```text
//! Client                                     Server
//!
//! 1. DNS Query for _esni.example.com
//!    Retrieves ECHConfig
//!
//! 2. Generate ClientHelloOuter
//!    - public_name (e.g., cloudflare.com)
//!    - encrypted_client_hello extension
//!
//! 3. Generate ClientHelloInner
//!    - real SNI (e.g., secret.example.com)
//!    - encrypted using HPKE
//!
//! ClientHelloOuter          -------->
//! (+ encrypted_client_hello)
//!                                    Decrypt ClientHelloInner
//!                           <--------       ServerHello
//!                                    (+ encrypted_client_hello)
//! ```
//!
//! # Security Properties
//!
//! - SNI privacy: Real server name encrypted
//! - ALPN privacy: Application protocols hidden
//! - Server certificate fingerprinting resistance
//! - Backward compatibility with non-ECH servers
//!
//! # GREASE (Generate Random Extensions And Sustain Extensibility)
//!
//! Clients can send GREASE ECH to test middlebox compatibility:
//! - Random encrypted_client_hello extension
//! - Helps maintain ecosystem compatibility

use crate::error::{Error, Result};
use crate::messages::ClientHello;
use zeroize::Zeroizing;

/// ECH version (0xFE0D for draft-13)
pub const ECH_VERSION: u16 = 0xFE0D;

/// Maximum name length for public_name
pub const MAX_PUBLIC_NAME_LENGTH: usize = 255;

/// ECH configuration mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchMode {
    /// Split mode: ClientHelloOuter and ClientHelloInner are different
    Split = 0,

    /// Shared mode: Most extensions are shared
    Shared = 1,
}

/// ECH configuration
///
/// Retrieved via DNS (HTTPS/SVCB record) or via retry_config in ServerHello
#[derive(Debug, Clone)]
pub struct EchConfig {
    /// ECH version (0xFE0D)
    pub version: u16,

    /// Configuration identifier (8-byte)
    pub config_id: [u8; 8],

    /// Key encapsulation mechanism ID
    pub kem_id: u16,

    /// Public key for key encapsulation
    pub public_key: Vec<u8>,

    /// Cipher suites supported for ECH encryption
    pub cipher_suites: Vec<EchCipherSuite>,

    /// Maximum name length
    pub maximum_name_length: u16,

    /// Public name (cover name)
    pub public_name: String,

    /// Extensions
    pub extensions: Vec<u8>,
}

impl EchConfig {
    /// Create a new ECH config
    pub fn new(
        config_id: [u8; 8],
        kem_id: u16,
        public_key: Vec<u8>,
        cipher_suites: Vec<EchCipherSuite>,
        public_name: String,
    ) -> Result<Self> {
        if public_name.len() > MAX_PUBLIC_NAME_LENGTH {
            return Err(Error::InvalidConfig("Public name too long".into()));
        }

        Ok(Self {
            version: ECH_VERSION,
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length: MAX_PUBLIC_NAME_LENGTH as u16,
            public_name,
            extensions: Vec::new(),
        })
    }

    /// Encode to wire format
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Version (2 bytes)
        buf.extend_from_slice(&self.version.to_be_bytes());

        // Config ID (8 bytes)
        buf.extend_from_slice(&self.config_id);

        // KEM ID (2 bytes)
        buf.extend_from_slice(&self.kem_id.to_be_bytes());

        // Public key length (2 bytes) + public key
        buf.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key);

        // Cipher suites length (2 bytes) + cipher suites
        let cs_len = self.cipher_suites.len() * 4; // Each cipher suite is 4 bytes
        buf.extend_from_slice(&(cs_len as u16).to_be_bytes());
        for cs in &self.cipher_suites {
            buf.extend_from_slice(&cs.encode());
        }

        // Maximum name length (2 bytes)
        buf.extend_from_slice(&self.maximum_name_length.to_be_bytes());

        // Public name length (1 byte) + public name
        buf.push(self.public_name.len() as u8);
        buf.extend_from_slice(self.public_name.as_bytes());

        // Extensions length (2 bytes) + extensions
        buf.extend_from_slice(&(self.extensions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.extensions);

        Ok(buf)
    }

    /// Decode from wire format
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 15 {
            return Err(Error::InvalidMessage("ECH config too short".into()));
        }

        let mut offset = 0;

        // Version
        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Config ID
        let mut config_id = [0u8; 8];
        config_id.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;

        // KEM ID
        let kem_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Public key
        let pk_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let public_key = data[offset..offset + pk_len].to_vec();
        offset += pk_len;

        // Cipher suites
        let cs_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let mut cipher_suites = Vec::new();
        let mut cs_offset = 0;
        while cs_offset < cs_len {
            let cs = EchCipherSuite::decode(&data[offset + cs_offset..])?;
            cipher_suites.push(cs);
            cs_offset += 4;
        }
        offset += cs_len;

        // Maximum name length
        let maximum_name_length = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Public name
        let name_len = data[offset] as usize;
        offset += 1;
        let public_name = String::from_utf8(data[offset..offset + name_len].to_vec())
            .map_err(|_| Error::InvalidMessage("Invalid public name".into()))?;
        offset += name_len;

        // Extensions
        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let extensions = data[offset..offset + ext_len].to_vec();

        Ok(Self {
            version,
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length,
            public_name,
            extensions,
        })
    }
}

/// ECH cipher suite
///
/// Specifies KDF and AEAD for ECH encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchCipherSuite {
    /// KDF ID (HKDF-SHA256 = 0x0001, HKDF-SHA384 = 0x0002)
    pub kdf_id: u16,

    /// AEAD ID (AES-128-GCM = 0x0001, AES-256-GCM = 0x0002, ChaCha20Poly1305 = 0x0003)
    pub aead_id: u16,
}

impl EchCipherSuite {
    /// HKDF-SHA256 + AES-128-GCM
    pub const HKDF_SHA256_AES128GCM: Self = Self {
        kdf_id: 0x0001,
        aead_id: 0x0001,
    };

    /// HKDF-SHA256 + AES-256-GCM
    pub const HKDF_SHA256_AES256GCM: Self = Self {
        kdf_id: 0x0001,
        aead_id: 0x0002,
    };

    /// HKDF-SHA256 + ChaCha20Poly1305
    pub const HKDF_SHA256_CHACHA20POLY1305: Self = Self {
        kdf_id: 0x0001,
        aead_id: 0x0003,
    };

    /// Encode to 4 bytes
    pub fn encode(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&self.kdf_id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.aead_id.to_be_bytes());
        buf
    }

    /// Decode from 4 bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidMessage("ECH cipher suite too short".into()));
        }

        Ok(Self {
            kdf_id: u16::from_be_bytes([data[0], data[1]]),
            aead_id: u16::from_be_bytes([data[2], data[3]]),
        })
    }
}

/// Encrypted Client Hello context
#[derive(Debug)]
pub struct EchContext {
    /// ECH configuration
    pub config: EchConfig,

    /// Selected cipher suite
    pub cipher_suite: EchCipherSuite,

    /// HPKE encryption context (encapsulated key)
    pub enc: Vec<u8>,

    /// Encrypted payload
    pub payload: Zeroizing<Vec<u8>>,
}

impl EchContext {
    /// Create a new ECH context
    pub fn new(
        config: EchConfig,
        cipher_suite: EchCipherSuite,
        enc: Vec<u8>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            config,
            cipher_suite,
            enc,
            payload: Zeroizing::new(payload),
        }
    }
}

/// ClientHello split for ECH
///
/// Separates ClientHello into outer (public) and inner (private) parts
#[derive(Debug, Clone)]
pub struct ClientHelloSplit {
    /// ClientHelloOuter (sent on wire)
    pub outer: ClientHello,

    /// ClientHelloInner (encrypted)
    pub inner: ClientHello,
}

impl ClientHelloSplit {
    /// Create a new split ClientHello
    pub fn new(outer: ClientHello, inner: ClientHello) -> Self {
        Self { outer, inner }
    }

    /// Get the outer ClientHello (to send)
    pub fn outer(&self) -> &ClientHello {
        &self.outer
    }

    /// Get the inner ClientHello (for transcript)
    pub fn inner(&self) -> &ClientHello {
        &self.inner
    }
}

/// GREASE ECH (for testing)
///
/// Sends random encrypted_client_hello extension to test compatibility
pub fn generate_grease_ech() -> Vec<u8> {
    // Generate random ECH extension data (minimum viable)
    let mut grease = Vec::new();

    // ECH version (2 bytes) - use GREASE value
    grease.extend_from_slice(&0xFAFA_u16.to_be_bytes());

    // Cipher suite (4 bytes) - GREASE
    grease.extend_from_slice(&0xFAFA_u16.to_be_bytes());
    grease.extend_from_slice(&0xFAFA_u16.to_be_bytes());

    // Config ID (8 bytes) - zeros
    grease.extend_from_slice(&[0u8; 8]);

    // Enc length (2 bytes) + enc (32 bytes of random)
    grease.extend_from_slice(&32_u16.to_be_bytes());
    grease.extend_from_slice(&[0xFA; 32]); // GREASE pattern

    // Payload length (2 bytes) + payload (64 bytes of random)
    grease.extend_from_slice(&64_u16.to_be_bytes());
    grease.extend_from_slice(&[0xFA; 64]); // GREASE pattern

    grease
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ech_cipher_suite_encode_decode() {
        let cs = EchCipherSuite::HKDF_SHA256_AES128GCM;
        let encoded = cs.encode();
        let decoded = EchCipherSuite::decode(&encoded).unwrap();
        assert_eq!(cs, decoded);
    }

    #[test]
    fn test_ech_config_creation() {
        let config = EchConfig::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            0x0020, // X25519
            vec![0x01; 32],
            vec![EchCipherSuite::HKDF_SHA256_AES128GCM],
            "cloudflare.com".to_string(),
        )
        .unwrap();

        assert_eq!(config.version, ECH_VERSION);
        assert_eq!(config.public_name, "cloudflare.com");
    }

    #[test]
    fn test_ech_config_encode_decode() {
        let config = EchConfig::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            0x0020,
            vec![0x01; 32],
            vec![EchCipherSuite::HKDF_SHA256_AES128GCM],
            "example.com".to_string(),
        )
        .unwrap();

        let encoded = config.encode().unwrap();
        let decoded = EchConfig::decode(&encoded).unwrap();

        assert_eq!(config.version, decoded.version);
        assert_eq!(config.config_id, decoded.config_id);
        assert_eq!(config.public_name, decoded.public_name);
    }

    #[test]
    fn test_ech_config_public_name_too_long() {
        let long_name = "a".repeat(300);
        let result = EchConfig::new(
            [1; 8],
            0x0020,
            vec![0x01; 32],
            vec![EchCipherSuite::HKDF_SHA256_AES128GCM],
            long_name,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_grease_ech_generation() {
        let grease = generate_grease_ech();

        // Should have minimum length
        assert!(grease.len() >= 100);

        // Should start with GREASE version
        assert_eq!(u16::from_be_bytes([grease[0], grease[1]]), 0xFAFA);
    }

    #[test]
    fn test_ech_cipher_suite_constants() {
        let cs1 = EchCipherSuite::HKDF_SHA256_AES128GCM;
        assert_eq!(cs1.kdf_id, 0x0001);
        assert_eq!(cs1.aead_id, 0x0001);

        let cs2 = EchCipherSuite::HKDF_SHA256_CHACHA20POLY1305;
        assert_eq!(cs2.kdf_id, 0x0001);
        assert_eq!(cs2.aead_id, 0x0003);
    }
}
