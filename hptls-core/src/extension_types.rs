//! Typed TLS 1.3 extensions with encoding/decoding support.
//!
//! This module provides strongly-typed extension structures that can be
//! encoded to and decoded from wire format.

use crate::error::{Error, Result};
use crate::extensions::Extension;
use crate::protocol::{ExtensionType, ProtocolVersion};
use bytes::{BufMut, BytesMut};
use hptls_crypto::KeyExchangeAlgorithm;

/// Typed TLS extension enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedExtension {
    /// Server Name Indication (SNI)
    ServerName(String),

    /// Supported TLS versions
    SupportedVersions(Vec<ProtocolVersion>),

    /// Supported elliptic curve groups
    SupportedGroups(Vec<KeyExchangeAlgorithm>),

    /// Signature algorithms
    SignatureAlgorithms(Vec<SignatureScheme>),

    /// Key share for ECDHE
    KeyShare(Vec<KeyShareEntry>),

    /// Pre-shared key exchange modes
    PskKeyExchangeModes(Vec<PskKeyExchangeMode>),

    /// Application-Layer Protocol Negotiation
    Alpn(Vec<String>),

    /// Early data indication (0-RTT) - empty in ClientHello
    EarlyData,

    /// Encrypted Client Hello (ECH)
    EncryptedClientHello {
        /// ECH cipher suite (KDF + AEAD)
        cipher_suite: crate::ech::EchCipherSuite,
        /// Config ID (8 bytes)
        config_id: [u8; 8],
        /// Encapsulated key from HPKE
        enc: Vec<u8>,
        /// Encrypted ClientHelloInner payload
        payload: Vec<u8>,
    },

    /// Cookie extension (RFC 8446 Section 4.2.2)
    ///
    /// Used in DTLS 1.3 for stateless DoS protection. The server sends a cookie
    /// in HelloRetryRequest, and the client echoes it in the second ClientHello.
    Cookie(Vec<u8>),

    /// Connection ID extension (RFC 9146)
    ///
    /// Used in DTLS 1.3 for connection migration. Allows endpoints to change
    /// IP address/port while maintaining the same DTLS connection.
    ConnectionId(Vec<u8>),

    /// Post-Handshake Authentication extension (RFC 8446 Section 4.2.6)
    ///
    /// Empty extension indicating client support for post-handshake authentication.
    /// Server can request client certificate after handshake completion.
    PostHandshakeAuth,
}

/// Key share entry (group + key_exchange data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: KeyExchangeAlgorithm,
    pub key_exchange: Vec<u8>,
}

/// Signature scheme (RFC 8446 Section 4.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SignatureScheme {
    // ECDSA algorithms
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,

    // EdDSA algorithms
    Ed25519 = 0x0807,
    Ed448 = 0x0808,

    // RSASSA-PSS algorithms
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,

    // RSASSA-PKCS1-v1_5 algorithms (legacy, not recommended for TLS 1.3)
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,

    // Post-Quantum Signature Algorithms (NIST PQC Standards)
    // ML-DSA (FIPS 204) - Module-Lattice-based Digital Signature Algorithm
    MlDsa44 = 0x0E01, // 128-bit security
    MlDsa65 = 0x0E02, // 192-bit security (recommended)
    MlDsa87 = 0x0E03, // 256-bit security

    // SLH-DSA (FIPS 205) - Stateless Hash-based Digital Signature Algorithm
    SlhDsaSha2_128s = 0x0E10, // Small signature
    SlhDsaSha2_128f = 0x0E11, // Fast verification
    SlhDsaShake256s = 0x0E20, // 256-bit security
}

impl SignatureScheme {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0403 => Some(SignatureScheme::EcdsaSecp256r1Sha256),
            0x0503 => Some(SignatureScheme::EcdsaSecp384r1Sha384),
            0x0603 => Some(SignatureScheme::EcdsaSecp521r1Sha512),
            0x0807 => Some(SignatureScheme::Ed25519),
            0x0808 => Some(SignatureScheme::Ed448),
            0x0804 => Some(SignatureScheme::RsaPssRsaeSha256),
            0x0805 => Some(SignatureScheme::RsaPssRsaeSha384),
            0x0806 => Some(SignatureScheme::RsaPssRsaeSha512),
            0x0401 => Some(SignatureScheme::RsaPkcs1Sha256),
            0x0501 => Some(SignatureScheme::RsaPkcs1Sha384),
            0x0601 => Some(SignatureScheme::RsaPkcs1Sha512),
            // Post-Quantum signatures
            0x0E01 => Some(SignatureScheme::MlDsa44),
            0x0E02 => Some(SignatureScheme::MlDsa65),
            0x0E03 => Some(SignatureScheme::MlDsa87),
            0x0E10 => Some(SignatureScheme::SlhDsaSha2_128s),
            0x0E11 => Some(SignatureScheme::SlhDsaSha2_128f),
            0x0E20 => Some(SignatureScheme::SlhDsaShake256s),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// PSK key exchange mode (RFC 8446 Section 4.2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PskKeyExchangeMode {
    /// PSK-only key exchange
    PskKe = 0,

    /// PSK with (EC)DHE key exchange
    PskDheKe = 1,
}

impl PskKeyExchangeMode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PskKeyExchangeMode::PskKe),
            1 => Some(PskKeyExchangeMode::PskDheKe),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl TypedExtension {
    /// Encode a typed extension to wire format.
    pub fn encode(&self) -> Result<Extension> {
        let (ext_type, data) = match self {
            TypedExtension::ServerName(name) => {
                let mut buf = BytesMut::new();
                // server_name_list length
                let list_len = 3 + name.len(); // 1 (type) + 2 (length) + name
                buf.put_u16(list_len as u16);
                // NameType (host_name = 0)
                buf.put_u8(0);
                // HostName length
                buf.put_u16(name.len() as u16);
                // HostName
                buf.put_slice(name.as_bytes());
                (ExtensionType::ServerName, buf.to_vec())
            },

            TypedExtension::SupportedVersions(versions) => {
                let mut buf = BytesMut::new();
                // Length of version list (in bytes)
                buf.put_u8((versions.len() * 2) as u8);
                // Versions
                for version in versions {
                    buf.put_u16(version.to_u16());
                }
                (ExtensionType::SupportedVersions, buf.to_vec())
            },

            TypedExtension::SupportedGroups(groups) => {
                let mut buf = BytesMut::new();
                // Length of group list (in bytes)
                buf.put_u16((groups.len() * 2) as u16);
                // Groups
                for group in groups {
                    buf.put_u16(group.to_u16());
                }
                (ExtensionType::SupportedGroups, buf.to_vec())
            },

            TypedExtension::SignatureAlgorithms(algorithms) => {
                let mut buf = BytesMut::new();
                // Length of algorithm list (in bytes)
                buf.put_u16((algorithms.len() * 2) as u16);
                // Algorithms
                for alg in algorithms {
                    buf.put_u16(alg.to_u16());
                }
                (ExtensionType::SignatureAlgorithms, buf.to_vec())
            },

            TypedExtension::KeyShare(entries) => {
                let mut buf = BytesMut::new();
                let mut entries_buf = BytesMut::new();

                // Encode each key share entry
                for entry in entries {
                    entries_buf.put_u16(entry.group.to_u16());
                    entries_buf.put_u16(entry.key_exchange.len() as u16);
                    entries_buf.put_slice(&entry.key_exchange);
                }

                // KeyShareClientHello: length + entries
                buf.put_u16(entries_buf.len() as u16);
                buf.put_slice(&entries_buf);

                (ExtensionType::KeyShare, buf.to_vec())
            },

            TypedExtension::PskKeyExchangeModes(modes) => {
                let mut buf = BytesMut::new();
                // Length of modes list
                buf.put_u8(modes.len() as u8);
                // Modes
                for mode in modes {
                    buf.put_u8(mode.to_u8());
                }
                (ExtensionType::PskKeyExchangeModes, buf.to_vec())
            },

            TypedExtension::Alpn(protocols) => {
                let mut buf = BytesMut::new();
                let mut protocols_buf = BytesMut::new();

                // Encode each protocol name
                for protocol in protocols {
                    protocols_buf.put_u8(protocol.len() as u8);
                    protocols_buf.put_slice(protocol.as_bytes());
                }

                // ALPN: length + protocols
                buf.put_u16(protocols_buf.len() as u16);
                buf.put_slice(&protocols_buf);

                (
                    ExtensionType::ApplicationLayerProtocolNegotiation,
                    buf.to_vec(),
                )
            },

            TypedExtension::EarlyData => {
                // RFC 8446: early_data extension is empty in ClientHello
                (ExtensionType::EarlyData, Vec::new())
            },

            TypedExtension::EncryptedClientHello {
                cipher_suite,
                config_id,
                enc,
                payload,
            } => {
                let mut buf = BytesMut::new();

                // Cipher suite (4 bytes: KDF ID + AEAD ID)
                buf.put_slice(&cipher_suite.encode());

                // Config ID (8 bytes)
                buf.put_slice(config_id);

                // Enc length (2 bytes) + enc data
                buf.put_u16(enc.len() as u16);
                buf.put_slice(enc);

                // Payload length (2 bytes) + payload data
                buf.put_u16(payload.len() as u16);
                buf.put_slice(payload);

                (ExtensionType::EncryptedClientHello, buf.to_vec())
            },

            TypedExtension::Cookie(cookie) => {
                // Cookie extension: opaque cookie<1..2^16-1>
                let mut buf = BytesMut::new();
                buf.put_u16(cookie.len() as u16);
                buf.put_slice(cookie);
                (ExtensionType::Cookie, buf.to_vec())
            },

            TypedExtension::ConnectionId(cid) => {
                // Connection ID extension (RFC 9146)
                // Format: opaque cid<0..255>
                // Used for connection migration in DTLS 1.3
                let mut buf = BytesMut::new();
                buf.put_u8(cid.len() as u8);
                buf.put_slice(cid);
                (ExtensionType::ConnectionId, buf.to_vec())
            },

            TypedExtension::PostHandshakeAuth => {
                // Post-Handshake Authentication extension (RFC 8446 Section 4.2.6)
                // Format: empty extension (0 bytes)
                // Indicates client supports post-handshake certificate requests
                (ExtensionType::PostHandshakeAuth, vec![])
            },
        };

        Ok(Extension::new(ext_type, data))
    }

    /// Decode a typed extension from wire format.
    pub fn decode(extension: &Extension) -> Result<Self> {
        let data = &extension.data;

        match extension.extension_type {
            ExtensionType::ServerName => {
                if data.len() < 2 {
                    return Err(Error::InvalidMessage(
                        "ServerName extension too short".into(),
                    ));
                }
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + list_len {
                    return Err(Error::InvalidMessage("ServerName list truncated".into()));
                }

                if list_len < 3 {
                    return Err(Error::InvalidMessage("ServerName entry too short".into()));
                }

                let name_type = data[2];
                if name_type != 0 {
                    return Err(Error::InvalidMessage("Unsupported name type".into()));
                }

                let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                if data.len() < 5 + name_len {
                    return Err(Error::InvalidMessage("ServerName data truncated".into()));
                }

                let name = String::from_utf8(data[5..5 + name_len].to_vec())
                    .map_err(|_| Error::InvalidMessage("Invalid UTF-8 in server name".into()))?;

                Ok(TypedExtension::ServerName(name))
            },

            ExtensionType::SupportedVersions => {
                if data.is_empty() {
                    return Err(Error::InvalidMessage(
                        "SupportedVersions extension empty".into(),
                    ));
                }

                // Auto-detect format: ServerHello vs ClientHello
                // ServerHello: version (2 bytes, single value)
                // ClientHello: list_length (1) + versions (variable)

                // Check if this is ServerHello format (exactly 2 bytes)
                if data.len() == 2 {
                    // Parse as ServerHello format (single version)
                    let version_u16 = u16::from_be_bytes([data[0], data[1]]);
                    if let Some(version) = ProtocolVersion::from_u16(version_u16) {
                        return Ok(TypedExtension::SupportedVersions(vec![version]));
                    } else {
                        return Err(Error::InvalidMessage("Unknown protocol version".into()));
                    }
                }

                // Parse as ClientHello format (list with length prefix)
                let list_len = data[0] as usize;
                if list_len % 2 != 0 {
                    return Err(Error::InvalidMessage("Invalid version list length".into()));
                }
                if data.len() < 1 + list_len {
                    return Err(Error::InvalidMessage("SupportedVersions truncated".into()));
                }

                let mut versions = Vec::new();
                for i in (1..1 + list_len).step_by(2) {
                    let version_u16 = u16::from_be_bytes([data[i], data[i + 1]]);
                    if let Some(version) = ProtocolVersion::from_u16(version_u16) {
                        versions.push(version);
                    }
                }

                Ok(TypedExtension::SupportedVersions(versions))
            },

            ExtensionType::SupportedGroups => {
                if data.len() < 2 {
                    return Err(Error::InvalidMessage("SupportedGroups too short".into()));
                }
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if list_len % 2 != 0 {
                    return Err(Error::InvalidMessage("Invalid group list length".into()));
                }
                if data.len() < 2 + list_len {
                    return Err(Error::InvalidMessage("SupportedGroups truncated".into()));
                }

                let mut groups = Vec::new();
                for i in (2..2 + list_len).step_by(2) {
                    let group_u16 = u16::from_be_bytes([data[i], data[i + 1]]);
                    if let Some(group) = KeyExchangeAlgorithm::from_u16(group_u16) {
                        groups.push(group);
                    }
                }

                Ok(TypedExtension::SupportedGroups(groups))
            },

            ExtensionType::SignatureAlgorithms => {
                if data.len() < 2 {
                    return Err(Error::InvalidMessage(
                        "SignatureAlgorithms too short".into(),
                    ));
                }
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if list_len % 2 != 0 {
                    return Err(Error::InvalidMessage(
                        "Invalid algorithm list length".into(),
                    ));
                }
                if data.len() < 2 + list_len {
                    return Err(Error::InvalidMessage(
                        "SignatureAlgorithms truncated".into(),
                    ));
                }

                let mut algorithms = Vec::new();
                for i in (2..2 + list_len).step_by(2) {
                    let alg_u16 = u16::from_be_bytes([data[i], data[i + 1]]);
                    if let Some(alg) = SignatureScheme::from_u16(alg_u16) {
                        algorithms.push(alg);
                    }
                }

                Ok(TypedExtension::SignatureAlgorithms(algorithms))
            },

            ExtensionType::KeyShare => {
                if data.len() < 4 {
                    return Err(Error::InvalidMessage("KeyShare too short".into()));
                }

                // Auto-detect format: ServerHello vs ClientHello
                // ServerHello: group (2) + key_length (2) + key_data (variable)
                // ClientHello: list_length (2) + entries (variable)

                // Try ServerHello format first (single entry without list length)
                let possible_group = u16::from_be_bytes([data[0], data[1]]);
                let possible_key_len = u16::from_be_bytes([data[2], data[3]]) as usize;

                // Check if this looks like ServerHello format:
                // 1. First 2 bytes should be a valid key exchange algorithm
                // 2. Total length should be exactly 4 + key_length
                if KeyExchangeAlgorithm::from_u16(possible_group).is_some()
                    && data.len() == 4 + possible_key_len
                {
                    // Parse as ServerHello format (single entry)
                    let group = KeyExchangeAlgorithm::from_u16(possible_group).unwrap();
                    let key_exchange = data[4..4 + possible_key_len].to_vec();

                    return Ok(TypedExtension::KeyShare(vec![KeyShareEntry {
                        group,
                        key_exchange,
                    }]));
                }

                // Parse as ClientHello format (vector with length prefix)
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + list_len {
                    return Err(Error::InvalidMessage("KeyShare truncated".into()));
                }

                let mut entries = Vec::new();
                let mut offset = 2;

                while offset < 2 + list_len {
                    if offset + 4 > data.len() {
                        return Err(Error::InvalidMessage("KeyShare entry truncated".into()));
                    }

                    let group_u16 = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    let key_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

                    if offset + 4 + key_len > data.len() {
                        return Err(Error::InvalidMessage("KeyShare key data truncated".into()));
                    }

                    if let Some(group) = KeyExchangeAlgorithm::from_u16(group_u16) {
                        let key_exchange = data[offset + 4..offset + 4 + key_len].to_vec();
                        entries.push(KeyShareEntry {
                            group,
                            key_exchange,
                        });
                    }

                    offset += 4 + key_len;
                }

                Ok(TypedExtension::KeyShare(entries))
            },

            ExtensionType::PskKeyExchangeModes => {
                if data.is_empty() {
                    return Err(Error::InvalidMessage(
                        "PskKeyExchangeModes extension empty".into(),
                    ));
                }
                let list_len = data[0] as usize;
                if data.len() < 1 + list_len {
                    return Err(Error::InvalidMessage(
                        "PskKeyExchangeModes truncated".into(),
                    ));
                }

                let mut modes = Vec::new();
                for i in 1..1 + list_len {
                    if let Some(mode) = PskKeyExchangeMode::from_u8(data[i]) {
                        modes.push(mode);
                    }
                }

                Ok(TypedExtension::PskKeyExchangeModes(modes))
            },

            ExtensionType::ApplicationLayerProtocolNegotiation => {
                if data.len() < 2 {
                    return Err(Error::InvalidMessage("ALPN extension too short".into()));
                }
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + list_len {
                    return Err(Error::InvalidMessage("ALPN list truncated".into()));
                }

                let mut protocols = Vec::new();
                let mut offset = 2;

                while offset < 2 + list_len {
                    if offset >= data.len() {
                        return Err(Error::InvalidMessage("ALPN protocol truncated".into()));
                    }

                    let proto_len = data[offset] as usize;
                    if offset + 1 + proto_len > data.len() {
                        return Err(Error::InvalidMessage("ALPN protocol data truncated".into()));
                    }

                    let protocol =
                        String::from_utf8(data[offset + 1..offset + 1 + proto_len].to_vec())
                            .map_err(|_| {
                                Error::InvalidMessage("Invalid UTF-8 in ALPN protocol".into())
                            })?;

                    protocols.push(protocol);
                    offset += 1 + proto_len;
                }

                Ok(TypedExtension::Alpn(protocols))
            },

            ExtensionType::EarlyData => {
                // RFC 8446: early_data extension should be empty in ClientHello
                // In EncryptedExtensions, it contains max_early_data_size (4 bytes)
                // For now, we just recognize it as present
                Ok(TypedExtension::EarlyData)
            },

            ExtensionType::EncryptedClientHello => {
                // Minimum: 4 (cipher_suite) + 8 (config_id) + 2 (enc_len) + 2 (payload_len) = 16
                if data.len() < 16 {
                    return Err(Error::InvalidMessage("ECH extension too short".into()));
                }

                // Decode cipher suite (4 bytes)
                let cipher_suite = crate::ech::EchCipherSuite::decode(&data[0..4])?;

                // Config ID (8 bytes)
                let mut config_id = [0u8; 8];
                config_id.copy_from_slice(&data[4..12]);

                // Enc length and data
                let enc_len = u16::from_be_bytes([data[12], data[13]]) as usize;
                if data.len() < 14 + enc_len {
                    return Err(Error::InvalidMessage("ECH enc data truncated".into()));
                }
                let enc = data[14..14 + enc_len].to_vec();

                // Payload length and data
                let payload_offset = 14 + enc_len;
                if data.len() < payload_offset + 2 {
                    return Err(Error::InvalidMessage("ECH payload length missing".into()));
                }
                let payload_len =
                    u16::from_be_bytes([data[payload_offset], data[payload_offset + 1]]) as usize;
                if data.len() < payload_offset + 2 + payload_len {
                    return Err(Error::InvalidMessage("ECH payload truncated".into()));
                }
                let payload = data[payload_offset + 2..payload_offset + 2 + payload_len].to_vec();

                Ok(TypedExtension::EncryptedClientHello {
                    cipher_suite,
                    config_id,
                    enc,
                    payload,
                })
            },

            ExtensionType::Cookie => {
                // Cookie extension: length (2 bytes) + cookie data
                if data.len() < 2 {
                    return Err(Error::InvalidMessage("Cookie extension too short".into()));
                }
                let cookie_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + cookie_len {
                    return Err(Error::InvalidMessage("Cookie data truncated".into()));
                }
                if cookie_len == 0 {
                    return Err(Error::InvalidMessage("Cookie cannot be empty".into()));
                }
                let cookie = data[2..2 + cookie_len].to_vec();
                Ok(TypedExtension::Cookie(cookie))
            },

            ExtensionType::ConnectionId => {
                // Connection ID extension (RFC 9146)
                // Format: length (1 byte) + cid data (0..255 bytes)
                // Validates: non-empty data, correct length, size within spec
                if data.is_empty() {
                    return Err(Error::InvalidMessage("ConnectionId extension too short".into()));
                }
                let cid_len = data[0] as usize;
                if data.len() < 1 + cid_len {
                    return Err(Error::InvalidMessage("ConnectionId data truncated".into()));
                }
                if cid_len > 255 {
                    return Err(Error::InvalidMessage("ConnectionId too long".into()));
                }
                let cid = data[1..1 + cid_len].to_vec();
                Ok(TypedExtension::ConnectionId(cid))
            },

            ExtensionType::PostHandshakeAuth => {
                // Post-Handshake Authentication extension (RFC 8446 Section 4.2.6)
                // Format: empty (0 bytes)
                // RFC requires this extension to be empty when present
                if !data.is_empty() {
                    return Err(Error::InvalidMessage(
                        "PostHandshakeAuth extension must be empty".into(),
                    ));
                }
                Ok(TypedExtension::PostHandshakeAuth)
            },

            _ => Err(Error::UnsupportedFeature(format!(
                "Extension type {:?} not yet supported",
                extension.extension_type
            ))),
        }
    }
}

/// Extension list helpers.
impl crate::extensions::Extensions {
    /// Add a typed extension to the list.
    pub fn add_typed(&mut self, typed_ext: TypedExtension) -> Result<()> {
        let ext = typed_ext.encode()?;
        self.add(ext);
        Ok(())
    }

    /// Get a typed extension from the list.
    pub fn get_typed(&self, ext_type: ExtensionType) -> Result<Option<TypedExtension>> {
        if let Some(ext) = self.get(ext_type) {
            Ok(Some(TypedExtension::decode(ext)?))
        } else {
            Ok(None)
        }
    }

    /// Check if the SupportedVersions extension is present and contains TLS 1.3.
    pub fn contains_supported_versions(&self) -> bool {
        if let Ok(Some(TypedExtension::SupportedVersions(versions))) =
            self.get_typed(ExtensionType::SupportedVersions)
        {
            versions.contains(&ProtocolVersion::Tls13)
        } else {
            false
        }
    }

    /// Get the KeyShare extension entries.
    pub fn get_key_share(&self) -> Result<Option<Vec<KeyShareEntry>>> {
        if let Some(TypedExtension::KeyShare(entries)) = self.get_typed(ExtensionType::KeyShare)? {
            Ok(Some(entries))
        } else {
            Ok(None)
        }
    }

    /// Get the server name from the SNI extension.
    pub fn get_server_name(&self) -> Result<Option<String>> {
        if let Some(TypedExtension::ServerName(name)) = self.get_typed(ExtensionType::ServerName)? {
            Ok(Some(name))
        } else {
            Ok(None)
        }
    }

    /// Get the ALPN protocols.
    pub fn get_alpn(&self) -> Result<Option<Vec<String>>> {
        if let Some(TypedExtension::Alpn(protocols)) =
            self.get_typed(ExtensionType::ApplicationLayerProtocolNegotiation)?
        {
            Ok(Some(protocols))
        } else {
            Ok(None)
        }
    }

    /// Add ALPN protocols extension.
    pub fn add_alpn(&mut self, protocols: Vec<String>) -> Result<()> {
        self.add_typed(TypedExtension::Alpn(protocols))
    }

    /// Add early_data extension (for 0-RTT).
    pub fn add_early_data(&mut self) -> Result<()> {
        self.add_typed(TypedExtension::EarlyData)
    }

    /// Check if early_data extension is present.
    pub fn has_early_data(&self) -> bool {
        self.has(ExtensionType::EarlyData)
    }

    /// Add ECH (Encrypted Client Hello) extension.
    ///
    /// # Arguments
    ///
    /// * `cipher_suite` - ECH cipher suite used for encryption
    /// * `config_id` - ECH configuration identifier (8 bytes)
    /// * `enc` - HPKE encapsulated key
    /// * `payload` - Encrypted ClientHelloInner
    pub fn add_ech(
        &mut self,
        cipher_suite: crate::ech::EchCipherSuite,
        config_id: [u8; 8],
        enc: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<()> {
        self.add_typed(TypedExtension::EncryptedClientHello {
            cipher_suite,
            config_id,
            enc,
            payload,
        })
    }

    /// Get the ECH extension if present.
    pub fn get_ech(
        &self,
    ) -> Result<
        Option<(
            crate::ech::EchCipherSuite,
            [u8; 8],
            Vec<u8>,
            Vec<u8>,
        )>,
    > {
        if let Some(TypedExtension::EncryptedClientHello {
            cipher_suite,
            config_id,
            enc,
            payload,
        }) = self.get_typed(ExtensionType::EncryptedClientHello)?
        {
            Ok(Some((cipher_suite, config_id, enc, payload)))
        } else {
            Ok(None)
        }
    }

    /// Check if ECH extension is present.
    pub fn has_ech(&self) -> bool {
        self.has(ExtensionType::EncryptedClientHello)
    }

    /// Add ECH retry_configs extension (server -> client in EncryptedExtensions).
    ///
    /// When ECH decryption fails, the server sends retry_configs to the client
    /// containing updated ECH configurations that the client should use for retry.
    ///
    /// # Arguments
    ///
    /// * `retry_configs` - ECH config list encoded as wire format bytes
    pub fn add_ech_retry_configs(&mut self, retry_configs: Vec<u8>) -> Result<()> {
        let ext = Extension::new(ExtensionType::EncryptedClientHello, retry_configs);
        self.add(ext);
        Ok(())
    }

    /// Get ECH retry_configs if present (from server's EncryptedExtensions).
    ///
    /// Returns the raw retry_configs bytes which can be decoded as an ECHConfigList.
    pub fn get_ech_retry_configs(&self) -> Option<Vec<u8>> {
        self.get(ExtensionType::EncryptedClientHello)
            .map(|ext| ext.data.clone())
    }

    /// Add a cookie extension.
    ///
    /// Used in DTLS 1.3 HelloRetryRequest and subsequent ClientHello for stateless
    /// DoS protection.
    ///
    /// # Arguments
    ///
    /// * `cookie` - The cookie data (HMAC-based tag)
    pub fn add_cookie(&mut self, cookie: Vec<u8>) -> Result<()> {
        self.add_typed(TypedExtension::Cookie(cookie))
    }

    /// Get the cookie extension if present.
    pub fn get_cookie(&self) -> Result<Option<Vec<u8>>> {
        if let Some(TypedExtension::Cookie(cookie)) = self.get_typed(ExtensionType::Cookie)? {
            Ok(Some(cookie))
        } else {
            Ok(None)
        }
    }

    /// Check if cookie extension is present.
    pub fn has_cookie(&self) -> bool {
        self.has(ExtensionType::Cookie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_name_encode_decode() {
        let typed = TypedExtension::ServerName("example.com".to_string());
        let ext = typed.encode().unwrap();
        let decoded = TypedExtension::decode(&ext).unwrap();
        assert_eq!(typed, decoded);
    }

    #[test]
    fn test_supported_versions_encode_decode() {
        let typed =
            TypedExtension::SupportedVersions(vec![ProtocolVersion::Tls13, ProtocolVersion::Tls12]);
        let ext = typed.encode().unwrap();
        let decoded = TypedExtension::decode(&ext).unwrap();
        assert_eq!(typed, decoded);
    }

    #[test]
    fn test_key_share_encode_decode() {
        let typed = TypedExtension::KeyShare(vec![KeyShareEntry {
            group: KeyExchangeAlgorithm::X25519,
            key_exchange: vec![1, 2, 3, 4],
        }]);
        let ext = typed.encode().unwrap();
        let decoded = TypedExtension::decode(&ext).unwrap();
        assert_eq!(typed, decoded);
    }

    #[test]
    fn test_cookie_encode_decode() {
        // Test cookie extension
        let cookie = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let typed = TypedExtension::Cookie(cookie.clone());
        let ext = typed.encode().unwrap();
        let decoded = TypedExtension::decode(&ext).unwrap();
        assert_eq!(typed, decoded);

        // Test with longer cookie (32 bytes, like HMAC-SHA256)
        let long_cookie = vec![0xAB; 32];
        let typed_long = TypedExtension::Cookie(long_cookie.clone());
        let ext_long = typed_long.encode().unwrap();
        let decoded_long = TypedExtension::decode(&ext_long).unwrap();
        assert_eq!(typed_long, decoded_long);
    }

    #[test]
    fn test_cookie_validation() {
        use crate::extensions::Extension;

        // Empty cookie should fail
        let empty_data = vec![0x00, 0x00]; // length = 0
        let ext = Extension::new(ExtensionType::Cookie, empty_data);
        let result = TypedExtension::decode(&ext);
        assert!(result.is_err());

        // Truncated cookie should fail
        let truncated_data = vec![0x00, 0x10]; // claims 16 bytes but no data
        let ext_truncated = Extension::new(ExtensionType::Cookie, truncated_data);
        let result_truncated = TypedExtension::decode(&ext_truncated);
        assert!(result_truncated.is_err());
    }
}
