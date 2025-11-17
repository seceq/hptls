//! TLS 1.2 Extension Helpers
//!
//! This module provides helper functions for encoding and decoding TLS 1.2-specific
//! extensions that are required for ECDHE cipher suites:
//!
//! - `supported_groups` (formerly `supported_curves`) - RFC 4492, RFC 8422
//! - `signature_algorithms` - RFC 5246 Section 7.4.1.4.1
//! - `ec_point_formats` - RFC 4492 (required for ECDHE)
//!
//! Optional but useful extensions:
//! - `server_name` (SNI) - RFC 6066
//! - `application_layer_protocol_negotiation` (ALPN) - RFC 7301
//! - `extended_master_secret` - RFC 7627 (recommended for security)

use crate::error::{Error, Result};
use crate::extensions::Extension;
use crate::protocol::ExtensionType;
use bytes::{Buf, BufMut, BytesMut};
use hptls_crypto::{KeyExchangeAlgorithm, SignatureAlgorithm};

/// Create a `supported_groups` extension for TLS 1.2.
///
/// This extension indicates which elliptic curves the client supports.
/// For ECDHE cipher suites, this is mandatory.
///
/// # Arguments
/// * `groups` - List of supported groups (e.g., X25519, secp256r1)
///
/// # Returns
/// Extension with encoded group list
pub fn supported_groups_extension(groups: &[KeyExchangeAlgorithm]) -> Result<Extension> {
    let mut buf = BytesMut::new();

    // List length (2 bytes)
    let list_len = groups.len() * 2;
    if list_len > 0xFFFF {
        return Err(Error::InvalidMessage("Too many supported groups".into()));
    }
    buf.put_u16(list_len as u16);

    // Each group (2 bytes)
    for group in groups {
        buf.put_u16(group.to_u16());
    }

    Ok(Extension::new(
        ExtensionType::SupportedGroups,
        buf.to_vec(),
    ))
}

/// Parse a `supported_groups` extension.
///
/// # Arguments
/// * `data` - Extension data bytes
///
/// # Returns
/// List of supported groups
pub fn parse_supported_groups(data: &[u8]) -> Result<Vec<KeyExchangeAlgorithm>> {
    if data.len() < 2 {
        return Err(Error::InvalidMessage(
            "supported_groups extension too short".into(),
        ));
    }

    let mut bytes = &data[..];
    let list_len = bytes.get_u16() as usize;

    if bytes.len() < list_len {
        return Err(Error::InvalidMessage(
            "Incomplete supported_groups list".into(),
        ));
    }

    if list_len % 2 != 0 {
        return Err(Error::InvalidMessage(
            "supported_groups list has odd length".into(),
        ));
    }

    let mut groups = Vec::new();
    for _ in 0..(list_len / 2) {
        let group_id = bytes.get_u16();
        if let Some(group) = KeyExchangeAlgorithm::from_u16(group_id) {
            groups.push(group);
        }
        // Ignore unknown groups (graceful degradation)
    }

    Ok(groups)
}

/// Create a `signature_algorithms` extension for TLS 1.2.
///
/// This extension indicates which signature algorithms the client supports
/// for certificate verification and ServerKeyExchange signatures.
///
/// # Arguments
/// * `algorithms` - List of supported signature algorithms
///
/// # Returns
/// Extension with encoded algorithm list
pub fn signature_algorithms_extension(
    algorithms: &[SignatureAlgorithm],
) -> Result<Extension> {
    let mut buf = BytesMut::new();

    // List length (2 bytes)
    let list_len = algorithms.len() * 2;
    if list_len > 0xFFFF {
        return Err(Error::InvalidMessage(
            "Too many signature algorithms".into(),
        ));
    }
    buf.put_u16(list_len as u16);

    // Each algorithm (2 bytes)
    for algo in algorithms {
        buf.put_u16(algo.iana_codepoint());
    }

    Ok(Extension::new(
        ExtensionType::SignatureAlgorithms,
        buf.to_vec(),
    ))
}

/// Parse a `signature_algorithms` extension.
///
/// # Arguments
/// * `data` - Extension data bytes
///
/// # Returns
/// List of supported signature algorithms
pub fn parse_signature_algorithms(data: &[u8]) -> Result<Vec<SignatureAlgorithm>> {
    if data.len() < 2 {
        return Err(Error::InvalidMessage(
            "signature_algorithms extension too short".into(),
        ));
    }

    let mut bytes = &data[..];
    let list_len = bytes.get_u16() as usize;

    if bytes.len() < list_len {
        return Err(Error::InvalidMessage(
            "Incomplete signature_algorithms list".into(),
        ));
    }

    if list_len % 2 != 0 {
        return Err(Error::InvalidMessage(
            "signature_algorithms list has odd length".into(),
        ));
    }

    let mut algorithms = Vec::new();
    for _ in 0..(list_len / 2) {
        let algo_id = bytes.get_u16();
        if let Some(algo) = SignatureAlgorithm::from_u16(algo_id) {
            algorithms.push(algo);
        }
        // Ignore unknown algorithms (graceful degradation)
    }

    Ok(algorithms)
}

/// Create an `ec_point_formats` extension for TLS 1.2.
///
/// This extension is required for ECDHE cipher suites (RFC 4492).
/// TLS 1.2 requires this, but TLS 1.3 removed it.
///
/// # Returns
/// Extension with uncompressed point format (the only one we support)
pub fn ec_point_formats_extension() -> Extension {
    // We only support uncompressed format (0x00)
    // Format: length (1 byte) + formats
    let data = vec![
        0x01, // Length: 1 format
        0x00, // Uncompressed
    ];

    Extension::new(ExtensionType::EcPointFormats, data)
}

/// Create a `server_name` (SNI) extension for TLS 1.2.
///
/// # Arguments
/// * `hostname` - Server hostname (e.g., "example.com")
///
/// # Returns
/// Extension with encoded hostname
pub fn server_name_extension(hostname: &str) -> Result<Extension> {
    if hostname.is_empty() || hostname.len() > 0xFFFF {
        return Err(Error::InvalidMessage("Invalid hostname length".into()));
    }

    let mut buf = BytesMut::new();

    // ServerNameList length (2 bytes)
    let list_len = 1 + 2 + hostname.len(); // type (1) + length (2) + hostname
    buf.put_u16(list_len as u16);

    // ServerName
    buf.put_u8(0x00); // name_type = host_name
    buf.put_u16(hostname.len() as u16); // hostname length
    buf.put_slice(hostname.as_bytes()); // hostname

    Ok(Extension::new(ExtensionType::ServerName, buf.to_vec()))
}

/// Parse a `server_name` extension.
///
/// # Arguments
/// * `data` - Extension data bytes
///
/// # Returns
/// Hostname string
pub fn parse_server_name(data: &[u8]) -> Result<String> {
    if data.len() < 2 {
        return Err(Error::InvalidMessage("server_name extension too short".into()));
    }

    let mut bytes = &data[..];
    let list_len = bytes.get_u16() as usize;

    if bytes.len() < list_len {
        return Err(Error::InvalidMessage(
            "Incomplete server_name list".into(),
        ));
    }

    if bytes.is_empty() {
        return Err(Error::InvalidMessage("Empty server_name list".into()));
    }

    let name_type = bytes.get_u8();
    if name_type != 0x00 {
        return Err(Error::InvalidMessage(format!(
            "Unsupported name type: {}",
            name_type
        )));
    }

    if bytes.len() < 2 {
        return Err(Error::InvalidMessage("server_name length missing".into()));
    }

    let hostname_len = bytes.get_u16() as usize;
    if bytes.len() < hostname_len {
        return Err(Error::InvalidMessage("Incomplete hostname".into()));
    }

    let hostname_bytes = &bytes[..hostname_len];
    String::from_utf8(hostname_bytes.to_vec())
        .map_err(|_| Error::InvalidMessage("Invalid UTF-8 in hostname".into()))
}

/// Create an `application_layer_protocol_negotiation` (ALPN) extension.
///
/// # Arguments
/// * `protocols` - List of protocol names (e.g., ["h2", "http/1.1"])
///
/// # Returns
/// Extension with encoded protocol list
pub fn alpn_extension(protocols: &[&str]) -> Result<Extension> {
    let mut buf = BytesMut::new();

    // Calculate total length
    let mut total_len = 0;
    for proto in protocols {
        if proto.is_empty() || proto.len() > 255 {
            return Err(Error::InvalidMessage("Invalid protocol name length".into()));
        }
        total_len += 1 + proto.len(); // length byte + protocol
    }

    if total_len > 0xFFFF {
        return Err(Error::InvalidMessage("ALPN list too long".into()));
    }

    // ProtocolNameList length (2 bytes)
    buf.put_u16(total_len as u16);

    // Each protocol
    for proto in protocols {
        buf.put_u8(proto.len() as u8); // length
        buf.put_slice(proto.as_bytes()); // protocol name
    }

    Ok(Extension::new(
        ExtensionType::ApplicationLayerProtocolNegotiation,
        buf.to_vec(),
    ))
}

/// Parse an ALPN extension.
///
/// # Arguments
/// * `data` - Extension data bytes
///
/// # Returns
/// List of protocol names
pub fn parse_alpn(data: &[u8]) -> Result<Vec<String>> {
    if data.len() < 2 {
        return Err(Error::InvalidMessage("ALPN extension too short".into()));
    }

    let mut bytes = &data[..];
    let list_len = bytes.get_u16() as usize;

    if bytes.len() < list_len {
        return Err(Error::InvalidMessage("Incomplete ALPN list".into()));
    }

    let mut protocols = Vec::new();
    let mut remaining = list_len;

    while remaining > 0 {
        if bytes.is_empty() {
            return Err(Error::InvalidMessage("Incomplete ALPN protocol".into()));
        }

        let proto_len = bytes.get_u8() as usize;
        remaining -= 1;

        if bytes.len() < proto_len || remaining < proto_len {
            return Err(Error::InvalidMessage("Incomplete ALPN protocol name".into()));
        }

        let proto_bytes = &bytes[..proto_len];
        bytes.advance(proto_len);
        remaining -= proto_len;

        let proto = String::from_utf8(proto_bytes.to_vec())
            .map_err(|_| Error::InvalidMessage("Invalid UTF-8 in protocol name".into()))?;
        protocols.push(proto);
    }

    Ok(protocols)
}

/// Create an `extended_master_secret` extension for TLS 1.2.
///
/// This extension (RFC 7627) improves security by binding the master secret
/// to the handshake transcript. Highly recommended for TLS 1.2.
///
/// # Returns
/// Empty extension (presence indicates support)
pub fn extended_master_secret_extension() -> Extension {
    Extension::new(ExtensionType::ExtendedMasterSecret, vec![])
}

/// Default set of supported groups for TLS 1.2 ECDHE.
///
/// Returns a reasonable default list: X25519, secp256r1, secp384r1
pub fn default_supported_groups() -> Vec<KeyExchangeAlgorithm> {
    vec![
        KeyExchangeAlgorithm::X25519,
        KeyExchangeAlgorithm::Secp256r1,
        KeyExchangeAlgorithm::Secp384r1,
    ]
}

/// Default set of signature algorithms for TLS 1.2.
///
/// Returns a reasonable default list for ECDSA and RSA signatures
pub fn default_signature_algorithms() -> Vec<SignatureAlgorithm> {
    vec![
        // ECDSA (preferred)
        SignatureAlgorithm::EcdsaSecp256r1Sha256,
        SignatureAlgorithm::EcdsaSecp384r1Sha384,
        // RSA-PSS
        SignatureAlgorithm::RsaPssRsaeSha256,
        SignatureAlgorithm::RsaPssRsaeSha384,
        SignatureAlgorithm::RsaPssRsaeSha512,
        // RSA-PKCS1 (legacy, less secure)
        SignatureAlgorithm::RsaPkcs1Sha256,
        SignatureAlgorithm::RsaPkcs1Sha384,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_groups_encode_decode() {
        let groups = vec![
            KeyExchangeAlgorithm::X25519,
            KeyExchangeAlgorithm::Secp256r1,
        ];

        let ext = supported_groups_extension(&groups).unwrap();
        assert_eq!(ext.extension_type, ExtensionType::SupportedGroups);

        let parsed = parse_supported_groups(&ext.data).unwrap();
        assert_eq!(parsed, groups);
    }

    #[test]
    fn test_signature_algorithms_encode_decode() {
        let algorithms = vec![
            SignatureAlgorithm::EcdsaSecp256r1Sha256,
            SignatureAlgorithm::RsaPssRsaeSha256,
        ];

        let ext = signature_algorithms_extension(&algorithms).unwrap();
        assert_eq!(ext.extension_type, ExtensionType::SignatureAlgorithms);

        let parsed = parse_signature_algorithms(&ext.data).unwrap();
        assert_eq!(parsed, algorithms);
    }

    #[test]
    fn test_ec_point_formats() {
        let ext = ec_point_formats_extension();
        assert_eq!(ext.data, vec![0x01, 0x00]); // Length 1, uncompressed
    }

    #[test]
    fn test_server_name_encode_decode() {
        let hostname = "example.com";
        let ext = server_name_extension(hostname).unwrap();
        assert_eq!(ext.extension_type, ExtensionType::ServerName);

        let parsed = parse_server_name(&ext.data).unwrap();
        assert_eq!(parsed, hostname);
    }

    #[test]
    fn test_alpn_encode_decode() {
        let protocols = vec!["h2", "http/1.1"];
        let ext = alpn_extension(&protocols).unwrap();
        assert_eq!(
            ext.extension_type,
            ExtensionType::ApplicationLayerProtocolNegotiation
        );

        let parsed = parse_alpn(&ext.data).unwrap();
        assert_eq!(parsed, protocols);
    }

    #[test]
    fn test_extended_master_secret() {
        let ext = extended_master_secret_extension();
        assert_eq!(ext.extension_type, ExtensionType::ExtendedMasterSecret);
        assert!(ext.data.is_empty());
    }

    #[test]
    fn test_default_supported_groups() {
        let groups = default_supported_groups();
        assert!(groups.contains(&KeyExchangeAlgorithm::X25519));
        assert!(groups.contains(&KeyExchangeAlgorithm::Secp256r1));
    }

    #[test]
    fn test_default_signature_algorithms() {
        let algorithms = default_signature_algorithms();
        assert!(algorithms.contains(&SignatureAlgorithm::EcdsaSecp256r1Sha256));
        assert!(algorithms.contains(&SignatureAlgorithm::RsaPssRsaeSha256));
    }
}
