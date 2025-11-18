//! TLS protocol constants and types.

/// TLS protocol version.
///
/// Represents the various TLS and DTLS protocol versions supported by HPTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum ProtocolVersion {
    /// TLS 1.0 (RFC 2246) - Legacy, not recommended
    Tls10 = 0x0301,

    /// TLS 1.1 (RFC 4346) - Legacy, not recommended
    Tls11 = 0x0302,

    /// TLS 1.2 (RFC 5246)
    Tls12 = 0x0303,

    /// TLS 1.3 (RFC 8446) - Recommended
    Tls13 = 0x0304,

    /// DTLS 1.0 (RFC 4347) - Legacy
    Dtls10 = 0xFEFF,

    /// DTLS 1.2 (RFC 6347)
    Dtls12 = 0xFEFD,

    /// DTLS 1.3 (RFC 9147)
    Dtls13 = 0xFEFC,
}

impl ProtocolVersion {
    /// Create from wire format (u16 big-endian).
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0301 => Some(ProtocolVersion::Tls10),
            0x0302 => Some(ProtocolVersion::Tls11),
            0x0303 => Some(ProtocolVersion::Tls12),
            0x0304 => Some(ProtocolVersion::Tls13),
            0xFEFF => Some(ProtocolVersion::Dtls10),
            0xFEFD => Some(ProtocolVersion::Dtls12),
            0xFEFC => Some(ProtocolVersion::Dtls13),
            _ => None,
        }
    }

    /// Convert to wire format (u16 big-endian).
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Get the protocol name.
    pub const fn name(self) -> &'static str {
        match self {
            ProtocolVersion::Tls10 => "TLS 1.0",
            ProtocolVersion::Tls11 => "TLS 1.1",
            ProtocolVersion::Tls12 => "TLS 1.2",
            ProtocolVersion::Tls13 => "TLS 1.3",
            ProtocolVersion::Dtls10 => "DTLS 1.0",
            ProtocolVersion::Dtls12 => "DTLS 1.2",
            ProtocolVersion::Dtls13 => "DTLS 1.3",
        }
    }

    /// Check if this is a TLS version (not DTLS).
    pub const fn is_tls(self) -> bool {
        matches!(
            self,
            ProtocolVersion::Tls10
                | ProtocolVersion::Tls11
                | ProtocolVersion::Tls12
                | ProtocolVersion::Tls13
        )
    }

    /// Check if this is a DTLS version.
    pub const fn is_dtls(self) -> bool {
        matches!(
            self,
            ProtocolVersion::Dtls10 | ProtocolVersion::Dtls12 | ProtocolVersion::Dtls13
        )
    }

    /// Check if this version is considered secure.
    ///
    /// TLS 1.0 and 1.1 are no longer considered secure.
    pub const fn is_secure(self) -> bool {
        !matches!(self, ProtocolVersion::Tls10 | ProtocolVersion::Tls11)
    }
}

/// TLS content type (RFC 8446 Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ContentType {
    /// Invalid content type (0)
    Invalid = 0,

    /// Change cipher spec (20) - Legacy TLS 1.2
    ChangeCipherSpec = 20,

    /// Alert (21)
    Alert = 21,

    /// Handshake (22)
    Handshake = 22,

    /// Application data (23)
    ApplicationData = 23,

    /// Heartbeat (24) - RFC 6520 (not used in TLS 1.3)
    Heartbeat = 24,

    /// ACK (26) - DTLS 1.3 explicit acknowledgment (RFC 9147 Section 7)
    Ack = 26,
}

impl ContentType {
    /// Create from wire format (u8).
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ContentType::Invalid),
            20 => Some(ContentType::ChangeCipherSpec),
            21 => Some(ContentType::Alert),
            22 => Some(ContentType::Handshake),
            23 => Some(ContentType::ApplicationData),
            24 => Some(ContentType::Heartbeat),
            26 => Some(ContentType::Ack),
            _ => None,
        }
    }

    /// Convert to wire format (u8).
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Check if this content type is valid for TLS 1.3.
    pub const fn is_valid_for_tls13(self) -> bool {
        matches!(
            self,
            ContentType::Alert | ContentType::Handshake | ContentType::ApplicationData
        )
    }

    /// Check if this content type is valid for DTLS 1.3.
    ///
    /// DTLS 1.3 supports all TLS 1.3 content types plus ACK messages.
    pub const fn is_valid_for_dtls13(self) -> bool {
        matches!(
            self,
            ContentType::Alert
                | ContentType::Handshake
                | ContentType::ApplicationData
                | ContentType::Ack
        )
    }
}

/// Handshake message type (RFC 8446 Section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HandshakeType {
    /// ClientHello (1)
    ClientHello = 1,

    /// ServerHello (2)
    ServerHello = 2,

    /// NewSessionTicket (4) - TLS 1.3
    NewSessionTicket = 4,

    /// EndOfEarlyData (5) - TLS 1.3
    EndOfEarlyData = 5,

    /// EncryptedExtensions (8) - TLS 1.3
    EncryptedExtensions = 8,

    /// Certificate (11)
    Certificate = 11,

    /// ServerKeyExchange (12) - TLS 1.2 only
    ServerKeyExchange = 12,

    /// CertificateRequest (13)
    CertificateRequest = 13,

    /// ServerHelloDone (14) - TLS 1.2 only
    ServerHelloDone = 14,

    /// CertificateVerify (15)
    CertificateVerify = 15,

    /// ClientKeyExchange (16) - TLS 1.2 only
    ClientKeyExchange = 16,

    /// Finished (20)
    Finished = 20,

    /// CertificateUrl (21) - RFC 6066
    CertificateUrl = 21,

    /// CertificateStatus (22) - RFC 6066
    CertificateStatus = 22,

    /// KeyUpdate (24) - TLS 1.3
    KeyUpdate = 24,

    /// MessageHash (254) - TLS 1.3
    MessageHash = 254,
}

impl HandshakeType {
    /// Create from wire format (u8).
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(HandshakeType::ClientHello),
            2 => Some(HandshakeType::ServerHello),
            4 => Some(HandshakeType::NewSessionTicket),
            5 => Some(HandshakeType::EndOfEarlyData),
            8 => Some(HandshakeType::EncryptedExtensions),
            11 => Some(HandshakeType::Certificate),
            12 => Some(HandshakeType::ServerKeyExchange),
            13 => Some(HandshakeType::CertificateRequest),
            14 => Some(HandshakeType::ServerHelloDone),
            15 => Some(HandshakeType::CertificateVerify),
            16 => Some(HandshakeType::ClientKeyExchange),
            20 => Some(HandshakeType::Finished),
            21 => Some(HandshakeType::CertificateUrl),
            22 => Some(HandshakeType::CertificateStatus),
            24 => Some(HandshakeType::KeyUpdate),
            254 => Some(HandshakeType::MessageHash),
            _ => None,
        }
    }

    /// Convert to wire format (u8).
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Check if this handshake type is valid for TLS 1.3.
    pub const fn is_valid_for_tls13(self) -> bool {
        !matches!(
            self,
            HandshakeType::ServerKeyExchange
                | HandshakeType::ClientKeyExchange
                | HandshakeType::ServerHelloDone
        )
    }
}

/// TLS extension type (IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExtensionType {
    /// server_name (0)
    ServerName = 0,

    /// max_fragment_length (1)
    MaxFragmentLength = 1,

    /// status_request (5) - OCSP stapling
    StatusRequest = 5,

    /// supported_groups (10) - formerly supported_curves
    SupportedGroups = 10,

    /// ec_point_formats (11) - TLS 1.2, RFC 4492
    EcPointFormats = 11,

    /// signature_algorithms (13)
    SignatureAlgorithms = 13,

    /// use_srtp (14)
    UseSrtp = 14,

    /// heartbeat (15)
    Heartbeat = 15,

    /// application_layer_protocol_negotiation (16) - ALPN
    ApplicationLayerProtocolNegotiation = 16,

    /// signed_certificate_timestamp (18) - Certificate Transparency
    SignedCertificateTimestamp = 18,

    /// client_certificate_type (19)
    ClientCertificateType = 19,

    /// server_certificate_type (20)
    ServerCertificateType = 20,

    /// padding (21)
    Padding = 21,

    /// encrypt_then_mac (22) - TLS 1.2
    EncryptThenMac = 22,

    /// extended_master_secret (23) - TLS 1.2
    ExtendedMasterSecret = 23,

    /// session_ticket (35)
    SessionTicket = 35,

    /// pre_shared_key (41) - TLS 1.3
    PreSharedKey = 41,

    /// early_data (42) - TLS 1.3
    EarlyData = 42,

    /// supported_versions (43) - TLS 1.3
    SupportedVersions = 43,

    /// cookie (44) - TLS 1.3
    Cookie = 44,

    /// psk_key_exchange_modes (45) - TLS 1.3
    PskKeyExchangeModes = 45,

    /// certificate_authorities (47) - TLS 1.3
    CertificateAuthorities = 47,

    /// oid_filters (48) - TLS 1.3
    OidFilters = 48,

    /// post_handshake_auth (49) - Post-handshake client authentication (RFC 8446 Section 4.2.6)
    /// Empty extension indicating client supports certificate requests after handshake
    PostHandshakeAuth = 49,

    /// signature_algorithms_cert (50) - TLS 1.3
    SignatureAlgorithmsCert = 50,

    /// key_share (51) - TLS 1.3
    KeyShare = 51,

    /// connection_id (54) - DTLS 1.3 connection migration support (RFC 9146)
    /// Enables endpoints to change IP address/port while maintaining connection state
    ConnectionId = 54,

    /// encrypted_client_hello (0xFE0D) - ECH draft
    EncryptedClientHello = 0xFE0D,

    /// renegotiation_info (0xFF01) - RFC 5746
    RenegotiationInfo = 0xFF01,
}

impl ExtensionType {
    /// Create from wire format (u16).
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(ExtensionType::ServerName),
            1 => Some(ExtensionType::MaxFragmentLength),
            5 => Some(ExtensionType::StatusRequest),
            10 => Some(ExtensionType::SupportedGroups),
            11 => Some(ExtensionType::EcPointFormats),
            13 => Some(ExtensionType::SignatureAlgorithms),
            14 => Some(ExtensionType::UseSrtp),
            15 => Some(ExtensionType::Heartbeat),
            16 => Some(ExtensionType::ApplicationLayerProtocolNegotiation),
            18 => Some(ExtensionType::SignedCertificateTimestamp),
            19 => Some(ExtensionType::ClientCertificateType),
            20 => Some(ExtensionType::ServerCertificateType),
            21 => Some(ExtensionType::Padding),
            22 => Some(ExtensionType::EncryptThenMac),
            23 => Some(ExtensionType::ExtendedMasterSecret),
            35 => Some(ExtensionType::SessionTicket),
            41 => Some(ExtensionType::PreSharedKey),
            42 => Some(ExtensionType::EarlyData),
            43 => Some(ExtensionType::SupportedVersions),
            44 => Some(ExtensionType::Cookie),
            45 => Some(ExtensionType::PskKeyExchangeModes),
            47 => Some(ExtensionType::CertificateAuthorities),
            48 => Some(ExtensionType::OidFilters),
            49 => Some(ExtensionType::PostHandshakeAuth),
            50 => Some(ExtensionType::SignatureAlgorithmsCert),
            51 => Some(ExtensionType::KeyShare),
            54 => Some(ExtensionType::ConnectionId),
            0xFE0D => Some(ExtensionType::EncryptedClientHello),
            0xFF01 => Some(ExtensionType::RenegotiationInfo),
            _ => None,
        }
    }

    /// Convert to wire format (u16).
    pub const fn to_u16(self) -> u16 {
        self as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        assert_eq!(
            ProtocolVersion::from_u16(0x0304),
            Some(ProtocolVersion::Tls13)
        );
        assert_eq!(ProtocolVersion::Tls13.to_u16(), 0x0304);
        assert_eq!(ProtocolVersion::Tls13.name(), "TLS 1.3");
        assert!(ProtocolVersion::Tls13.is_tls());
        assert!(!ProtocolVersion::Tls13.is_dtls());
        assert!(ProtocolVersion::Tls13.is_secure());
    }

    #[test]
    fn test_content_type() {
        assert_eq!(ContentType::from_u8(22), Some(ContentType::Handshake));
        assert_eq!(ContentType::Handshake.to_u8(), 22);
        assert!(ContentType::Handshake.is_valid_for_tls13());
        assert!(!ContentType::ChangeCipherSpec.is_valid_for_tls13());
    }

    #[test]
    fn test_handshake_type() {
        assert_eq!(HandshakeType::from_u8(1), Some(HandshakeType::ClientHello));
        assert_eq!(HandshakeType::ClientHello.to_u8(), 1);
        assert!(HandshakeType::ClientHello.is_valid_for_tls13());
        assert!(!HandshakeType::ServerKeyExchange.is_valid_for_tls13());
    }

    #[test]
    fn test_extension_type() {
        assert_eq!(ExtensionType::from_u16(51), Some(ExtensionType::KeyShare));
        assert_eq!(ExtensionType::KeyShare.to_u16(), 51);
    }
}
