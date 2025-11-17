//! Error types for HPTLS core.

use core::fmt;

/// Result type for HPTLS operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur in HPTLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid configuration
    InvalidConfig(String),

    /// Protocol error
    ProtocolError(ProtocolError),

    /// Cryptographic error
    CryptoError(String),

    /// I/O error
    IoError(String),

    /// Handshake failure
    HandshakeFailure(String),

    /// Alert received from peer
    AlertReceived(AlertDescription),

    /// Unexpected message
    UnexpectedMessage(String),

    /// Invalid message format
    InvalidMessage(String),

    /// Decryption failure
    DecryptionFailed,

    /// Certificate verification failed
    CertificateVerificationFailed(String),

    /// Unsupported feature
    UnsupportedFeature(String),

    /// Internal error
    InternalError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            Error::ProtocolError(e) => write!(f, "Protocol error: {:?}", e),
            Error::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            Error::IoError(msg) => write!(f, "I/O error: {}", msg),
            Error::HandshakeFailure(msg) => write!(f, "Handshake failure: {}", msg),
            Error::AlertReceived(desc) => write!(f, "Alert received: {:?}", desc),
            Error::UnexpectedMessage(msg) => write!(f, "Unexpected message: {}", msg),
            Error::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::CertificateVerificationFailed(msg) => {
                write!(f, "Certificate verification failed: {}", msg)
            },
            Error::UnsupportedFeature(msg) => write!(f, "Unsupported feature: {}", msg),
            Error::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<hptls_crypto::Error> for Error {
    fn from(e: hptls_crypto::Error) -> Self {
        Error::CryptoError(format!("{:?}", e))
    }
}

/// Protocol-level errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolError {
    /// Decode error
    DecodeError,

    /// Unexpected message type
    UnexpectedMessage,

    /// Bad record MAC
    BadRecordMac,

    /// Record overflow
    RecordOverflow,

    /// Handshake failure
    HandshakeFailure,

    /// Bad certificate
    BadCertificate,

    /// Unsupported certificate
    UnsupportedCertificate,

    /// Certificate revoked
    CertificateRevoked,

    /// Certificate expired
    CertificateExpired,

    /// Certificate unknown
    CertificateUnknown,

    /// Illegal parameter
    IllegalParameter,

    /// Unknown CA
    UnknownCa,

    /// Access denied
    AccessDenied,

    /// Insufficient security
    InsufficientSecurity,

    /// Internal error
    InternalError,

    /// Protocol version not supported
    ProtocolVersion,

    /// No application protocol
    NoApplicationProtocol,

    /// Missing extension
    MissingExtension,

    /// Unsupported extension
    UnsupportedExtension,

    /// Unrecognized name
    UnrecognizedName,

    /// Bad certificate status response
    BadCertificateStatusResponse,

    /// Unknown PSK identity
    UnknownPskIdentity,

    /// Certificate required
    CertificateRequired,
}

/// TLS alert descriptions (RFC 8446 Section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AlertDescription {
    /// Close notify
    CloseNotify = 0,

    /// Unexpected message
    UnexpectedMessage = 10,

    /// Bad record MAC
    BadRecordMac = 20,

    /// Record overflow
    RecordOverflow = 22,

    /// Handshake failure
    HandshakeFailure = 40,

    /// Bad certificate
    BadCertificate = 42,

    /// Unsupported certificate
    UnsupportedCertificate = 43,

    /// Certificate revoked
    CertificateRevoked = 44,

    /// Certificate expired
    CertificateExpired = 45,

    /// Certificate unknown
    CertificateUnknown = 46,

    /// Illegal parameter
    IllegalParameter = 47,

    /// Unknown CA
    UnknownCa = 48,

    /// Access denied
    AccessDenied = 49,

    /// Decode error
    DecodeError = 50,

    /// Decrypt error
    DecryptError = 51,

    /// Protocol version
    ProtocolVersion = 70,

    /// Insufficient security
    InsufficientSecurity = 71,

    /// Internal error
    InternalError = 80,

    /// Inappropriate fallback
    InappropriateFallback = 86,

    /// User canceled
    UserCanceled = 90,

    /// Missing extension
    MissingExtension = 109,

    /// Unsupported extension
    UnsupportedExtension = 110,

    /// Unrecognized name
    UnrecognizedName = 112,

    /// Bad certificate status response
    BadCertificateStatusResponse = 113,

    /// Unknown PSK identity
    UnknownPskIdentity = 115,

    /// Certificate required
    CertificateRequired = 116,

    /// No application protocol
    NoApplicationProtocol = 120,
}

impl AlertDescription {
    /// Convert from wire format (u8).
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(AlertDescription::CloseNotify),
            10 => Some(AlertDescription::UnexpectedMessage),
            20 => Some(AlertDescription::BadRecordMac),
            22 => Some(AlertDescription::RecordOverflow),
            40 => Some(AlertDescription::HandshakeFailure),
            42 => Some(AlertDescription::BadCertificate),
            43 => Some(AlertDescription::UnsupportedCertificate),
            44 => Some(AlertDescription::CertificateRevoked),
            45 => Some(AlertDescription::CertificateExpired),
            46 => Some(AlertDescription::CertificateUnknown),
            47 => Some(AlertDescription::IllegalParameter),
            48 => Some(AlertDescription::UnknownCa),
            49 => Some(AlertDescription::AccessDenied),
            50 => Some(AlertDescription::DecodeError),
            51 => Some(AlertDescription::DecryptError),
            70 => Some(AlertDescription::ProtocolVersion),
            71 => Some(AlertDescription::InsufficientSecurity),
            80 => Some(AlertDescription::InternalError),
            86 => Some(AlertDescription::InappropriateFallback),
            90 => Some(AlertDescription::UserCanceled),
            109 => Some(AlertDescription::MissingExtension),
            110 => Some(AlertDescription::UnsupportedExtension),
            112 => Some(AlertDescription::UnrecognizedName),
            113 => Some(AlertDescription::BadCertificateStatusResponse),
            115 => Some(AlertDescription::UnknownPskIdentity),
            116 => Some(AlertDescription::CertificateRequired),
            120 => Some(AlertDescription::NoApplicationProtocol),
            _ => None,
        }
    }

    /// Convert to wire format (u8).
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Check if this alert is fatal.
    ///
    /// All alerts except CloseNotify and UserCanceled are fatal in TLS 1.3.
    pub const fn is_fatal(self) -> bool {
        !matches!(
            self,
            AlertDescription::CloseNotify | AlertDescription::UserCanceled
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_description_conversion() {
        assert_eq!(
            AlertDescription::from_u8(0),
            Some(AlertDescription::CloseNotify)
        );
        assert_eq!(
            AlertDescription::from_u8(40),
            Some(AlertDescription::HandshakeFailure)
        );
        assert_eq!(AlertDescription::from_u8(255), None);

        assert_eq!(AlertDescription::CloseNotify.to_u8(), 0);
        assert_eq!(AlertDescription::HandshakeFailure.to_u8(), 40);
    }

    #[test]
    fn test_alert_fatality() {
        assert!(!AlertDescription::CloseNotify.is_fatal());
        assert!(!AlertDescription::UserCanceled.is_fatal());
        assert!(AlertDescription::HandshakeFailure.is_fatal());
        assert!(AlertDescription::BadCertificate.is_fatal());
    }
}
