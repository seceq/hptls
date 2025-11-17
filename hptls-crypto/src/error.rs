//! Error types for the cryptographic provider.

use std::fmt;

/// Result type for cryptographic operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The requested algorithm is not supported by this provider.
    UnsupportedAlgorithm(String),

    /// Invalid key size for the algorithm.
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size in bytes
        actual: usize,
    },

    /// Invalid key length (generic).
    InvalidKeyLength,

    /// Invalid nonce/IV size for the algorithm.
    InvalidNonceSize {
        /// Expected nonce size in bytes
        expected: usize,
        /// Actual nonce size in bytes
        actual: usize,
    },

    /// Invalid length parameter.
    InvalidLength,

    /// Authentication tag verification failed (AEAD).
    AuthenticationFailed,

    /// Signature verification failed.
    SignatureVerificationFailed,

    /// Invalid signature format.
    InvalidSignature,

    /// Invalid public key.
    InvalidPublicKey,

    /// Invalid private key.
    InvalidPrivateKey,

    /// Key exchange failed.
    KeyExchangeFailed,

    /// Encryption failed.
    EncryptionFailed,

    /// Decryption failed.
    DecryptionFailed,

    /// Random number generation failed.
    RandomGenerationFailed,

    /// General cryptographic error with a message.
    CryptoError(String),

    /// Internal error (should not happen in correct usage).
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedAlgorithm(s) => write!(f, "Algorithm not supported: {}", s),
            Error::InvalidKeySize { expected, actual } => {
                write!(
                    f,
                    "Invalid key size: expected {} bytes, got {}",
                    expected, actual
                )
            },
            Error::InvalidKeyLength => write!(f, "Invalid key length"),
            Error::InvalidNonceSize { expected, actual } => {
                write!(
                    f,
                    "Invalid nonce size: expected {} bytes, got {}",
                    expected, actual
                )
            },
            Error::InvalidLength => write!(f, "Invalid length parameter"),
            Error::AuthenticationFailed => write!(f, "Authentication tag verification failed"),
            Error::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            Error::InvalidSignature => write!(f, "Invalid signature format"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidPrivateKey => write!(f, "Invalid private key"),
            Error::EncryptionFailed => write!(f, "Encryption failed"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::KeyExchangeFailed => write!(f, "Key exchange failed"),
            Error::RandomGenerationFailed => write!(f, "Random number generation failed"),
            Error::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            Error::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}
