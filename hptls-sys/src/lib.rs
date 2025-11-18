//! Platform-specific bindings for HPTLS.
//!
//! This crate provides low-level bindings to platform-specific features:
//! - kTLS (Kernel TLS) on Linux and FreeBSD
//! - io_uring on Linux
//! - Windows Secure Channel bindings
//!
//! # Safety
//!
//! This crate contains `unsafe` code as it interfaces directly with OS APIs.

#![allow(unsafe_code)]
#![warn(missing_docs)]

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

#[cfg(target_os = "windows")]
pub mod windows;

/// Platform-specific error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Operation not supported on this platform
    Unsupported,

    /// System error with errno
    SystemError(i32),

    /// Invalid parameter
    InvalidParameter(String),

    /// Feature not available (e.g., kTLS not enabled in kernel)
    FeatureNotAvailable(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unsupported => write!(f, "Operation not supported on this platform"),
            Error::SystemError(errno) => write!(f, "System error: {}", errno),
            Error::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            Error::FeatureNotAvailable(msg) => write!(f, "Feature not available: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Result type for platform operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::Unsupported;
        assert!(!err.to_string().is_empty());
    }
}
