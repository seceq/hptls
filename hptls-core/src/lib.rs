//! # HPTLS Core
//!
//! Core TLS protocol implementation for High-Performance TLS.
//!
//! This crate provides the foundational components for TLS/DTLS/QUIC protocols:
//! - Protocol state machines
//! - Message parsing and serialization
//! - Cryptographic operations integration
//! - Record layer processing
//! - Handshake protocol
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │         Public API (hptls)              │
//! └─────────────────┬───────────────────────┘
//!                   │
//! ┌─────────────────▼───────────────────────┐
//! │       hptls-core (this crate)           │
//! │  ┌──────────────────────────────────┐   │
//! │  │   Protocol State Machines        │   │
//! │  ├──────────────────────────────────┤   │
//! │  │   Message Parser/Serializer      │   │
//! │  ├──────────────────────────────────┤   │
//! │  │   Record Layer                   │   │
//! │  ├──────────────────────────────────┤   │
//! │  │   Handshake Protocol             │   │
//! │  └──────────────────────────────────┘   │
//! └─────────────────┬───────────────────────┘
//!                   │
//! ┌─────────────────▼───────────────────────┐
//! │      hptls-crypto (trait interface)     │
//! └─────────────────────────────────────────┘
//! ```
//!
//! ## Feature Flags
//!
//! - `std` (default): Enable standard library support
//! - `async`: Enable async I/O support with Tokio
//! - `tls12`: Enable TLS 1.2 protocol
//! - `tls13`: Enable TLS 1.3 protocol
//! - `dtls12`: Enable DTLS 1.2 protocol
//! - `dtls13`: Enable DTLS 1.3 protocol
//! - `quic`: Enable QUIC support
//! - `post-quantum`: Enable post-quantum cryptography
//! - `ech`: Enable Encrypted Client Hello
//! - `simd`: Enable SIMD optimizations
//! - `kTLS`: Enable kernel TLS offload
//! - `io-uring`: Enable io_uring for Linux

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    unused_qualifications
)]
#![forbid(unsafe_code)]

// Re-export crypto interface
pub use hptls_crypto;

// Core modules
pub mod alert;
pub mod certificate_validator;
pub mod cipher;
pub mod connection_rate_tracker;
pub mod cookie_manager;
pub mod dtls;
pub mod dtls_handshake;
pub mod dtls_record_protection;
pub mod early_data;
pub mod ech;
pub mod ech_helpers;
pub mod error;
pub mod extension_types;
pub mod extensions;
pub mod grease;
pub mod handshake;
pub mod handshake_io;
pub mod key_schedule;
pub mod messages;
pub mod pqc;
pub mod protocol;
pub mod psk;
pub mod quic;
pub mod record;
pub mod record_protection;
pub mod signature_verify;
pub mod state;
pub mod ticket_encryption;
pub mod tls12;
pub mod transcript;
pub mod x509_simple;

// Re-exports
pub use error::{Error, Result};
pub use protocol::{ContentType, ProtocolVersion};

/// TLS configuration builder.
///
/// This is the main entry point for configuring a TLS connection.
///
/// # Example
///
/// ```rust
/// use hptls_core::{Config, ProtocolVersion};
///
/// let config = Config::builder()
///     .with_protocol_versions(&[ProtocolVersion::Tls13])
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    /// Supported protocol versions
    pub protocol_versions: Vec<ProtocolVersion>,

    /// Maximum fragment length (default: 16384)
    pub max_fragment_length: u16,

    /// Enable session resumption
    pub enable_session_resumption: bool,

    /// Enable early data (0-RTT)
    pub enable_early_data: bool,

    /// Maximum early data size
    pub max_early_data_size: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_versions: vec![ProtocolVersion::Tls13],
            max_fragment_length: 16384,
            enable_session_resumption: true,
            enable_early_data: false,
            max_early_data_size: 0,
        }
    }
}

impl Config {
    /// Create a new configuration builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Configuration builder for TLS.
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Set supported protocol versions.
    pub fn with_protocol_versions(mut self, versions: &[ProtocolVersion]) -> Self {
        self.config.protocol_versions = versions.to_vec();
        self
    }

    /// Set maximum fragment length.
    pub fn with_max_fragment_length(mut self, length: u16) -> Self {
        self.config.max_fragment_length = length;
        self
    }

    /// Enable session resumption.
    pub fn with_session_resumption(mut self, enable: bool) -> Self {
        self.config.enable_session_resumption = enable;
        self
    }

    /// Enable early data (0-RTT).
    pub fn with_early_data(mut self, enable: bool, max_size: u32) -> Self {
        self.config.enable_early_data = enable;
        self.config.max_early_data_size = max_size;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Result<Config> {
        // Validate configuration
        if self.config.protocol_versions.is_empty() {
            return Err(Error::InvalidConfig(
                "No protocol versions specified".into(),
            ));
        }

        if self.config.max_fragment_length > 16384 {
            return Err(Error::InvalidConfig("Max fragment length too large".into()));
        }

        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.protocol_versions, vec![ProtocolVersion::Tls13]);
        assert_eq!(config.max_fragment_length, 16384);
        assert!(config.enable_session_resumption);
        assert!(!config.enable_early_data);
    }

    #[test]
    fn test_config_builder() {
        let config = Config::builder()
            .with_protocol_versions(&[ProtocolVersion::Tls13, ProtocolVersion::Tls12])
            .with_max_fragment_length(8192)
            .with_session_resumption(false)
            .with_early_data(true, 16384)
            .build()
            .unwrap();

        assert_eq!(config.protocol_versions.len(), 2);
        assert_eq!(config.max_fragment_length, 8192);
        assert!(!config.enable_session_resumption);
        assert!(config.enable_early_data);
        assert_eq!(config.max_early_data_size, 16384);
    }

    #[test]
    fn test_config_validation() {
        // Test empty protocol versions
        let result = Config::builder().with_protocol_versions(&[]).build();
        assert!(result.is_err());

        // Test invalid fragment length
        let result = Config::builder().with_max_fragment_length(20000).build();
        assert!(result.is_err());
    }
}
