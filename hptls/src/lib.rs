//! # HPTLS - High-Performance TLS Library
//!
//! A modern, high-performance TLS library for Rust with support for:
//! - TLS 1.3, TLS 1.2, DTLS 1.3, DTLS 1.2, QUIC
//! - Post-quantum cryptography (ML-KEM, ML-DSA)
//! - Kernel TLS (kTLS) offload for extreme performance
//! - io_uring for modern async I/O on Linux
//! - Zero-copy operations
//! - SIMD acceleration
//!
//! ## Quick Start
//!
//! ### Async Client Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "async")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use hptls::{ClientConfig, TlsStream};
//! use tokio::net::TcpStream;
//!
//! // Create client configuration
//! let config = ClientConfig::builder()
//!     .with_root_certificates(/* ... */)
//!     .build()?;
//!
//! // Connect to server
//! let tcp_stream = TcpStream::connect("example.com:443").await?;
//! let tls_stream = TlsStream::connect(config, "example.com", tcp_stream).await?;
//!
//! // Use the TLS connection
//! // ...
//! # Ok(())
//! # }
//! ```
//!
//! ### Async Server Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "async")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use hptls::{ServerConfig, TlsStream};
//! use tokio::net::TcpListener;
//!
//! // Create server configuration
//! let config = ServerConfig::builder()
//!     .with_certificate_chain(/* ... */)
//!     .with_private_key(/* ... */)
//!     .build()?;
//!
//! // Accept connections
//! let listener = TcpListener::bind("0.0.0.0:443").await?;
//! loop {
//!     let (tcp_stream, _) = listener.accept().await?;
//!     let tls_stream = TlsStream::accept(config.clone(), tcp_stream).await?;
//!     // Handle connection...
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature Flags
//!
//! - `std` (default): Enable standard library support
//! - `async`: Enable async I/O with Tokio
//! - `tls12`: Enable TLS 1.2 protocol
//! - `tls13` (default): Enable TLS 1.3 protocol
//! - `dtls12`: Enable DTLS 1.2 protocol
//! - `dtls13`: Enable DTLS 1.3 protocol
//! - `quic`: Enable QUIC protocol support
//! - `post-quantum`: Enable post-quantum cryptography
//! - `ech`: Enable Encrypted Client Hello
//! - `simd`: Enable SIMD optimizations
//! - `kTLS`: Enable kernel TLS offload (Linux/FreeBSD)
//! - `io-uring`: Enable io_uring for async I/O (Linux)

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    unused_qualifications
)]
#![forbid(unsafe_code)]

// Re-export core types
pub use hptls_core::{self, cipher, error, protocol, Config, Error, ProtocolVersion, Result};

// Re-export specific types
pub use hptls_core::cipher::CipherSuite;

// Re-export crypto interface
pub use hptls_crypto;

// Public modules
pub mod client;
pub mod server;

#[cfg(feature = "async")]
pub mod stream;

// Re-exports
pub use client::ClientConfig;
pub use server::ServerConfig;

#[cfg(feature = "async")]
pub use stream::TlsStream;

/// HPTLS version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get the HPTLS version.
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let ver = version();
        assert!(!ver.is_empty());
        assert!(ver.starts_with("0."));
    }
}
