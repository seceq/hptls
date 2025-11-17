//! TLS 1.2 Implementation Module
//!
//! This module provides a complete TLS 1.2 implementation separate from the TLS 1.3 code.
//! TLS 1.2 is maintained for legacy compatibility but is deprecated (RFC 8996).
//!
//! ## Architecture
//!
//! ```text
//! tls12/
//! ├── mod.rs                 - Module root (this file)
//! ├── cipher_suites.rs       - TLS 1.2 cipher suite definitions
//! ├── messages/              - TLS 1.2-specific messages
//! │   ├── mod.rs
//! │   ├── server_key_exchange.rs
//! │   ├── client_key_exchange.rs
//! │   └── server_hello_done.rs
//! ├── key_exchange.rs        - ECDHE and RSA key exchange
//! ├── prf.rs                 - TLS 1.2 PRF (via hpcrypt-kdf)
//! ├── certificate_parser.rs  - X.509 certificate parsing
//! ├── extensions.rs          - TLS 1.2 extensions
//! ├── client.rs              - TLS 1.2 client handshake
//! ├── server.rs              - TLS 1.2 server handshake
//! └── record.rs              - TLS 1.2 record layer specifics
//! ```
//!
//! ## Supported Features
//!
//! - **Cipher Suites**: ECDHE-RSA/ECDSA with AES-GCM and ChaCha20-Poly1305
//! - **Key Exchange**: ECDHE (P-256, P-384, X25519)
//! - **Signature**: RSA-PSS, ECDSA P-256/P-384
//! - **AEAD**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
//! - **Extensions**: SNI, ALPN, signature_algorithms, supported_groups
//!
//! ## Not Supported (Legacy/Insecure)
//!
//! - CBC cipher suites (padding oracle vulnerabilities)
//! - RC4 (broken)
//! - MD5 and SHA-1 (weak hashes)
//! - Static RSA key exchange (no forward secrecy)
//! - Export cipher suites (intentionally weak)
//! - Compression (CRIME attack)

pub mod certificate_parser;
pub mod cipher_suites;
pub mod client;
pub mod extensions;
pub mod key_exchange;
pub mod messages;
pub mod prf;
pub mod record;
pub mod server;

// Re-export PRF functions
pub use prf::{compute_key_block, compute_master_secret, compute_verify_data, Tls12Prf};
