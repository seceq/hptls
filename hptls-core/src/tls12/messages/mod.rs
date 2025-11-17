//! TLS 1.2 Handshake Messages
//!
//! This module contains TLS 1.2-specific handshake messages that don't exist in TLS 1.3:
//! - ServerKeyExchange: Contains server's ephemeral ECDHE public key + signature
//! - ClientKeyExchange: Contains client's ephemeral ECDHE public key
//! - ServerHelloDone: Empty message indicating server finished its part
//! - Tls12Certificate: TLS 1.2 Certificate message format (simpler than TLS 1.3)
//!
//! Messages that exist in both TLS 1.2 and 1.3 (ClientHello, ServerHello,
//! CertificateVerify, Finished) are in the main messages module with version-specific handling.

pub mod certificate;
pub mod client_key_exchange;
pub mod server_hello_done;
pub mod server_key_exchange;

pub use certificate::Tls12Certificate;
pub use client_key_exchange::ClientKeyExchange;
pub use server_hello_done::ServerHelloDone;
pub use server_key_exchange::ServerKeyExchange;
