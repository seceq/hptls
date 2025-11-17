//! TLS handshake protocol implementation.
//!
//! This module implements the TLS 1.3 handshake protocol for both
//! client and server sides.

pub mod client;
pub mod server;

// Re-exports
pub use client::{ClientHandshake, ClientState};
pub use server::{ServerHandshake, ServerState};
