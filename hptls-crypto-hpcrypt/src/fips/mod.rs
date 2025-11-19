//! FIPS 140-2/140-3 Compliance Module
//!
//! This module provides comprehensive FIPS 140-2 and FIPS 140-3 compliance features
//! for the HPTLS cryptographic library.
//!
//! # Module Organization
//!
//! - [`state`] - FIPS operational state management and Power-On Self-Tests (POST)
//! - [`csp`] - Critical Security Parameter (CSP) lifecycle tracking and zeroization
//! - [`kat`] - Known-Answer Tests (KAT) for cryptographic algorithm validation
//!
//! # Quick Start
//!
//! ```rust
//! use hptls_crypto_hpcrypt::fips::{self, FipsMode, FipsState};
//!
//! // Enable FIPS mode
//! FipsMode::enable();
//!
//! // Run Power-On Self-Tests
//! fips::run_power_on_self_tests()?;
//!
//! // Verify operational state
//! if fips::check_fips_state().is_ok() {
//!     // Proceed with cryptographic operations
//! }
//! # Ok::<(), hptls_crypto::Error>(())
//! ```
//!
//! # CSP Tracking Example
//!
//! ```rust
//! use hptls_crypto_hpcrypt::fips::csp::{CspType, register_csp, unregister_csp};
//! use zeroize::Zeroize;
//!
//! // Register CSP when created
//! let mut key = vec![0x42; 32];
//! let csp_id = register_csp(CspType::AesKey, key.len());
//!
//! // ... use the key ...
//!
//! // Zeroize and unregister when done
//! key.zeroize();
//! unregister_csp(csp_id)?;
//! # Ok::<(), hptls_crypto::Error>(())
//! ```
//!
//! # FIPS Compliance Features
//!
//! ## State Management (Section 4.7.1)
//! - **Uninitialized** → **Operational** → **Error** state machine
//! - Power-On Self-Tests (POST) execution
//! - Irreversible error state (no recovery)
//!
//! ## Known-Answer Tests (Section 4.9.1)
//! - RSA-PSS signatures (PKCS#1 v2.1)
//! - ECDSA (FIPS 186-4)
//! - EdDSA (RFC 8032)
//! - ECDH (RFC 7748)
//! - HKDF/HMAC (RFC 5869/4231)
//! - AES-GCM (NIST SP 800-38D)
//! - ChaCha20-Poly1305 (RFC 8439)
//!
//! ## CSP Zeroization (Section 4.7.6)
//! - 16 CSP types tracked
//! - Lifecycle management (creation → use → zeroization)
//! - Audit trail with timestamps
//! - Emergency shutdown procedures
//!
//! # References
//!
//! - [FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final)
//! - [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final)

// Sub-modules
pub mod state;
pub mod csp;
pub mod kat;

// Re-export commonly used types from state module
pub use state::{FipsMode, FipsState, check_fips_state, run_power_on_self_tests};

// Re-export commonly used types from csp module
pub use csp::{CspType, register_csp, unregister_csp, csp_statistics, verify_all_csps_zeroized};
