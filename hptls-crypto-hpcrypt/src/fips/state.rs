//! FIPS 140-2/140-3 State Management
//!
//! This module provides FIPS operational state management including Power-On Self-Tests (POST),
//! state transitions, and error state enforcement.
//!
//! ## FIPS Requirements
//!
//! FIPS 140-2/140-3 requires:
//! - Power-On Self-Tests (POST) before first cryptographic operation
//! - Known-Answer Tests (KAT) for all approved algorithms
//! - Continuous operation tests for RNG
//! - Error state management with no recovery from error state
//! - Zeroization of critical security parameters (CSPs)
//!
//! ## Current Status
//!
//! This module provides complete FIPS 140-2/140-3 compliance framework:
//! - FIPS mode toggle
//! - State management (Uninitialized → Operational → Error)
//! - Error state enforcement (no recovery)
//! - KAT implementations for all algorithms
//! - Zeroization hooks with full CSP tracking
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Note: This module is currently internal. FIPS support will be exposed via public API later.
//! use hptls_crypto_hpcrypt::fips::{FipsMode, run_power_on_self_tests};
//!
//! // Enable FIPS mode
//! FipsMode::enable();
//!
//! // Run POST before using cryptographic operations
//! run_power_on_self_tests().expect("FIPS POST failed");
//!
//! // Check if FIPS mode is enabled
//! if FipsMode::is_enabled() {
//!     println!("Operating in FIPS mode");
//! }
//! ```

use hptls_crypto::{Error, Result};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Helper to create FIPS error
fn fips_error(msg: &str) -> Error {
    Error::CryptoError(format!("FIPS: {}", msg))
}

/// FIPS operational state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsState {
    /// Initial state - POST not yet run
    Uninitialized = 0,
    /// POST completed successfully
    Operational = 1,
    /// Error state - no recovery possible
    Error = 2,
}

/// Global FIPS state
static FIPS_STATE: AtomicU8 = AtomicU8::new(FipsState::Uninitialized as u8);

/// Global FIPS mode flag
static FIPS_ENABLED: AtomicBool = AtomicBool::new(false);

/// FIPS mode management
pub struct FipsMode;

impl FipsMode {
    /// Enable FIPS mode
    ///
    /// When FIPS mode is enabled:
    /// - Only FIPS-approved algorithms are available
    /// - Power-On Self-Tests must pass before operations
    /// - All operations must complete self-tests
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use hptls_crypto_hpcrypt::fips::FipsMode;
    ///
    /// FipsMode::enable();
    /// assert!(FipsMode::is_enabled());
    /// ```
    pub fn enable() {
        FIPS_ENABLED.store(true, Ordering::SeqCst);
    }

    /// Disable FIPS mode
    pub fn disable() {
        FIPS_ENABLED.store(false, Ordering::SeqCst);
    }

    /// Check if FIPS mode is enabled
    pub fn is_enabled() -> bool {
        FIPS_ENABLED.load(Ordering::SeqCst)
    }

    /// Get current FIPS state
    pub fn state() -> FipsState {
        match FIPS_STATE.load(Ordering::SeqCst) {
            0 => FipsState::Uninitialized,
            1 => FipsState::Operational,
            2 => FipsState::Error,
            _ => FipsState::Error,
        }
    }

    /// Set FIPS state to error (no recovery)
    pub(crate) fn set_error() {
        FIPS_STATE.store(FipsState::Error as u8, Ordering::SeqCst);
    }

    /// Check if in operational state
    pub fn is_operational() -> bool {
        Self::state() == FipsState::Operational
    }

    /// Check if in error state
    pub fn is_error() -> bool {
        Self::state() == FipsState::Error
    }
}

/// Run all Power-On Self-Tests (POST)
///
/// This function must be called before performing any cryptographic operations
/// when operating in FIPS mode. It runs Known-Answer Tests (KAT) for all
/// approved algorithms.
///
/// # Returns
///
/// - `Ok(())` if all tests pass
/// - `Err(Error)` if any test fails (module enters error state)
///
/// # Example
///
/// ```rust,ignore
/// use hptls_crypto_hpcrypt::fips::run_power_on_self_tests;
///
/// run_power_on_self_tests().expect("FIPS POST failed");
/// ```
pub fn run_power_on_self_tests() -> Result<()> {
    // If already operational, no need to run again
    if FipsMode::is_operational() {
        return Ok(());
    }

    // If in error state, cannot recover
    if FipsMode::is_error() {
        return Err(fips_error("FIPS module in error state - cannot recover"));
    }

    // Run all self-tests
    if let Err(e) = run_all_self_tests() {
        FipsMode::set_error();
        return Err(e);
    }

    // Transition to operational state
    FIPS_STATE.store(FipsState::Operational as u8, Ordering::SeqCst);

    Ok(())
}

/// Run all Known-Answer Tests
///
/// Executes KATs for all FIPS-approved algorithms:
/// - SHA-256/384/512 (via HMAC KATs)
/// - HMAC-SHA256/384/512 (RFC test vectors)
/// - AES-128-GCM / AES-256-GCM (NIST test vectors)
/// - RSA-PSS-SHA256/384/512 (NIST test vectors)
/// - ECDSA P-256/P-384 (NIST test vectors)
pub(crate) fn run_all_self_tests() -> Result<()> {
    // Call the KAT module function
    crate::fips::kat::run_all_kats()
}

/// Check FIPS compliance before cryptographic operation
///
/// This should be called at the start of every cryptographic operation
/// when operating in FIPS mode.
///
/// # Returns
///
/// - `Ok(())` if module is operational
/// - `Err(Error)` if module is not initialized or in error state
pub fn check_fips_state() -> Result<()> {
    if !FipsMode::is_enabled() {
        return Ok(());
    }

    match FipsMode::state() {
        FipsState::Uninitialized => Err(fips_error(
            "FIPS POST not run - call run_power_on_self_tests() first",
        )),
        FipsState::Operational => Ok(()),
        FipsState::Error => Err(fips_error(
            "FIPS module in error state - cannot perform cryptographic operations",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_mode_toggle() {
        FipsMode::disable();
        assert!(!FipsMode::is_enabled());

        FipsMode::enable();
        assert!(FipsMode::is_enabled());

        FipsMode::disable();
        assert!(!FipsMode::is_enabled());
    }

    #[test]
    fn test_power_on_self_tests() {
        // Disable FIPS mode for this test
        FipsMode::disable();

        // Reset state
        FIPS_STATE.store(FipsState::Uninitialized as u8, Ordering::SeqCst);

        // Run POST
        let result = run_power_on_self_tests();
        assert!(result.is_ok(), "POST should pass: {:?}", result);

        // Should be operational now
        assert!(FipsMode::is_operational());
    }

    #[test]
    fn test_fips_state_management() {
        // Reset to uninitialized
        FIPS_STATE.store(FipsState::Uninitialized as u8, Ordering::SeqCst);

        assert_eq!(FipsMode::state(), FipsState::Uninitialized);
        assert!(!FipsMode::is_operational());
        assert!(!FipsMode::is_error());

        // Run POST
        run_power_on_self_tests().expect("POST should pass");

        assert_eq!(FipsMode::state(), FipsState::Operational);
        assert!(FipsMode::is_operational());
        assert!(!FipsMode::is_error());
    }

    #[test]
    fn test_fips_error_state() {
        // Set to error state
        FipsMode::set_error();

        assert!(FipsMode::is_error());
        assert!(!FipsMode::is_operational());

        // Cannot recover from error state
        let result = run_power_on_self_tests();
        assert!(result.is_err());

        // Reset for other tests
        FIPS_STATE.store(FipsState::Uninitialized as u8, Ordering::SeqCst);
    }

    #[test]
    fn test_check_fips_state() {
        // Disable FIPS mode
        FipsMode::disable();
        FIPS_STATE.store(FipsState::Uninitialized as u8, Ordering::SeqCst);

        // Should be OK when FIPS disabled
        assert!(check_fips_state().is_ok());

        // Enable FIPS mode
        FipsMode::enable();

        // Should fail when uninitialized
        assert!(check_fips_state().is_err());

        // Run POST
        run_power_on_self_tests().expect("POST should pass");

        // Should be OK when operational
        assert!(check_fips_state().is_ok());

        // Clean up
        FipsMode::disable();
        FIPS_STATE.store(FipsState::Uninitialized as u8, Ordering::SeqCst);
    }
}
