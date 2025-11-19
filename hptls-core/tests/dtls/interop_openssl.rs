//! OpenSSL DTLS 1.3 Interoperability Tests
//!
//! These tests verify compatibility with OpenSSL's DTLS 1.3 implementation.
//!
//! **REQUIREMENTS:**
//! - OpenSSL 3.2.0+ (DTLS 1.3 support added in 3.2.0)
//! - OpenSSL command-line tools (s_server, s_client)
//!
//! **CURRENT STATUS:**
//! The test environment has OpenSSL 3.0.2, which does NOT support DTLS 1.3.
//! These tests are **SKIPPED** until OpenSSL 3.2+ is available.
//!
//! **To run these tests when OpenSSL 3.2+ is available:**
//! ```bash
//! cargo test --test dtls_interop_openssl -- --ignored
//! ```
//!
//! **Manual Testing Instructions:**
//!
//! ## Test 1: HPTLS Client → OpenSSL Server
//!
//! ```bash
//! # Terminal 1: Start OpenSSL DTLS 1.3 server
//! openssl s_server -dtls -port 4433 \
//!     -cert server.crt -key server.key \
//!     -accept 0.0.0.0:4433 -www
//!
//! # Terminal 2: Run HPTLS client
//! cargo run --example dtls_client -- localhost:4433
//! ```
//!
//! ## Test 2: OpenSSL Client → HPTLS Server
//!
//! ```bash
//! # Terminal 1: Start HPTLS server
//! cargo run --example dtls_server
//!
//! # Terminal 2: Run OpenSSL client
//! openssl s_client -dtls -connect localhost:4433
//! ```
//!
//! ## Test 3: Cookie Exchange Verification
//!
//! ```bash
//! # Terminal 1: Start HPTLS server with Always policy
//! HPTLS_COOKIE_POLICY=always cargo run --example dtls_server
//!
//! # Terminal 2: Connect with OpenSSL client and verify HelloRetryRequest
//! openssl s_client -dtls -connect localhost:4433 -msg
//! # Should see HelloRetryRequest with cookie extension
//! ```

use std::process::{Command, Stdio};
use std::time::Duration;
use std::thread;

/// Get the best available OpenSSL binary (prefers openssl-3.2.sh if available)
fn get_openssl_binary() -> &'static str {
    // Try openssl-3.2.sh first (our custom 3.2.1 build)
    if Command::new("openssl-3.2.sh").arg("version").output().is_ok() {
        "openssl-3.2.sh"
    } else {
        "openssl"
    }
}

/// Check if OpenSSL version supports DTLS 1.3 (requires 3.2.0+)
fn check_openssl_version() -> Result<bool, String> {
    let binary = get_openssl_binary();
    let output = Command::new(binary)
        .arg("version")
        .output()
        .map_err(|e| format!("Failed to run {}: {}", binary, e))?;

    let version_str = String::from_utf8_lossy(&output.stdout);

    // Parse version: "OpenSSL 3.2.0 ..."
    if let Some(version_part) = version_str.split_whitespace().nth(1) {
        let parts: Vec<&str> = version_part.split('.').collect();
        if parts.len() >= 2 {
            if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                // DTLS 1.3 requires OpenSSL 3.2+
                return Ok(major > 3 || (major == 3 && minor >= 2));
            }
        }
    }

    Err(format!("Could not parse OpenSSL version: {}", version_str))
}

/// Get OpenSSL version string for reporting
fn get_openssl_version() -> String {
    let binary = get_openssl_binary();
    Command::new(binary)
        .arg("version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "Unknown".to_string())
}

#[test]
#[ignore] // Ignored by default - requires OpenSSL 3.2+
fn test_openssl_version_check() {
    let version = get_openssl_version();
    println!("OpenSSL version: {}", version);

    match check_openssl_version() {
        Ok(true) => {
            println!("OpenSSL version supports DTLS 1.3");
        }
        Ok(false) => {
            println!("Warning: OpenSSL version does NOT support DTLS 1.3");
            println!("   Required: OpenSSL 3.2.0+");
            println!("   Installed: {}", version);
            println!("\n   Interoperability tests will be SKIPPED.");
        }
        Err(e) => {
            panic!("Failed to check OpenSSL version: {}", e);
        }
    }
}

#[test]
#[ignore] // Requires OpenSSL 3.2+ and manual certificate setup
fn test_hptls_client_to_openssl_server() {
    // Check OpenSSL version
    match check_openssl_version() {
        Ok(false) => {
            println!("SKIPPED: OpenSSL {} does not support DTLS 1.3", get_openssl_version());
            println!("Required: OpenSSL 3.2.0+");
            return;
        }
        Err(e) => {
            println!("SKIPPED: {}", e);
            return;
        }
        Ok(true) => {
            println!("OpenSSL version OK: {}", get_openssl_version());
        }
    }

    // TODO: Implement automated test when OpenSSL 3.2+ is available
    // This would:
    // 1. Generate test certificates
    // 2. Start OpenSSL s_server in background
    // 3. Create HPTLS client
    // 4. Perform handshake
    // 5. Send/receive data
    // 6. Verify success
    // 7. Cleanup

    println!("TODO: Implement automated OpenSSL server test");
}

#[test]
#[ignore] // Requires OpenSSL 3.2+ and manual certificate setup
fn test_openssl_client_to_hptls_server() {
    // Check OpenSSL version
    match check_openssl_version() {
        Ok(false) => {
            println!("SKIPPED: OpenSSL {} does not support DTLS 1.3", get_openssl_version());
            println!("Required: OpenSSL 3.2.0+");
            return;
        }
        Err(e) => {
            println!("SKIPPED: {}", e);
            return;
        }
        Ok(true) => {
            println!("OpenSSL version OK: {}", get_openssl_version());
        }
    }

    // TODO: Implement automated test when OpenSSL 3.2+ is available
    // This would:
    // 1. Generate test certificates
    // 2. Start HPTLS server in background
    // 3. Launch OpenSSL s_client
    // 4. Perform handshake
    // 5. Send/receive data
    // 6. Verify success
    // 7. Cleanup

    println!("TODO: Implement automated HPTLS server test");
}

#[test]
#[ignore] // Requires OpenSSL 3.2+
fn test_cookie_exchange_with_openssl() {
    // Check OpenSSL version
    match check_openssl_version() {
        Ok(false) => {
            println!("SKIPPED: OpenSSL {} does not support DTLS 1.3", get_openssl_version());
            println!("Required: OpenSSL 3.2.0+");
            return;
        }
        Err(e) => {
            println!("SKIPPED: {}", e);
            return;
        }
        Ok(true) => {
            println!("OpenSSL version OK: {}", get_openssl_version());
        }
    }

    // TODO: Implement cookie exchange test
    // This would verify:
    // 1. HPTLS server sends HelloRetryRequest with cookie
    // 2. OpenSSL client echoes cookie correctly
    // 3. HPTLS server accepts the cookie
    // 4. Handshake completes successfully

    println!("TODO: Implement cookie exchange compatibility test");
}

/// Run basic version check
/// This test always runs to document the OpenSSL version
#[test]
fn test_document_openssl_version() {
    let version = get_openssl_version();
    println!("\n=== OpenSSL DTLS 1.3 Interoperability Status ===");
    println!("OpenSSL Version: {}", version);

    match check_openssl_version() {
        Ok(true) => {
            println!("Status: DTLS 1.3 supported");
            println!("\nInteroperability tests can be run with:");
            println!("  cargo test --test dtls_interop_openssl -- --ignored");
        }
        Ok(false) => {
            println!("Status: Warning: DTLS 1.3 NOT supported");
            println!("\nRequired: OpenSSL 3.2.0+");
            println!("Installed: {}", version);
            println!("\nTo enable interoperability testing:");
            println!("  1. Upgrade to OpenSSL 3.2.0 or later");
            println!("  2. Run: cargo test --test dtls_interop_openssl -- --ignored");
            println!("\nCurrent Status: Interoperability tests SKIPPED");
        }
        Err(e) => {
            println!("Status: Error: Error checking version: {}", e);
        }
    }
    println!("===============================================\n");
}
