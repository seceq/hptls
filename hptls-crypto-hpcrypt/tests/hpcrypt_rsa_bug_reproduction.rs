//! Minimal reproduction case for hpcrypt-rsa repeated sign bug
//!
//! To run: cargo test --package hptls-crypto-hpcrypt --test hpcrypt_rsa_bug_reproduction
//!
//! This reproduces the bug with commit cebbf721 (num-bigint crash)
//! With commit 8b339359, it shows MessageTooLong error instead

use hptls_crypto::{CryptoProvider, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;

// Real 2048-bit RSA key in PKCS#8 DER format (generated with OpenSSL)
const RSA_PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_private_pkcs8.der");
const RSA_PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_public_spki.der");
const TEST_MESSAGE: &[u8] = b"Test message for bug reproduction";

#[test]
#[ignore] // Ignore by default since it will crash
fn reproduce_bug_with_100_iterations() {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create RSA-PSS signature");

    println!("\n🧪 Attempting 100 sign iterations...");
    println!("Expected: Crash around iteration 50-100 with num-bigint panic\n");

    for i in 1..=100 {
        match sig.sign(RSA_PRIVATE_KEY, TEST_MESSAGE) {
            Ok(_) => {
                if i % 10 == 0 {
                    println!("✅ Iteration {} succeeded", i);
                }
            }
            Err(e) => {
                println!("❌ FAILED at iteration {}: {:?}", i, e);
                panic!("Bug reproduced at iteration {}", i);
            }
        }
    }

    println!("✅ All 100 iterations completed - bug is fixed!");
}

#[test]
fn demonstrate_safe_iteration_count() {
    // This should pass reliably with 30 iterations
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create RSA-PSS signature");

    println!("\n✅ Testing 30 iterations (safe threshold)...");

    for i in 1..=30 {
        sig.sign(RSA_PRIVATE_KEY, TEST_MESSAGE)
            .expect(&format!("Sign failed at iteration {}", i));
    }

    println!("✅ 30 iterations completed successfully\n");
}

#[test]
fn demonstrate_verify_works_fine() {
    // Verify operations don't have the bug - can do 200+ iterations
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create RSA-PSS signature");

    let signature = sig.sign(RSA_PRIVATE_KEY, TEST_MESSAGE)
        .expect("Failed to create signature");

    println!("\n✅ Testing 200 verify iterations (no bug here)...");

    for i in 1..=200 {
        sig.verify(RSA_PUBLIC_KEY, TEST_MESSAGE, &signature)
            .expect(&format!("Verify failed at iteration {}", i));
    }

    println!("✅ 200 verify iterations completed successfully\n");
}
