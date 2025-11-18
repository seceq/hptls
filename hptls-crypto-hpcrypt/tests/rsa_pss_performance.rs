//! RSA-PSS Performance Validation Test
//!
//! Simple performance measurement to validate RSA-PSS operations are within acceptable bounds.
//! This is not a full benchmark suite but validates performance is reasonable.

use hptls_crypto::{CryptoProvider, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;
use std::time::Instant;

const RSA_PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_private_pkcs8.der");
const RSA_PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_public_spki.der");
const TEST_MESSAGE: &[u8] = b"Performance test message for RSA-PSS";

#[test]
fn test_rsa_pss_sha256_sign_performance() {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create signature algorithm");

    // Warm up
    for _ in 0..5 {
        let _ = sig.sign(RSA_PRIVATE_KEY, TEST_MESSAGE);
    }

    // Measure 100 sign operations
    let start = Instant::now();
    let iterations = 100;

    for _ in 0..iterations {
        sig.sign(RSA_PRIVATE_KEY, TEST_MESSAGE)
            .expect("Sign failed");
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() / iterations;

    println!("RSA-PSS-SHA256 Sign (2048-bit):");
    println!("  {} operations in {:?}", iterations, elapsed);
    println!("  Average: {} µs per operation", avg_micros);
    println!("  Throughput: {} ops/sec", 1_000_000 / avg_micros);

    // Sanity check: 2048-bit RSA sign should be 0.5-5ms on modern hardware
    assert!(
        avg_micros < 10_000,
        "RSA-PSS sign too slow: {} µs (expected < 10ms)",
        avg_micros
    );
}

#[test]
fn test_rsa_pss_sha256_verify_performance() {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create signature algorithm");

    // Create signature once
    let signature = sig
        .sign(RSA_PRIVATE_KEY, TEST_MESSAGE)
        .expect("Sign failed");

    // Warm up
    for _ in 0..10 {
        let _ = sig.verify(RSA_PUBLIC_KEY, TEST_MESSAGE, &signature);
    }

    // Measure 1000 verify operations (verification is much faster)
    let start = Instant::now();
    let iterations = 1000;

    for _ in 0..iterations {
        sig.verify(RSA_PUBLIC_KEY, TEST_MESSAGE, &signature)
            .expect("Verify failed");
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() / iterations;

    println!("RSA-PSS-SHA256 Verify (2048-bit):");
    println!("  {} operations in {:?}", iterations, elapsed);
    println!("  Average: {} µs per operation", avg_micros);
    println!("  Throughput: {} ops/sec", 1_000_000 / avg_micros);

    // Sanity check: RSA verify should be 50-500µs on modern hardware
    assert!(
        avg_micros < 2_000,
        "RSA-PSS verify too slow: {} µs (expected < 2ms)",
        avg_micros
    );
}

#[test]
fn test_rsa_pss_variants_performance() {
    let provider = HpcryptProvider::new();
    let iterations = 100; // Bug is fixed - can handle high iteration counts

    for (name, algorithm) in &[
        ("SHA-256", SignatureAlgorithm::RsaPssRsaeSha256),
        ("SHA-384", SignatureAlgorithm::RsaPssRsaeSha384),
        ("SHA-512", SignatureAlgorithm::RsaPssRsaeSha512),
    ] {
        println!("\n🔍 Testing RSA-PSS-{}...", name);
        let sig = provider.signature(*algorithm).expect("Failed to create signature");

        // Measure sign
        let start = Instant::now();
        for i in 0..iterations {
            if i % 5 == 0 {
                println!("  Sign iteration {}/{}", i, iterations);
            }
            sig.sign(RSA_PRIVATE_KEY, TEST_MESSAGE).expect(&format!("Sign failed at iteration {}", i));
        }
        let sign_elapsed = start.elapsed();
        let sign_avg = sign_elapsed.as_micros() / iterations;

        // Measure verify
        let signature = sig.sign(RSA_PRIVATE_KEY, TEST_MESSAGE).expect("Sign failed");
        let start = Instant::now();
        for _ in 0..iterations {
            sig.verify(RSA_PUBLIC_KEY, TEST_MESSAGE, &signature)
                .expect("Verify failed");
        }
        let verify_elapsed = start.elapsed();
        let verify_avg = verify_elapsed.as_micros() / iterations;

        println!("RSA-PSS-{} Performance:", name);
        println!("  Sign:   {} µs ({} ops/sec)", sign_avg, 1_000_000 / sign_avg);
        println!("  Verify: {} µs ({} ops/sec)", verify_avg, 1_000_000 / verify_avg);
    }
}

#[test]
fn test_der_parsing_performance() {
    use hptls_crypto_hpcrypt::der::{parse_rsa_private_key_pkcs8, parse_rsa_public_key_spki};

    let iterations = 10_000;

    // Measure PKCS#8 private key parsing
    let start = Instant::now();
    for _ in 0..iterations {
        parse_rsa_private_key_pkcs8(RSA_PRIVATE_KEY).expect("Parse failed");
    }
    let elapsed = start.elapsed();
    let avg_nanos = elapsed.as_nanos() / iterations;

    println!("DER Parsing - PKCS#8 Private Key:");
    println!("  {} operations in {:?}", iterations, elapsed);
    println!("  Average: {} ns per operation", avg_nanos);

    // Should be very fast (< 10µs)
    assert!(
        avg_nanos < 50_000,
        "PKCS#8 parsing too slow: {} ns",
        avg_nanos
    );

    // Measure X.509 SPKI public key parsing
    let start = Instant::now();
    for _ in 0..iterations {
        parse_rsa_public_key_spki(RSA_PUBLIC_KEY).expect("Parse failed");
    }
    let elapsed = start.elapsed();
    let avg_nanos = elapsed.as_nanos() / iterations;

    println!("DER Parsing - X.509 SPKI Public Key:");
    println!("  {} operations in {:?}", iterations, elapsed);
    println!("  Average: {} ns per operation", avg_nanos);

    // Should be very fast (< 10µs)
    assert!(
        avg_nanos < 50_000,
        "SPKI parsing too slow: {} ns",
        avg_nanos
    );
}

#[test]
fn test_comparison_with_ecdsa() {
    // Compare RSA-PSS with ECDSA P-256 for reference
    let provider = HpcryptProvider::new();
    let iterations = 100;

    // ECDSA P-256
    let ecdsa = provider
        .signature(SignatureAlgorithm::EcdsaSecp256r1Sha256)
        .expect("Failed to create ECDSA");
    let (ecdsa_sign_key, ecdsa_verify_key) = ecdsa.generate_keypair().expect("Failed to generate");

    let start = Instant::now();
    for _ in 0..iterations {
        ecdsa
            .sign(ecdsa_sign_key.as_bytes(), TEST_MESSAGE)
            .expect("Sign failed");
    }
    let ecdsa_sign_time = start.elapsed().as_micros() / iterations;

    let ecdsa_sig = ecdsa
        .sign(ecdsa_sign_key.as_bytes(), TEST_MESSAGE)
        .expect("Sign failed");
    let start = Instant::now();
    for _ in 0..iterations {
        ecdsa
            .verify(ecdsa_verify_key.as_bytes(), TEST_MESSAGE, &ecdsa_sig)
            .expect("Verify failed");
    }
    let ecdsa_verify_time = start.elapsed().as_micros() / iterations;

    // RSA-PSS-SHA256
    let rsa = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create RSA-PSS");

    let start = Instant::now();
    for _ in 0..iterations {
        rsa.sign(RSA_PRIVATE_KEY, TEST_MESSAGE).expect("Sign failed");
    }
    let rsa_sign_time = start.elapsed().as_micros() / iterations;

    let rsa_sig = rsa.sign(RSA_PRIVATE_KEY, TEST_MESSAGE).expect("Sign failed");
    let start = Instant::now();
    for _ in 0..iterations {
        rsa.verify(RSA_PUBLIC_KEY, TEST_MESSAGE, &rsa_sig)
            .expect("Verify failed");
    }
    let rsa_verify_time = start.elapsed().as_micros() / iterations;

    println!("\nPerformance Comparison:");
    println!("ECDSA P-256:");
    println!("  Sign:   {} µs", ecdsa_sign_time);
    println!("  Verify: {} µs", ecdsa_verify_time);
    println!("RSA-PSS-SHA256 (2048-bit):");
    println!("  Sign:   {} µs", rsa_sign_time);
    println!("  Verify: {} µs", rsa_verify_time);
    println!("\nRSA vs ECDSA:");
    println!("  Sign ratio:   {:.2}x slower", rsa_sign_time as f64 / ecdsa_sign_time as f64);
    println!("  Verify ratio: {:.2}x slower", rsa_verify_time as f64 / ecdsa_verify_time as f64);
}
