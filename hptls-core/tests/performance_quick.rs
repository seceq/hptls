//! Quick Performance Test
//!
//! This is a simple performance test to measure TLS handshake latency
//! without the overhead of criterion benchmarking framework.

use hptls_core::cipher::CipherSuite;
use hptls_core::handshake::{ClientHandshake, ServerHandshake};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;
use std::time::Instant;

// RSA-PSS certificates
const SERVER_CERT_RSA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/server.der");
const INTERMEDIATE_CA_RSA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/intermediate-ca.der");
const SERVER_KEY_RSA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/server.key.der");

// ECDSA P-256 certificates
const SERVER_CERT_ECDSA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/ecdsa-chain/server.der");
const INTERMEDIATE_CA_ECDSA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/ecdsa-chain/intermediate-ca.der");
const SERVER_KEY_ECDSA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/ecdsa-chain/server.key.raw");

fn benchmark_auth_method(
    name: &str,
    cipher_suite: CipherSuite,
    cert_chain: Vec<Vec<u8>>,
    server_key: &[u8],
    iterations: usize,
) {
    println!("Testing {} ...", name);

    let mut times = Vec::new();

    for _ in 0..iterations {
        let start = Instant::now();

        let provider = HpcryptProvider::new();
        let mut client = ClientHandshake::new();
        let mut server = ServerHandshake::new(vec![cipher_suite]);

        // Full handshake
        let client_hello = client
            .client_hello(&provider, &vec![cipher_suite], Some("test.example.com"), None)
            .unwrap();

        server.process_client_hello(&provider, &client_hello).unwrap();
        let server_hello = server.generate_server_hello(&provider).unwrap();

        client.process_server_hello(&provider, &server_hello).unwrap();

        let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
        client.process_encrypted_extensions(&encrypted_extensions).unwrap();

        let certificate = server.generate_certificate(cert_chain.clone()).unwrap();
        client.process_certificate(&certificate).unwrap();

        let cert_verify = server.generate_certificate_verify(&provider, server_key).unwrap();
        client.process_certificate_verify(&cert_verify).unwrap();

        let server_finished = server.generate_server_finished(&provider).unwrap();
        let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();

        server.process_client_finished(&provider, &client_finished).unwrap();

        let duration = start.elapsed();
        times.push(duration.as_micros() as f64);
    }

    // Calculate statistics
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean: f64 = times.iter().sum::<f64>() / times.len() as f64;
    let median = times[times.len() / 2];
    let min = times[0];
    let max = times[times.len() - 1];
    let p95 = times[(times.len() as f64 * 0.95) as usize];

    println!("  Results ({} iterations):", iterations);
    println!("    Mean:   {:.2} ms", mean / 1000.0);
    println!("    Median: {:.2} ms", median / 1000.0);
    println!("    Min:    {:.2} ms", min / 1000.0);
    println!("    Max:    {:.2} ms", max / 1000.0);
    println!("    P95:    {:.2} ms", p95 / 1000.0);
    println!();
}

#[test]
#[ignore] // Run with: cargo test --test performance_quick -- --ignored --nocapture
fn test_handshake_performance_rsa_pss() {
    println!("\n=== TLS 1.3 Handshake Performance (RSA-PSS 2048) ===\n");

    let cipher_suites = vec![
        ("AES-128-GCM-SHA256", CipherSuite::Aes128GcmSha256),
        ("AES-256-GCM-SHA384", CipherSuite::Aes256GcmSha384),
        ("ChaCha20-Poly1305-SHA256", CipherSuite::ChaCha20Poly1305Sha256),
    ];

    let cert_chain = vec![
        SERVER_CERT_RSA.to_vec(),
        INTERMEDIATE_CA_RSA.to_vec(),
    ];

    for (name, cipher_suite) in cipher_suites {
        benchmark_auth_method(name, cipher_suite, cert_chain.clone(), SERVER_KEY_RSA, 100);
    }
}

#[test]
#[ignore] // Run with: cargo test --test performance_quick -- --ignored --nocapture
fn test_handshake_performance_ecdsa_p256() {
    println!("\n=== TLS 1.3 Handshake Performance (ECDSA P-256) ===\n");

    let cipher_suites = vec![
        ("AES-128-GCM-SHA256", CipherSuite::Aes128GcmSha256),
        ("AES-256-GCM-SHA384", CipherSuite::Aes256GcmSha384),
        ("ChaCha20-Poly1305-SHA256", CipherSuite::ChaCha20Poly1305Sha256),
    ];

    let cert_chain = vec![
        SERVER_CERT_ECDSA.to_vec(),
        INTERMEDIATE_CA_ECDSA.to_vec(),
    ];

    for (name, cipher_suite) in cipher_suites {
        benchmark_auth_method(name, cipher_suite, cert_chain.clone(), SERVER_KEY_ECDSA, 100);
    }
}

#[test]
#[ignore] // Run with: cargo test --test performance_quick -- --ignored --nocapture
fn test_handshake_performance_comparison() {
    println!("\n=== TLS 1.3 Handshake Performance Comparison ===\n");
    println!("Comparing RSA-PSS 2048 vs ECDSA P-256\n");

    let cipher_suite = CipherSuite::Aes256GcmSha384;
    let iterations = 100;

    let rsa_cert_chain = vec![
        SERVER_CERT_RSA.to_vec(),
        INTERMEDIATE_CA_RSA.to_vec(),
    ];

    let ecdsa_cert_chain = vec![
        SERVER_CERT_ECDSA.to_vec(),
        INTERMEDIATE_CA_ECDSA.to_vec(),
    ];

    println!("--- RSA-PSS 2048 ---");
    benchmark_auth_method("AES-256-GCM-SHA384", cipher_suite, rsa_cert_chain, SERVER_KEY_RSA, iterations);

    println!("--- ECDSA P-256 ---");
    benchmark_auth_method("AES-256-GCM-SHA384", cipher_suite, ecdsa_cert_chain, SERVER_KEY_ECDSA, iterations);
}
