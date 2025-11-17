//! TLS 1.3 Handshake Performance Benchmarks
//!
//! This benchmark suite measures:
//! - Full TLS 1.3 handshake latency
//! - Individual handshake message processing time
//! - Different cipher suites performance
//! - RSA-PSS vs ECDSA certificate verification

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hptls_core::cipher::CipherSuite;
use hptls_core::handshake::{ClientHandshake, ServerHandshake};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

// Test certificates and keys
const SERVER_CERT_RSA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/server.der");
const INTERMEDIATE_CA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/intermediate-ca.der");
const SERVER_KEY_RSA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/server.key.der");

/// Benchmark full TLS 1.3 handshake (ClientHello → Connected)
fn benchmark_full_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("tls13_full_handshake");

    let cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ];

    for cs in &cipher_suites {
        group.bench_with_input(
            BenchmarkId::new("full", format!("{:?}", cs)),
            cs,
            |b, &cipher_suite| {
                b.iter(|| {
                    let provider = HpcryptProvider::new();
                    let mut client = ClientHandshake::new();
                    let mut server = ServerHandshake::new(vec![cipher_suite]);

                    let cert_chain = vec![
                        SERVER_CERT_RSA.to_vec(),
                        INTERMEDIATE_CA.to_vec(),
                    ];

                    // Full handshake
                    let client_hello = client
                        .client_hello(&provider, &vec![cipher_suite], Some("test.example.com"), None)
                        .unwrap();

                    server.process_client_hello(&provider, &client_hello).unwrap();
                    let server_hello = server.generate_server_hello(&provider).unwrap();

                    client.process_server_hello(&provider, &server_hello).unwrap();

                    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
                    client.process_encrypted_extensions(&encrypted_extensions).unwrap();

                    let certificate = server.generate_certificate(cert_chain).unwrap();
                    client.process_certificate(&certificate).unwrap();

                    let cert_verify = server.generate_certificate_verify(&provider, SERVER_KEY_RSA).unwrap();
                    client.process_certificate_verify(&cert_verify).unwrap();

                    let server_finished = server.generate_server_finished(&provider).unwrap();
                    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();

                    server.process_client_finished(&provider, &client_finished).unwrap();

                    black_box((client, server))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark individual handshake message operations
fn benchmark_handshake_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("tls13_messages");
    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    // ClientHello generation
    group.bench_function("client_hello", |b| {
        b.iter(|| {
            let mut client = ClientHandshake::new();
            let msg = client
                .client_hello(&provider, &vec![cipher_suite], Some("test.example.com"), None)
                .unwrap();
            black_box(msg)
        });
    });

    // ServerHello generation (requires state from ClientHello)
    group.bench_function("server_hello", |b| {
        let mut client = ClientHandshake::new();
        let client_hello = client
            .client_hello(&provider, &vec![cipher_suite], Some("test.example.com"), None)
            .unwrap();

        b.iter(|| {
            let mut server = ServerHandshake::new(vec![cipher_suite]);
            server.process_client_hello(&provider, &client_hello).unwrap();
            let msg = server.generate_server_hello(&provider).unwrap();
            black_box(msg)
        });
    });

    // Certificate generation
    group.bench_function("certificate", |b| {
        let cert_chain = vec![
            SERVER_CERT_RSA.to_vec(),
            INTERMEDIATE_CA.to_vec(),
        ];

        b.iter(|| {
            let mut server = ServerHandshake::new(vec![cipher_suite]);
            let msg = server.generate_certificate(cert_chain.clone()).unwrap();
            black_box(msg)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_full_handshake,
    benchmark_handshake_messages
);
criterion_main!(benches);
