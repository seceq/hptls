//! RSA-PSS Performance Benchmarks
//!
//! Comprehensive benchmarks for RSA-PSS signature operations to validate
//! performance characteristics and compare against expected metrics.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hptls_crypto::{CryptoProvider, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;

/// RSA 2048-bit test key (PKCS#8 DER format)
const RSA_PRIVATE_KEY: &[u8] = include_bytes!("../tests/data/rsa_private_pkcs8.der");
const RSA_PUBLIC_KEY: &[u8] = include_bytes!("../tests/data/rsa_public_spki.der");

/// Test messages of varying sizes
const MESSAGE_SMALL: &[u8] = b"Hello, World!"; // 13 bytes
const MESSAGE_MEDIUM: &[u8] = b"This is a medium-sized test message for RSA-PSS signature benchmarking. It represents typical TLS handshake message sizes."; // ~120 bytes
const MESSAGE_LARGE: &[u8] = &[0x42; 4096]; // 4KB - typical for hashing larger structures

fn bench_rsa_pss_sha256_sign(c: &mut Criterion) {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create signature algorithm");

    let mut group = c.benchmark_group("RSA-PSS-SHA256 Sign");

    // Benchmark with different message sizes
    for (name, message) in &[
        ("13B", MESSAGE_SMALL),
        ("120B", MESSAGE_MEDIUM),
        ("4KB", MESSAGE_LARGE),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(name), message, |b, msg| {
            b.iter(|| {
                sig.sign(black_box(RSA_PRIVATE_KEY), black_box(msg))
                    .expect("Sign failed")
            });
        });
    }

    group.finish();
}

fn bench_rsa_pss_sha256_verify(c: &mut Criterion) {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create signature algorithm");

    // Pre-compute signatures
    let signature_small = sig.sign(RSA_PRIVATE_KEY, MESSAGE_SMALL).expect("Sign failed");
    let signature_medium = sig.sign(RSA_PRIVATE_KEY, MESSAGE_MEDIUM).expect("Sign failed");
    let signature_large = sig.sign(RSA_PRIVATE_KEY, MESSAGE_LARGE).expect("Sign failed");

    let mut group = c.benchmark_group("RSA-PSS-SHA256 Verify");

    for (name, message, signature) in &[
        ("13B", MESSAGE_SMALL, &signature_small),
        ("120B", MESSAGE_MEDIUM, &signature_medium),
        ("4KB", MESSAGE_LARGE, &signature_large),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(name), message, |b, msg| {
            b.iter(|| {
                sig.verify(
                    black_box(RSA_PUBLIC_KEY),
                    black_box(msg),
                    black_box(signature),
                )
                .expect("Verify failed")
            });
        });
    }

    group.finish();
}

fn bench_rsa_pss_sha384_sign(c: &mut Criterion) {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha384)
        .expect("Failed to create signature algorithm");

    c.bench_function("RSA-PSS-SHA384 Sign (120B)", |b| {
        b.iter(|| {
            sig.sign(black_box(RSA_PRIVATE_KEY), black_box(MESSAGE_MEDIUM))
                .expect("Sign failed")
        });
    });
}

fn bench_rsa_pss_sha384_verify(c: &mut Criterion) {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha384)
        .expect("Failed to create signature algorithm");

    let signature = sig.sign(RSA_PRIVATE_KEY, MESSAGE_MEDIUM).expect("Sign failed");

    c.bench_function("RSA-PSS-SHA384 Verify (120B)", |b| {
        b.iter(|| {
            sig.verify(
                black_box(RSA_PUBLIC_KEY),
                black_box(MESSAGE_MEDIUM),
                black_box(&signature),
            )
            .expect("Verify failed")
        });
    });
}

fn bench_rsa_pss_sha512_sign(c: &mut Criterion) {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha512)
        .expect("Failed to create signature algorithm");

    c.bench_function("RSA-PSS-SHA512 Sign (120B)", |b| {
        b.iter(|| {
            sig.sign(black_box(RSA_PRIVATE_KEY), black_box(MESSAGE_MEDIUM))
                .expect("Sign failed")
        });
    });
}

fn bench_rsa_pss_sha512_verify(c: &mut Criterion) {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha512)
        .expect("Failed to create signature algorithm");

    let signature = sig.sign(RSA_PRIVATE_KEY, MESSAGE_MEDIUM).expect("Sign failed");

    c.bench_function("RSA-PSS-SHA512 Verify (120B)", |b| {
        b.iter(|| {
            sig.verify(
                black_box(RSA_PUBLIC_KEY),
                black_box(MESSAGE_MEDIUM),
                black_box(&signature),
            )
            .expect("Verify failed")
        });
    });
}

fn bench_der_parsing(c: &mut Criterion) {
    use hptls_crypto_hpcrypt::der::{parse_rsa_private_key_pkcs8, parse_rsa_public_key_spki};

    let mut group = c.benchmark_group("DER Parsing");

    group.bench_function("PKCS#8 Private Key", |b| {
        b.iter(|| {
            parse_rsa_private_key_pkcs8(black_box(RSA_PRIVATE_KEY))
                .expect("Parse failed")
        });
    });

    group.bench_function("X.509 SPKI Public Key", |b| {
        b.iter(|| {
            parse_rsa_public_key_spki(black_box(RSA_PUBLIC_KEY))
                .expect("Parse failed")
        });
    });

    group.finish();
}

fn bench_comparison_ecdsa_p256(c: &mut Criterion) {
    // Benchmark ECDSA P-256 for comparison
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::EcdsaSecp256r1Sha256)
        .expect("Failed to create signature algorithm");

    let (signing_key, verifying_key) = sig.generate_keypair().expect("Failed to generate keypair");

    let mut group = c.benchmark_group("Comparison: ECDSA P-256");

    group.bench_function("Sign (120B)", |b| {
        b.iter(|| {
            sig.sign(black_box(signing_key.as_bytes()), black_box(MESSAGE_MEDIUM))
                .expect("Sign failed")
        });
    });

    let signature = sig.sign(signing_key.as_bytes(), MESSAGE_MEDIUM).expect("Sign failed");

    group.bench_function("Verify (120B)", |b| {
        b.iter(|| {
            sig.verify(
                black_box(verifying_key.as_bytes()),
                black_box(MESSAGE_MEDIUM),
                black_box(&signature),
            )
            .expect("Verify failed")
        });
    });

    group.finish();
}

fn bench_comparison_ed25519(c: &mut Criterion) {
    // Benchmark Ed25519 for comparison
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::Ed25519)
        .expect("Failed to create signature algorithm");

    let (signing_key, verifying_key) = sig.generate_keypair().expect("Failed to generate keypair");

    let mut group = c.benchmark_group("Comparison: Ed25519");

    group.bench_function("Sign (120B)", |b| {
        b.iter(|| {
            sig.sign(black_box(signing_key.as_bytes()), black_box(MESSAGE_MEDIUM))
                .expect("Sign failed")
        });
    });

    let signature = sig.sign(signing_key.as_bytes(), MESSAGE_MEDIUM).expect("Sign failed");

    group.bench_function("Verify (120B)", |b| {
        b.iter(|| {
            sig.verify(
                black_box(verifying_key.as_bytes()),
                black_box(MESSAGE_MEDIUM),
                black_box(&signature),
            )
            .expect("Verify failed")
        });
    });

    group.finish();
}

criterion_group!(
    rsa_pss_benches,
    bench_rsa_pss_sha256_sign,
    bench_rsa_pss_sha256_verify,
    bench_rsa_pss_sha384_sign,
    bench_rsa_pss_sha384_verify,
    bench_rsa_pss_sha512_sign,
    bench_rsa_pss_sha512_verify,
    bench_der_parsing,
    bench_comparison_ecdsa_p256,
    bench_comparison_ed25519,
);

criterion_main!(rsa_pss_benches);
