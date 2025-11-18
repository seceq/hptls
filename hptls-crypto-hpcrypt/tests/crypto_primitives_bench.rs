//! Cryptographic Primitives Performance Benchmark
//!
//! Measures individual crypto operation performance to identify bottlenecks

use hptls_crypto::{CryptoProvider, HashAlgorithm, AeadAlgorithm, KdfAlgorithm, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;
use std::time::Instant;

const RSA_PRIVATE_KEY: &[u8] = include_bytes!("../tests/data/rsa_private_pkcs8.der");
const RSA_PUBLIC_KEY: &[u8] = include_bytes!("../tests/data/rsa_public_spki.der");

#[test]
#[ignore] // Run with: cargo test --package hptls-crypto-hpcrypt --test crypto_primitives_bench -- --ignored --nocapture
fn test_crypto_primitives_performance() {
    println!("\n=== Cryptographic Primitives Performance ===\n");

    let provider = HpcryptProvider::new();

    // Hash functions
    benchmark_hash(&provider);

    // HMAC
    benchmark_hmac(&provider);

    // HKDF
    benchmark_hkdf(&provider);

    // AEAD (AES-GCM, ChaCha20-Poly1305)
    benchmark_aead(&provider);

    // Signatures (RSA-PSS)
    benchmark_signatures(&provider);
}

fn benchmark_hash(provider: &HpcryptProvider) {
    println!("--- Hash Functions ---");

    let data_sizes = vec![
        ("16 bytes", vec![0u8; 16]),
        ("256 bytes", vec![0u8; 256]),
        ("1 KB", vec![0u8; 1024]),
        ("4 KB", vec![0u8; 4096]),
    ];

    for algo in &[HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512] {
        println!("\n{:?}:", algo);

        for (size_name, data) in &data_sizes {
            let iterations = if data.len() <= 256 { 10000 } else { 1000 };

            let start = Instant::now();
            for _ in 0..iterations {
                let mut hash = provider.hash(*algo).unwrap();
                hash.update(data);
                let _ = hash.finalize();
            }
            let elapsed = start.elapsed();

            let avg_micros = elapsed.as_micros() as f64 / iterations as f64;
            let throughput_mbps = (data.len() as f64 * iterations as f64) / (1024.0 * 1024.0) / elapsed.as_secs_f64();

            println!("  {}: {:.2} µs/op, {:.1} MB/s", size_name, avg_micros, throughput_mbps);
        }
    }
    println!();
}

fn benchmark_hmac(provider: &HpcryptProvider) {
    println!("--- HMAC ---");

    let key = b"test_key_32_bytes_long_hmac_key!";
    let data = vec![0u8; 1024];

    for algo in &[HashAlgorithm::Sha256, HashAlgorithm::Sha384] {
        let iterations = 10000;

        let start = Instant::now();
        for _ in 0..iterations {
            let mut hmac = provider.hmac(*algo, key).unwrap();
            hmac.update(&data);
            let _ = hmac.finalize();
        }
        let elapsed = start.elapsed();

        let avg_micros = elapsed.as_micros() as f64 / iterations as f64;
        println!("  {:?} (1KB): {:.2} µs/op", algo, avg_micros);
    }
    println!();
}

fn benchmark_hkdf(provider: &HpcryptProvider) {
    println!("--- HKDF ---");

    let ikm = &[0x42; 32];
    let salt = &[0x00; 13];
    let info = &[0xf0; 10];

    for algo in &[KdfAlgorithm::HkdfSha256, KdfAlgorithm::HkdfSha384] {
        for okm_len in &[32, 48, 64] {
            let iterations = 10000;

            let start = Instant::now();
            for _ in 0..iterations {
                let kdf = provider.kdf(*algo).unwrap();
                let _ = kdf.derive(salt, ikm, info, *okm_len).unwrap();
            }
            let elapsed = start.elapsed();

            let avg_micros = elapsed.as_micros() as f64 / iterations as f64;
            println!("  {:?} ({} bytes): {:.2} µs/op", algo, okm_len, avg_micros);
        }
    }
    println!();
}

fn benchmark_aead(provider: &HpcryptProvider) {
    println!("--- AEAD Encryption/Decryption ---");

    let data_sizes = vec![
        ("64 bytes", vec![0u8; 64]),
        ("1 KB", vec![0u8; 1024]),
        ("4 KB", vec![0u8; 4096]),
        ("16 KB", vec![0u8; 16384]),
    ];

    for algo in &[AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm, AeadAlgorithm::ChaCha20Poly1305] {
        println!("\n{:?}:", algo);

        let key = match algo {
            AeadAlgorithm::Aes128Gcm => &[0x42; 16][..],
            _ => &[0x42; 32][..],
        };
        let nonce = &[0x00; 12];
        let aad = b"additional_authenticated_data";

        for (size_name, plaintext) in &data_sizes {
            let iterations = if plaintext.len() <= 1024 { 10000 } else { 1000 };

            let aead = provider.aead(*algo).unwrap();

            // Encrypt
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = aead.seal(key, nonce, aad, plaintext).unwrap();
            }
            let encrypt_elapsed = start.elapsed();
            let encrypt_avg = encrypt_elapsed.as_micros() as f64 / iterations as f64;
            let encrypt_throughput = (plaintext.len() as f64 * iterations as f64) / (1024.0 * 1024.0) / encrypt_elapsed.as_secs_f64();

            // Decrypt (prepare ciphertext first)
            let ciphertext = aead.seal(key, nonce, aad, plaintext).unwrap();

            let start = Instant::now();
            for _ in 0..iterations {
                let _ = aead.open(key, nonce, aad, &ciphertext).unwrap();
            }
            let decrypt_elapsed = start.elapsed();
            let decrypt_avg = decrypt_elapsed.as_micros() as f64 / iterations as f64;
            let decrypt_throughput = (plaintext.len() as f64 * iterations as f64) / (1024.0 * 1024.0) / decrypt_elapsed.as_secs_f64();

            println!("  {} - Encrypt: {:.2} µs/op ({:.1} MB/s), Decrypt: {:.2} µs/op ({:.1} MB/s)",
                     size_name, encrypt_avg, encrypt_throughput, decrypt_avg, decrypt_throughput);
        }
    }
    println!();
}

fn benchmark_signatures(provider: &HpcryptProvider) {
    println!("--- Digital Signatures (RSA-PSS) ---");

    let message = b"This is a test message for signature benchmarking";

    for algo in &[
        SignatureAlgorithm::RsaPssRsaeSha256,
        SignatureAlgorithm::RsaPssRsaeSha384,
        SignatureAlgorithm::RsaPssRsaeSha512,
    ] {
        let sig_impl = provider.signature(*algo).unwrap();

        // Sign benchmark
        let iterations = 100; // RSA is slow
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = sig_impl.sign(RSA_PRIVATE_KEY, message).unwrap();
        }
        let sign_elapsed = start.elapsed();
        let sign_avg = sign_elapsed.as_micros() as f64 / iterations as f64;

        // Verify benchmark
        let signature = sig_impl.sign(RSA_PRIVATE_KEY, message).unwrap();
        let iterations_verify = 1000;

        let start = Instant::now();
        for _ in 0..iterations_verify {
            sig_impl.verify(RSA_PUBLIC_KEY, message, &signature).unwrap();
        }
        let verify_elapsed = start.elapsed();
        let verify_avg = verify_elapsed.as_micros() as f64 / iterations_verify as f64;

        println!("  {:?}:", algo);
        println!("    Sign:   {:.2} ms/op", sign_avg / 1000.0);
        println!("    Verify: {:.2} µs/op", verify_avg);
    }
    println!();
}
