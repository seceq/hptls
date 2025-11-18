//! Test to reproduce the RSA-PSS crash with deterministic iteration count

use hptls_crypto::{CryptoProvider, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;

const RSA_PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_private_pkcs8.der");
const TEST_MESSAGE: &[u8] = b"Test message for crash reproduction";

#[test]
fn test_sequential_signs_until_crash() {
    let provider = HpcryptProvider::new();
    let sig = provider
        .signature(SignatureAlgorithm::RsaPssRsaeSha256)
        .expect("Failed to create signature");

    println!("\n🔍 Attempting to reproduce crash with sequential signs...");

    for i in 1..=200 {
        match sig.sign(RSA_PRIVATE_KEY, TEST_MESSAGE) {
            Ok(_) => {
                if i % 10 == 0 {
                    println!("✓ Iteration {} succeeded", i);
                }
            }
            Err(e) => {
                println!("❌ CRASHED at iteration {}: {:?}", i, e);
                panic!("Bug reproduced at iteration {}", i);
            }
        }
    }

    println!("✅ All 200 iterations completed successfully!");
}
