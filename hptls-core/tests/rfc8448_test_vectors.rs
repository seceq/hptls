//! RFC 8448 Test Vectors for TLS 1.3
//!
//! This module tests HPTLS against the official RFC 8448 test vectors
//! to verify correct implementation of the TLS 1.3 key schedule and
//! cryptographic operations.

use hptls_core::{cipher::CipherSuite, key_schedule::KeySchedule, transcript::hkdf_expand_label};
use hptls_crypto::{CryptoProvider, HashAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Helper function to decode hex strings (spaces and newlines allowed)
fn hex_decode(hex: &str) -> Vec<u8> {
    let clean = hex.replace(" ", "").replace("\n", "");
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

/// Helper function to encode bytes as hex
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

/// Test RFC 8448 Section 3: HKDF Operations for Early and Handshake Secrets
///
/// This test verifies HKDF operations by directly testing the HKDF-Extract
/// and HKDF-Expand operations that underlie the key schedule.
///
/// Note: We test these directly because early_secret and handshake_secret
/// are not exposed by the KeySchedule API.
#[test]
fn test_rfc8448_hkdf_operations() {
    let provider = HpcryptProvider::new();

    // RFC 8448 Section 3: Test HKDF-Extract for early secret
    // Early secret = HKDF-Extract(salt=0^HashLen, IKM=0^HashLen)
    let hash_len = 32; // SHA-256
    let zero_salt = vec![0u8; hash_len];
    let zero_ikm = vec![0u8; hash_len];

    let kdf = provider.kdf(HashAlgorithm::Sha256.to_kdf_algorithm()).unwrap();
    let actual_early_secret = kdf.extract(&zero_salt, &zero_ikm);

    let expected_early_secret_hex =
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
    let expected_early_secret = hex_decode(expected_early_secret_hex);

    assert_eq!(
        actual_early_secret,
        expected_early_secret,
        "\nEarly secret (HKDF-Extract) mismatch!\n\
         Expected: {}\n\
         Got:      {}\n",
        expected_early_secret_hex,
        hex_encode(&actual_early_secret)
    );
    println!("✅ Early secret (HKDF-Extract) matches RFC 8448");

    // Test HKDF-Extract for handshake secret
    // Handshake secret = HKDF-Extract(early_secret, shared_secret)
    let shared_secret_hex = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
    let shared_secret = hex_decode(shared_secret_hex);

    // First derive the "derived" secret from early secret
    // The context is the hash of an empty string for "derived" label
    let empty_hash = {
        let hasher = provider.hash(HashAlgorithm::Sha256).unwrap();
        hasher.finalize()
    };

    let derived = hkdf_expand_label(
        &provider,
        HashAlgorithm::Sha256,
        &actual_early_secret,
        b"derived",
        &empty_hash, // Hash of empty string
        hash_len,
    )
    .expect("Failed to derive 'derived' secret");

    // Then extract handshake secret
    let actual_handshake_secret = kdf.extract(&derived, &shared_secret);

    let expected_handshake_secret_hex =
        "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    let expected_handshake_secret = hex_decode(expected_handshake_secret_hex);

    assert_eq!(
        actual_handshake_secret,
        expected_handshake_secret,
        "\nHandshake secret (HKDF-Extract) mismatch!\n\
         Expected: {}\n\
         Got:      {}\n",
        expected_handshake_secret_hex,
        hex_encode(&actual_handshake_secret)
    );
    println!("✅ Handshake secret (HKDF-Extract) matches RFC 8448");
}

/// Test RFC 8448 Section 3: Handshake Traffic Secret Derivation
///
/// This test verifies that we correctly derive the client and server handshake
/// traffic secrets from the handshake secret and transcript hash.
#[test]
fn test_rfc8448_handshake_traffic_secrets() {
    let provider = HpcryptProvider::new();

    // RFC 8448 Section 3 values
    let shared_secret_hex = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
    let shared_secret = hex_decode(shared_secret_hex);

    // Transcript hash after ClientHello...ServerHello
    // This is the SHA-256 hash of ClientHello || ServerHello
    let transcript_hash_hex = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
    let transcript_hash = hex_decode(transcript_hash_hex);

    // Expected handshake traffic secrets
    let expected_client_hs_traffic_hex =
        "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    let expected_client_hs_traffic = hex_decode(expected_client_hs_traffic_hex);

    let expected_server_hs_traffic_hex =
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    let expected_server_hs_traffic = hex_decode(expected_server_hs_traffic_hex);

    // Create key schedule
    let cipher_suite = CipherSuite::Aes128GcmSha256;
    let mut key_schedule = KeySchedule::new(cipher_suite);

    // Initialize and derive handshake secret
    key_schedule
        .init_early_secret(&provider, &[])
        .expect("Failed to init early secret");
    key_schedule
        .derive_handshake_secret(&provider, &shared_secret)
        .expect("Failed to derive handshake secret");

    // DEBUG: Print what the handshake secret is
    // We can't access it directly, but we can derive a known value to check
    println!("\n=== DEBUG: KeySchedule State ===");

    // Derive client handshake traffic secret
    let actual_client_hs_traffic_result = key_schedule
        .derive_client_handshake_traffic_secret(&provider, &transcript_hash)
        .expect("Failed to derive client handshake traffic secret");

    println!(
        "Client HS traffic (from KeySchedule): {}",
        hex_encode(&actual_client_hs_traffic_result)
    );
    println!(
        "Client HS traffic (expected):          {}",
        expected_client_hs_traffic_hex
    );

    let actual_client_hs_traffic = key_schedule
        .get_client_handshake_traffic_secret()
        .expect("Client handshake traffic secret not available");

    assert_eq!(
        actual_client_hs_traffic,
        &expected_client_hs_traffic[..],
        "\nClient handshake traffic secret mismatch!\n\
         Expected: {}\n\
         Got:      {}\n",
        expected_client_hs_traffic_hex,
        hex_encode(actual_client_hs_traffic)
    );
    println!("✅ Client handshake traffic secret matches RFC 8448");

    // Derive server handshake traffic secret
    key_schedule
        .derive_server_handshake_traffic_secret(&provider, &transcript_hash)
        .expect("Failed to derive server handshake traffic secret");

    let actual_server_hs_traffic = key_schedule
        .get_server_handshake_traffic_secret()
        .expect("Server handshake traffic secret not available");

    assert_eq!(
        actual_server_hs_traffic,
        &expected_server_hs_traffic[..],
        "\nServer handshake traffic secret mismatch!\n\
         Expected: {}\n\
         Got:      {}\n",
        expected_server_hs_traffic_hex,
        hex_encode(actual_server_hs_traffic)
    );
    println!("✅ Server handshake traffic secret matches RFC 8448");
}

/// Test RFC 8448 Section 3: HKDF-Expand-Label Direct Test
///
/// This test verifies our HKDF-Expand-Label implementation using values
/// extracted from RFC 8448's key derivation process.
#[test]
fn test_rfc8448_hkdf_expand_label() {
    let provider = HpcryptProvider::new();

    // Test deriving the client handshake traffic secret from handshake secret
    // handshake_secret as the PRK
    let handshake_secret_hex = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    let handshake_secret = hex_decode(handshake_secret_hex);

    // Transcript hash as context
    let transcript_hash_hex = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
    let transcript_hash = hex_decode(transcript_hash_hex);

    // Expected output: client_handshake_traffic_secret
    let expected_output_hex = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    let expected_output = hex_decode(expected_output_hex);

    // Call HKDF-Expand-Label with label "c hs traffic"
    let result = hkdf_expand_label(
        &provider,
        HashAlgorithm::Sha256,
        &handshake_secret,
        b"c hs traffic",
        &transcript_hash,
        32, // Output length (SHA-256 hash length)
    )
    .expect("HKDF-Expand-Label failed");

    assert_eq!(
        result,
        expected_output,
        "\nHKDF-Expand-Label output mismatch!\n\
         Expected: {}\n\
         Got:      {}\n\
         \n\
         This indicates a bug in our HKDF-Expand-Label implementation.",
        expected_output_hex,
        hex_encode(&result)
    );
    println!("✅ HKDF-Expand-Label matches RFC 8448 (client handshake traffic)");

    // Test deriving the server handshake traffic secret
    let expected_server_hs_traffic_hex =
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    let expected_server_hs_traffic = hex_decode(expected_server_hs_traffic_hex);

    let result = hkdf_expand_label(
        &provider,
        HashAlgorithm::Sha256,
        &handshake_secret,
        b"s hs traffic",
        &transcript_hash,
        32,
    )
    .expect("HKDF-Expand-Label failed");

    assert_eq!(
        result,
        expected_server_hs_traffic,
        "\nHKDF-Expand-Label output mismatch!\n\
         Expected: {}\n\
         Got:      {}\n",
        expected_server_hs_traffic_hex,
        hex_encode(&result)
    );
    println!("✅ HKDF-Expand-Label matches RFC 8448 (server handshake traffic)");
}

/// Test RFC 8448 Section 3: Handshake Keys and IVs Derivation
///
/// This test verifies that we correctly derive the encryption keys and IVs
/// from the handshake traffic secrets.
#[test]
fn test_rfc8448_handshake_keys_ivs() {
    let provider = HpcryptProvider::new();

    // Server handshake traffic secret
    let server_hs_traffic_hex = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    let server_hs_traffic = hex_decode(server_hs_traffic_hex);

    // Expected server handshake key (16 bytes for AES-128)
    let expected_server_key_hex = "3fce516009c21727d0f2e4e86ee403bc";
    let expected_server_key = hex_decode(expected_server_key_hex);

    // Expected server handshake IV (12 bytes)
    let expected_server_iv_hex = "5d313eb2671276ee13000b30";
    let expected_server_iv = hex_decode(expected_server_iv_hex);

    // Derive key using HKDF-Expand-Label with label "key"
    let server_key = hkdf_expand_label(
        &provider,
        HashAlgorithm::Sha256,
        &server_hs_traffic,
        b"key",
        &[], // Empty context for key derivation
        16,  // 16 bytes for AES-128
    )
    .expect("Failed to derive server handshake key");

    assert_eq!(
        server_key,
        expected_server_key,
        "\nServer handshake key mismatch!\n\
         Expected: {}\n\
         Got:      {}\n",
        expected_server_key_hex,
        hex_encode(&server_key)
    );
    println!("✅ Server handshake key matches RFC 8448");

    // Derive IV using HKDF-Expand-Label with label "iv"
    let server_iv = hkdf_expand_label(
        &provider,
        HashAlgorithm::Sha256,
        &server_hs_traffic,
        b"iv",
        &[], // Empty context for IV derivation
        12,  // 12 bytes for GCM IV
    )
    .expect("Failed to derive server handshake IV");

    assert_eq!(
        server_iv,
        expected_server_iv,
        "\nServer handshake IV mismatch!\n\
         Expected: {}\n\
         Got:      {}\n",
        expected_server_iv_hex,
        hex_encode(&server_iv)
    );
    println!("✅ Server handshake IV matches RFC 8448");

    // Also test client handshake keys/IVs
    let client_hs_traffic_hex = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    let client_hs_traffic = hex_decode(client_hs_traffic_hex);

    let expected_client_key_hex = "dbfaa693d1762c5b666af5d950258d01";
    let expected_client_key = hex_decode(expected_client_key_hex);

    let expected_client_iv_hex = "5bd3c71b836e0b76bb73265f";
    let expected_client_iv = hex_decode(expected_client_iv_hex);

    let client_key = hkdf_expand_label(
        &provider,
        HashAlgorithm::Sha256,
        &client_hs_traffic,
        b"key",
        &[],
        16,
    )
    .expect("Failed to derive client handshake key");

    assert_eq!(
        client_key,
        expected_client_key,
        "\nClient handshake key mismatch!\n\
         Expected: {}\n\
         Got:      {}\n",
        expected_client_key_hex,
        hex_encode(&client_key)
    );
    println!("✅ Client handshake key matches RFC 8448");

    let client_iv = hkdf_expand_label(
        &provider,
        HashAlgorithm::Sha256,
        &client_hs_traffic,
        b"iv",
        &[],
        12,
    )
    .expect("Failed to derive client handshake IV");

    assert_eq!(
        client_iv,
        expected_client_iv,
        "\nClient handshake IV mismatch!\n\
         Expected: {}\n\
         Got:      {}\n",
        expected_client_iv_hex,
        hex_encode(&client_iv)
    );
    println!("✅ Client handshake IV matches RFC 8448");
}
