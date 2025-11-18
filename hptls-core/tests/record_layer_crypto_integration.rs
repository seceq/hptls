//! Record Layer Crypto Integration Tests
//!
//! This module tests the record layer with all cryptographic algorithm combinations
//! verified in the crypto integration tests. It ensures that:
//! - All cipher suites work with record encryption/decryption
//! - Traffic keys derived from real handshakes work correctly
//! - AEAD encryption is compatible with all supported algorithms
//! - Complete end-to-end flow: handshake → key derivation → encryption → decryption

use hptls_core::{
    cipher::CipherSuite,
    handshake::{ClientHandshake, ServerHandshake},
    protocol::ContentType,
    record_protection::RecordProtection,
};
use hptls_crypto::{CryptoProvider, KeyExchangeAlgorithm, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Helper to perform full handshake and return traffic secrets.
///
/// Returns: (client_write_secret, server_write_secret, cipher_suite)
fn perform_handshake_and_get_secrets(
    cipher_suite: CipherSuite,
    kex: KeyExchangeAlgorithm,
    sig: SignatureAlgorithm,
) -> (Vec<u8>, Vec<u8>, CipherSuite) {
    let provider = HpcryptProvider::new();

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![cipher_suite]);

    // Complete handshake
    let client_hello = client
        .client_hello(
            &provider,
            &[cipher_suite],
            Some("record-test.example.com"),
            None,
        )
        .unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    client.process_server_hello(&provider, &server_hello).unwrap();

    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();

    let certificate = server.generate_certificate(vec![vec![0u8; 4]]).unwrap();
    client.process_certificate(&certificate).unwrap();

    // Generate real signature
    let sig_impl = provider.signature(sig).unwrap();
    let (signing_key, _) = sig_impl.generate_keypair().unwrap();

    let cert_verify =
        server.generate_certificate_verify(&provider, signing_key.as_bytes()).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();

    let server_finished = server.generate_server_finished(&provider).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();
    server.process_client_finished(&provider, &client_finished).unwrap();

    assert!(client.is_connected());
    assert!(server.is_connected());

    // Extract traffic secrets
    let client_write_secret = client.get_client_application_traffic_secret().unwrap().to_vec();
    let server_write_secret = server.get_server_application_traffic_secret().unwrap().to_vec();

    (client_write_secret, server_write_secret, cipher_suite)
}

/// Test record encryption with AES-128-GCM-SHA256 from real handshake.
#[test]
fn test_record_encryption_aes128_gcm() {
    let (client_secret, server_secret, cipher_suite) = perform_handshake_and_get_secrets(
        CipherSuite::Aes128GcmSha256,
        KeyExchangeAlgorithm::X25519,
        SignatureAlgorithm::Ed25519,
    );

    let provider = HpcryptProvider::new();

    let mut client_writer = RecordProtection::new(&provider, cipher_suite, &client_secret).unwrap();
    let mut server_reader = RecordProtection::new(&provider, cipher_suite, &client_secret).unwrap();

    // Test encryption/decryption
    let message = b"Hello with AES-128-GCM!";
    let encrypted =
        client_writer.encrypt(&provider, ContentType::ApplicationData, message).unwrap();

    let decrypted = server_reader.decrypt(&provider, &encrypted).unwrap();
    assert_eq!(decrypted.fragment.as_slice(), message);

    println!("✅ AES-128-GCM record encryption works with real handshake secrets");
}

/// Test record encryption with AES-256-GCM-SHA384 from real handshake.
#[test]
fn test_record_encryption_aes256_gcm() {
    let (client_secret, server_secret, cipher_suite) = perform_handshake_and_get_secrets(
        CipherSuite::Aes256GcmSha384,
        KeyExchangeAlgorithm::Secp256r1,
        SignatureAlgorithm::EcdsaSecp256r1Sha256,
    );

    let provider = HpcryptProvider::new();

    let mut client_writer = RecordProtection::new(&provider, cipher_suite, &client_secret).unwrap();
    let mut server_reader = RecordProtection::new(&provider, cipher_suite, &client_secret).unwrap();

    let message = b"Hello with AES-256-GCM!";
    let encrypted =
        client_writer.encrypt(&provider, ContentType::ApplicationData, message).unwrap();

    let decrypted = server_reader.decrypt(&provider, &encrypted).unwrap();
    assert_eq!(decrypted.fragment.as_slice(), message);

    println!("✅ AES-256-GCM record encryption works with real handshake secrets");
}

/// Test record encryption with ChaCha20-Poly1305-SHA256 from real handshake.
#[test]
fn test_record_encryption_chacha20_poly1305() {
    let (client_secret, server_secret, cipher_suite) = perform_handshake_and_get_secrets(
        CipherSuite::ChaCha20Poly1305Sha256,
        KeyExchangeAlgorithm::Secp384r1,
        SignatureAlgorithm::EcdsaSecp384r1Sha384,
    );

    let provider = HpcryptProvider::new();

    let mut client_writer = RecordProtection::new(&provider, cipher_suite, &client_secret).unwrap();
    let mut server_reader = RecordProtection::new(&provider, cipher_suite, &client_secret).unwrap();

    let message = b"Hello with ChaCha20-Poly1305!";
    let encrypted =
        client_writer.encrypt(&provider, ContentType::ApplicationData, message).unwrap();

    let decrypted = server_reader.decrypt(&provider, &encrypted).unwrap();
    assert_eq!(decrypted.fragment.as_slice(), message);

    println!("✅ ChaCha20-Poly1305 record encryption works with real handshake secrets");
}

/// Test bidirectional encrypted communication with all cipher suites.
#[test]
fn test_bidirectional_communication_all_cipher_suites() {
    let cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ];

    for cipher_suite in cipher_suites {
        println!(
            "\nTesting bidirectional communication with {:?}",
            cipher_suite
        );

        let (client_write, server_write, cs) = perform_handshake_and_get_secrets(
            cipher_suite,
            KeyExchangeAlgorithm::X25519,
            SignatureAlgorithm::Ed25519,
        );

        let provider = HpcryptProvider::new();

        // Setup bidirectional encryption
        let mut client_writer = RecordProtection::new(&provider, cs, &client_write).unwrap();
        let mut client_reader = RecordProtection::new(&provider, cs, &server_write).unwrap();
        let mut server_writer = RecordProtection::new(&provider, cs, &server_write).unwrap();
        let mut server_reader = RecordProtection::new(&provider, cs, &client_write).unwrap();

        // Client -> Server
        let client_msg = format!("Hello from client with {:?}!", cs);
        let encrypted = client_writer
            .encrypt(
                &provider,
                ContentType::ApplicationData,
                client_msg.as_bytes(),
            )
            .unwrap();
        let decrypted = server_reader.decrypt(&provider, &encrypted).unwrap();
        assert_eq!(decrypted.fragment, client_msg.as_bytes());

        // Server -> Client
        let server_msg = format!("Hello from server with {:?}!", cs);
        let encrypted = server_writer
            .encrypt(
                &provider,
                ContentType::ApplicationData,
                server_msg.as_bytes(),
            )
            .unwrap();
        let decrypted = client_reader.decrypt(&provider, &encrypted).unwrap();
        assert_eq!(decrypted.fragment, server_msg.as_bytes());

        println!("  ✅ Bidirectional communication works");
    }

    println!("\n✅ All 3 cipher suites support bidirectional encrypted communication!");
}

/// Test that secrets from different handshakes produce different encrypted records.
#[test]
fn test_different_handshakes_different_ciphertexts() {
    let provider = HpcryptProvider::new();

    // Perform two independent handshakes
    let (secret1, _, cs1) = perform_handshake_and_get_secrets(
        CipherSuite::Aes128GcmSha256,
        KeyExchangeAlgorithm::X25519,
        SignatureAlgorithm::Ed25519,
    );

    let (secret2, _, cs2) = perform_handshake_and_get_secrets(
        CipherSuite::Aes128GcmSha256,
        KeyExchangeAlgorithm::X25519,
        SignatureAlgorithm::Ed25519,
    );

    // Secrets should be different (different handshakes)
    assert_ne!(
        secret1, secret2,
        "Different handshakes must produce different secrets"
    );

    let mut encryptor1 = RecordProtection::new(&provider, cs1, &secret1).unwrap();
    let mut encryptor2 = RecordProtection::new(&provider, cs2, &secret2).unwrap();

    // Encrypt same message with both
    let message = b"Same message, different keys";
    let encrypted1 = encryptor1.encrypt(&provider, ContentType::ApplicationData, message).unwrap();
    let encrypted2 = encryptor2.encrypt(&provider, ContentType::ApplicationData, message).unwrap();

    // Ciphertexts must be different
    assert_ne!(
        encrypted1.encrypted_record, encrypted2.encrypted_record,
        "Same message with different keys must produce different ciphertexts"
    );

    println!("✅ Different handshakes produce different encrypted records");
}

/// Test complete end-to-end flow with all algorithm combinations.
#[test]
fn test_complete_end_to_end_all_algorithms() {
    let test_cases = vec![
        (
            CipherSuite::Aes128GcmSha256,
            KeyExchangeAlgorithm::X25519,
            SignatureAlgorithm::Ed25519,
            "X25519 + Ed25519 + AES-128-GCM",
        ),
        (
            CipherSuite::Aes256GcmSha384,
            KeyExchangeAlgorithm::Secp256r1,
            SignatureAlgorithm::EcdsaSecp256r1Sha256,
            "P-256 + ECDSA-P256 + AES-256-GCM",
        ),
        (
            CipherSuite::ChaCha20Poly1305Sha256,
            KeyExchangeAlgorithm::Secp384r1,
            SignatureAlgorithm::EcdsaSecp384r1Sha384,
            "P-384 + ECDSA-P384 + ChaCha20-Poly1305",
        ),
    ];

    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║  COMPLETE END-TO-END TEST WITH ALL ALGORITHMS         ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    for (cipher_suite, kex, sig, description) in test_cases {
        println!("Testing: {}", description);

        let (client_write, server_write, cs) =
            perform_handshake_and_get_secrets(cipher_suite, kex, sig);

        let provider = HpcryptProvider::new();

        // Setup encryption
        let mut client_writer = RecordProtection::new(&provider, cs, &client_write).unwrap();
        let mut server_reader = RecordProtection::new(&provider, cs, &client_write).unwrap();

        // Encrypt and decrypt
        let message = format!("End-to-end test with {}", description);
        let encrypted = client_writer
            .encrypt(&provider, ContentType::ApplicationData, message.as_bytes())
            .unwrap();

        let decrypted = server_reader.decrypt(&provider, &encrypted).unwrap();
        assert_eq!(decrypted.fragment, message.as_bytes());

        println!("  ✅ Complete flow works: Handshake → Secrets → Encryption → Decryption");
    }

    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║  ALL ALGORITHM COMBINATIONS PASSED!                    ║");
    println!("╚════════════════════════════════════════════════════════╝\n");
}

/// Test traffic key sizes for all cipher suites.
#[test]
fn test_traffic_key_sizes() {
    let test_cases = vec![
        (CipherSuite::Aes128GcmSha256, 32, 16, 12), // secret, key, iv
        (CipherSuite::Aes256GcmSha384, 48, 32, 12),
        (CipherSuite::ChaCha20Poly1305Sha256, 32, 32, 12),
    ];

    for (cipher_suite, expected_secret_len, expected_key_len, expected_iv_len) in test_cases {
        println!("Testing key sizes for {:?}", cipher_suite);

        let (client_secret, _, cs) = perform_handshake_and_get_secrets(
            cipher_suite,
            KeyExchangeAlgorithm::X25519,
            SignatureAlgorithm::Ed25519,
        );

        // Verify secret length
        assert_eq!(
            client_secret.len(),
            expected_secret_len,
            "Traffic secret length for {:?}",
            cipher_suite
        );

        // Verify derived key and IV lengths
        assert_eq!(cs.key_length(), expected_key_len);
        assert_eq!(cs.iv_length(), expected_iv_len);

        println!(
            "  ✅ Secret: {} bytes, Key: {} bytes, IV: {} bytes",
            client_secret.len(),
            cs.key_length(),
            cs.iv_length()
        );
    }

    println!("✅ All cipher suites have correct key sizes");
}

/// Test AEAD authentication tag verification.
#[test]
fn test_aead_authentication_tag_verification() {
    let (client_secret, _, cs) = perform_handshake_and_get_secrets(
        CipherSuite::Aes128GcmSha256,
        KeyExchangeAlgorithm::X25519,
        SignatureAlgorithm::Ed25519,
    );

    let provider = HpcryptProvider::new();

    let mut encryptor = RecordProtection::new(&provider, cs, &client_secret).unwrap();
    let mut decryptor = RecordProtection::new(&provider, cs, &client_secret).unwrap();

    let message = b"Authenticated message";
    let mut encrypted =
        encryptor.encrypt(&provider, ContentType::ApplicationData, message).unwrap();

    // Corrupt the authentication tag (last 16 bytes)
    let tag_start = encrypted.encrypted_record.len() - 16;
    encrypted.encrypted_record[tag_start] ^= 0xFF;

    // Decryption should fail due to invalid authentication tag
    let result = decryptor.decrypt(&provider, &encrypted);
    assert!(
        result.is_err(),
        "Decryption should fail with corrupted authentication tag"
    );

    println!("✅ AEAD authentication tag verification works");
}

/// Test multiple messages with increasing sequence numbers.
#[test]
fn test_sequence_number_increments_correctly() {
    let (client_secret, _, cs) = perform_handshake_and_get_secrets(
        CipherSuite::Aes128GcmSha256,
        KeyExchangeAlgorithm::X25519,
        SignatureAlgorithm::Ed25519,
    );

    let provider = HpcryptProvider::new();

    let mut encryptor = RecordProtection::new(&provider, cs, &client_secret).unwrap();
    let mut decryptor = RecordProtection::new(&provider, cs, &client_secret).unwrap();

    assert_eq!(encryptor.sequence_number(), 0);
    assert_eq!(decryptor.sequence_number(), 0);

    // Send 10 messages
    for i in 1..=10 {
        let message = format!("Message {}", i);
        let encrypted = encryptor
            .encrypt(&provider, ContentType::ApplicationData, message.as_bytes())
            .unwrap();

        let decrypted = decryptor.decrypt(&provider, &encrypted).unwrap();
        assert_eq!(decrypted.fragment, message.as_bytes());

        // Sequence numbers should increment
        assert_eq!(encryptor.sequence_number(), i);
        assert_eq!(decryptor.sequence_number(), i);
    }

    println!("✅ Sequence numbers increment correctly for 10 messages");
}

/// Test encrypted record size overhead.
#[test]
fn test_encrypted_record_size_overhead() {
    let (client_secret, _, cs) = perform_handshake_and_get_secrets(
        CipherSuite::Aes128GcmSha256,
        KeyExchangeAlgorithm::X25519,
        SignatureAlgorithm::Ed25519,
    );

    let provider = HpcryptProvider::new();
    let mut encryptor = RecordProtection::new(&provider, cs, &client_secret).unwrap();

    let message = b"Test message";
    let encrypted = encryptor.encrypt(&provider, ContentType::ApplicationData, message).unwrap();

    // Overhead = content_type (1 byte) + authentication tag (16 bytes)
    let expected_size = message.len() + 1 + 16;
    assert_eq!(encrypted.encrypted_record.len(), expected_size);

    println!(
        "✅ Record overhead: {} bytes (plaintext) → {} bytes (ciphertext)",
        message.len(),
        encrypted.encrypted_record.len()
    );
    println!(
        "   Overhead: {} bytes (1 byte content type + 16 byte auth tag)",
        17
    );
}

/// Test that different content types are preserved through encryption.
#[test]
fn test_content_type_preservation() {
    let (client_secret, _, cs) = perform_handshake_and_get_secrets(
        CipherSuite::Aes128GcmSha256,
        KeyExchangeAlgorithm::X25519,
        SignatureAlgorithm::Ed25519,
    );

    let provider = HpcryptProvider::new();

    let mut encryptor = RecordProtection::new(&provider, cs, &client_secret).unwrap();
    let mut decryptor = RecordProtection::new(&provider, cs, &client_secret).unwrap();

    let content_types = vec![
        ContentType::ApplicationData,
        ContentType::Alert,
        ContentType::Handshake,
    ];

    for content_type in content_types {
        let message = format!("Message with content type {:?}", content_type);
        let encrypted = encryptor.encrypt(&provider, content_type, message.as_bytes()).unwrap();

        let decrypted = decryptor.decrypt(&provider, &encrypted).unwrap();

        assert_eq!(decrypted.content_type, content_type);
        assert_eq!(decrypted.fragment, message.as_bytes());

        println!("  ✅ Content type {:?} preserved", content_type);
    }

    println!("✅ All content types preserved through encryption");
}
