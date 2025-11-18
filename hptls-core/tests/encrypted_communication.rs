//! End-to-End Encrypted Communication Tests
//!
//! This test module verifies that a complete TLS 1.3 connection can be established
//! and used to exchange encrypted application data between client and server.

use hptls_core::cipher::CipherSuite;
use hptls_core::handshake::{ClientHandshake, ServerHandshake};
use hptls_core::protocol::ContentType;
use hptls_core::record_protection::RecordProtection;
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Test complete encrypted communication flow.
///
/// This test demonstrates:
/// 1. Full TLS 1.3 handshake
/// 2. Deriving application traffic secrets
/// 3. Encrypting application data with AEAD
/// 4. Decrypting application data with AEAD
/// 5. Bidirectional encrypted communication
#[test]
fn test_end_to_end_encrypted_communication() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    println!("=== Phase 1: TLS 1.3 Handshake ===");

    // Initialize client and server
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Step 1-13: Complete handshake
    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("example.com"), None)
        .unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();

    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();

    let certificate = server.generate_certificate(vec![vec![0u8; 4]]).unwrap();
    client.process_certificate(&certificate).unwrap();

    // Generate a keypair for signing (use Ed25519 as it's fast)
    let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
    let (signing_key, _verifying_key) = sig_impl.generate_keypair().unwrap();

    let cert_verify =
        server.generate_certificate_verify(&provider, signing_key.as_bytes()).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();

    let server_finished = server.generate_server_finished(&provider).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();

    server.process_client_finished(&provider, &client_finished).unwrap();

    assert!(client.is_connected());
    assert!(server.is_connected());

    println!("✅ Handshake complete!");

    println!("\n=== Phase 2: Setup Record Protection ===");

    // Get application traffic secrets
    let client_write_secret = client
        .get_client_application_traffic_secret()
        .expect("Client should have application secret");
    let server_write_secret = server
        .get_server_application_traffic_secret()
        .expect("Server should have application secret");

    let server_read_secret = server
        .get_client_application_traffic_secret()
        .expect("Server should have client secret");
    let client_read_secret = client
        .get_server_application_traffic_secret()
        .expect("Client should have server secret");

    println!("Client write secret: {} bytes", client_write_secret.len());
    println!("Server write secret: {} bytes", server_write_secret.len());

    // Create record protection for both directions
    let mut client_writer =
        RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, client_write_secret)
            .unwrap();

    let mut client_reader =
        RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, client_read_secret).unwrap();

    let mut server_writer =
        RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, server_write_secret)
            .unwrap();

    let mut server_reader =
        RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, server_read_secret).unwrap();

    println!("✅ Record protection initialized!");

    println!("\n=== Phase 3: Client -> Server Encrypted Data ===");

    // Client sends encrypted application data
    let client_message = b"Hello from client! This is encrypted with TLS 1.3.";
    println!(
        "Client plaintext: {:?}",
        std::str::from_utf8(client_message).unwrap()
    );

    let encrypted_record = client_writer
        .encrypt(&provider, ContentType::ApplicationData, client_message)
        .unwrap();

    println!(
        "Encrypted record size: {} bytes (includes auth tag)",
        encrypted_record.encrypted_record.len()
    );
    assert!(encrypted_record.encrypted_record.len() > client_message.len());

    // Verify it's actually encrypted (ciphertext should be different)
    assert_ne!(
        &encrypted_record.encrypted_record[..client_message.len()],
        client_message
    );

    // Server decrypts
    let decrypted_record = server_reader.decrypt(&provider, &encrypted_record).unwrap();

    assert_eq!(decrypted_record.content_type, ContentType::ApplicationData);
    assert_eq!(decrypted_record.fragment.as_slice(), client_message);

    println!(
        "Server decrypted: {:?}",
        std::str::from_utf8(&decrypted_record.fragment).unwrap()
    );
    println!("✅ Client -> Server communication successful!");

    println!("\n=== Phase 4: Server -> Client Encrypted Data ===");

    // Server sends encrypted response
    let server_message = b"Hello from server! Your message was received.";
    println!(
        "Server plaintext: {:?}",
        std::str::from_utf8(server_message).unwrap()
    );

    let encrypted_response = server_writer
        .encrypt(&provider, ContentType::ApplicationData, server_message)
        .unwrap();

    println!(
        "Encrypted response size: {} bytes",
        encrypted_response.encrypted_record.len()
    );

    // Client decrypts
    let decrypted_response = client_reader.decrypt(&provider, &encrypted_response).unwrap();

    assert_eq!(
        decrypted_response.content_type,
        ContentType::ApplicationData
    );
    assert_eq!(decrypted_response.fragment.as_slice(), server_message);

    println!(
        "Client decrypted: {:?}",
        std::str::from_utf8(&decrypted_response.fragment).unwrap()
    );
    println!("✅ Server -> Client communication successful!");

    println!("\n=== Phase 5: Multiple Messages ===");

    // Send multiple messages to verify sequence numbers work correctly
    for i in 1..=5 {
        let message = format!("Message {} from client", i);
        let encrypted = client_writer
            .encrypt(&provider, ContentType::ApplicationData, message.as_bytes())
            .unwrap();

        let decrypted = server_reader.decrypt(&provider, &encrypted).unwrap();
        assert_eq!(decrypted.fragment, message.as_bytes());

        println!("✅ Message {}: {}", i, message);
    }

    println!("✅ All 5 messages transmitted successfully!");

    // Verify sequence numbers incremented
    assert_eq!(client_writer.sequence_number(), 6); // 1 initial + 5 messages
    assert_eq!(server_reader.sequence_number(), 6); // Should match

    println!("\n🎉 End-to-end encrypted communication test PASSED!");
    println!("   - Handshake: ✅");
    println!("   - Key derivation: ✅");
    println!("   - AEAD encryption: ✅");
    println!("   - AEAD decryption: ✅");
    println!("   - Bidirectional communication: ✅");
    println!("   - Sequence number tracking: ✅");
}

/// Test that encrypted records cannot be decrypted with wrong keys.
#[test]
fn test_encrypted_data_requires_correct_keys() {
    let provider = HpcryptProvider::new();

    // Create two independent connections with different secrets
    let secret1 = vec![1u8; 32];
    let secret2 = vec![2u8; 32];

    let mut encryptor =
        RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &secret1).unwrap();

    let mut wrong_decryptor = RecordProtection::new(
        &provider,
        CipherSuite::Aes128GcmSha256,
        &secret2, // Different secret!
    )
    .unwrap();

    let message = b"Secret message";
    let encrypted = encryptor.encrypt(&provider, ContentType::ApplicationData, message).unwrap();

    // Attempt to decrypt with wrong key should fail
    let result = wrong_decryptor.decrypt(&provider, &encrypted);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

/// Test multiple cipher suites in end-to-end scenario.
#[test]
fn test_encrypted_communication_with_different_cipher_suites() {
    let provider = HpcryptProvider::new();

    // Test with AES-256-GCM-SHA384
    let cipher_suites = vec![CipherSuite::Aes256GcmSha384];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Quick handshake
    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();
    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    client.process_server_hello(&provider, &server_hello).unwrap();
    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();
    let certificate = server.generate_certificate(vec![vec![0u8; 4]]).unwrap();
    client.process_certificate(&certificate).unwrap();

    // Generate a keypair for signing
    let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
    let (signing_key, _verifying_key) = sig_impl.generate_keypair().unwrap();

    let cert_verify =
        server.generate_certificate_verify(&provider, signing_key.as_bytes()).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();
    let server_finished = server.generate_server_finished(&provider).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();
    server.process_client_finished(&provider, &client_finished).unwrap();

    // Setup encryption with AES-256-GCM
    let mut client_writer = RecordProtection::new(
        &provider,
        CipherSuite::Aes256GcmSha384,
        client.get_client_application_traffic_secret().unwrap(),
    )
    .unwrap();

    let mut server_reader = RecordProtection::new(
        &provider,
        CipherSuite::Aes256GcmSha384,
        server.get_client_application_traffic_secret().unwrap(),
    )
    .unwrap();

    // Test encryption/decryption
    let message = b"Testing AES-256-GCM-SHA384";
    let encrypted =
        client_writer.encrypt(&provider, ContentType::ApplicationData, message).unwrap();

    let decrypted = server_reader.decrypt(&provider, &encrypted).unwrap();
    assert_eq!(decrypted.fragment, message);

    println!("✅ AES-256-GCM-SHA384 encrypted communication works!");
}

/// Test large message fragmentation and encryption.
#[test]
fn test_large_message_encryption() {
    let provider = HpcryptProvider::new();
    let secret = vec![1u8; 32];

    let mut encryptor =
        RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &secret).unwrap();

    let mut decryptor =
        RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &secret).unwrap();

    // Create a large message (10 KB)
    let large_message = vec![42u8; 10240];

    let encrypted = encryptor
        .encrypt(&provider, ContentType::ApplicationData, &large_message)
        .unwrap();

    // Verify encrypted size includes auth tag
    assert_eq!(
        encrypted.encrypted_record.len(),
        large_message.len() + 1 + 16 // data + content_type + auth_tag
    );

    let decrypted = decryptor.decrypt(&provider, &encrypted).unwrap();
    assert_eq!(decrypted.fragment, large_message);

    println!("✅ Large message (10 KB) encrypted and decrypted successfully!");
}

/// Test that sequence numbers prevent replay attacks.
#[test]
fn test_sequence_number_prevents_replay() {
    let provider = HpcryptProvider::new();
    let secret = vec![1u8; 32];

    let mut encryptor =
        RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &secret).unwrap();

    let mut decryptor =
        RecordProtection::new(&provider, CipherSuite::Aes128GcmSha256, &secret).unwrap();

    // Encrypt two messages
    let msg1 = b"First message";
    let msg2 = b"Second message";

    let encrypted1 = encryptor.encrypt(&provider, ContentType::ApplicationData, msg1).unwrap();
    let encrypted2 = encryptor.encrypt(&provider, ContentType::ApplicationData, msg2).unwrap();

    // Decrypt in order should work
    let dec1 = decryptor.decrypt(&provider, &encrypted1).unwrap();
    assert_eq!(dec1.fragment, msg1);

    let dec2 = decryptor.decrypt(&provider, &encrypted2).unwrap();
    assert_eq!(dec2.fragment, msg2);

    // Try to replay first message - should fail because sequence number is wrong
    let replay_result = decryptor.decrypt(&provider, &encrypted1);
    assert!(
        replay_result.is_err(),
        "Replayed message should fail authentication"
    );

    println!("✅ Sequence numbers prevent replay attacks!");
}
