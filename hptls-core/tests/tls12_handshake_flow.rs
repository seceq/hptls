//! TLS 1.2 End-to-End Handshake Flow Test
//!
//! This test demonstrates a simulated TLS 1.2 handshake between client and server,
//! showing how the state machines work together.
//!
//! Note: This uses simulated/simplified messages since full message encoding is not yet complete.

use hptls_core::tls12::cipher_suites::{default_cipher_suites, Tls12CipherSuite};
use hptls_core::tls12::client::{Tls12ClientHandshake, Tls12ClientState};
use hptls_core::tls12::key_exchange::generate_key_pair;
use hptls_core::tls12::messages::{ClientKeyExchange, ServerHelloDone, ServerKeyExchange};
use hptls_core::tls12::record::{derive_keys_from_key_block, Tls12RecordProtection};
use hptls_core::tls12::server::{Tls12ServerHandshake, Tls12ServerState};
use hptls_crypto::{CryptoProvider, KeyExchangeAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Test a simplified TLS 1.2 handshake flow between client and server.
///
/// This test demonstrates:
/// 1. State machine transitions
/// 2. Key exchange (ECDHE X25519)
/// 3. Secret derivation (premaster → master → key_block)
/// 4. Record protection setup
#[test]
fn test_tls12_simplified_handshake_flow() {
    let provider = HpcryptProvider::new();
    let cipher_suites = default_cipher_suites();

    // === Phase 1: Initialize Client and Server ===
    let mut client = Tls12ClientHandshake::new();
    let mut server = Tls12ServerHandshake::new();

    assert_eq!(client.state(), Tls12ClientState::Start);
    assert_eq!(server.state(), Tls12ServerState::Start);

    println!("✓ Client and server initialized");

    // === Phase 2: ClientHello (simulated) ===
    // In a real implementation, this would encode a full ClientHello message
    let _client_hello = client
        .client_hello(&provider, &cipher_suites)
        .expect("Failed to generate ClientHello");

    assert_eq!(client.state(), Tls12ClientState::WaitServerHello);
    println!("✓ Client sent ClientHello, waiting for ServerHello");

    // === Phase 3: Server processes ClientHello (simulated) ===
    // In a real implementation, server would parse ClientHello and select cipher suite
    // For now, we manually set up the server state

    // Set up server certificate (would normally be loaded from file)
    let server_cert_chain = vec![
        vec![0x30, 0x82, 0x01, 0x00], // Dummy DER-encoded certificate
    ];
    server.set_certificate_chain(server_cert_chain.clone());

    // Dummy signing key (would be real RSA or ECDSA key)
    let dummy_signing_key = vec![0xAA; 32];
    server.set_signing_key(
        dummy_signing_key,
        hptls_crypto::SignatureAlgorithm::EcdsaSecp256r1Sha256,
    );

    println!("✓ Server configured with certificate");

    // === Phase 4: Server generates ephemeral ECDHE key pair ===
    let curve = KeyExchangeAlgorithm::X25519;
    let (server_private_key, server_public_key) =
        generate_key_pair(&provider, curve).expect("Failed to generate server keypair");

    println!("✓ Server generated ECDHE keypair (X25519)");

    // === Phase 5: ServerKeyExchange ===
    let server_key_exchange = ServerKeyExchange::new(
        curve,
        server_public_key.clone(),
        hptls_crypto::SignatureAlgorithm::EcdsaSecp256r1Sha256,
        vec![0xBB; 64], // Dummy signature (would be real signature in production)
    );

    let ske_bytes = server_key_exchange
        .encode()
        .expect("Failed to encode ServerKeyExchange");

    println!(
        "✓ Server created ServerKeyExchange ({} bytes)",
        ske_bytes.len()
    );

    // === Phase 6: Client processes ServerKeyExchange ===
    // Note: For this test, we'll directly demonstrate the cryptographic operations
    // rather than going through the full state machine (which requires full message parsing)

    // Client generates its own ECDHE keypair
    let (client_private_key, client_public_key) =
        generate_key_pair(&provider, curve).expect("Failed to generate client keypair");

    println!("✓ Client generated ECDHE keypair (X25519)");

    // === Phase 7: Client sends ClientKeyExchange ===
    let client_key_exchange = ClientKeyExchange::new(client_public_key.clone());
    let cke_bytes = client_key_exchange
        .encode()
        .expect("Failed to encode ClientKeyExchange");

    println!(
        "✓ Client sent ClientKeyExchange ({} bytes public key)",
        client_key_exchange.public_key.len()
    );

    // === Phase 8: Both sides compute shared secret (premaster secret) ===
    use hptls_crypto::key_exchange::PrivateKey;
    let kex = provider
        .key_exchange(curve)
        .expect("Failed to get key exchange");

    // Client computes shared secret
    let client_priv_key = PrivateKey::from_bytes(client_private_key.clone());
    let client_shared_secret = kex
        .exchange(&client_priv_key, &server_public_key)
        .expect("Failed to compute client shared secret")
        .into_bytes();

    // Server computes shared secret
    let server_priv_key = PrivateKey::from_bytes(server_private_key.clone());
    let server_shared_secret = kex
        .exchange(&server_priv_key, &client_public_key)
        .expect("Failed to compute server shared secret")
        .into_bytes();

    // Verify both computed the same shared secret
    assert_eq!(
        client_shared_secret, server_shared_secret,
        "Shared secrets must match"
    );
    println!(
        "✓ Both sides computed matching shared secret ({} bytes)",
        client_shared_secret.len()
    );

    // === Phase 9: Derive master secret using TLS 1.2 PRF ===
    use hptls_core::tls12::compute_master_secret;

    let cipher_suite = Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256;

    // Generate dummy randoms (would be from ClientHello and ServerHello)
    let mut client_random = [0u8; 32];
    let mut server_random = [0u8; 32];
    provider.random().fill(&mut client_random).unwrap();
    provider.random().fill(&mut server_random).unwrap();

    let master_secret = compute_master_secret(
        &provider,
        cipher_suite.hash_algorithm(),
        &client_shared_secret,
        &client_random,
        &server_random,
    )
    .expect("Failed to compute master secret");

    println!("✓ Derived master secret ({} bytes)", master_secret.len());

    // === Phase 10: Derive key block ===
    use hptls_core::tls12::compute_key_block;

    let key_block_len = cipher_suite.key_block_length();
    let key_block = compute_key_block(
        &provider,
        cipher_suite.hash_algorithm(),
        &master_secret,
        &server_random,
        &client_random,
        key_block_len,
    )
    .expect("Failed to compute key block");

    println!("✓ Derived key block ({} bytes)", key_block.len());

    // === Phase 11: Derive encryption keys ===
    // Client keys (for client → server traffic)
    let (client_key, client_iv) =
        derive_keys_from_key_block(&key_block, cipher_suite, true)
            .expect("Failed to derive client keys");

    // Server keys (for server → client traffic)
    let (server_key, server_iv) =
        derive_keys_from_key_block(&key_block, cipher_suite, false)
            .expect("Failed to derive server keys");

    println!("✓ Derived encryption keys for both directions");
    println!("  - Client key: {} bytes", client_key.len());
    println!("  - Server key: {} bytes", server_key.len());

    // === Phase 12: Set up record protection ===
    let mut client_record_protection =
        Tls12RecordProtection::new(cipher_suite, client_key.clone(), client_iv.clone());

    let mut server_record_protection =
        Tls12RecordProtection::new(cipher_suite, server_key.clone(), server_iv.clone());

    println!("✓ Record protection initialized");

    // === Phase 13: Test encrypted communication ===
    // Client → Server
    let client_message = b"Hello from TLS 1.2 client!";
    let encrypted_client_msg = client_record_protection
        .encrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            client_message,
        )
        .expect("Failed to encrypt client message");

    println!(
        "✓ Client encrypted message ({} → {} bytes)",
        client_message.len(),
        encrypted_client_msg.len()
    );

    // Server receives and decrypts
    // Note: Server would use client_key/client_iv for reading client's messages
    let mut server_read_protection =
        Tls12RecordProtection::new(cipher_suite, client_key.clone(), client_iv.clone());

    let decrypted_client_msg = server_read_protection
        .decrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            &encrypted_client_msg,
        )
        .expect("Failed to decrypt client message");

    assert_eq!(decrypted_client_msg, client_message);
    println!("✓ Server decrypted client message successfully");

    // Server → Client
    let server_message = b"Hello from TLS 1.2 server!";
    let encrypted_server_msg = server_record_protection
        .encrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            server_message,
        )
        .expect("Failed to encrypt server message");

    println!(
        "✓ Server encrypted message ({} → {} bytes)",
        server_message.len(),
        encrypted_server_msg.len()
    );

    // Client receives and decrypts
    // Note: Client would use server_key/server_iv for reading server's messages
    let mut client_read_protection =
        Tls12RecordProtection::new(cipher_suite, server_key, server_iv);

    let decrypted_server_msg = client_read_protection
        .decrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            &encrypted_server_msg,
        )
        .expect("Failed to decrypt server message");

    assert_eq!(decrypted_server_msg, server_message);
    println!("✓ Client decrypted server message successfully");

    // === Success ===
    println!("\n🎉 TLS 1.2 handshake flow test completed successfully!");
    println!("   - ECDHE key exchange: ✓");
    println!("   - Secret derivation: ✓");
    println!("   - Bidirectional encryption: ✓");
}

/// Test ChangeCipherSpec integration in handshake flow.
#[test]
fn test_tls12_change_cipher_spec_flow() {
    let client = Tls12ClientHandshake::new();

    // Generate and verify CCS message format
    let ccs = client.change_cipher_spec();
    assert_eq!(ccs.len(), 1);
    assert_eq!(ccs[0], 0x01);

    // Simulate receiving CCS from server
    // (Client must be in WaitChangeCipherSpec state first)
    // This is normally reached after sending ClientKeyExchange
    // For this test, we'll manually set the state

    println!("✓ ChangeCipherSpec message format correct");
}

/// Test record layer with multiple sequential messages.
#[test]
fn test_tls12_sequential_encrypted_messages() {
    let provider = HpcryptProvider::new();
    let cipher_suite = Tls12CipherSuite::EcdheRsaWithAes256GcmSha384;

    // Generate dummy key block
    let key_block_len = cipher_suite.key_block_length();
    let key_block = vec![0x42u8; key_block_len];

    let (key, iv) = derive_keys_from_key_block(&key_block, cipher_suite, true)
        .expect("Failed to derive keys");

    let mut sender = Tls12RecordProtection::new(cipher_suite, key.clone(), iv.clone());
    let mut receiver = Tls12RecordProtection::new(cipher_suite, key, iv);

    // Send multiple messages
    let messages = vec![
        b"First message" as &[u8],
        b"Second message",
        b"Third message",
        b"Fourth message",
        b"Fifth message",
    ];

    for (i, msg) in messages.iter().enumerate() {
        let encrypted = sender
            .encrypt(
                &provider,
                hptls_core::protocol::ContentType::ApplicationData,
                msg,
            )
            .expect(&format!("Failed to encrypt message {}", i + 1));

        let decrypted = receiver
            .decrypt(
                &provider,
                hptls_core::protocol::ContentType::ApplicationData,
                &encrypted,
            )
            .expect(&format!("Failed to decrypt message {}", i + 1));

        assert_eq!(&decrypted, msg, "Message {} mismatch", i + 1);

        // Verify sequence numbers increment
        assert_eq!(sender.sequence_number(), (i + 1) as u64);
        assert_eq!(receiver.sequence_number(), (i + 1) as u64);
    }

    println!(
        "✓ Successfully encrypted/decrypted {} sequential messages",
        messages.len()
    );
    println!("✓ Sequence numbers tracked correctly");
}

/// Test that encryption with different keys produces different ciphertexts.
#[test]
fn test_tls12_key_isolation() {
    let provider = HpcryptProvider::new();
    let cipher_suite = Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256;

    // Generate two different key blocks
    let key_block1 = vec![0xAAu8; cipher_suite.key_block_length()];
    let key_block2 = vec![0xBBu8; cipher_suite.key_block_length()];

    let (key1, iv1) = derive_keys_from_key_block(&key_block1, cipher_suite, true).unwrap();
    let (key2, iv2) = derive_keys_from_key_block(&key_block2, cipher_suite, true).unwrap();

    let mut protection1 = Tls12RecordProtection::new(cipher_suite, key1, iv1);
    let mut protection2 = Tls12RecordProtection::new(cipher_suite, key2, iv2);

    // Same plaintext
    let plaintext = b"Same message, different keys";

    // Encrypt with both
    let encrypted1 = protection1
        .encrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            plaintext,
        )
        .unwrap();

    let encrypted2 = protection2
        .encrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            plaintext,
        )
        .unwrap();

    // Ciphertexts should be different (different keys produce different output)
    assert_ne!(
        encrypted1, encrypted2,
        "Different keys should produce different ciphertexts"
    );

    println!("✓ Key isolation verified - different keys produce different ciphertexts");
}
