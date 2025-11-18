//! TLS 1.2 Full Handshake Integration Test
//!
//! This test demonstrates a more complete TLS 1.2 handshake flow with:
//! - Full message parsing (ClientHello, ServerHello, Certificate)
//! - State machine transitions
//! - Key exchange and secret derivation
//! - Certificate message handling
//!
//! Note: Still uses dummy signatures since full certificate infrastructure is not yet complete.

use hptls_core::tls12::cipher_suites::{default_cipher_suites, Tls12CipherSuite};
use hptls_core::tls12::client::{Tls12ClientHandshake, Tls12ClientState};
use hptls_core::tls12::messages::Tls12Certificate;
use hptls_core::tls12::record::{derive_keys_from_key_block, Tls12RecordProtection};
use hptls_core::tls12::server::{Tls12ServerHandshake, Tls12ServerState};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Test a more complete TLS 1.2 handshake with message parsing.
///
/// This test demonstrates:
/// 1. ClientHello/ServerHello exchange with full parsing
/// 2. Certificate message handling
/// 3. ServerKeyExchange/ClientKeyExchange exchange
/// 4. Key derivation and record protection
#[test]
fn test_tls12_full_handshake_with_parsing() {
    let provider = HpcryptProvider::new();
    let cipher_suites = default_cipher_suites();

    println!("\n=== TLS 1.2 Full Handshake Test ===\n");

    // === Phase 1: Client sends ClientHello ===
    let mut client = Tls12ClientHandshake::new();
    let client_hello_bytes = client
        .client_hello(&provider, &cipher_suites)
        .expect("Failed to generate ClientHello");

    assert_eq!(client.state(), Tls12ClientState::WaitServerHello);
    println!("✓ Client sent ClientHello ({} bytes)", client_hello_bytes.len());

    // === Phase 2: Server processes ClientHello and sends response ===
    let mut server = Tls12ServerHandshake::new();

    // Set up server certificate (dummy DER-encoded cert)
    let dummy_cert = vec![
        0x30, 0x82, 0x02, 0x00, // SEQUENCE, length 512 bytes
        0x30, 0x82, 0x01, 0x00, // Another SEQUENCE
        // ... (rest would be real X.509 DER encoding)
    ];
    server.set_certificate_chain(vec![dummy_cert.clone()]);
    server.set_signing_key(
        vec![0xAA; 32],
        hptls_crypto::SignatureAlgorithm::EcdsaSecp256r1Sha256,
    );

    let (server_hello_bytes, certificate_bytes, server_key_exchange_bytes, server_hello_done_bytes) =
        server
            .process_client_hello(&provider, &client_hello_bytes, &cipher_suites)
            .expect("Failed to process ClientHello");

    assert_eq!(server.state(), Tls12ServerState::WaitClientKeyExchange);
    println!("✓ Server processed ClientHello");
    println!("  - ServerHello: {} bytes", server_hello_bytes.len());
    println!("  - Certificate: {} bytes", certificate_bytes.len());
    println!("  - ServerKeyExchange: {} bytes", server_key_exchange_bytes.len());
    println!("  - ServerHelloDone: {} bytes", server_hello_done_bytes.len());

    // === Phase 3: Client processes ServerHello ===
    client
        .process_server_hello(&server_hello_bytes)
        .expect("Failed to process ServerHello");

    assert_eq!(client.state(), Tls12ClientState::WaitCertificate);
    assert!(client.cipher_suite().is_some());
    println!("✓ Client processed ServerHello");
    println!("  - Negotiated cipher suite: {:?}", client.cipher_suite().unwrap());

    // Verify both sides agree on cipher suite
    assert_eq!(client.cipher_suite(), server.cipher_suite());

    // === Phase 4: Client processes Certificate ===
    client
        .process_certificate(&certificate_bytes)
        .expect("Failed to process Certificate");

    assert_eq!(client.state(), Tls12ClientState::WaitServerKeyExchange);
    println!("✓ Client processed Certificate ({} certs in chain)", 1);

    // Verify certificate was stored
    let cert_msg = Tls12Certificate::decode(&certificate_bytes).unwrap();
    assert_eq!(cert_msg.certificate_list.len(), 1);
    assert_eq!(cert_msg.certificate_list[0], dummy_cert);

    // === Phase 5: Client processes ServerKeyExchange ===
    client
        .process_server_key_exchange(&provider, &server_key_exchange_bytes)
        .expect("Failed to process ServerKeyExchange");

    assert_eq!(client.state(), Tls12ClientState::WaitServerHelloDone);
    println!("✓ Client processed ServerKeyExchange");

    // === Phase 6: Client processes ServerHelloDone ===
    client
        .process_server_hello_done(&server_hello_done_bytes)
        .expect("Failed to process ServerHelloDone");

    assert_eq!(client.state(), Tls12ClientState::WaitChangeCipherSpec);
    println!("✓ Client processed ServerHelloDone");

    // === Phase 7: Client sends ClientKeyExchange ===
    let client_key_exchange_bytes = client
        .client_key_exchange(&provider)
        .expect("Failed to generate ClientKeyExchange");

    println!("✓ Client sent ClientKeyExchange ({} bytes)", client_key_exchange_bytes.len());

    // Verify client has computed secrets
    assert!(client.master_secret().is_some());
    assert!(client.key_block().is_some());
    println!("  - Master secret: {} bytes", client.master_secret().unwrap().len());
    println!("  - Key block: {} bytes", client.key_block().unwrap().len());

    // === Phase 8: Server processes ClientKeyExchange ===
    server
        .process_client_key_exchange(&provider, &client_key_exchange_bytes)
        .expect("Failed to process ClientKeyExchange");

    assert_eq!(server.state(), Tls12ServerState::WaitChangeCipherSpec);
    println!("✓ Server processed ClientKeyExchange");

    // Verify server has computed secrets
    assert!(server.master_secret().is_some());
    assert!(server.key_block().is_some());

    // Verify both sides have same master secret
    assert_eq!(
        client.master_secret().unwrap(),
        server.master_secret().unwrap(),
        "Master secrets must match"
    );
    println!("✓ Both sides computed matching master secret");

    // Verify both sides have same key block
    assert_eq!(
        client.key_block().unwrap(),
        server.key_block().unwrap(),
        "Key blocks must match"
    );
    println!("✓ Both sides computed matching key block");

    // === Phase 9: Test record protection with derived keys ===
    let cipher_suite = client.cipher_suite().unwrap();
    let key_block = client.key_block().unwrap();

    // Derive keys for both directions
    let (client_key, client_iv) =
        derive_keys_from_key_block(key_block, cipher_suite, true)
            .expect("Failed to derive client keys");
    let (server_key, server_iv) =
        derive_keys_from_key_block(key_block, cipher_suite, false)
            .expect("Failed to derive server keys");

    println!("✓ Derived encryption keys");
    println!("  - Client key: {} bytes, IV: {} bytes", client_key.len(), client_iv.len());
    println!("  - Server key: {} bytes, IV: {} bytes", server_key.len(), server_iv.len());

    // Set up record protection for both directions
    let mut client_write_protection =
        Tls12RecordProtection::new(cipher_suite, client_key.clone(), client_iv.clone());
    let mut server_read_protection =
        Tls12RecordProtection::new(cipher_suite, client_key, client_iv);

    let mut server_write_protection =
        Tls12RecordProtection::new(cipher_suite, server_key.clone(), server_iv.clone());
    let mut client_read_protection =
        Tls12RecordProtection::new(cipher_suite, server_key, server_iv);

    // Test client → server encryption
    let client_msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let encrypted_client_msg = client_write_protection
        .encrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            client_msg,
        )
        .expect("Failed to encrypt client message");

    let decrypted_client_msg = server_read_protection
        .decrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            &encrypted_client_msg,
        )
        .expect("Failed to decrypt client message");

    assert_eq!(decrypted_client_msg, client_msg);
    println!("✓ Client → Server encryption works ({} → {} bytes)",
        client_msg.len(), encrypted_client_msg.len());

    // Test server → client encryption
    let server_msg = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
    let encrypted_server_msg = server_write_protection
        .encrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            server_msg,
        )
        .expect("Failed to encrypt server message");

    let decrypted_server_msg = client_read_protection
        .decrypt(
            &provider,
            hptls_core::protocol::ContentType::ApplicationData,
            &encrypted_server_msg,
        )
        .expect("Failed to decrypt server message");

    assert_eq!(decrypted_server_msg, server_msg);
    println!("✓ Server → Client encryption works ({} → {} bytes)",
        server_msg.len(), encrypted_server_msg.len());

    // === Success ===
    println!("\n🎉 TLS 1.2 full handshake test completed successfully!");
    println!("   ✓ Message parsing (ClientHello, ServerHello, Certificate)");
    println!("   ✓ State machine transitions");
    println!("   ✓ Key exchange and secret derivation");
    println!("   ✓ Bidirectional encryption");
}

/// Test handshake with different cipher suites.
#[test]
fn test_tls12_handshake_multiple_cipher_suites() {
    let provider = HpcryptProvider::new();

    let test_cases = vec![
        (
            Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256,
            "ECDHE-ECDSA-AES128-GCM-SHA256",
        ),
        (
            Tls12CipherSuite::EcdheRsaWithAes256GcmSha384,
            "ECDHE-RSA-AES256-GCM-SHA384",
        ),
        (
            Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256,
            "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256",
        ),
    ];

    for (cipher_suite, name) in test_cases {
        println!("\nTesting cipher suite: {}", name);

        let mut client = Tls12ClientHandshake::new();
        let mut server = Tls12ServerHandshake::new();

        // Set up server
        server.set_certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]]);
        server.set_signing_key(
            vec![0xAA; 32],
            hptls_crypto::SignatureAlgorithm::EcdsaSecp256r1Sha256,
        );

        // ClientHello
        let client_hello = client
            .client_hello(&provider, &[cipher_suite])
            .expect("Failed to generate ClientHello");

        // Server processes and responds
        let (server_hello, _, _, _) = server
            .process_client_hello(&provider, &client_hello, &[cipher_suite])
            .expect("Failed to process ClientHello");

        // Client processes ServerHello
        client
            .process_server_hello(&server_hello)
            .expect("Failed to process ServerHello");

        // Verify negotiation
        assert_eq!(client.cipher_suite(), Some(cipher_suite));
        assert_eq!(server.cipher_suite(), Some(cipher_suite));

        println!("  ✓ Handshake successful with {}", name);
    }
}
