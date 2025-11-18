//! TLS 1.2 Integration Tests
//!
//! This integration test module verifies the TLS 1.2 implementation components:
//! - Client and server handshake state machines
//! - Record layer encryption/decryption
//! - Key derivation (PRF)
//! - ECDHE key exchange
//!
//! Note: Full handshake tests are limited until message encoding/decoding is complete.

use hptls_core::error::Result;
use hptls_core::protocol::ContentType;
use hptls_core::tls12::cipher_suites::{default_cipher_suites, Tls12CipherSuite};
use hptls_core::tls12::client::{Tls12ClientHandshake, Tls12ClientState};
use hptls_core::tls12::key_exchange::{compute_premaster_secret, generate_key_pair};
use hptls_core::tls12::messages::{ClientKeyExchange, ServerHelloDone, ServerKeyExchange};
use hptls_core::tls12::record::{derive_keys_from_key_block, Tls12RecordProtection};
use hptls_core::tls12::server::{Tls12ServerHandshake, Tls12ServerState};
use hptls_core::tls12::{compute_key_block, compute_master_secret};
use hptls_crypto::{CryptoProvider, KeyExchangeAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Test TLS 1.2 client initial state.
#[test]
fn test_tls12_client_initialization() {
    let client = Tls12ClientHandshake::new();
    assert_eq!(client.state(), Tls12ClientState::Start);
    assert!(client.cipher_suite().is_none());
    assert!(client.master_secret().is_none());
}

/// Test TLS 1.2 server initial state.
#[test]
fn test_tls12_server_initialization() {
    let server = Tls12ServerHandshake::new();
    assert_eq!(server.state(), Tls12ServerState::Start);
    assert!(server.cipher_suite().is_none());
    assert!(server.master_secret().is_none());
}

/// Test TLS 1.2 ECDHE key exchange with X25519.
#[test]
fn test_tls12_ecdhe_x25519_key_exchange() {
    let provider = HpcryptProvider::new();

    // Generate key pairs for both client and server
    let (client_private, client_public) =
        generate_key_pair(&provider, KeyExchangeAlgorithm::X25519)
            .expect("Failed to generate client keypair");

    let (server_private, server_public) =
        generate_key_pair(&provider, KeyExchangeAlgorithm::X25519)
            .expect("Failed to generate server keypair");

    // Both sides compute premaster secret
    let client_premaster = compute_premaster_secret(
        &provider,
        KeyExchangeAlgorithm::X25519,
        &client_private,
        &server_public,
    )
    .expect("Client failed to compute premaster secret");

    let server_premaster = compute_premaster_secret(
        &provider,
        KeyExchangeAlgorithm::X25519,
        &server_private,
        &client_public,
    )
    .expect("Server failed to compute premaster secret");

    // Premaster secrets must match
    assert_eq!(
        client_premaster, server_premaster,
        "Premaster secrets don't match"
    );
    assert_eq!(client_premaster.len(), 32, "X25519 shared secret is 32 bytes");
}

/// Test TLS 1.2 key derivation: premaster -> master -> key_block.
#[test]
fn test_tls12_key_derivation() {
    let provider = HpcryptProvider::new();
    let cipher_suite = Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384;

    // Generate ECDHE key pair and compute premaster secret
    let (client_private, client_public) =
        generate_key_pair(&provider, KeyExchangeAlgorithm::X25519).unwrap();
    let (server_private, server_public) =
        generate_key_pair(&provider, KeyExchangeAlgorithm::X25519).unwrap();

    let premaster_secret = compute_premaster_secret(
        &provider,
        KeyExchangeAlgorithm::X25519,
        &client_private,
        &server_public,
    )
    .unwrap();

    // Generate random values
    let mut client_random = [0u8; 32];
    let mut server_random = [0u8; 32];
    provider.random().fill(&mut client_random).unwrap();
    provider.random().fill(&mut server_random).unwrap();

    // Derive master secret
    let master_secret = compute_master_secret(
        &provider,
        cipher_suite.hash_algorithm(),
        &premaster_secret,
        &client_random,
        &server_random,
    )
    .expect("Failed to compute master secret");

    assert_eq!(master_secret.len(), 48, "Master secret is always 48 bytes");

    // Derive key block
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

    assert_eq!(
        key_block.len(),
        key_block_len,
        "Key block length mismatch"
    );
}

/// Test TLS 1.2 record layer encryption and decryption.
#[test]
fn test_tls12_record_encryption_decryption() {
    let provider = HpcryptProvider::new();
    let cipher_suite = Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256;

    // Generate keys
    let key_block_len = cipher_suite.key_block_length();
    let key_block = vec![0xAAu8; key_block_len]; // Dummy key block

    // Derive client and server keys
    let (client_key, client_iv) =
        derive_keys_from_key_block(&key_block, cipher_suite, true).unwrap();
    let (server_key, server_iv) =
        derive_keys_from_key_block(&key_block, cipher_suite, false).unwrap();

    // Create record protection for client (writing) and server (reading)
    let mut client_protection =
        Tls12RecordProtection::new(cipher_suite, client_key.clone(), client_iv.clone());
    let mut server_protection =
        Tls12RecordProtection::new(cipher_suite, client_key.clone(), client_iv.clone());

    // Encrypt application data
    let plaintext = b"Hello, TLS 1.2!";
    let encrypted_record = client_protection
        .encrypt(&provider, ContentType::ApplicationData, plaintext)
        .expect("Encryption failed");

    // Verify structure: explicit_nonce (8 bytes) + ciphertext
    assert!(
        encrypted_record.len() > 8,
        "Encrypted record too short: {}",
        encrypted_record.len()
    );

    // Decrypt
    let decrypted = server_protection
        .decrypt(&provider, ContentType::ApplicationData, &encrypted_record)
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext, "Decrypted data doesn't match plaintext");
}

/// Test TLS 1.2 record layer with multiple messages (sequence number increment).
#[test]
fn test_tls12_record_sequence_numbers() {
    let provider = HpcryptProvider::new();
    let cipher_suite = Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256;

    // Generate keys
    let key_block_len = cipher_suite.key_block_length();
    let key_block = vec![0x55u8; key_block_len];

    let (key, iv) = derive_keys_from_key_block(&key_block, cipher_suite, true).unwrap();

    let mut protection = Tls12RecordProtection::new(cipher_suite, key, iv);

    assert_eq!(protection.sequence_number(), 0);

    // Encrypt first message
    let msg1 = b"First message";
    let _encrypted1 = protection
        .encrypt(&provider, ContentType::ApplicationData, msg1)
        .unwrap();
    assert_eq!(protection.sequence_number(), 1);

    // Encrypt second message
    let msg2 = b"Second message";
    let _encrypted2 = protection
        .encrypt(&provider, ContentType::ApplicationData, msg2)
        .unwrap();
    assert_eq!(protection.sequence_number(), 2);

    // Encrypt third message
    let msg3 = b"Third message";
    let _encrypted3 = protection
        .encrypt(&provider, ContentType::ApplicationData, msg3)
        .unwrap();
    assert_eq!(protection.sequence_number(), 3);
}

/// Test TLS 1.2 ChangeCipherSpec message format.
#[test]
fn test_tls12_change_cipher_spec() {
    let client = Tls12ClientHandshake::new();
    let ccs = client.change_cipher_spec();

    // ChangeCipherSpec is always a single byte: 0x01
    assert_eq!(ccs.len(), 1);
    assert_eq!(ccs[0], 0x01);
}

/// Test TLS 1.2 message encoding/decoding: ServerHelloDone.
#[test]
fn test_tls12_server_hello_done_message() {
    let msg = ServerHelloDone;
    let encoded = msg.encode().expect("Failed to encode ServerHelloDone");

    // ServerHelloDone is empty (0 bytes)
    assert_eq!(encoded.len(), 0);

    // Decode
    let decoded = ServerHelloDone::decode(&encoded).expect("Failed to decode ServerHelloDone");
    // ServerHelloDone has no fields, just verify it decodes successfully
}

/// Test TLS 1.2 message encoding/decoding: ClientKeyExchange.
#[test]
fn test_tls12_client_key_exchange_message() {
    let provider = HpcryptProvider::new();

    // Generate X25519 public key
    let (_private, public) = generate_key_pair(&provider, KeyExchangeAlgorithm::X25519).unwrap();

    let cke = ClientKeyExchange::new(public.clone());
    let encoded = cke.encode().expect("Failed to encode ClientKeyExchange");

    // Verify encoding: 1 byte length + public key
    assert_eq!(encoded.len(), 1 + public.len());
    assert_eq!(encoded[0] as usize, public.len());

    // Decode
    let decoded =
        ClientKeyExchange::decode(&encoded).expect("Failed to decode ClientKeyExchange");
    assert_eq!(decoded.public_key, public);
}

/// Test TLS 1.2 message encoding/decoding: ServerKeyExchange.
#[test]
fn test_tls12_server_key_exchange_message() {
    let provider = HpcryptProvider::new();

    // Generate X25519 public key
    let (_private, public) = generate_key_pair(&provider, KeyExchangeAlgorithm::X25519).unwrap();

    // Create ServerKeyExchange (with dummy signature)
    let ske = ServerKeyExchange::new(
        KeyExchangeAlgorithm::X25519,
        public.clone(),
        hptls_crypto::SignatureAlgorithm::EcdsaSecp256r1Sha256,
        vec![0xAA; 64], // Dummy signature
    );

    let encoded = ske.encode().expect("Failed to encode ServerKeyExchange");

    // Verify non-empty
    assert!(encoded.len() > 10, "Encoded ServerKeyExchange too short");

    // Decode
    let decoded =
        ServerKeyExchange::decode(&encoded).expect("Failed to decode ServerKeyExchange");
    assert_eq!(decoded.named_curve, KeyExchangeAlgorithm::X25519);
    assert_eq!(decoded.public_key, public);
}

/// Test all supported TLS 1.2 cipher suites.
#[test]
fn test_tls12_all_cipher_suites() {
    let cipher_suites = default_cipher_suites();

    // Verify we have 6 cipher suites
    assert_eq!(cipher_suites.len(), 6, "Should have 6 default cipher suites");

    // Verify all cipher suites have valid properties
    for cs in &cipher_suites {
        // Check AEAD algorithm
        let aead = cs.aead_algorithm();
        assert!(
            matches!(
                aead,
                hptls_crypto::AeadAlgorithm::Aes128Gcm
                    | hptls_crypto::AeadAlgorithm::Aes256Gcm
                    | hptls_crypto::AeadAlgorithm::ChaCha20Poly1305
            ),
            "Invalid AEAD algorithm for cipher suite: {:?}",
            cs
        );

        // Check hash algorithm
        let hash = cs.hash_algorithm();
        assert!(
            matches!(
                hash,
                hptls_crypto::HashAlgorithm::Sha256 | hptls_crypto::HashAlgorithm::Sha384
            ),
            "Invalid hash algorithm for cipher suite: {:?}",
            cs
        );

        // Check key block length is reasonable
        let key_block_len = cs.key_block_length();
        assert!(
            key_block_len >= 40 && key_block_len <= 100,
            "Key block length out of range: {}",
            key_block_len
        );
    }
}

/// Test TLS 1.2 key block derivation for different cipher suites.
#[test]
fn test_tls12_key_block_all_cipher_suites() {
    let provider = HpcryptProvider::new();
    let cipher_suites = default_cipher_suites();

    for cipher_suite in cipher_suites {
        // Generate dummy master secret
        let master_secret = vec![0x42u8; 48];

        // Generate random values
        let mut client_random = [0u8; 32];
        let mut server_random = [0u8; 32];
        provider.random().fill(&mut client_random).unwrap();
        provider.random().fill(&mut server_random).unwrap();

        // Derive key block
        let key_block_len = cipher_suite.key_block_length();
        let key_block = compute_key_block(
            &provider,
            cipher_suite.hash_algorithm(),
            &master_secret,
            &server_random,
            &client_random,
            key_block_len,
        )
        .expect(&format!(
            "Failed to compute key block for {:?}",
            cipher_suite
        ));

        assert_eq!(
            key_block.len(),
            key_block_len,
            "Key block length mismatch for {:?}",
            cipher_suite
        );

        // Verify key derivation
        let (client_key, client_iv) =
            derive_keys_from_key_block(&key_block, cipher_suite, true).expect(&format!(
                "Failed to derive client keys for {:?}",
                cipher_suite
            ));

        let (server_key, server_iv) =
            derive_keys_from_key_block(&key_block, cipher_suite, false).expect(&format!(
                "Failed to derive server keys for {:?}",
                cipher_suite
            ));

        // Keys should be different
        assert_ne!(client_key, server_key, "Client and server keys should differ");

        // IVs should be different
        assert_ne!(client_iv, server_iv, "Client and server IVs should differ");
    }
}

/// Test TLS 1.2 record layer with all cipher suites.
#[test]
fn test_tls12_record_layer_all_cipher_suites() {
    let provider = HpcryptProvider::new();
    let cipher_suites = default_cipher_suites();

    for cipher_suite in cipher_suites {
        // Generate key block
        let key_block_len = cipher_suite.key_block_length();
        let key_block = vec![0x77u8; key_block_len];

        let (key, iv) = derive_keys_from_key_block(&key_block, cipher_suite, true).unwrap();

        let mut encryptor = Tls12RecordProtection::new(cipher_suite, key.clone(), iv.clone());
        let mut decryptor = Tls12RecordProtection::new(cipher_suite, key, iv);

        // Test encryption/decryption
        let plaintext = b"Test data for TLS 1.2";
        let encrypted = encryptor
            .encrypt(&provider, ContentType::ApplicationData, plaintext)
            .expect(&format!("Encryption failed for {:?}", cipher_suite));

        let decrypted = decryptor
            .decrypt(&provider, ContentType::ApplicationData, &encrypted)
            .expect(&format!("Decryption failed for {:?}", cipher_suite));

        assert_eq!(
            decrypted, plaintext,
            "Decryption mismatch for {:?}",
            cipher_suite
        );
    }
}

/// Test full ClientHello/ServerHello message exchange with parsing.
#[test]
fn test_tls12_client_server_hello_exchange() {
    let provider = HpcryptProvider::new();
    let cipher_suites = default_cipher_suites();

    // Initialize client
    let mut client = Tls12ClientHandshake::new();

    // Client generates ClientHello
    let client_hello = client
        .client_hello(&provider, &cipher_suites)
        .expect("Failed to generate ClientHello");

    // Verify ClientHello is non-empty
    assert!(client_hello.len() > 50, "ClientHello too short");
    assert_eq!(client.state(), Tls12ClientState::WaitServerHello);

    // Initialize server
    let mut server = Tls12ServerHandshake::new();

    // Set up server certificate (dummy for now)
    server.set_certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]]);
    server.set_signing_key(
        vec![0xAA; 32],
        hptls_crypto::SignatureAlgorithm::EcdsaSecp256r1Sha256,
    );

    // Server processes ClientHello and generates response
    let (server_hello, _certificate, _server_key_exchange, _server_hello_done) = server
        .process_client_hello(&provider, &client_hello, &cipher_suites)
        .expect("Failed to process ClientHello");

    // Verify ServerHello is non-empty
    assert!(server_hello.len() > 50, "ServerHello too short");
    assert_eq!(server.state(), Tls12ServerState::WaitClientKeyExchange);

    // Client processes ServerHello
    client
        .process_server_hello(&server_hello)
        .expect("Failed to process ServerHello");

    // Verify client extracted cipher suite
    assert!(client.cipher_suite().is_some());
    assert_eq!(client.state(), Tls12ClientState::WaitCertificate);

    // Verify both sides have matching cipher suite
    assert_eq!(client.cipher_suite(), server.cipher_suite());

    println!("✓ ClientHello/ServerHello exchange successful");
    println!("✓ Negotiated cipher suite: {:?}", client.cipher_suite().unwrap());
}
