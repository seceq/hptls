//! Integration tests for ECH retry configuration handling.
//!
//! This tests the full flow:
//! 1. Client sends ECH with wrong config
//! 2. Server fails to decrypt ECH
//! 3. Server sends retry_configs in EncryptedExtensions
//! 4. Client extracts and can use retry_configs

use hptls_core::cipher::CipherSuite;
use hptls_core::ech::{EchCipherSuite, EchConfigBuilder, EchConfigList};
use hptls_core::handshake::{ClientHandshake, ServerHandshake};
use hptls_core::messages::EncryptedExtensions;
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;
use std::collections::HashMap;

#[test]
fn test_ech_retry_config_flow() {
    let provider = <HpcryptProvider as CryptoProvider>::new();

    // Server generates correct ECH config
    let (correct_config, correct_secret_key) = EchConfigBuilder::new()
        .public_name("example.com")
        .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
        .build(&provider)
        .unwrap();

    // Client has a wrong/outdated config (simulated)
    let (wrong_config, _wrong_secret_key) = EchConfigBuilder::new()
        .public_name("example.com")
        .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
        .build(&provider)
        .unwrap();

    // === Client Side: Generate ClientHello with wrong ECH config ===
    let mut client = ClientHandshake::new();
    client.set_ech_config(wrong_config.clone());

    let client_hello = client
        .client_hello(
            &provider,
            &[CipherSuite::Aes128GcmSha256],
            Some("secret.example.com"),
            None,
        )
        .unwrap();

    // Verify ECH extension is present
    assert!(client_hello.extensions.has_ech());

    // === Server Side: Try to decrypt with correct config (will fail) ===
    let config_list = EchConfigList::new(vec![correct_config.clone()]);
    let mut secret_keys = HashMap::new();
    secret_keys.insert(correct_config.config_id, correct_secret_key);

    let mut server = ServerHandshake::new(vec![CipherSuite::Aes128GcmSha256]);
    server.set_ech_config(config_list.clone(), secret_keys);

    // Process ClientHello (ECH decryption will fail due to wrong config)
    server.process_client_hello(&provider, &client_hello).unwrap();

    // Generate ServerHello
    let server_hello = server.generate_server_hello(&provider).unwrap();

    // === Server: Generate EncryptedExtensions (should include retry_configs) ===
    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();

    // Verify retry_configs are present in EncryptedExtensions
    let retry_configs_bytes = encrypted_extensions
        .extensions
        .get_ech_retry_configs()
        .expect("retry_configs should be present when ECH decryption fails");

    // Decode retry_configs
    let retry_config_list = EchConfigList::decode(&retry_configs_bytes).unwrap();
    assert_eq!(retry_config_list.configs.len(), 1);
    assert_eq!(
        retry_config_list.configs[0].config_id,
        correct_config.config_id
    );

    // === Client Side: Process EncryptedExtensions and extract retry_configs ===
    client.process_server_hello(&provider, &server_hello).unwrap();
    client
        .process_encrypted_extensions(&encrypted_extensions)
        .unwrap();

    // Verify client received retry configs
    let client_retry_configs = client
        .get_ech_retry_configs()
        .expect("Client should have retry_configs");
    assert_eq!(client_retry_configs.len(), 1);
    assert_eq!(
        client_retry_configs[0].config_id,
        correct_config.config_id
    );
    assert_eq!(client_retry_configs[0].public_name, "example.com");

    println!("✅ ECH retry configuration flow successful!");
    println!("   - Client sent ECH with wrong config");
    println!("   - Server failed to decrypt");
    println!("   - Server sent retry_configs");
    println!("   - Client received and parsed retry_configs");
}

#[test]
fn test_ech_successful_no_retry_configs() {
    let provider = <HpcryptProvider as CryptoProvider>::new();

    // Generate ECH config
    let (config, secret_key) = EchConfigBuilder::new()
        .public_name("example.com")
        .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
        .build(&provider)
        .unwrap();

    // === Client Side: Generate ClientHello with correct ECH config ===
    let mut client = ClientHandshake::new();
    client.set_ech_config(config.clone());

    let client_hello = client
        .client_hello(
            &provider,
            &[CipherSuite::Aes128GcmSha256],
            Some("secret.example.com"),
            None,
        )
        .unwrap();

    // === Server Side: Decrypt successfully ===
    let config_list = EchConfigList::new(vec![config.clone()]);
    let mut secret_keys = HashMap::new();
    secret_keys.insert(config.config_id, secret_key);

    let mut server = ServerHandshake::new(vec![CipherSuite::Aes128GcmSha256]);
    server.set_ech_config(config_list, secret_keys);

    server.process_client_hello(&provider, &client_hello).unwrap();

    // Generate ServerHello and EncryptedExtensions
    let server_hello = server.generate_server_hello(&provider).unwrap();
    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();

    // Verify NO retry_configs when ECH succeeds
    assert!(
        encrypted_extensions
            .extensions
            .get_ech_retry_configs()
            .is_none(),
        "retry_configs should NOT be sent when ECH decryption succeeds"
    );

    // Process on client side
    client.process_server_hello(&provider, &server_hello).unwrap();
    client
        .process_encrypted_extensions(&encrypted_extensions)
        .unwrap();

    // Verify client has no retry configs
    assert!(
        client.get_ech_retry_configs().is_none(),
        "Client should not have retry_configs when ECH succeeded"
    );

    // Verify server name is the decrypted one
    assert_eq!(
        server.server_name().as_deref(),
        Some("secret.example.com")
    );

    println!("✅ ECH successful - no retry configs sent");
}

#[test]
fn test_ech_retry_config_encoding_decoding() {
    let provider = <HpcryptProvider as CryptoProvider>::new();

    // Generate multiple configs for retry
    let (config1, _) = EchConfigBuilder::new()
        .public_name("example.com")
        .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
        .build(&provider)
        .unwrap();

    let (config2, _) = EchConfigBuilder::new()
        .public_name("example.org")
        .add_cipher_suite(EchCipherSuite::HKDF_SHA256_CHACHA20POLY1305)
        .build(&provider)
        .unwrap();

    let config_list = EchConfigList::new(vec![config1.clone(), config2.clone()]);

    // Encode as retry_configs
    let encoded = config_list.encode().unwrap();

    // Create EncryptedExtensions with retry_configs
    let mut extensions = hptls_core::extensions::Extensions::new();
    extensions.add_ech_retry_configs(encoded.clone()).unwrap();

    let encrypted_extensions = EncryptedExtensions::new(extensions);

    // Extract and decode
    let retry_configs_bytes = encrypted_extensions
        .extensions
        .get_ech_retry_configs()
        .expect("retry_configs should be extractable");

    let decoded_list = EchConfigList::decode(&retry_configs_bytes).unwrap();

    // Verify
    assert_eq!(decoded_list.configs.len(), 2);
    assert_eq!(decoded_list.configs[0].config_id, config1.config_id);
    assert_eq!(decoded_list.configs[1].config_id, config2.config_id);
    assert_eq!(decoded_list.configs[0].public_name, "example.com");
    assert_eq!(decoded_list.configs[1].public_name, "example.org");

    println!("✅ ECH retry_configs encoding/decoding works correctly");
}
