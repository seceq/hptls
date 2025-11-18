//! Integration tests for 0-RTT Early Data (RFC 8446 Section 4.2.10)
//!
//! These tests verify the basic 0-RTT functionality including:
//! - Early data extension in ClientHello
//! - Early data configuration
//! - EndOfEarlyData message handling
//!
//! Note: Full handshake tests with ServerHello/EncryptedExtensions would require
//! a complete mock server implementation and are better suited for end-to-end tests.

use hptls_core::{
    cipher::CipherSuite,
    early_data::{EarlyDataConfig, EarlyDataState},
    handshake::client::ClientHandshake,
    messages::EndOfEarlyData,
    protocol::ExtensionType,
};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

#[test]
fn test_early_data_extension_in_client_hello() {
    let provider = HpcryptProvider::new();
    let mut client = ClientHandshake::new();

    // Enable early data (use permissive for testing)
    let config = EarlyDataConfig::permissive();
    client.enable_early_data(config).unwrap();

    assert!(client.is_early_data_enabled());

    // Generate ClientHello
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("example.com"), None)
        .unwrap();

    // Verify early_data extension is present
    assert!(client_hello.extensions.has(ExtensionType::EarlyData));

    // Verify early data state transitioned to Offered
    assert!(matches!(
        client.early_data_context().unwrap().state,
        EarlyDataState::Offered
    ));
}

#[test]
fn test_early_data_not_present_when_disabled() {
    let provider = HpcryptProvider::new();
    let mut client = ClientHandshake::new();

    // Do NOT enable early data
    assert!(!client.is_early_data_enabled());

    // Generate ClientHello
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("example.com"), None)
        .unwrap();

    // Verify early_data extension is NOT present
    assert!(!client_hello.extensions.has(ExtensionType::EarlyData));
}

#[test]
fn test_end_of_early_data_encode_decode() {
    let eoed = EndOfEarlyData::new();

    // Encode
    let encoded = eoed.encode().unwrap();
    assert!(encoded.is_empty()); // Should be empty

    // Decode
    let decoded = EndOfEarlyData::decode(&encoded).unwrap();
    assert_eq!(eoed, decoded);
}

#[test]
fn test_end_of_early_data_rejects_non_empty_body() {
    let data = vec![0x01, 0x02, 0x03];
    let result = EndOfEarlyData::decode(&data);

    // Should error on non-empty body
    assert!(result.is_err());
}

#[test]
fn test_early_data_config_defaults() {
    let config = EarlyDataConfig::default();

    // Default is disabled for security
    assert!(!config.enabled);
    assert!(config.max_early_data_size > 0);
}

#[test]
fn test_early_data_config_permissive() {
    let config = EarlyDataConfig::permissive();

    assert!(config.enabled);
    assert!(config.max_early_data_size >= EarlyDataConfig::default().max_early_data_size);
}

#[test]
fn test_early_data_config_strict() {
    let config = EarlyDataConfig::strict();

    assert!(config.enabled);
    assert!(config.max_early_data_size <= EarlyDataConfig::default().max_early_data_size);
}

#[test]
fn test_cannot_enable_early_data_after_client_hello() {
    let provider = HpcryptProvider::new();
    let mut client = ClientHandshake::new();

    // Generate ClientHello first
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    let _client_hello = client
        .client_hello(&provider, &cipher_suites, Some("example.com"), None)
        .unwrap();

    // Try to enable early data after ClientHello
    let config = EarlyDataConfig::permissive();
    let result = client.enable_early_data(config);

    // Should fail
    assert!(result.is_err());
}

#[test]
fn test_early_data_state_offered_after_client_hello() {
    let provider = HpcryptProvider::new();
    let mut client = ClientHandshake::new();

    let config = EarlyDataConfig::permissive();
    client.enable_early_data(config).unwrap();

    // Initial state should be NotUsed
    assert!(matches!(
        client.early_data_context().unwrap().state,
        EarlyDataState::NotUsed
    ));

    // After ClientHello, state should be Offered
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    let _client_hello = client
        .client_hello(&provider, &cipher_suites, Some("example.com"), None)
        .unwrap();

    assert!(matches!(
        client.early_data_context().unwrap().state,
        EarlyDataState::Offered
    ));
}

#[test]
fn test_early_data_context_max_size() {
    let provider = HpcryptProvider::new();
    let mut client = ClientHandshake::new();

    let config = EarlyDataConfig::strict();
    let expected_max = config.max_early_data_size;
    client.enable_early_data(config).unwrap();

    let context = client.early_data_context().unwrap();
    assert_eq!(context.max_early_data_size(), expected_max);
}
