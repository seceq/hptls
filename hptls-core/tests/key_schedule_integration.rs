//! Integration test for TLS 1.3 Key Schedule with mock crypto provider.

use hptls_core::cipher::CipherSuite;
use hptls_core::key_schedule::KeySchedule;
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

#[test]
fn test_key_schedule_with_mock_provider() {
    let provider = HpcryptProvider::new();
    let mut ks = KeySchedule::new(CipherSuite::Aes128GcmSha256);

    // Initialize early secret (no PSK)
    ks.init_early_secret(&provider, &[]).unwrap();

    // Generate a fake shared secret for testing
    let shared_secret = vec![0x42u8; 32];

    // Derive handshake secret
    ks.derive_handshake_secret(&provider, &shared_secret).unwrap();

    // Derive handshake traffic secrets
    let transcript_hash = vec![0u8; 32]; // Fake transcript hash
    let client_hs_secret =
        ks.derive_client_handshake_traffic_secret(&provider, &transcript_hash).unwrap();
    let server_hs_secret =
        ks.derive_server_handshake_traffic_secret(&provider, &transcript_hash).unwrap();

    // Both secrets should be 32 bytes for SHA-256
    assert_eq!(client_hs_secret.len(), 32);
    assert_eq!(server_hs_secret.len(), 32);

    // They should be different
    assert_ne!(client_hs_secret, server_hs_secret);

    // Derive master secret
    ks.derive_master_secret(&provider).unwrap();

    // Derive application traffic secrets
    let client_app_secret = ks
        .derive_client_application_traffic_secret(&provider, &transcript_hash)
        .unwrap();
    let server_app_secret = ks
        .derive_server_application_traffic_secret(&provider, &transcript_hash)
        .unwrap();

    assert_eq!(client_app_secret.len(), 32);
    assert_eq!(server_app_secret.len(), 32);
    assert_ne!(client_app_secret, server_app_secret);

    // Test traffic key derivation
    let (key, iv) = ks.derive_traffic_keys(&provider, &client_app_secret).unwrap();
    assert_eq!(key.len(), 16); // AES-128 key
    assert_eq!(iv.len(), 12); // GCM IV
}

#[test]
fn test_key_schedule_with_psk() {
    let provider = HpcryptProvider::new();
    let mut ks = KeySchedule::new(CipherSuite::Aes256GcmSha384);

    // Initialize early secret with PSK
    let psk = vec![0x55u8; 48]; // SHA-384 outputs 48 bytes
    ks.init_early_secret(&provider, &psk).unwrap();

    // Generate a shared secret
    let shared_secret = vec![0x42u8; 48];

    // Derive handshake secret
    ks.derive_handshake_secret(&provider, &shared_secret).unwrap();

    // Derive master secret
    ks.derive_master_secret(&provider).unwrap();

    let transcript_hash = vec![0u8; 48]; // SHA-384 hash
    let exporter_secret = ks.derive_exporter_master_secret(&provider, &transcript_hash).unwrap();
    let resumption_secret =
        ks.derive_resumption_master_secret(&provider, &transcript_hash).unwrap();

    assert_eq!(exporter_secret.len(), 48);
    assert_eq!(resumption_secret.len(), 48);
    assert_ne!(exporter_secret, resumption_secret);
}
