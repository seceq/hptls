//! Session Resumption Integration Tests
//!
//! This module tests TLS 1.3 session resumption using Pre-Shared Keys (PSK).
//! It verifies:
//! - Resumption master secret derivation
//! - PSK establishment from initial connection
//! - Key schedule with PSK (early secret initialization)
//! - 0-RTT early data capability
//!
//! # TLS 1.3 Session Resumption Flow
//!
//! ```text
//! Initial Connection:
//!   1. Full handshake (ECDH + certificates)
//!   2. Derive resumption_master_secret
//!   3. Server sends NewSessionTicket (contains PSK)
//!
//! Resumed Connection:
//!   1. Client uses PSK from ticket
//!   2. Early secret = HKDF-Extract(0, PSK)
//!   3. Can send 0-RTT early data
//!   4. Abbreviated handshake (no certificates)
//! ```

use hptls_core::{cipher::CipherSuite, key_schedule::KeySchedule};
use hptls_crypto::CryptoProvider;
use hptls_crypto::HashAlgorithm;
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Simulate a complete initial handshake and derive resumption secret.
///
/// In practice, this would happen through a full TLS handshake.
/// For this test, we'll directly use the key schedule to simulate it.
///
/// Returns:
/// - (resumption_secret, cipher_suite)
fn perform_initial_handshake_and_derive_resumption() -> (Vec<u8>, CipherSuite) {
    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    // Simulate complete handshake by running through key schedule
    let mut ks = KeySchedule::new(cipher_suite);

    // 1. Early secret (no PSK for initial connection)
    ks.init_early_secret(&provider, &[]).unwrap();

    // 2. Handshake secret (from ECDH)
    let shared_secret = vec![0x42u8; 32];
    ks.derive_handshake_secret(&provider, &shared_secret).unwrap();

    // 3. Handshake traffic secrets
    let hs_transcript = vec![0u8; 32];
    let _client_hs = ks.derive_client_handshake_traffic_secret(&provider, &hs_transcript).unwrap();
    let _server_hs = ks.derive_server_handshake_traffic_secret(&provider, &hs_transcript).unwrap();

    // 4. Master secret
    ks.derive_master_secret(&provider).unwrap();

    // 5. Application traffic secrets
    let app_transcript = vec![0u8; 32];
    let _client_app =
        ks.derive_client_application_traffic_secret(&provider, &app_transcript).unwrap();
    let _server_app =
        ks.derive_server_application_traffic_secret(&provider, &app_transcript).unwrap();

    // 6. Derive resumption master secret (for session tickets)
    let final_transcript = vec![0u8; 32]; // After all Finished messages
    let resumption_secret =
        ks.derive_resumption_master_secret(&provider, &final_transcript).unwrap();

    println!("✅ Initial handshake completed");
    println!(
        "   Resumption master secret length: {} bytes",
        resumption_secret.len()
    );

    (resumption_secret, cipher_suite)
}

/// Test that resumption master secret is derived correctly.
#[test]
fn test_resumption_master_secret_derivation() {
    let (resumption_secret, cipher_suite) = perform_initial_handshake_and_derive_resumption();

    // Length should match hash algorithm
    let expected_len = match cipher_suite.hash_algorithm() {
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha384 => 48,
        _ => panic!("Unexpected hash algorithm"),
    };

    assert_eq!(resumption_secret.len(), expected_len);
    println!("✅ Resumption master secret derivation verified");
}

/// Test PSK-based key schedule initialization.
#[test]
fn test_key_schedule_with_psk_from_resumption() {
    let (resumption_secret, cipher_suite) = perform_initial_handshake_and_derive_resumption();

    let provider = HpcryptProvider::new();

    // Create new key schedule for resumed connection
    let mut resumed_ks = KeySchedule::new(cipher_suite);

    // Initialize with PSK (derived from resumption secret)
    // In practice, the PSK would be: HKDF-Expand-Label(resumption_secret, "resumption", ticket_nonce, Hash.length)
    // For this test, we'll use the resumption secret directly as the PSK
    resumed_ks.init_early_secret(&provider, &resumption_secret).unwrap();

    println!("✅ Key schedule initialized with PSK");

    // Derive early data secret (for 0-RTT)
    let early_transcript = vec![0u8; 32]; // ClientHello transcript
    let early_secret = resumed_ks
        .derive_client_early_traffic_secret(&provider, &early_transcript)
        .unwrap();

    assert_eq!(early_secret.len(), 32); // SHA-256
    println!(
        "✅ Early data secret derived (length: {} bytes)",
        early_secret.len()
    );

    // Continue with (EC)DHE for forward secrecy
    let shared_secret = vec![0x42u8; 32];
    resumed_ks.derive_handshake_secret(&provider, &shared_secret).unwrap();

    // Derive handshake traffic secrets
    let hs_transcript = vec![0u8; 32];
    let client_hs = resumed_ks
        .derive_client_handshake_traffic_secret(&provider, &hs_transcript)
        .unwrap();
    let server_hs = resumed_ks
        .derive_server_handshake_traffic_secret(&provider, &hs_transcript)
        .unwrap();

    assert_eq!(client_hs.len(), 32);
    assert_eq!(server_hs.len(), 32);
    assert_ne!(client_hs, server_hs);
    println!("✅ Handshake traffic secrets derived with PSK");

    // Derive master secret and application secrets
    resumed_ks.derive_master_secret(&provider).unwrap();

    let app_transcript = vec![0u8; 32];
    let client_app = resumed_ks
        .derive_client_application_traffic_secret(&provider, &app_transcript)
        .unwrap();
    let server_app = resumed_ks
        .derive_server_application_traffic_secret(&provider, &app_transcript)
        .unwrap();

    assert_eq!(client_app.len(), 32);
    assert_eq!(server_app.len(), 32);
    assert_ne!(client_app, server_app);
    println!("✅ Application traffic secrets derived");
}

/// Test that early secret differs between PSK and non-PSK handshakes.
#[test]
fn test_psk_changes_early_secret() {
    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    // Key schedule WITHOUT PSK
    let mut ks_no_psk = KeySchedule::new(cipher_suite);
    ks_no_psk.init_early_secret(&provider, &[]).unwrap();

    // Key schedule WITH PSK
    let psk = vec![0x55u8; 32];
    let mut ks_with_psk = KeySchedule::new(cipher_suite);
    ks_with_psk.init_early_secret(&provider, &psk).unwrap();

    // Derive early secrets from same transcript
    let transcript = vec![0u8; 32];
    let early_no_psk =
        ks_no_psk.derive_client_early_traffic_secret(&provider, &transcript).unwrap();
    let early_with_psk =
        ks_with_psk.derive_client_early_traffic_secret(&provider, &transcript).unwrap();

    // Early secrets MUST be different when PSK is used
    assert_ne!(
        early_no_psk, early_with_psk,
        "PSK must change early secret derivation"
    );

    println!("✅ PSK correctly changes early secret derivation");
}

/// Test 0-RTT early data secret derivation.
#[test]
fn test_zero_rtt_early_data_secret() {
    let (resumption_secret, cipher_suite) = perform_initial_handshake_and_derive_resumption();

    let provider = HpcryptProvider::new();
    let mut resumed_ks = KeySchedule::new(cipher_suite);

    // Initialize with resumption PSK
    resumed_ks.init_early_secret(&provider, &resumption_secret).unwrap();

    // Derive 0-RTT early data secret
    let client_hello_transcript = vec![0u8; 32];
    let early_data_secret = resumed_ks
        .derive_client_early_traffic_secret(&provider, &client_hello_transcript)
        .unwrap();

    assert_eq!(early_data_secret.len(), 32);
    println!("✅ 0-RTT early data secret derived");

    // Derive traffic keys for early data encryption
    let (early_key, early_iv) =
        resumed_ks.derive_traffic_keys(&provider, &early_data_secret).unwrap();

    assert_eq!(early_key.len(), 16); // AES-128
    assert_eq!(early_iv.len(), 12); // GCM IV
    println!(
        "✅ 0-RTT traffic keys derived (key: {} bytes, IV: {} bytes)",
        early_key.len(),
        early_iv.len()
    );
}

/// Test full resumption flow: initial handshake → PSK → resumed handshake.
#[test]
fn test_full_resumption_flow() {
    println!("\n========================================");
    println!("  FULL SESSION RESUMPTION TEST");
    println!("========================================\n");

    let provider = HpcryptProvider::new();

    // ========================================
    // Phase 1: Initial Full Handshake
    // ========================================
    println!("Phase 1: Initial Full Handshake");
    println!("--------------------------------");

    let (resumption_secret, cipher_suite) = perform_initial_handshake_and_derive_resumption();

    println!("✅ Phase 1 complete - Resumption secret established\n");

    // ========================================
    // Phase 2: Derive PSK for Resumption
    // ========================================
    println!("Phase 2: PSK Derivation");
    println!("--------------------------------");

    // In practice, the server would:
    // 1. Generate a ticket_nonce
    // 2. Compute PSK = HKDF-Expand-Label(resumption_secret, "resumption", ticket_nonce, Hash.length)
    // 3. Send NewSessionTicket containing encrypted ticket state
    //
    // For this test, we'll use resumption_secret directly as PSK
    let psk = resumption_secret;

    println!("✅ PSK derived from resumption secret");
    println!("   PSK length: {} bytes\n", psk.len());

    // ========================================
    // Phase 3: Resumed Handshake with PSK
    // ========================================
    println!("Phase 3: Resumed Handshake");
    println!("--------------------------------");

    // Create new key schedules for client and server (resumed connection)
    let mut client_ks = KeySchedule::new(cipher_suite);
    let mut server_ks = KeySchedule::new(cipher_suite);

    // Both sides initialize with the PSK
    client_ks.init_early_secret(&provider, &psk).unwrap();
    server_ks.init_early_secret(&provider, &psk).unwrap();

    println!("✅ Both sides initialized early secret with PSK");

    // Derive 0-RTT early data secrets (client can send encrypted data before ServerHello!)
    let early_transcript = vec![0u8; 32];
    let client_early = client_ks
        .derive_client_early_traffic_secret(&provider, &early_transcript)
        .unwrap();
    let server_early = server_ks
        .derive_client_early_traffic_secret(&provider, &early_transcript)
        .unwrap();

    assert_eq!(client_early, server_early, "Early secrets must match!");
    println!(
        "✅ 0-RTT early data secrets match (length: {} bytes)",
        client_early.len()
    );

    // Continue with (EC)DHE for forward secrecy
    let shared_secret = vec![0x42u8; 32];
    client_ks.derive_handshake_secret(&provider, &shared_secret).unwrap();
    server_ks.derive_handshake_secret(&provider, &shared_secret).unwrap();

    // Derive handshake traffic secrets
    let hs_transcript = vec![0u8; 32];
    let client_hs_from_client = client_ks
        .derive_client_handshake_traffic_secret(&provider, &hs_transcript)
        .unwrap();
    let client_hs_from_server = server_ks
        .derive_client_handshake_traffic_secret(&provider, &hs_transcript)
        .unwrap();
    let server_hs_from_client = client_ks
        .derive_server_handshake_traffic_secret(&provider, &hs_transcript)
        .unwrap();
    let server_hs_from_server = server_ks
        .derive_server_handshake_traffic_secret(&provider, &hs_transcript)
        .unwrap();

    // Both sides should derive the SAME client handshake secret
    assert_eq!(
        client_hs_from_client, client_hs_from_server,
        "Client handshake secrets must match!"
    );
    // Both sides should derive the SAME server handshake secret
    assert_eq!(
        server_hs_from_client, server_hs_from_server,
        "Server handshake secrets must match!"
    );
    // Client and server secrets should be DIFFERENT (different traffic directions)
    assert_ne!(
        client_hs_from_client, server_hs_from_client,
        "Client and server handshake secrets should differ!"
    );
    println!("✅ Handshake traffic secrets match on both sides");

    // Derive master secrets
    client_ks.derive_master_secret(&provider).unwrap();
    server_ks.derive_master_secret(&provider).unwrap();

    // Derive application traffic secrets
    let app_transcript = vec![0u8; 32];
    let client_app_from_client = client_ks
        .derive_client_application_traffic_secret(&provider, &app_transcript)
        .unwrap();
    let client_app_from_server = server_ks
        .derive_client_application_traffic_secret(&provider, &app_transcript)
        .unwrap();
    let server_app_from_client = client_ks
        .derive_server_application_traffic_secret(&provider, &app_transcript)
        .unwrap();
    let server_app_from_server = server_ks
        .derive_server_application_traffic_secret(&provider, &app_transcript)
        .unwrap();

    // Both sides should derive the SAME client application secret
    assert_eq!(
        client_app_from_client, client_app_from_server,
        "Client application secrets must match!"
    );
    // Both sides should derive the SAME server application secret
    assert_eq!(
        server_app_from_client, server_app_from_server,
        "Server application secrets must match!"
    );
    // Client and server secrets should be DIFFERENT (different traffic directions)
    assert_ne!(
        client_app_from_client, server_app_from_client,
        "Client and server application secrets should differ!"
    );
    println!("✅ Application traffic secrets match on both sides");

    println!("\n========================================");
    println!("✅ FULL SESSION RESUMPTION SUCCESSFUL!");
    println!("========================================");
    println!("\nKey observations:");
    println!("  • Initial handshake established resumption secret");
    println!("  • PSK derived from resumption secret");
    println!("  • Resumed handshake used PSK for early secret");
    println!("  • 0-RTT early data secrets available");
    println!("  • Forward secrecy maintained with (EC)DHE");
    println!("  • All traffic secrets derived correctly");
    println!("========================================\n");
}

/// Test that different PSKs produce different secrets.
#[test]
fn test_different_psks_produce_different_secrets() {
    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    let psk1 = vec![0x01u8; 32];
    let psk2 = vec![0x02u8; 32];

    let mut ks1 = KeySchedule::new(cipher_suite);
    let mut ks2 = KeySchedule::new(cipher_suite);

    ks1.init_early_secret(&provider, &psk1).unwrap();
    ks2.init_early_secret(&provider, &psk2).unwrap();

    let transcript = vec![0u8; 32];
    let early1 = ks1.derive_client_early_traffic_secret(&provider, &transcript).unwrap();
    let early2 = ks2.derive_client_early_traffic_secret(&provider, &transcript).unwrap();

    // Different PSKs must produce different early secrets
    assert_ne!(
        early1, early2,
        "Different PSKs must produce different secrets"
    );

    println!("✅ Different PSKs produce different early secrets");
}

/// Test security: resumed connection still uses (EC)DHE for forward secrecy.
#[test]
fn test_resumption_maintains_forward_secrecy() {
    let (psk, cipher_suite) = perform_initial_handshake_and_derive_resumption();

    let provider = HpcryptProvider::new();

    // Two different (EC)DHE exchanges - create separate key schedules
    let shared_secret1 = vec![0x01u8; 32];
    let shared_secret2 = vec![0x02u8; 32];

    // Create two separate key schedules, both initialized with same PSK
    let mut ks1 = KeySchedule::new(cipher_suite);
    ks1.init_early_secret(&provider, &psk).unwrap();

    let mut ks2 = KeySchedule::new(cipher_suite);
    ks2.init_early_secret(&provider, &psk).unwrap();

    // Derive handshake secrets with different (EC)DHE outputs
    ks1.derive_handshake_secret(&provider, &shared_secret1).unwrap();
    ks2.derive_handshake_secret(&provider, &shared_secret2).unwrap();

    let transcript = vec![0u8; 32];
    let hs1 = ks1.derive_client_handshake_traffic_secret(&provider, &transcript).unwrap();
    let hs2 = ks2.derive_client_handshake_traffic_secret(&provider, &transcript).unwrap();

    // Different (EC)DHE outputs must produce different handshake secrets
    assert_ne!(
        hs1, hs2,
        "Forward secrecy requires different (EC)DHE outputs produce different secrets"
    );

    println!("✅ Forward secrecy maintained: (EC)DHE affects handshake secrets");
}

/// Test that resumption works with different cipher suites (same hash).
#[test]
fn test_resumption_with_same_hash_different_cipher() {
    let provider = HpcryptProvider::new();

    // Both use SHA-256
    let cipher1 = CipherSuite::Aes128GcmSha256;
    let cipher2 = CipherSuite::ChaCha20Poly1305Sha256;

    assert_eq!(cipher1.hash_algorithm(), cipher2.hash_algorithm());

    let psk = vec![0x42u8; 32];

    // Key schedules with different ciphers but same hash
    let mut ks1 = KeySchedule::new(cipher1);
    let mut ks2 = KeySchedule::new(cipher2);

    ks1.init_early_secret(&provider, &psk).unwrap();
    ks2.init_early_secret(&provider, &psk).unwrap();

    let transcript = vec![0u8; 32];
    let early1 = ks1.derive_client_early_traffic_secret(&provider, &transcript).unwrap();
    let early2 = ks2.derive_client_early_traffic_secret(&provider, &transcript).unwrap();

    // Same PSK + same hash = same early secrets (only AEAD cipher differs)
    assert_eq!(
        early1, early2,
        "Same hash algorithm should produce same early secrets"
    );

    println!("✅ Resumption compatible across cipher suites with same hash");
}

/// Test multiple resumptions from same initial handshake.
#[test]
fn test_multiple_resumptions_from_same_initial() {
    let (resumption_secret, cipher_suite) = perform_initial_handshake_and_derive_resumption();

    let provider = HpcryptProvider::new();

    // Simulate 3 resumed connections using the same resumption secret
    for i in 1..=3 {
        println!("Resumed connection #{}", i);

        let mut ks = KeySchedule::new(cipher_suite);
        ks.init_early_secret(&provider, &resumption_secret).unwrap();

        // Each resumed connection uses different (EC)DHE for forward secrecy
        let shared_secret = vec![i as u8; 32];
        ks.derive_handshake_secret(&provider, &shared_secret).unwrap();

        let transcript = vec![0u8; 32];
        let client_hs = ks.derive_client_handshake_traffic_secret(&provider, &transcript).unwrap();

        assert_eq!(client_hs.len(), 32);
        println!(
            "  ✅ Connection #{} handshake secret: {} bytes",
            i,
            client_hs.len()
        );
    }

    println!("✅ Multiple resumptions successful");
}
