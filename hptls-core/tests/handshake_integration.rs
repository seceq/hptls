//! TLS 1.3 Handshake Integration Tests
//!
//! This integration test module verifies that the client and server handshake
//! state machines can successfully complete a full TLS 1.3 handshake.

use hptls_core::cipher::CipherSuite;
use hptls_core::handshake::{ClientHandshake, ClientState, ServerHandshake, ServerState};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Test a complete TLS 1.3 handshake between client and server.
///
/// This test verifies:
/// - ClientHello generation
/// - ServerHello processing
/// - EncryptedExtensions processing
/// - Certificate processing
/// - CertificateVerify processing
/// - Finished message exchange
/// - Traffic secret derivation
#[test]
fn test_full_tls13_handshake() {
    let provider = HpcryptProvider::new();

    // Setup cipher suites
    let cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ];

    // Initialize client and server
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    assert_eq!(client.state(), ClientState::Start);
    assert_eq!(server.state(), ServerState::Start);

    // Step 1: Client generates ClientHello
    println!("Step 1: Client -> ClientHello");
    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("example.com"), None)
        .expect("Failed to generate ClientHello");

    assert_eq!(client.state(), ClientState::WaitServerHello);
    assert_eq!(client_hello.cipher_suites.len(), 3);
    assert!(client_hello.extensions.contains_supported_versions());

    // Step 2: Server processes ClientHello
    println!("Step 2: Server processes ClientHello");
    server
        .process_client_hello(&provider, &client_hello)
        .expect("Failed to process ClientHello");

    assert_eq!(server.state(), ServerState::Negotiate);
    assert_eq!(server.cipher_suite(), Some(CipherSuite::Aes128GcmSha256));

    // Step 3: Server generates ServerHello
    println!("Step 3: Server -> ServerHello");
    let server_hello =
        server.generate_server_hello(&provider).expect("Failed to generate ServerHello");

    assert_eq!(server_hello.cipher_suite, CipherSuite::Aes128GcmSha256);
    assert!(server_hello.extensions.contains_supported_versions());
    assert!(server_hello.extensions.get_key_share().unwrap().is_some());

    // Verify server has derived handshake secrets
    assert!(server.get_server_handshake_traffic_secret().is_some());
    assert!(server.get_client_handshake_traffic_secret().is_some());

    // Step 4: Client processes ServerHello
    println!("Step 4: Client processes ServerHello");
    client
        .process_server_hello(&provider, &server_hello)
        .expect("Failed to process ServerHello");

    assert_eq!(client.state(), ClientState::WaitEncryptedExtensions);
    assert_eq!(client.cipher_suite(), Some(CipherSuite::Aes128GcmSha256));

    // Step 5: Server generates EncryptedExtensions
    println!("Step 5: Server -> EncryptedExtensions");
    let encrypted_extensions = server
        .generate_encrypted_extensions(None)
        .expect("Failed to generate EncryptedExtensions");

    // Step 6: Client processes EncryptedExtensions
    println!("Step 6: Client processes EncryptedExtensions");
    client
        .process_encrypted_extensions(&encrypted_extensions)
        .expect("Failed to process EncryptedExtensions");

    assert_eq!(client.state(), ClientState::WaitCertCr);

    // Step 7: Server generates Certificate
    println!("Step 7: Server -> Certificate");
    let cert_chain = vec![
        vec![0x30, 0x82, 0x01, 0x00], // Dummy certificate (DER-encoded placeholder)
    ];
    let certificate =
        server.generate_certificate(cert_chain).expect("Failed to generate Certificate");

    assert_eq!(certificate.certificate_list.len(), 1);

    // Step 8: Client processes Certificate
    println!("Step 8: Client processes Certificate");
    client.process_certificate(&certificate).expect("Failed to process Certificate");

    assert_eq!(client.state(), ClientState::WaitCertVerify);

    // Step 9: Server generates CertificateVerify
    println!("Step 9: Server -> CertificateVerify");
    let signing_key = vec![0u8; 32]; // Dummy signing key
    let cert_verify = server
        .generate_certificate_verify(&provider, &signing_key)
        .expect("Failed to generate CertificateVerify");

    assert!(!cert_verify.signature.is_empty());

    // Step 10: Client processes CertificateVerify
    println!("Step 10: Client processes CertificateVerify");
    client
        .process_certificate_verify(&cert_verify)
        .expect("Failed to process CertificateVerify");

    assert_eq!(client.state(), ClientState::WaitFinished);

    // Step 11: Server generates Finished
    println!("Step 11: Server -> Finished (server)");
    let server_finished = server
        .generate_server_finished(&provider)
        .expect("Failed to generate server Finished");

    assert_eq!(server.state(), ServerState::WaitFinished);
    assert!(!server_finished.verify_data.is_empty());

    // Verify server has derived application secrets
    assert!(server.get_server_application_traffic_secret().is_some());
    assert!(server.get_client_application_traffic_secret().is_some());

    // Step 12: Client processes server Finished and generates client Finished
    println!("Step 12: Client processes server Finished and generates client Finished");
    let client_finished = client
        .process_server_finished(&provider, &server_finished)
        .expect("Failed to process server Finished");

    assert_eq!(client.state(), ClientState::Connected);
    assert!(!client_finished.verify_data.is_empty());

    // Step 13: Server processes client Finished
    println!("Step 13: Server processes client Finished");
    server
        .process_client_finished(&provider, &client_finished)
        .expect("Failed to process client Finished");

    assert_eq!(server.state(), ServerState::Connected);

    // Verify both sides are connected
    assert!(client.is_connected());
    assert!(server.is_connected());

    // Verify all traffic secrets are available
    assert!(
        client.get_client_handshake_traffic_secret().is_some(),
        "Client should have client handshake traffic secret"
    );
    assert!(
        client.get_server_handshake_traffic_secret().is_some(),
        "Client should have server handshake traffic secret"
    );
    assert!(
        client.get_client_application_traffic_secret().is_some(),
        "Client should have client application traffic secret"
    );
    assert!(
        client.get_server_application_traffic_secret().is_some(),
        "Client should have server application traffic secret"
    );

    assert!(
        server.get_client_handshake_traffic_secret().is_some(),
        "Server should have client handshake traffic secret"
    );
    assert!(
        server.get_server_handshake_traffic_secret().is_some(),
        "Server should have server handshake traffic secret"
    );
    assert!(
        server.get_client_application_traffic_secret().is_some(),
        "Server should have client application traffic secret"
    );
    assert!(
        server.get_server_application_traffic_secret().is_some(),
        "Server should have server application traffic secret"
    );

    // Verify handshake traffic secrets match (these should be identical)
    let client_hs_secret = client.get_client_handshake_traffic_secret().unwrap();
    let client_hs_secret_from_server = server.get_client_handshake_traffic_secret().unwrap();
    assert_eq!(
        client_hs_secret, client_hs_secret_from_server,
        "Client handshake traffic secrets should match between client and server"
    );

    let server_hs_secret = server.get_server_handshake_traffic_secret().unwrap();
    let server_hs_secret_from_client = client.get_server_handshake_traffic_secret().unwrap();
    assert_eq!(
        server_hs_secret, server_hs_secret_from_client,
        "Server handshake traffic secrets should match between client and server"
    );

    // Note: Application traffic secrets correctness will be validated when used
    // for actual record encryption/decryption in record layer tests

    println!("✅ Full TLS 1.3 handshake completed successfully!");
}

/// Test handshake with different cipher suites.
#[test]
fn test_handshake_with_aes256_gcm() {
    let provider = HpcryptProvider::new();

    // Only offer AES-256-GCM
    let cipher_suites = vec![CipherSuite::Aes256GcmSha384];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Complete handshake
    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();

    // Verify correct cipher suite was negotiated
    assert_eq!(client.cipher_suite(), Some(CipherSuite::Aes256GcmSha384));
    assert_eq!(server.cipher_suite(), Some(CipherSuite::Aes256GcmSha384));
}

/// Test handshake with ChaCha20-Poly1305.
#[test]
fn test_handshake_with_chacha20_poly1305() {
    let provider = HpcryptProvider::new();

    let cipher_suites = vec![CipherSuite::ChaCha20Poly1305Sha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();

    assert_eq!(
        client.cipher_suite(),
        Some(CipherSuite::ChaCha20Poly1305Sha256)
    );
    assert_eq!(
        server.cipher_suite(),
        Some(CipherSuite::ChaCha20Poly1305Sha256)
    );
}

/// Test cipher suite negotiation priority (server prefers first match from client's list).
#[test]
fn test_cipher_suite_negotiation() {
    let provider = HpcryptProvider::new();

    // Client offers multiple cipher suites
    let client_suites = vec![
        CipherSuite::ChaCha20Poly1305Sha256,
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
    ];

    // Server only supports AES-128-GCM and AES-256-GCM
    let server_suites = vec![CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(server_suites);

    let client_hello = client.client_hello(&provider, &client_suites, None, None).unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();

    // Server should select AES-128-GCM (first match from client's list that server supports)
    assert_eq!(server.cipher_suite(), Some(CipherSuite::Aes128GcmSha256));
}

/// Test that handshake fails when no common cipher suite is available.
#[test]
fn test_handshake_fails_with_no_common_cipher_suite() {
    let provider = HpcryptProvider::new();

    // Client only offers ChaCha20
    let client_suites = vec![CipherSuite::ChaCha20Poly1305Sha256];

    // Server only supports AES
    let server_suites = vec![CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(server_suites);

    let client_hello = client.client_hello(&provider, &client_suites, None, None).unwrap();

    // Server should reject due to no common cipher suite
    let result = server.process_client_hello(&provider, &client_hello);
    assert!(result.is_err());
}

/// Test that client validates server's Finished message.
#[test]
fn test_client_rejects_invalid_server_finished() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Complete handshake up to server Finished
    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    client.process_server_hello(&provider, &server_hello).unwrap();

    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();

    let certificate = server.generate_certificate(vec![vec![0u8; 4]]).unwrap();
    client.process_certificate(&certificate).unwrap();

    let cert_verify = server
        .generate_certificate_verify(&provider, &{
            let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
            let (signing_key, _) = sig_impl.generate_keypair().unwrap();
            signing_key.as_bytes().to_vec()
        })
        .unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();

    let mut server_finished = server.generate_server_finished(&provider).unwrap();

    // Corrupt the verify_data
    server_finished.verify_data[0] ^= 0xFF;

    // Client should reject invalid Finished
    let result = client.process_server_finished(&provider, &server_finished);
    assert!(result.is_err());
}

/// Test that server validates client's Finished message.
#[test]
fn test_server_rejects_invalid_client_finished() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Complete handshake up to client Finished
    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    client.process_server_hello(&provider, &server_hello).unwrap();

    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();

    let certificate = server.generate_certificate(vec![vec![0u8; 4]]).unwrap();
    client.process_certificate(&certificate).unwrap();

    let cert_verify = server
        .generate_certificate_verify(&provider, &{
            let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
            let (signing_key, _) = sig_impl.generate_keypair().unwrap();
            signing_key.as_bytes().to_vec()
        })
        .unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();

    let server_finished = server.generate_server_finished(&provider).unwrap();
    let mut client_finished = client.process_server_finished(&provider, &server_finished).unwrap();

    // Corrupt the verify_data
    client_finished.verify_data[0] ^= 0xFF;

    // Server should reject invalid Finished
    let result = server.process_client_finished(&provider, &client_finished);
    assert!(result.is_err());
}

/// Test SNI (Server Name Indication) extension handling.
#[test]
fn test_sni_extension() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Client sends SNI
    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("www.example.com"), None)
        .unwrap();

    // Verify SNI is in ClientHello
    let sni = client_hello.extensions.get_server_name().unwrap();
    assert_eq!(sni, Some("www.example.com".to_string()));

    // Server processes and extracts SNI
    server.process_client_hello(&provider, &client_hello).unwrap();

    // Note: ServerHandshake.server_name is private, but we can verify it was processed
    // by checking that the handshake succeeded
    assert_eq!(server.state(), ServerState::Negotiate);
}

/// Test handshake state machine validates message order.
#[test]
fn test_state_machine_rejects_out_of_order_messages() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();

    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    let certificate = server.generate_certificate(vec![vec![0u8; 4]]).unwrap();

    // Try to process Certificate before EncryptedExtensions - should fail
    let result = client.process_certificate(&certificate);
    assert!(
        result.is_err(),
        "Should reject Certificate before EncryptedExtensions"
    );
}

/// Test multiple handshakes can be performed sequentially.
#[test]
fn test_multiple_sequential_handshakes() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    for i in 0..3 {
        println!("Handshake iteration {}", i + 1);

        let mut client = ClientHandshake::new();
        let mut server = ServerHandshake::new(cipher_suites.clone());

        // Perform complete handshake
        let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();
        server.process_client_hello(&provider, &client_hello).unwrap();
        let server_hello = server.generate_server_hello(&provider).unwrap();
        client.process_server_hello(&provider, &server_hello).unwrap();
        let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
        client.process_encrypted_extensions(&encrypted_extensions).unwrap();
        let certificate = server.generate_certificate(vec![vec![0u8; 4]]).unwrap();
        client.process_certificate(&certificate).unwrap();
        let cert_verify = server
            .generate_certificate_verify(&provider, &{
                let sig_impl =
                    provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
                let (signing_key, _) = sig_impl.generate_keypair().unwrap();
                signing_key.as_bytes().to_vec()
            })
            .unwrap();
        client.process_certificate_verify(&cert_verify).unwrap();
        let server_finished = server.generate_server_finished(&provider).unwrap();
        let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();
        server.process_client_finished(&provider, &client_finished).unwrap();

        assert!(client.is_connected());
        assert!(server.is_connected());
    }
}
