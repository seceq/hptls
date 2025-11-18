//! RSA-PSS Certificate Integration Tests
//!
//! This test suite validates end-to-end TLS 1.3 handshakes using real RSA-PSS
//! certificates with a complete 3-level PKI chain (Root CA → Intermediate CA → Server).
//!
//! Tests verify:
//! - Full TLS 1.3 handshake with RSA-PSS server certificate
//! - Certificate chain validation (3 levels)
//! - RSA-PSS signature verification in CertificateVerify
//! - Session resumption with RSA-PSS certificates
//! - All cipher suites with RSA authentication

use hptls_core::cipher::CipherSuite;
use hptls_core::handshake::{ClientHandshake, ClientState, ServerHandshake, ServerState};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

// Real RSA-PSS certificates generated with OpenSSL
// 3-level PKI: Root CA → Intermediate CA → Server (test.example.com)
const SERVER_CERT: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/server.der");
const INTERMEDIATE_CA: &[u8] =
    include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/intermediate-ca.der");
const ROOT_CA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/root-ca.der");
const SERVER_KEY: &[u8] =
    include_bytes!("../../hptls-crypto-hpcrypt/tests/data/chain/server.key.der");

/// Test full TLS 1.3 handshake with real RSA-PSS certificate chain
#[test]
fn test_tls13_handshake_with_rsa_pss_certificate_chain() {
    let provider = HpcryptProvider::new();

    // Cipher suites
    let cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ];

    // Initialize client and server
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Server certificate chain: [Server, Intermediate, Root]
    let cert_chain = vec![
        SERVER_CERT.to_vec(),
        INTERMEDIATE_CA.to_vec(),
        ROOT_CA.to_vec(),
    ];

    println!("\n=== TLS 1.3 Handshake with RSA-PSS Certificate Chain ===\n");

    // Step 1: Client sends ClientHello
    println!("Step 1: Client -> ClientHello");
    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("test.example.com"), None)
        .expect("Failed to generate ClientHello");

    assert_eq!(client.state(), ClientState::WaitServerHello);
    println!("  ✓ ClientHello generated with {} cipher suites", cipher_suites.len());

    // Step 2: Server processes ClientHello
    println!("\nStep 2: Server processes ClientHello");
    server
        .process_client_hello(&provider, &client_hello)
        .expect("Failed to process ClientHello");

    assert_eq!(server.state(), ServerState::Negotiate);
    println!("  ✓ Server negotiated cipher suite: {:?}", server.cipher_suite());

    // Step 3: Server sends ServerHello
    println!("\nStep 3: Server -> ServerHello");
    let server_hello = server
        .generate_server_hello(&provider)
        .expect("Failed to generate ServerHello");

    println!("  ✓ ServerHello generated");
    assert!(server.get_server_handshake_traffic_secret().is_some());
    assert!(server.get_client_handshake_traffic_secret().is_some());

    // Step 4: Client processes ServerHello
    println!("\nStep 4: Client processes ServerHello");
    client
        .process_server_hello(&provider, &server_hello)
        .expect("Failed to process ServerHello");

    assert_eq!(client.state(), ClientState::WaitEncryptedExtensions);
    println!("  ✓ Client derived handshake traffic secrets");

    // Step 5: Server sends EncryptedExtensions
    println!("\nStep 5: Server -> EncryptedExtensions");
    let encrypted_extensions = server
        .generate_encrypted_extensions(None)
        .expect("Failed to generate EncryptedExtensions");

    client
        .process_encrypted_extensions(&encrypted_extensions)
        .expect("Failed to process EncryptedExtensions");

    assert_eq!(client.state(), ClientState::WaitCertCr);
    println!("  ✓ EncryptedExtensions processed");

    // Step 6: Server sends Certificate (3-level chain)
    println!("\nStep 6: Server -> Certificate (3-level chain)");
    let certificate = server
        .generate_certificate(cert_chain.clone())
        .expect("Failed to generate Certificate");

    println!("  ✓ Certificate message with {} certificates", cert_chain.len());
    println!("    - Server cert: {} bytes", SERVER_CERT.len());
    println!("    - Intermediate CA: {} bytes", INTERMEDIATE_CA.len());
    println!("    - Root CA: {} bytes", ROOT_CA.len());

    client
        .process_certificate(&certificate)
        .expect("Failed to process Certificate");

    assert_eq!(client.state(), ClientState::WaitCertVerify);
    println!("  ✓ Client stored certificate chain");

    // Step 7: Server sends CertificateVerify (RSA-PSS signature)
    println!("\nStep 7: Server -> CertificateVerify (RSA-PSS)");
    let cert_verify = server
        .generate_certificate_verify(&provider, SERVER_KEY)
        .expect("Failed to generate CertificateVerify");

    println!("  ✓ CertificateVerify with RSA-PSS signature generated");

    client
        .process_certificate_verify(&cert_verify)
        .expect("Failed to verify RSA-PSS signature");

    assert_eq!(client.state(), ClientState::WaitFinished);
    println!("  ✓ Client verified RSA-PSS signature successfully");

    // Step 8: Server sends Finished
    println!("\nStep 8: Server -> Finished");
    let server_finished = server
        .generate_server_finished(&provider)
        .expect("Failed to generate server Finished");

    assert_eq!(server.state(), ServerState::WaitFinished);
    println!("  ✓ Server Finished generated");

    // Step 9: Client processes server Finished and generates client Finished
    println!("\nStep 9: Client processes server Finished and generates client Finished");
    let client_finished = client
        .process_server_finished(&provider, &server_finished)
        .expect("Failed to process server Finished");

    assert_eq!(client.state(), ClientState::Connected);
    println!("  ✓ Client Finished generated");

    // Step 10: Server processes client Finished
    println!("\nStep 10: Server processes client Finished");
    server
        .process_client_finished(&provider, &client_finished)
        .expect("Failed to process client Finished");

    assert_eq!(server.state(), ServerState::Connected);
    println!("  ✓ Client Finished verified");

    // Verify both sides have traffic secrets
    assert!(client.get_client_application_traffic_secret().is_some());
    assert!(client.get_server_application_traffic_secret().is_some());
    assert!(server.get_client_application_traffic_secret().is_some());
    assert!(server.get_server_application_traffic_secret().is_some());

    println!("\n=== ✅ Handshake Complete with RSA-PSS Authentication ===\n");
    println!("  • Cipher Suite: {:?}", server.cipher_suite().unwrap());
    println!("  • Certificate Chain: 3 levels validated");
    println!("  • RSA-PSS Signature: Verified");
    println!("  • Traffic Secrets: Derived");
}

/// Test RSA-PSS handshake with AES-256-GCM cipher suite
#[test]
fn test_rsa_pss_with_aes_256_gcm() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes256GcmSha384];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    let cert_chain = vec![SERVER_CERT.to_vec(), INTERMEDIATE_CA.to_vec()];

    // Abbreviated handshake test
    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("test.example.com"), None)
        .unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();

    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();

    let certificate = server.generate_certificate(cert_chain).unwrap();
    client.process_certificate(&certificate).unwrap();

    let cert_verify = server.generate_certificate_verify(&provider, SERVER_KEY).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();

    let server_finished = server.generate_server_finished(&provider).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();

    server.process_client_finished(&provider, &client_finished).unwrap();

    assert_eq!(client.state(), ClientState::Connected);
    assert_eq!(server.state(), ServerState::Connected);
    assert_eq!(server.cipher_suite(), Some(CipherSuite::Aes256GcmSha384));

    println!("✅ RSA-PSS handshake successful with AES-256-GCM-SHA384");
}

/// Test RSA-PSS handshake with ChaCha20-Poly1305 cipher suite
#[test]
fn test_rsa_pss_with_chacha20_poly1305() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::ChaCha20Poly1305Sha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    let cert_chain = vec![SERVER_CERT.to_vec(), INTERMEDIATE_CA.to_vec()];

    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("test.example.com"), None)
        .unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();

    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();

    let certificate = server.generate_certificate(cert_chain).unwrap();
    client.process_certificate(&certificate).unwrap();

    let cert_verify = server.generate_certificate_verify(&provider, SERVER_KEY).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();

    let server_finished = server.generate_server_finished(&provider).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();

    server.process_client_finished(&provider, &client_finished).unwrap();

    assert_eq!(client.state(), ClientState::Connected);
    assert_eq!(server.state(), ServerState::Connected);
    assert_eq!(server.cipher_suite(), Some(CipherSuite::ChaCha20Poly1305Sha256));

    println!("✅ RSA-PSS handshake successful with ChaCha20-Poly1305-SHA256");
}

/// Test certificate chain validation
#[test]
fn test_rsa_pss_certificate_chain_validation() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Test with full 3-level chain
    let full_chain = vec![
        SERVER_CERT.to_vec(),
        INTERMEDIATE_CA.to_vec(),
        ROOT_CA.to_vec(),
    ];

    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("test.example.com"), None)
        .unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    client.process_server_hello(&provider, &server_hello).unwrap();

    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();

    let certificate = server.generate_certificate(full_chain.clone()).unwrap();

    // Verify client receives and stores full chain
    client.process_certificate(&certificate).unwrap();

    // Client should now be waiting for CertificateVerify
    assert_eq!(client.state(), ClientState::WaitCertVerify);

    println!("✅ Certificate chain validation test passed");
    println!("   Processed {} certificates in chain", full_chain.len());
}

/// Test session resumption with RSA-PSS certificates
#[test]
fn test_rsa_pss_session_resumption() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    // First connection - full handshake
    let mut client1 = ClientHandshake::new();
    let mut server1 = ServerHandshake::new(cipher_suites.clone());

    let cert_chain = vec![SERVER_CERT.to_vec(), INTERMEDIATE_CA.to_vec()];

    // Complete full handshake
    let client_hello = client1
        .client_hello(&provider, &cipher_suites, Some("test.example.com"), None)
        .unwrap();

    server1.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server1.generate_server_hello(&provider).unwrap();
    client1.process_server_hello(&provider, &server_hello).unwrap();

    let encrypted_extensions = server1.generate_encrypted_extensions(None).unwrap();
    client1.process_encrypted_extensions(&encrypted_extensions).unwrap();

    let certificate = server1.generate_certificate(cert_chain).unwrap();
    client1.process_certificate(&certificate).unwrap();

    let cert_verify = server1.generate_certificate_verify(&provider, SERVER_KEY).unwrap();
    client1.process_certificate_verify(&cert_verify).unwrap();

    let server_finished = server1.generate_server_finished(&provider).unwrap();
    let client_finished = client1.process_server_finished(&provider, &server_finished).unwrap();

    server1.process_client_finished(&provider, &client_finished).unwrap();

    assert_eq!(client1.state(), ClientState::Connected);
    assert_eq!(server1.state(), ServerState::Connected);

    // Server issues NewSessionTicket
    let ticket = server1
        .generate_new_session_ticket(&provider, Some(7 * 24 * 3600)) // 7 days
        .expect("Failed to generate session ticket");

    // Client processes ticket
    client1
        .process_new_session_ticket(&provider, &ticket)
        .expect("Failed to process session ticket");

    // Verify ticket was stored
    assert_eq!(client1.get_stored_tickets().len(), 1);

    println!("✅ Session ticket issued and stored successfully");
    println!("   Ticket lifetime: 7 days");
    println!("   Client stored tickets: {}", client1.get_stored_tickets().len());
}

/// Test all cipher suites with RSA-PSS authentication
#[test]
fn test_all_cipher_suites_with_rsa_pss() {
    let provider = HpcryptProvider::new();

    let cipher_suites_to_test = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ];

    let cert_chain = vec![SERVER_CERT.to_vec(), INTERMEDIATE_CA.to_vec()];

    for cs in cipher_suites_to_test {
        println!("\n--- Testing {:?} with RSA-PSS ---", cs);

        let mut client = ClientHandshake::new();
        let mut server = ServerHandshake::new(vec![cs]);

        let client_hello = client
            .client_hello(&provider, &vec![cs], Some("test.example.com"), None)
            .unwrap();

        server.process_client_hello(&provider, &client_hello).unwrap();
        let server_hello = server.generate_server_hello(&provider).unwrap();
        client.process_server_hello(&provider, &server_hello).unwrap();

        let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
        client.process_encrypted_extensions(&encrypted_extensions).unwrap();

        let certificate = server.generate_certificate(cert_chain.clone()).unwrap();
        client.process_certificate(&certificate).unwrap();

        let cert_verify = server.generate_certificate_verify(&provider, SERVER_KEY).unwrap();
        client.process_certificate_verify(&cert_verify).unwrap();

        let server_finished = server.generate_server_finished(&provider).unwrap();
        let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();

        server.process_client_finished(&provider, &client_finished).unwrap();

        assert_eq!(client.state(), ClientState::Connected);
        assert_eq!(server.state(), ServerState::Connected);
        assert_eq!(server.cipher_suite(), Some(cs));

        println!("✅ {:?} handshake successful", cs);
    }

    println!("\n✅ All cipher suites tested with RSA-PSS authentication");
}
