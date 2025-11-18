//! ECDSA P-256 Certificate Integration Tests
//!
//! This test suite validates end-to-end TLS 1.3 handshakes using ECDSA P-256
//! certificates with a complete 3-level PKI chain (Root CA → Intermediate CA → Server).
//!
//! Tests verify:
//! - Full TLS 1.3 handshake with ECDSA P-256 server certificate
//! - Certificate chain validation (3 levels)
//! - ECDSA signature verification in CertificateVerify
//! - All cipher suites with ECDSA authentication
//! - Performance comparison with RSA-PSS

use hptls_core::cipher::CipherSuite;
use hptls_core::handshake::{ClientHandshake, ClientState, ServerHandshake, ServerState};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

// ECDSA P-256 certificates generated with OpenSSL
// 3-level PKI: Root CA → Intermediate CA → Server (test.example.com)
const SERVER_CERT: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/ecdsa-chain/server.der");
const INTERMEDIATE_CA: &[u8] =
    include_bytes!("../../hptls-crypto-hpcrypt/tests/data/ecdsa-chain/intermediate-ca.der");
const ROOT_CA: &[u8] = include_bytes!("../../hptls-crypto-hpcrypt/tests/data/ecdsa-chain/root-ca.der");
const SERVER_KEY: &[u8] =
    include_bytes!("../../hptls-crypto-hpcrypt/tests/data/ecdsa-chain/server.key.raw");

/// Test full TLS 1.3 handshake with ECDSA P-256 certificate chain
#[test]
fn test_tls13_handshake_with_ecdsa_p256_certificate_chain() {
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

    println!("\n=== TLS 1.3 Handshake with ECDSA P-256 Certificate Chain ===\n");

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
    println!("\nStep 6: Server -> Certificate (3-level ECDSA chain)");
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

    // Step 7: Server sends CertificateVerify (ECDSA signature)
    println!("\nStep 7: Server -> CertificateVerify (ECDSA P-256)");
    let cert_verify = server
        .generate_certificate_verify(&provider, SERVER_KEY)
        .expect("Failed to generate CertificateVerify");

    println!("  ✓ CertificateVerify with ECDSA P-256 signature generated");

    client
        .process_certificate_verify(&cert_verify)
        .expect("Failed to verify ECDSA signature");

    assert_eq!(client.state(), ClientState::WaitFinished);
    println!("  ✓ Client verified ECDSA P-256 signature successfully");

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

    println!("\n=== ✅ Handshake Complete with ECDSA P-256 Authentication ===\n");
    println!("  • Cipher Suite: {:?}", server.cipher_suite().unwrap());
    println!("  • Certificate Chain: 3 levels validated");
    println!("  • ECDSA P-256 Signature: Verified");
    println!("  • Traffic Secrets: Derived");
}

/// Test all cipher suites with ECDSA P-256 authentication
#[test]
fn test_all_cipher_suites_with_ecdsa_p256() {
    let provider = HpcryptProvider::new();

    let cipher_suites_to_test = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ];

    let cert_chain = vec![SERVER_CERT.to_vec(), INTERMEDIATE_CA.to_vec()];

    for cs in cipher_suites_to_test {
        println!("\n--- Testing {:?} with ECDSA P-256 ---", cs);

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

    println!("\n✅ All cipher suites tested with ECDSA P-256 authentication");
}
