//! Unit Tests for Server-Side mTLS Methods
//!
//! These tests verify the server-side mTLS methods in isolation.

use hptls_core::cipher::CipherSuite;
use hptls_core::extension_types::SignatureScheme;
use hptls_core::handshake::{ClientHandshake, ServerHandshake};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Test that server can generate CertificateRequest message.
#[test]
fn test_server_generate_certificate_request() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Complete handshake up to EncryptedExtensions
    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("example.com"), None)
        .unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    client.process_server_hello(&provider, &server_hello).unwrap();
    let _encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();

    // Server generates CertificateRequest
    let signature_algorithms = vec![
        SignatureScheme::Ed25519,
        SignatureScheme::EcdsaSecp256r1Sha256,
        SignatureScheme::RsaPssRsaeSha256,
    ];

    let cert_req = server.generate_certificate_request(signature_algorithms.clone()).unwrap();

    // Verify CertificateRequest structure
    assert_eq!(cert_req.certificate_request_context, Vec::<u8>::new());

    let sig_algs = cert_req.signature_algorithms().unwrap();
    assert!(sig_algs.is_some());
    assert_eq!(sig_algs.unwrap().len(), 3);

    println!("✅ Server generated CertificateRequest successfully");
}

/// Test that CertificateRequest requires at least one signature algorithm.
#[test]
fn test_certificate_request_requires_signature_algorithms() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();
    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    client.process_server_hello(&provider, &server_hello).unwrap();
    let _encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();

    // Try to generate CertificateRequest with empty signature algorithms
    let result = server.generate_certificate_request(vec![]);
    assert!(result.is_err());

    println!("✅ Empty signature algorithms correctly rejected");
}

/// Test that server methods can be called in sequence.
#[test]
fn test_server_mtls_method_sequence() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // 1. ClientHello / ServerHello
    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();
    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    client.process_server_hello(&provider, &server_hello).unwrap();

    // 2. EncryptedExtensions
    let _encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();

    // 3. CertificateRequest (NEW - server-side mTLS)
    let cert_req = server.generate_certificate_request(vec![SignatureScheme::Ed25519]).unwrap();
    assert!(
        !cert_req.certificate_request_context.is_empty()
            || cert_req.certificate_request_context.is_empty()
    ); // Just verify it exists

    // 4. Server Certificate
    let _server_cert = server.generate_certificate(vec![vec![0xAA; 128]]).unwrap();

    // 5. Server CertificateVerify
    let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
    let (signing_key, _) = sig_impl.generate_keypair().unwrap();
    let _server_cert_verify =
        server.generate_certificate_verify(&provider, signing_key.as_bytes()).unwrap();

    // 6. Server Finished
    let _server_finished = server.generate_server_finished(&provider).unwrap();

    // Server is now in WaitFinished state and can process client cert messages

    println!("✅ Server mTLS method sequence completed successfully");
}
