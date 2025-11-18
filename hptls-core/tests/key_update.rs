//! Integration tests for TLS 1.3 KeyUpdate functionality.
//!
//! These tests verify the KeyUpdate message handling and traffic secret rotation
//! as specified in RFC 8446 Section 4.6.3.

use hptls_core::{
    cipher::CipherSuite,
    handshake::{ClientHandshake, ServerHandshake},
    messages::key_update::KeyUpdateRequest,
    protocol::ContentType,
    record_protection::RecordProtection,
};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Test that client can initiate a key update without requesting peer update.
#[test]
fn test_client_initiated_key_update_without_request() {
    let provider = HpcryptProvider::new();

    // Phase 1: Complete handshake to establish connection
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384];

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Perform full handshake (abbreviated for brevity)
    let client_hello = client
        .client_hello(&provider, &cipher_suites, Some("example.com"), None)
        .unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    let certificate = server.generate_certificate(vec![b"cert".to_vec()]).unwrap();
    let cert_verify = server
        .generate_certificate_verify(&provider, &{
            let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
            let (signing_key, _) = sig_impl.generate_keypair().unwrap();
            signing_key.as_bytes().to_vec()
        })
        .unwrap();
    let server_finished = server.generate_server_finished(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();
    client.process_certificate(&certificate).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();

    server.process_client_finished(&provider, &client_finished).unwrap();

    // Verify both are connected
    assert!(client.is_connected());
    assert!(server.is_connected());

    // Phase 2: Client initiates key update (without requesting server to update)
    let old_client_secret = client.get_client_application_traffic_secret().unwrap().to_vec();

    let key_update =
        client.send_key_update(&provider, KeyUpdateRequest::UpdateNotRequested).unwrap();

    assert_eq!(
        key_update.request_update,
        KeyUpdateRequest::UpdateNotRequested
    );

    // Verify client secret has been updated
    let new_client_secret = client.get_client_application_traffic_secret().unwrap().to_vec();

    assert_ne!(old_client_secret, new_client_secret);

    // Server's secrets should remain unchanged since no update was requested
    let server_secret = server.get_server_application_traffic_secret().unwrap();
    assert!(server_secret.len() > 0);
}

/// Test that client can request peer to also update keys.
#[test]
fn test_client_initiated_key_update_with_request() {
    let provider = HpcryptProvider::new();

    // Phase 1: Complete handshake
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    // Abbreviated handshake
    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();
    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    let certificate = server.generate_certificate(vec![b"cert".to_vec()]).unwrap();
    let cert_verify = server
        .generate_certificate_verify(&provider, &{
            let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
            let (signing_key, _) = sig_impl.generate_keypair().unwrap();
            signing_key.as_bytes().to_vec()
        })
        .unwrap();
    let server_finished = server.generate_server_finished(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();
    client.process_certificate(&certificate).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();
    server.process_client_finished(&provider, &client_finished).unwrap();

    // Phase 2: Client sends KeyUpdate with update request
    let old_client_secret = client.get_client_application_traffic_secret().unwrap().to_vec();
    let old_server_secret_at_client =
        client.get_server_application_traffic_secret().unwrap().to_vec();

    let key_update = client.send_key_update(&provider, KeyUpdateRequest::UpdateRequested).unwrap();

    assert_eq!(key_update.request_update, KeyUpdateRequest::UpdateRequested);

    // Verify client's sending secret updated
    let new_client_secret = client.get_client_application_traffic_secret().unwrap().to_vec();
    assert_ne!(old_client_secret, new_client_secret);

    // Phase 3: Server processes KeyUpdate and responds
    let old_server_secret = server.get_server_application_traffic_secret().unwrap().to_vec();

    let (new_client_secret_at_server, response) =
        server.process_key_update(&provider, &key_update).unwrap();

    // Server should have updated client's receiving secret
    assert_ne!(old_client_secret, new_client_secret_at_server);
    assert_eq!(new_client_secret, new_client_secret_at_server);

    // Server should send a KeyUpdate response (without requesting further update)
    let response_ku = response.expect("Server should respond with KeyUpdate");
    assert_eq!(
        response_ku.request_update,
        KeyUpdateRequest::UpdateNotRequested
    );

    // Server's sending secret should also be updated
    let new_server_secret = server.get_server_application_traffic_secret().unwrap();
    assert_ne!(old_server_secret.as_slice(), new_server_secret);
}

/// Test server-initiated key update.
#[test]
fn test_server_initiated_key_update() {
    let provider = HpcryptProvider::new();

    // Phase 1: Complete handshake
    let cipher_suites = vec![CipherSuite::Aes256GcmSha384];
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();
    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    let certificate = server.generate_certificate(vec![b"cert".to_vec()]).unwrap();
    let cert_verify = server
        .generate_certificate_verify(&provider, &{
            let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
            let (signing_key, _) = sig_impl.generate_keypair().unwrap();
            signing_key.as_bytes().to_vec()
        })
        .unwrap();
    let server_finished = server.generate_server_finished(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();
    client.process_certificate(&certificate).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();
    server.process_client_finished(&provider, &client_finished).unwrap();

    // Phase 2: Server initiates key update
    let old_server_secret = server.get_server_application_traffic_secret().unwrap().to_vec();

    let key_update =
        server.send_key_update(&provider, KeyUpdateRequest::UpdateNotRequested).unwrap();

    let new_server_secret = server.get_server_application_traffic_secret().unwrap();
    assert_ne!(old_server_secret.as_slice(), new_server_secret);

    // Phase 3: Client processes server's KeyUpdate
    let old_server_secret_at_client =
        client.get_server_application_traffic_secret().unwrap().to_vec();

    let (new_server_secret_at_client, response) =
        client.process_key_update(&provider, &key_update).unwrap();

    assert_eq!(new_server_secret, new_server_secret_at_client.as_slice());
    assert!(response.is_none()); // No update was requested, so no response
}

/// Test key update with RecordProtection (traffic secret rotation).
#[test]
fn test_key_update_with_record_protection() {
    let provider = HpcryptProvider::new();

    // Phase 1: Complete handshake
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();
    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    let certificate = server.generate_certificate(vec![b"cert".to_vec()]).unwrap();
    let cert_verify = server
        .generate_certificate_verify(&provider, &{
            let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
            let (signing_key, _) = sig_impl.generate_keypair().unwrap();
            signing_key.as_bytes().to_vec()
        })
        .unwrap();
    let server_finished = server.generate_server_finished(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();
    client.process_certificate(&certificate).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();
    server.process_client_finished(&provider, &client_finished).unwrap();

    // Phase 2: Setup record protection with initial secrets
    let mut client_writer = RecordProtection::new(
        &provider,
        CipherSuite::Aes128GcmSha256,
        client.get_client_application_traffic_secret().unwrap(),
    )
    .unwrap();

    let mut server_reader = RecordProtection::new(
        &provider,
        CipherSuite::Aes128GcmSha256,
        server.get_client_application_traffic_secret().unwrap(),
    )
    .unwrap();

    // Phase 3: Send message before key update
    let message1 = b"Message before key update";
    let encrypted1 = client_writer
        .encrypt(&provider, ContentType::ApplicationData, message1)
        .unwrap();
    let decrypted1 = server_reader.decrypt(&provider, &encrypted1).unwrap();
    assert_eq!(decrypted1.fragment, message1);

    // Phase 4: Perform key update
    let _key_update =
        client.send_key_update(&provider, KeyUpdateRequest::UpdateNotRequested).unwrap();

    let new_client_secret = client.get_client_application_traffic_secret().unwrap();

    // Update record protection with new secret
    client_writer.update_traffic_secret(&provider, new_client_secret).unwrap();

    // Sequence number should be reset
    assert_eq!(client_writer.sequence_number(), 0);

    // Phase 5: Server updates its receiving keys
    server_reader.update_traffic_secret(&provider, new_client_secret).unwrap();
    assert_eq!(server_reader.sequence_number(), 0);

    // Phase 6: Send message after key update
    let message2 = b"Message after key update";
    let encrypted2 = client_writer
        .encrypt(&provider, ContentType::ApplicationData, message2)
        .unwrap();
    let decrypted2 = server_reader.decrypt(&provider, &encrypted2).unwrap();
    assert_eq!(decrypted2.fragment, message2);

    // Verify the new message uses different encryption (ciphertext should differ even for same plaintext)
    let encrypted1_again = client_writer
        .encrypt(&provider, ContentType::ApplicationData, message1)
        .unwrap();
    // Even though plaintext is same as message1, ciphertext should differ due to sequence number
    assert_ne!(
        encrypted1.encrypted_record,
        encrypted1_again.encrypted_record
    );
}

/// Test that KeyUpdate cannot be sent before connection is established.
#[test]
fn test_key_update_fails_before_connected() {
    let provider = HpcryptProvider::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    let mut client = ClientHandshake::new();

    // Try to send KeyUpdate before handshake completes
    let result = client.send_key_update(&provider, KeyUpdateRequest::UpdateNotRequested);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("before connection is established"));
}

/// Test multiple consecutive key updates.
#[test]
fn test_multiple_key_updates() {
    let provider = HpcryptProvider::new();

    // Phase 1: Complete handshake
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(cipher_suites.clone());

    let client_hello = client.client_hello(&provider, &cipher_suites, None, None).unwrap();
    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();
    let encrypted_extensions = server.generate_encrypted_extensions(None).unwrap();
    let certificate = server.generate_certificate(vec![b"cert".to_vec()]).unwrap();
    let cert_verify = server
        .generate_certificate_verify(&provider, &{
            let sig_impl = provider.signature(hptls_crypto::SignatureAlgorithm::Ed25519).unwrap();
            let (signing_key, _) = sig_impl.generate_keypair().unwrap();
            signing_key.as_bytes().to_vec()
        })
        .unwrap();
    let server_finished = server.generate_server_finished(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();
    client.process_encrypted_extensions(&encrypted_extensions).unwrap();
    client.process_certificate(&certificate).unwrap();
    client.process_certificate_verify(&cert_verify).unwrap();
    let client_finished = client.process_server_finished(&provider, &server_finished).unwrap();
    server.process_client_finished(&provider, &client_finished).unwrap();

    // Phase 2: Perform multiple key updates
    let mut secrets = vec![];
    secrets.push(client.get_client_application_traffic_secret().unwrap().to_vec());

    for i in 0..5 {
        let _key_update =
            client.send_key_update(&provider, KeyUpdateRequest::UpdateNotRequested).unwrap();

        let new_secret = client.get_client_application_traffic_secret().unwrap().to_vec();
        secrets.push(new_secret);

        // Verify each new secret is different from all previous secrets
        for j in 0..=i {
            assert_ne!(secrets[j], secrets[i + 1]);
        }
    }

    // After 5 updates, we should have 6 different secrets (initial + 5 updates)
    assert_eq!(secrets.len(), 6);
}
