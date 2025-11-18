//! PSK Resumption Integration Tests
//!
//! This test module verifies the complete end-to-end PSK-based session resumption flow,
//! including both client and server sides.
//!
//! Tested functionality:
//! - Client offers PSK in ClientHello
//! - Server validates PSK binder
//! - Server accepts PSK and indicates in ServerHello
//! - Key derivation with PSK
//! - Complete handshake with PSK resumption

use hptls_core::cipher::CipherSuite;
use hptls_core::handshake::client::StoredTicket as ClientTicket;
use hptls_core::handshake::server::ServerTicket;
use hptls_core::handshake::{ClientHandshake, ServerHandshake};
use hptls_crypto::{CryptoProvider, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;
use zeroize::Zeroizing;

/// Helper: Generate test certificate
fn generate_test_certificate(
    provider: &dyn CryptoProvider,
    sig_algorithm: SignatureAlgorithm,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_size = match sig_algorithm {
        SignatureAlgorithm::Ed25519 => 32,
        SignatureAlgorithm::EcdsaSecp256r1Sha256 => 32,
        SignatureAlgorithm::EcdsaSecp384r1Sha384 => 48,
        _ => panic!("Unsupported signature algorithm"),
    };

    let key = provider.random().generate(key_size)?;
    Ok(key)
}

/// Helper: Perform initial full handshake and get tickets
fn perform_initial_handshake_with_ticket(
    cipher_suite: CipherSuite,
) -> Result<(ClientTicket, ServerTicket), Box<dyn std::error::Error>> {
    let provider = HpcryptProvider::new();

    // Phase 1: Full handshake
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![cipher_suite]);

    // ClientHello
    let client_hello = client.client_hello(
        &provider,
        &[cipher_suite],
        Some("psk-test.example.com"),
        None,
    )?;

    // Server processes ClientHello
    server.process_client_hello(&provider, &client_hello)?;

    // ServerHello
    let server_hello = server.generate_server_hello(&provider)?;

    // Client processes ServerHello
    client.process_server_hello(&provider, &server_hello)?;

    // EncryptedExtensions
    let encrypted_extensions = server.generate_encrypted_extensions(None)?;
    client.process_encrypted_extensions(&encrypted_extensions)?;

    // Certificate
    let test_cert = generate_test_certificate(&provider, SignatureAlgorithm::Ed25519)?;
    let certificate = server.generate_certificate(vec![test_cert.clone()])?;
    client.process_certificate(&certificate)?;

    // CertificateVerify
    let cert_verify = server.generate_certificate_verify(&provider, &test_cert)?;
    client.process_certificate_verify(&cert_verify)?;

    // Finished messages
    let server_finished = server.generate_server_finished(&provider)?;
    let client_finished = client.process_server_finished(&provider, &server_finished)?;
    server.process_client_finished(&provider, &client_finished)?;

    // Both should be connected
    assert!(client.is_connected());
    assert!(server.is_connected());

    // Phase 2: Issue NewSessionTicket
    let ticket_msg = server.generate_new_session_ticket(&provider, Some(7200))?;
    let client_ticket = client.process_new_session_ticket(&provider, &ticket_msg)?;

    // Phase 3: Create matching server ticket
    // In production, server would encrypt this info into the ticket blob
    // For testing, we simulate by creating a matching ServerTicket
    let server_ticket = ServerTicket {
        ticket: ticket_msg.ticket.clone(),
        psk: client_ticket.psk.clone(),
        cipher_suite,
        issued_at: client_ticket.received_at,
        lifetime: ticket_msg.ticket_lifetime,
        ticket_age_add: ticket_msg.ticket_age_add,
    };

    Ok((client_ticket, server_ticket))
}

#[test]
fn test_psk_resumption_server_validates_binder() {
    println!("\n========================================");
    println!("  TEST: Server PSK Binder Validation");
    println!("========================================\n");

    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    // Get tickets from initial handshake
    let (client_ticket, server_ticket) =
        perform_initial_handshake_with_ticket(cipher_suite).unwrap();

    println!("✅ Initial handshake complete, tickets issued");

    // Create new client and server for resumption
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![cipher_suite]);

    // Store ticket on server
    server.store_ticket(server_ticket.clone());

    println!("✅ Server stored ticket");

    // Client generates ClientHello with PSK
    let client_hello_with_psk = client
        .client_hello_with_psk(
            &provider,
            &[cipher_suite],
            Some("psk-test.example.com"),
            None,
            &client_ticket,
        )
        .unwrap();

    println!("✅ Client generated ClientHello with PSK");

    // Server processes ClientHello (should validate binder and select PSK)
    server.process_client_hello(&provider, &client_hello_with_psk).unwrap();

    println!("✅ Server processed ClientHello");

    // Verify server selected PSK
    assert!(
        server.is_psk_resumption(),
        "Server should have selected PSK"
    );

    println!("✅ Server validated binder and selected PSK");
}

#[test]
fn test_psk_resumption_server_hello_indicates_psk() {
    println!("\n========================================");
    println!("  TEST: ServerHello PSK Indication");
    println!("========================================\n");

    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    let (client_ticket, server_ticket) =
        perform_initial_handshake_with_ticket(cipher_suite).unwrap();

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![cipher_suite]);
    server.store_ticket(server_ticket);

    // Client offers PSK
    let client_hello_with_psk = client
        .client_hello_with_psk(
            &provider,
            &[cipher_suite],
            Some("psk-test.example.com"),
            None,
            &client_ticket,
        )
        .unwrap();

    // Server processes and generates ServerHello
    server.process_client_hello(&provider, &client_hello_with_psk).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();

    println!("✅ ServerHello generated");

    // Verify ServerHello contains PSK extension
    let psk_server_ext = server_hello.extensions.get_pre_shared_key_server().unwrap();
    assert!(
        psk_server_ext.is_some(),
        "ServerHello should contain PSK extension"
    );

    let psk_ext = psk_server_ext.unwrap();
    assert_eq!(
        psk_ext.selected_identity, 0,
        "Server should select identity 0"
    );

    println!("✅ ServerHello indicates PSK acceptance (selected_identity = 0)");
}

#[test]
fn test_psk_resumption_invalid_binder_rejected() {
    println!("\n========================================");
    println!("  TEST: Invalid PSK Binder Rejection");
    println!("========================================\n");

    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    let (mut client_ticket, server_ticket) =
        perform_initial_handshake_with_ticket(cipher_suite).unwrap();

    // Corrupt the PSK to make binder invalid
    client_ticket.psk = Zeroizing::new(vec![0xFF; 32]);

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![cipher_suite]);
    server.store_ticket(server_ticket);

    // Client generates ClientHello with corrupted PSK (will have invalid binder)
    let client_hello_with_psk = client
        .client_hello_with_psk(
            &provider,
            &[cipher_suite],
            Some("psk-test.example.com"),
            None,
            &client_ticket,
        )
        .unwrap();

    println!("✅ Client generated ClientHello with invalid PSK");

    // Server processes ClientHello
    server.process_client_hello(&provider, &client_hello_with_psk).unwrap();

    // Server should NOT select PSK (invalid binder)
    assert!(
        !server.is_psk_resumption(),
        "Server should reject invalid binder"
    );

    println!("✅ Server correctly rejected invalid PSK binder");
}

#[test]
fn test_psk_resumption_expired_ticket_rejected() {
    println!("\n========================================");
    println!("  TEST: Expired Ticket Rejection");
    println!("========================================\n");

    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    let (client_ticket, mut server_ticket) =
        perform_initial_handshake_with_ticket(cipher_suite).unwrap();

    // Make ticket expired on server side
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    server_ticket.issued_at = now - 10000; // 10000 seconds ago
    server_ticket.lifetime = 3600; // 1 hour lifetime

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![cipher_suite]);
    server.store_ticket(server_ticket);

    // Client offers PSK
    let client_hello_with_psk = client
        .client_hello_with_psk(
            &provider,
            &[cipher_suite],
            Some("psk-test.example.com"),
            None,
            &client_ticket,
        )
        .unwrap();

    // Server processes ClientHello
    server.process_client_hello(&provider, &client_hello_with_psk).unwrap();

    // Server should NOT select PSK (expired ticket)
    assert!(
        !server.is_psk_resumption(),
        "Server should reject expired ticket"
    );

    println!("✅ Server correctly rejected expired ticket");
}

#[test]
fn test_psk_resumption_unknown_ticket_rejected() {
    println!("\n========================================");
    println!("  TEST: Unknown Ticket Rejection");
    println!("========================================\n");

    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    let (client_ticket, _server_ticket) =
        perform_initial_handshake_with_ticket(cipher_suite).unwrap();

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![cipher_suite]);
    // Note: NOT storing the ticket on server

    // Client offers PSK
    let client_hello_with_psk = client
        .client_hello_with_psk(
            &provider,
            &[cipher_suite],
            Some("psk-test.example.com"),
            None,
            &client_ticket,
        )
        .unwrap();

    // Server processes ClientHello
    server.process_client_hello(&provider, &client_hello_with_psk).unwrap();

    // Server should NOT select PSK (unknown ticket)
    assert!(
        !server.is_psk_resumption(),
        "Server should reject unknown ticket"
    );

    println!("✅ Server correctly rejected unknown ticket");
}

#[test]
fn test_psk_resumption_cipher_suite_mismatch() {
    println!("\n========================================");
    println!("  TEST: Cipher Suite Mismatch");
    println!("========================================\n");

    let provider = HpcryptProvider::new();
    let original_cipher = CipherSuite::Aes128GcmSha256;
    let different_cipher = CipherSuite::Aes256GcmSha384;

    let (client_ticket, server_ticket) =
        perform_initial_handshake_with_ticket(original_cipher).unwrap();

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![different_cipher]);
    server.store_ticket(server_ticket);

    // Client offers PSK with different cipher suite
    let client_hello_with_psk = client
        .client_hello_with_psk(
            &provider,
            &[different_cipher],
            Some("psk-test.example.com"),
            None,
            &client_ticket,
        )
        .unwrap();

    // Server processes ClientHello
    server.process_client_hello(&provider, &client_hello_with_psk).unwrap();

    // Server should NOT select PSK (cipher suite mismatch)
    assert!(
        !server.is_psk_resumption(),
        "Server should reject PSK with mismatched cipher suite"
    );

    println!("✅ Server correctly rejected PSK with cipher suite mismatch");
}

#[test]
fn test_full_psk_resumption_handshake() {
    println!("\n========================================");
    println!("  TEST: Full PSK Resumption Handshake");
    println!("========================================\n");

    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    // Phase 1: Get tickets
    println!("Phase 1: Initial Handshake & Ticket Issuance");
    let (client_ticket, server_ticket) =
        perform_initial_handshake_with_ticket(cipher_suite).unwrap();
    println!("✅ Tickets obtained");

    // Phase 2: PSK Resumption Handshake
    println!("\nPhase 2: PSK Resumption Handshake");

    let mut client2 = ClientHandshake::new();
    let mut server2 = ServerHandshake::new(vec![cipher_suite]);
    server2.store_ticket(server_ticket);

    // Step 1: Client -> ClientHello with PSK
    println!("  Step 1: Client -> ClientHello with PSK");
    let client_hello = client2
        .client_hello_with_psk(
            &provider,
            &[cipher_suite],
            Some("psk-test.example.com"),
            None,
            &client_ticket,
        )
        .unwrap();

    // Verify PSK extension present
    assert!(client_hello.extensions.get_pre_shared_key().unwrap().is_some());
    println!("    ✅ PSK extension present");

    // Step 2: Server processes ClientHello
    println!("  Step 2: Server processes ClientHello");
    server2.process_client_hello(&provider, &client_hello).unwrap();
    assert!(server2.is_psk_resumption());
    println!("    ✅ Server selected PSK");

    // Step 3: Server -> ServerHello
    println!("  Step 3: Server -> ServerHello");
    let server_hello = server2.generate_server_hello(&provider).unwrap();

    // Verify PSK indication in ServerHello
    let psk_ext = server_hello.extensions.get_pre_shared_key_server().unwrap();
    assert!(psk_ext.is_some());
    assert_eq!(psk_ext.unwrap().selected_identity, 0);
    println!("    ✅ ServerHello indicates PSK acceptance");

    // Step 4: Client processes ServerHello
    println!("  Step 4: Client processes ServerHello");
    client2.process_server_hello(&provider, &server_hello).unwrap();
    println!("    ✅ Client processed ServerHello");

    // Step 5: EncryptedExtensions
    println!("  Step 5: Server -> EncryptedExtensions");
    let encrypted_extensions = server2.generate_encrypted_extensions(None).unwrap();
    client2.process_encrypted_extensions(&encrypted_extensions).unwrap();
    println!("    ✅ EncryptedExtensions processed");

    // Step 6: Certificate (still required even with PSK+DHE)
    println!("  Step 6: Server -> Certificate");
    let test_cert = generate_test_certificate(&provider, SignatureAlgorithm::Ed25519).unwrap();
    let certificate = server2.generate_certificate(vec![test_cert.clone()]).unwrap();
    client2.process_certificate(&certificate).unwrap();
    println!("    ✅ Certificate processed");

    // Step 7: CertificateVerify
    println!("  Step 7: Server -> CertificateVerify");
    let cert_verify = server2.generate_certificate_verify(&provider, &test_cert).unwrap();
    client2.process_certificate_verify(&cert_verify).unwrap();
    println!("    ✅ CertificateVerify processed");

    // Step 8: Finished messages
    println!("  Step 8: Finished exchange");
    let server_finished = server2.generate_server_finished(&provider).unwrap();
    let client_finished = client2.process_server_finished(&provider, &server_finished).unwrap();
    server2.process_client_finished(&provider, &client_finished).unwrap();
    println!("    ✅ Finished messages exchanged");

    // Verify both sides connected
    assert!(client2.is_connected());
    assert!(server2.is_connected());

    println!("\n========================================");
    println!("✅ FULL PSK RESUMPTION HANDSHAKE SUCCESS!");
    println!("========================================");
}

#[test]
fn test_psk_key_derivation() {
    println!("\n========================================");
    println!("  TEST: PSK-Based Key Derivation");
    println!("========================================\n");

    let provider = HpcryptProvider::new();
    let cipher_suite = CipherSuite::Aes128GcmSha256;

    let (client_ticket, server_ticket) =
        perform_initial_handshake_with_ticket(cipher_suite).unwrap();

    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![cipher_suite]);
    server.store_ticket(server_ticket);

    // Perform PSK handshake up to ServerHello
    let client_hello = client
        .client_hello_with_psk(
            &provider,
            &[cipher_suite],
            Some("psk-test.example.com"),
            None,
            &client_ticket,
        )
        .unwrap();

    server.process_client_hello(&provider, &client_hello).unwrap();
    let server_hello = server.generate_server_hello(&provider).unwrap();

    client.process_server_hello(&provider, &server_hello).unwrap();

    // At this point, both sides should have derived handshake keys
    // Verify keys are present
    let client_hs_secret = client.get_client_handshake_traffic_secret();
    let server_hs_secret = client.get_server_handshake_traffic_secret();

    assert!(
        client_hs_secret.is_some(),
        "Client should have handshake traffic secret"
    );
    assert!(
        server_hs_secret.is_some(),
        "Server should have handshake traffic secret"
    );

    println!("✅ Handshake traffic secrets derived");
    println!(
        "   Client handshake secret: {} bytes",
        client_hs_secret.unwrap().len()
    );
    println!(
        "   Server handshake secret: {} bytes",
        server_hs_secret.unwrap().len()
    );
}
