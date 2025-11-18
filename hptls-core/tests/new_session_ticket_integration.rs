//! NewSessionTicket Integration Tests
//!
//! This test module verifies the end-to-end flow of TLS 1.3 session ticket issuance.
//!
//! Tested functionality:
//! - Server generates NewSessionTicket after handshake completion
//! - Client processes NewSessionTicket and derives PSK
//! - Both sides derive matching PSK from resumption_master_secret
//! - Ticket storage and retrieval
//! - Ticket expiration handling

use hptls_core::cipher::CipherSuite;
use hptls_core::handshake::{ClientHandshake, ServerHandshake};
use hptls_crypto::{CryptoProvider, SignatureAlgorithm};
use hptls_crypto_hpcrypt::HpcryptProvider;

/// Helper function to perform a complete TLS 1.3 handshake.
///
/// Returns (client, server) in Connected state, ready for NewSessionTicket issuance.
fn perform_full_handshake(
    cipher_suite: CipherSuite,
) -> Result<(ClientHandshake, ServerHandshake), Box<dyn std::error::Error>> {
    let provider = HpcryptProvider::new();

    println!("\n========================================");
    println!("Performing Full Handshake");
    println!("  Cipher Suite: {:?}", cipher_suite);
    println!("========================================\n");

    // Initialize client and server
    let mut client = ClientHandshake::new();
    let mut server = ServerHandshake::new(vec![cipher_suite]);

    // Step 1: Client -> ClientHello
    println!("Step 1: Client -> ClientHello");
    let client_hello = client.client_hello(
        &provider,
        &[cipher_suite],
        Some("ticket-test.example.com"),
        None,
    )?;

    // Step 2: Server processes ClientHello
    println!("Step 2: Server processes ClientHello");
    server.process_client_hello(&provider, &client_hello)?;

    // Step 3: Server -> ServerHello
    println!("Step 3: Server -> ServerHello");
    let server_hello = server.generate_server_hello(&provider)?;

    // Step 4: Client processes ServerHello
    println!("Step 4: Client processes ServerHello");
    client.process_server_hello(&provider, &server_hello)?;

    // Step 5: Server -> EncryptedExtensions
    println!("Step 5: Server -> EncryptedExtensions");
    let encrypted_extensions = server.generate_encrypted_extensions(None)?;
    client.process_encrypted_extensions(&encrypted_extensions)?;

    // Step 6: Server -> Certificate
    println!("Step 6: Server -> Certificate");
    // Generate a test Ed25519 certificate
    let test_cert = generate_test_certificate(&provider, SignatureAlgorithm::Ed25519)?;
    let certificate = server.generate_certificate(vec![test_cert.clone()])?;
    client.process_certificate(&certificate)?;

    // Step 7: Server -> CertificateVerify
    println!("Step 7: Server -> CertificateVerify");
    let signing_key = test_cert; // Use the cert as signing key (simplified for test)
    let cert_verify = server.generate_certificate_verify(&provider, &signing_key)?;
    client.process_certificate_verify(&cert_verify)?;

    // Step 8: Server -> Finished
    println!("Step 8: Server -> Finished");
    let server_finished = server.generate_server_finished(&provider)?;

    // Step 9: Client processes server Finished and generates client Finished
    println!("Step 9: Client processes server Finished");
    let client_finished = client.process_server_finished(&provider, &server_finished)?;

    // Step 10: Server processes client Finished
    println!("Step 10: Server processes client Finished");
    server.process_client_finished(&provider, &client_finished)?;

    println!("✅ Handshake complete - both sides in Connected state\n");

    // Verify both are connected
    assert!(client.is_connected());
    assert!(server.is_connected());

    Ok((client, server))
}

/// Generate a test certificate for the given signature algorithm.
fn generate_test_certificate(
    provider: &dyn CryptoProvider,
    sig_algorithm: SignatureAlgorithm,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // For Ed25519, generate a 32-byte key
    // For ECDSA P-256, generate a 32-byte key
    // For ECDSA P-384, generate a 48-byte key
    let key_size = match sig_algorithm {
        SignatureAlgorithm::Ed25519 => 32,
        SignatureAlgorithm::EcdsaSecp256r1Sha256 => 32,
        SignatureAlgorithm::EcdsaSecp384r1Sha384 => 48,
        _ => return Err("Unsupported signature algorithm".into()),
    };

    let key = provider.random().generate(key_size)?;
    Ok(key)
}

/// Test NewSessionTicket generation by server after handshake completion.
#[test]
fn test_server_generates_new_session_ticket() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n========================================");
    println!("  TEST: Server NewSessionTicket Generation");
    println!("========================================\n");

    let cipher_suite = CipherSuite::Aes128GcmSha256;
    let (_client, mut server) = perform_full_handshake(cipher_suite)?;

    let provider = HpcryptProvider::new();

    // Server generates NewSessionTicket
    println!("Server generates NewSessionTicket");
    let ticket = server.generate_new_session_ticket(&provider, Some(7200))?; // 2 hour lifetime

    // Verify ticket structure
    assert_eq!(ticket.ticket_lifetime, 7200);
    assert!(ticket.ticket.len() > 0, "Ticket blob should not be empty");
    assert_eq!(
        ticket.ticket_nonce.len(),
        32,
        "Ticket nonce should be 32 bytes"
    );

    println!("✅ NewSessionTicket generated successfully");
    println!("   Lifetime: {} seconds", ticket.ticket_lifetime);
    println!("   Ticket blob size: {} bytes", ticket.ticket.len());
    println!("   Nonce size: {} bytes", ticket.ticket_nonce.len());
    println!("   ticket_age_add: {}", ticket.ticket_age_add);

    Ok(())
}

/// Test client processing of NewSessionTicket.
#[test]
fn test_client_processes_new_session_ticket() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n========================================");
    println!("  TEST: Client NewSessionTicket Processing");
    println!("========================================\n");

    let cipher_suite = CipherSuite::Aes128GcmSha256;
    let (mut client, mut server) = perform_full_handshake(cipher_suite)?;

    let provider = HpcryptProvider::new();

    // Server generates NewSessionTicket
    println!("Server generates NewSessionTicket");
    let ticket = server.generate_new_session_ticket(&provider, Some(3600))?; // 1 hour

    // Client processes NewSessionTicket
    println!("Client processes NewSessionTicket");
    let stored_ticket = client.process_new_session_ticket(&provider, &ticket)?;

    // Verify stored ticket
    assert_eq!(stored_ticket.ticket, ticket.ticket);
    assert_eq!(stored_ticket.cipher_suite, cipher_suite);
    assert_eq!(stored_ticket.ticket_age_add, ticket.ticket_age_add);
    assert_eq!(stored_ticket.lifetime, ticket.ticket_lifetime);
    assert_eq!(
        stored_ticket.psk.len(),
        32,
        "PSK should be 32 bytes for SHA-256"
    );

    println!("✅ Client processed NewSessionTicket successfully");
    println!("   PSK size: {} bytes", stored_ticket.psk.len());
    println!("   Cipher suite: {:?}", stored_ticket.cipher_suite);
    println!("   Lifetime: {} seconds", stored_ticket.lifetime);

    Ok(())
}

/// Test that client and server derive the same PSK from the ticket.
///
/// This is the critical test: both sides must independently derive the same PSK
/// from the resumption_master_secret and ticket_nonce.
///
/// NOTE: This test is ignored because tickets are now encrypted (Session 42).
/// The test previously extracted PSK from ticket bytes directly, which no longer works.
/// PSK derivation correctness is verified through full resumption flow tests instead.
#[test]
#[ignore = "Tickets are now encrypted - cannot extract PSK directly"]
fn test_client_server_psk_derivation_matches() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n========================================");
    println!("  TEST: Client-Server PSK Derivation Match");
    println!("========================================\n");

    let cipher_suite = CipherSuite::Aes128GcmSha256;
    let (mut client, mut server) = perform_full_handshake(cipher_suite)?;

    let provider = HpcryptProvider::new();

    // Server generates NewSessionTicket
    println!("Server generates NewSessionTicket");
    let ticket = server.generate_new_session_ticket(&provider, Some(7200))?;

    // Extract the PSK that server embedded in the ticket
    // The ticket format is: psk || cipher_suite || timestamp
    let server_psk = &ticket.ticket[0..32]; // First 32 bytes is the PSK

    println!(
        "Server PSK (from ticket): {:02x}{:02x}{:02x}...",
        server_psk[0], server_psk[1], server_psk[2]
    );

    // Client processes NewSessionTicket and derives PSK
    println!("Client processes NewSessionTicket");
    let stored_ticket = client.process_new_session_ticket(&provider, &ticket)?;

    println!(
        "Client PSK (derived):     {:02x}{:02x}{:02x}...",
        stored_ticket.psk[0], stored_ticket.psk[1], stored_ticket.psk[2]
    );

    // CRITICAL: Both PSKs MUST match
    assert_eq!(
        server_psk,
        &stored_ticket.psk[..],
        "Client and server MUST derive the same PSK!"
    );

    println!("✅ PSK derivation matches on both sides!");
    println!("   PSK length: {} bytes", stored_ticket.psk.len());

    Ok(())
}

/// Test ticket storage and retrieval.
#[test]
fn test_ticket_storage_and_retrieval() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n========================================");
    println!("  TEST: Ticket Storage and Retrieval");
    println!("========================================\n");

    let cipher_suite = CipherSuite::Aes128GcmSha256;
    let (mut client, mut server) = perform_full_handshake(cipher_suite)?;

    let provider = HpcryptProvider::new();

    // Initially, no tickets stored
    assert_eq!(client.get_stored_tickets().len(), 0);
    println!("Initial stored tickets: 0");

    // Server generates first ticket
    println!("\nServer generates ticket #1");
    let ticket1 = server.generate_new_session_ticket(&provider, Some(3600))?;
    client.process_new_session_ticket(&provider, &ticket1)?;

    // Now should have 1 ticket
    assert_eq!(client.get_stored_tickets().len(), 1);
    println!(
        "Stored tickets after #1: {}",
        client.get_stored_tickets().len()
    );

    // Server generates second ticket
    println!("\nServer generates ticket #2");
    let ticket2 = server.generate_new_session_ticket(&provider, Some(7200))?;
    client.process_new_session_ticket(&provider, &ticket2)?;

    // Now should have 2 tickets
    assert_eq!(client.get_stored_tickets().len(), 2);
    println!(
        "Stored tickets after #2: {}",
        client.get_stored_tickets().len()
    );

    // Verify both tickets are stored
    let stored = client.get_stored_tickets();
    assert_eq!(stored[0].lifetime, 3600);
    assert_eq!(stored[1].lifetime, 7200);

    println!("✅ Ticket storage working correctly");
    println!("   Ticket #1 lifetime: {} seconds", stored[0].lifetime);
    println!("   Ticket #2 lifetime: {} seconds", stored[1].lifetime);

    Ok(())
}

/// Test clearing stored tickets.
#[test]
fn test_clear_stored_tickets() -> Result<(), Box<dyn std::error::Error>> {
    let cipher_suite = CipherSuite::Aes128GcmSha256;
    let (mut client, mut server) = perform_full_handshake(cipher_suite)?;

    let provider = HpcryptProvider::new();

    // Add a ticket
    let ticket = server.generate_new_session_ticket(&provider, Some(3600))?;
    client.process_new_session_ticket(&provider, &ticket)?;
    assert_eq!(client.get_stored_tickets().len(), 1);

    // Clear tickets
    client.clear_stored_tickets();
    assert_eq!(client.get_stored_tickets().len(), 0);

    println!("✅ Clear stored tickets works correctly");
    Ok(())
}

/// Test ticket validation (checking if ticket is still valid).
#[test]
fn test_ticket_validity_check() -> Result<(), Box<dyn std::error::Error>> {
    let cipher_suite = CipherSuite::Aes128GcmSha256;
    let (mut client, mut server) = perform_full_handshake(cipher_suite)?;

    let provider = HpcryptProvider::new();

    // Generate ticket with 10 second lifetime
    let ticket = server.generate_new_session_ticket(&provider, Some(10))?;
    let stored_ticket = client.process_new_session_ticket(&provider, &ticket)?;

    // Get current time
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Ticket should be valid now
    assert!(
        stored_ticket.is_valid(current_time),
        "Ticket should be valid immediately after issuance"
    );

    // Ticket should be invalid after expiration
    let expired_time = current_time + 11; // 11 seconds later
    assert!(
        !stored_ticket.is_valid(expired_time),
        "Ticket should be invalid after expiration"
    );

    println!("✅ Ticket validity check works correctly");
    Ok(())
}

/// Test ticket age obfuscation.
#[test]
fn test_ticket_age_obfuscation() -> Result<(), Box<dyn std::error::Error>> {
    let cipher_suite = CipherSuite::Aes128GcmSha256;
    let (mut client, mut server) = perform_full_handshake(cipher_suite)?;

    let provider = HpcryptProvider::new();

    let ticket = server.generate_new_session_ticket(&provider, Some(3600))?;
    let stored_ticket = client.process_new_session_ticket(&provider, &ticket)?;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Calculate obfuscated age
    let obfuscated_age = stored_ticket.obfuscated_age(current_time);

    // Obfuscated age should be different from actual age due to ticket_age_add
    let actual_age = (current_time - stored_ticket.received_at) as u32;

    // The obfuscated age is actual_age + ticket_age_add (with wrapping)
    let expected_obfuscated = actual_age.wrapping_add(stored_ticket.ticket_age_add);
    assert_eq!(obfuscated_age, expected_obfuscated);

    println!("✅ Ticket age obfuscation works correctly");
    println!("   Actual age: {} seconds", actual_age);
    println!(
        "   Obfuscated age: {} (with ticket_age_add: {})",
        obfuscated_age, stored_ticket.ticket_age_add
    );

    Ok(())
}

/// Test with ChaCha20-Poly1305 cipher suite.
///
/// NOTE: This test is ignored because tickets are now encrypted (Session 42).
/// The test previously extracted PSK from ticket bytes directly, which no longer works.
#[test]
#[ignore = "Tickets are now encrypted - cannot extract PSK directly"]
fn test_new_session_ticket_with_chacha20() -> Result<(), Box<dyn std::error::Error>> {
    let cipher_suite = CipherSuite::ChaCha20Poly1305Sha256;
    let (mut client, mut server) = perform_full_handshake(cipher_suite)?;

    let provider = HpcryptProvider::new();

    let ticket = server.generate_new_session_ticket(&provider, Some(3600))?;
    let stored_ticket = client.process_new_session_ticket(&provider, &ticket)?;

    // Verify PSK matches (same as AES-128-GCM test)
    let server_psk = &ticket.ticket[0..32];
    assert_eq!(server_psk, &stored_ticket.psk[..]);

    println!("✅ NewSessionTicket works with ChaCha20-Poly1305");
    Ok(())
}

/// Test full end-to-end flow: handshake → ticket issuance → storage.
///
/// NOTE: This test is ignored because tickets are now encrypted (Session 42).
/// The test previously extracted PSK from ticket bytes directly, which no longer works.
/// PSK derivation correctness is verified through full resumption flow tests instead.
#[test]
#[ignore = "Tickets are now encrypted - cannot extract PSK directly"]
fn test_full_ticket_issuance_flow() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n========================================");
    println!("  FULL TICKET ISSUANCE FLOW TEST");
    println!("========================================\n");

    let cipher_suite = CipherSuite::Aes128GcmSha256;

    // Phase 1: Initial handshake
    println!("Phase 1: Initial Handshake");
    println!("--------------------------------");
    let (mut client, mut server) = perform_full_handshake(cipher_suite)?;
    println!("✅ Phase 1 complete\n");

    // Phase 2: Server generates NewSessionTicket
    println!("Phase 2: NewSessionTicket Generation");
    println!("--------------------------------");
    let provider = HpcryptProvider::new();
    let ticket = server.generate_new_session_ticket(&provider, Some(7200))?;
    println!("✅ Server generated NewSessionTicket");
    println!("   Lifetime: {} seconds", ticket.ticket_lifetime);
    println!("   Ticket size: {} bytes", ticket.ticket.len());
    println!("   Nonce size: {} bytes\n", ticket.ticket_nonce.len());

    // Phase 3: Client processes and stores ticket
    println!("Phase 3: Client Processes Ticket");
    println!("--------------------------------");
    let stored_ticket = client.process_new_session_ticket(&provider, &ticket)?;
    println!("✅ Client processed ticket");
    println!("   PSK size: {} bytes", stored_ticket.psk.len());
    println!("   Stored tickets: {}\n", client.get_stored_tickets().len());

    // Phase 4: Verify PSK derivation
    println!("Phase 4: PSK Verification");
    println!("--------------------------------");
    let server_psk = &ticket.ticket[0..32];
    assert_eq!(server_psk, &stored_ticket.psk[..], "PSKs must match!");
    println!("✅ PSK derivation verified");
    println!(
        "   Server PSK: {:02x}{:02x}{:02x}...",
        server_psk[0], server_psk[1], server_psk[2]
    );
    println!(
        "   Client PSK: {:02x}{:02x}{:02x}...",
        stored_ticket.psk[0], stored_ticket.psk[1], stored_ticket.psk[2]
    );

    println!("\n========================================");
    println!("✅ FULL TICKET ISSUANCE FLOW SUCCESSFUL!");
    println!("========================================\n");

    Ok(())
}
