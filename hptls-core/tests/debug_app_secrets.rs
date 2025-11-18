//! Debug test to investigate application traffic secret availability

use hptls_core::{
    cipher::CipherSuite,
    handshake::ClientHandshake,
    handshake_io::{extract_handshake_messages, parse_tls_records},
    messages::{Certificate, CertificateVerify, EncryptedExtensions, Finished, ServerHello},
    protocol::{ContentType, HandshakeType, ProtocolVersion},
    record::TlsPlaintext,
    record_protection::RecordProtection,
};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const OPENSSL_SERVER_HOST: &str = "127.0.0.1";
const OPENSSL_SERVER_PORT: u16 = 4433;

fn is_server_available() -> bool {
    TcpStream::connect_timeout(
        &format!("{}:{}", OPENSSL_SERVER_HOST, OPENSSL_SERVER_PORT).parse().unwrap(),
        Duration::from_millis(100),
    )
    .is_ok()
}

#[test]
#[ignore]
fn test_application_secrets_after_handshake() {
    if !is_server_available() {
        println!("⚠ OpenSSL server not available - skipping test");
        return;
    }

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Debug: Application Secret Availability After Handshake ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let provider = HpcryptProvider::new();

    // Connect to OpenSSL
    let mut stream = TcpStream::connect(format!("{}:{}", OPENSSL_SERVER_HOST, OPENSSL_SERVER_PORT))
        .expect("Failed to connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .expect("Failed to set timeout");

    // Create handshake
    let mut handshake = ClientHandshake::new();
    let cipher_suites = vec![CipherSuite::Aes128GcmSha256];

    // Generate and send ClientHello
    println!("→ Sending ClientHello...");
    let client_hello = handshake
        .client_hello(&provider, &cipher_suites, Some("localhost"), None)
        .expect("Failed to create ClientHello");
    let client_hello_payload = client_hello.encode().expect("Failed to encode");

    let client_hello_hs_msg = hptls_core::handshake_io::HandshakeMessage::new(
        HandshakeType::ClientHello,
        client_hello_payload,
    );
    let client_hello_hs_bytes = client_hello_hs_msg.encode().expect("Failed to encode");
    let client_hello_for_transcript = client_hello_hs_bytes.clone();

    let record = TlsPlaintext::new(
        ContentType::Handshake,
        ProtocolVersion::Tls12,
        client_hello_hs_bytes,
    );
    stream
        .write_all(&record.encode().expect("Failed to encode"))
        .expect("Write failed");

    // Receive response
    println!("← Receiving ServerHello...");
    let mut buffer = vec![0u8; 16384];
    let n = stream.read(&mut buffer).expect("Read failed");

    let (records, _) = parse_tls_records(&buffer[..n]).expect("Parse failed");
    let messages = extract_handshake_messages(&records).expect("Extract failed");

    // Parse ServerHello
    let server_hello = ServerHello::decode(&messages[0].payload).expect("Decode failed");
    println!("✓ ServerHello received: {:?}", server_hello.cipher_suite);

    // Process ServerHello
    handshake
        .process_server_hello(&provider, &server_hello)
        .expect("Process failed");

    // Fix transcript
    let server_hello_hs_bytes = messages[0].encode().expect("Encode failed");
    let hash_algorithm = server_hello.cipher_suite.hash_algorithm();
    handshake
        .replace_transcript(
            hash_algorithm,
            vec![client_hello_for_transcript, server_hello_hs_bytes],
        )
        .expect("Replace transcript failed");
    handshake.rederive_handshake_secrets(&provider).expect("Rederive failed");

    // Get server handshake secret and decrypt
    let server_hs_secret =
        handshake.get_server_handshake_traffic_secret().expect("No server HS secret");
    let mut decryptor =
        RecordProtection::new(&provider, server_hello.cipher_suite, server_hs_secret)
            .expect("Failed to create decryptor");

    // Decrypt encrypted messages
    println!("→ Decrypting handshake messages...");
    let mut encrypted_extensions: Option<EncryptedExtensions> = None;
    let mut certificate: Option<Certificate> = None;
    let mut certificate_verify: Option<CertificateVerify> = None;
    let mut finished: Option<Finished> = None;

    let mut ee_bytes: Option<Vec<u8>> = None;
    let mut cert_bytes: Option<Vec<u8>> = None;
    let mut cv_bytes: Option<Vec<u8>> = None;

    let mut encrypted_index = 0u64;
    for record in records.iter().skip(1) {
        if record.content_type == ContentType::ApplicationData {
            decryptor.set_sequence_number(encrypted_index);
            let ciphertext =
                hptls_core::record_protection::TlsCiphertext::decode(&record.encode().unwrap())
                    .unwrap();

            if let Ok(plaintext) = decryptor.decrypt(&provider, &ciphertext) {
                if plaintext.content_type == ContentType::Handshake {
                    let (hs_msgs, _) =
                        hptls_core::handshake_io::parse_handshake_messages(&plaintext.fragment)
                            .unwrap();
                    for hs_msg in &hs_msgs {
                        match hs_msg.msg_type {
                            HandshakeType::EncryptedExtensions => {
                                encrypted_extensions =
                                    Some(EncryptedExtensions::decode(&hs_msg.payload).unwrap());
                                ee_bytes = Some(hs_msg.encode().unwrap());
                            },
                            HandshakeType::Certificate => {
                                certificate = Some(Certificate::decode(&hs_msg.payload).unwrap());
                                cert_bytes = Some(hs_msg.encode().unwrap());
                            },
                            HandshakeType::CertificateVerify => {
                                certificate_verify =
                                    Some(CertificateVerify::decode(&hs_msg.payload).unwrap());
                                cv_bytes = Some(hs_msg.encode().unwrap());
                            },
                            HandshakeType::Finished => {
                                finished = Some(Finished::decode(&hs_msg.payload).unwrap());
                            },
                            _ => {},
                        }
                    }
                }
            }
            encrypted_index += 1;
        }
    }

    // Process messages
    println!("→ Processing handshake messages...");

    if let Some(ref bytes) = ee_bytes {
        handshake.update_transcript(bytes).unwrap();
    }
    if let Some(ee) = encrypted_extensions {
        handshake.process_encrypted_extensions(&ee).unwrap();
    }

    if let Some(ref bytes) = cert_bytes {
        handshake.update_transcript(bytes).unwrap();
    }
    if let Some(cert) = certificate {
        handshake.process_certificate(&cert).unwrap();
    }

    if let Some(cv) = certificate_verify {
        handshake.verify_server_certificate_signature(&provider, &cv).unwrap();
        if let Some(ref bytes) = cv_bytes {
            handshake.update_transcript(bytes).unwrap();
        }
        handshake.process_certificate_verify(&cv).unwrap();
    }

    // Process server Finished - THIS is where application secrets should be derived
    println!("\n→ Processing server Finished (BEFORE - checking if secrets are available)...");
    println!(
        "   Client app secret available: {}",
        handshake.get_client_application_traffic_secret().is_some()
    );
    println!(
        "   Server app secret available: {}",
        handshake.get_server_application_traffic_secret().is_some()
    );

    println!("   Finished message captured: {}", finished.is_some());
    if let Some(fin) = finished {
        println!("→ Calling process_server_finished()...");
        let _client_finished = handshake
            .process_server_finished(&provider, &fin)
            .expect("Failed to process server Finished");
        println!("✓ Server Finished processed successfully");
    } else {
        panic!("❌ Finished message was NOT captured!");
    }

    // Check if secrets are NOW available
    println!("\n→ AFTER process_server_finished() - checking if secrets are available...");
    let client_secret = handshake.get_client_application_traffic_secret();
    let server_secret = handshake.get_server_application_traffic_secret();

    println!(
        "   Client app secret available: {}",
        client_secret.is_some()
    );
    if let Some(secret) = client_secret {
        println!("   Client app secret length: {} bytes", secret.len());
    }

    println!(
        "   Server app secret available: {}",
        server_secret.is_some()
    );
    if let Some(secret) = server_secret {
        println!("   Server app secret length: {} bytes", secret.len());
    }

    // Assertions
    assert!(
        client_secret.is_some(),
        "❌ FAIL: Client application traffic secret should be available after handshake"
    );
    assert!(
        server_secret.is_some(),
        "❌ FAIL: Server application traffic secret should be available after handshake"
    );

    println!("\n✅ SUCCESS: Both application secrets are available!");
}
