//! Debug test to investigate ChaCha20-Poly1305 signature verification failure
//!
//! This test runs identical handshakes with AES-128-GCM and ChaCha20-Poly1305,
//! collecting detailed debug information to identify where they differ.

use hptls_core::{
    cipher::CipherSuite,
    error::Result,
    handshake::ClientHandshake,
    handshake_io::{extract_handshake_messages, parse_tls_records},
    messages::ServerHello,
    protocol::{ContentType, HandshakeType, ProtocolVersion},
    record::TlsPlaintext,
    record_protection::RecordProtection,
    transcript::TranscriptHash,
};
use hptls_crypto::CryptoProvider;
use hptls_crypto_hpcrypt::HpcryptProvider;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const OPENSSL_SERVER_HOST: &str = "127.0.0.1";
const OPENSSL_SERVER_PORT: u16 = 4433;
const CONNECTION_TIMEOUT_MS: u64 = 5000;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn is_server_available() -> bool {
    TcpStream::connect_timeout(
        &format!("{}:{}", OPENSSL_SERVER_HOST, OPENSSL_SERVER_PORT).parse().unwrap(),
        Duration::from_millis(100),
    )
    .is_ok()
}

/// Run handshake and collect debug info
fn debug_handshake(cipher_suite: CipherSuite) -> Result<()> {
    println!("\n{}", "=".repeat(60));
    println!("Testing cipher suite: {:?}", cipher_suite);
    println!("{}\n", "=".repeat(60));

    let provider = HpcryptProvider::new();

    // Connect to OpenSSL
    let mut stream = TcpStream::connect(format!("{}:{}", OPENSSL_SERVER_HOST, OPENSSL_SERVER_PORT))
        .map_err(|e| {
            hptls_core::error::Error::InvalidMessage(format!("TCP connect failed: {}", e))
        })?;
    stream
        .set_read_timeout(Some(Duration::from_millis(CONNECTION_TIMEOUT_MS)))
        .map_err(|e| {
            hptls_core::error::Error::InvalidMessage(format!("Failed to set read timeout: {}", e))
        })?;
    stream
        .set_write_timeout(Some(Duration::from_millis(CONNECTION_TIMEOUT_MS)))
        .map_err(|e| {
            hptls_core::error::Error::InvalidMessage(format!("Failed to set write timeout: {}", e))
        })?;

    // Create handshake
    let mut handshake = ClientHandshake::new();

    // Generate ClientHello
    let cipher_suites = vec![cipher_suite];
    let client_hello =
        handshake.client_hello(&provider, &cipher_suites, Some("localhost"), None)?;
    let client_hello_payload = client_hello.encode()?;

    // Wrap in handshake message
    let client_hello_hs_msg = hptls_core::handshake_io::HandshakeMessage::new(
        HandshakeType::ClientHello,
        client_hello_payload,
    );
    let client_hello_hs_bytes = client_hello_hs_msg.encode()?;

    println!("📤 ClientHello:");
    println!("   Size: {} bytes", client_hello_hs_bytes.len());
    println!(
        "   First 32 bytes: {}",
        hex_encode(&client_hello_hs_bytes[..32.min(client_hello_hs_bytes.len())])
    );

    // Save for transcript
    let client_hello_hs_bytes_for_transcript = client_hello_hs_bytes.clone();

    // Send ClientHello
    let record = TlsPlaintext::new(
        ContentType::Handshake,
        ProtocolVersion::Tls12,
        client_hello_hs_bytes,
    );
    let record_bytes = record.encode()?;
    stream
        .write_all(&record_bytes)
        .map_err(|e| hptls_core::error::Error::InvalidMessage(format!("Write failed: {}", e)))?;

    // Receive ServerHello + encrypted messages
    let mut buffer = vec![0u8; 16384];
    let n = stream
        .read(&mut buffer)
        .map_err(|e| hptls_core::error::Error::InvalidMessage(format!("Read failed: {}", e)))?;

    if n == 0 {
        return Err(hptls_core::error::Error::InvalidMessage(
            "Server closed connection".to_string(),
        ));
    }

    println!("\n📥 Received {} bytes from server", n);

    // Parse records
    let (records, _) = parse_tls_records(&buffer[..n])?;
    let messages = extract_handshake_messages(&records)?;

    if messages.is_empty() || messages[0].msg_type != HandshakeType::ServerHello {
        return Err(hptls_core::error::Error::InvalidMessage(
            "No ServerHello received".to_string(),
        ));
    }

    // Parse ServerHello
    let server_hello = ServerHello::decode(&messages[0].payload)?;
    println!("\n📥 ServerHello:");
    println!("   Cipher suite: {:?}", server_hello.cipher_suite);
    println!("   Size: {} bytes", messages[0].encode()?.len());

    // Process ServerHello
    handshake.process_server_hello(&provider, &server_hello)?;

    // Fix transcript with actual bytes
    let server_hello_hs_bytes = messages[0].encode()?;
    let hash_algorithm = server_hello.cipher_suite.hash_algorithm();

    println!("\n🔐 Transcript Fixup:");
    println!("   Hash algorithm: {:?}", hash_algorithm);
    println!(
        "   ClientHello HS msg: {} bytes",
        client_hello_hs_bytes_for_transcript.len()
    );
    println!(
        "   ServerHello HS msg: {} bytes",
        server_hello_hs_bytes.len()
    );

    // Compute transcript hash manually BEFORE replacement
    let mut test_transcript = TranscriptHash::new(hash_algorithm);
    test_transcript.update(&client_hello_hs_bytes_for_transcript);
    test_transcript.update(&server_hello_hs_bytes);
    let transcript_hash_after_server_hello = test_transcript.current_hash(&provider)?;
    println!(
        "   Transcript after ServerHello: {}",
        hex_encode(&transcript_hash_after_server_hello)
    );

    handshake.replace_transcript(
        hash_algorithm,
        vec![
            client_hello_hs_bytes_for_transcript.clone(),
            server_hello_hs_bytes.clone(),
        ],
    )?;
    handshake.rederive_handshake_secrets(&provider)?;

    // Get secrets
    let server_hs_secret = handshake.get_server_handshake_traffic_secret().ok_or_else(|| {
        hptls_core::error::Error::InternalError("Server handshake secret not available".to_string())
    })?;

    println!("\n🔑 Handshake Secrets:");
    println!(
        "   Server HS secret: {}",
        hex_encode(&server_hs_secret[..16.min(server_hs_secret.len())])
    );

    // Initialize decryptor
    let mut decryptor =
        RecordProtection::new(&provider, server_hello.cipher_suite, server_hs_secret)?;

    // Decrypt encrypted messages
    println!("\n🔓 Decrypting messages:");
    let mut encrypted_record_index = 0u64;
    let mut certificate_bytes: Option<Vec<u8>> = None;
    let mut certificate_verify_signature: Option<Vec<u8>> = None;
    let mut certificate_verify_algorithm: Option<hptls_crypto::SignatureAlgorithm> = None;

    for (i, record) in records.iter().enumerate().skip(1) {
        if record.content_type == ContentType::ApplicationData {
            println!("   Record {}: {} bytes", i + 1, record.fragment.len());

            decryptor.set_sequence_number(encrypted_record_index);
            let ciphertext_data = record.encode()?;
            let ciphertext =
                hptls_core::record_protection::TlsCiphertext::decode(&ciphertext_data)?;

            match decryptor.decrypt(&provider, &ciphertext) {
                Ok(plaintext) => {
                    if plaintext.content_type == ContentType::Handshake {
                        let (hs_msgs, _) = hptls_core::handshake_io::parse_handshake_messages(
                            &plaintext.fragment,
                        )?;
                        for hs_msg in &hs_msgs {
                            match hs_msg.msg_type {
                                HandshakeType::EncryptedExtensions => {
                                    println!("     ✓ EncryptedExtensions");
                                    let ee = hptls_core::messages::EncryptedExtensions::decode(
                                        &hs_msg.payload,
                                    )?;
                                    handshake.update_transcript(&hs_msg.encode()?)?;
                                    handshake.process_encrypted_extensions(&ee)?;
                                },
                                HandshakeType::Certificate => {
                                    println!("     ✓ Certificate");
                                    let cert =
                                        hptls_core::messages::Certificate::decode(&hs_msg.payload)?;
                                    certificate_bytes = Some(hs_msg.encode()?);
                                    handshake
                                        .update_transcript(certificate_bytes.as_ref().unwrap())?;
                                    handshake.process_certificate(&cert)?;
                                },
                                HandshakeType::CertificateVerify => {
                                    println!("     ✓ CertificateVerify");
                                    let cv = hptls_core::messages::CertificateVerify::decode(
                                        &hs_msg.payload,
                                    )?;
                                    certificate_verify_algorithm = Some(cv.algorithm);
                                    certificate_verify_signature = Some(cv.signature.clone());
                                    println!("       Algorithm: {:?}", cv.algorithm);
                                    println!("       Signature: {} bytes", cv.signature.len());
                                    println!(
                                        "       Signature (first 32): {}",
                                        hex_encode(&cv.signature[..32.min(cv.signature.len())])
                                    );

                                    // Get transcript hash BEFORE CertificateVerify
                                    let transcript_hash_before_cv =
                                        handshake.get_transcript_hash(&provider)?;
                                    println!(
                                        "       Transcript before CertificateVerify: {}",
                                        hex_encode(&transcript_hash_before_cv)
                                    );

                                    // Try to verify signature
                                    match handshake
                                        .verify_server_certificate_signature(&provider, &cv)
                                    {
                                        Ok(_) => println!("       ✅ Signature VERIFIED!"),
                                        Err(e) => {
                                            println!("       ❌ Signature FAILED: {}", e);

                                            // Additional debug info
                                            println!("\n🔍 Debug Info:");
                                            println!("   Transcript messages so far:");
                                            println!(
                                                "     1. ClientHello ({} bytes)",
                                                client_hello_hs_bytes_for_transcript.len()
                                            );
                                            println!(
                                                "     2. ServerHello ({} bytes)",
                                                server_hello_hs_bytes.len()
                                            );
                                            if let Some(ref cb) = certificate_bytes {
                                                println!(
                                                    "     3. Certificate ({} bytes)",
                                                    cb.len()
                                                );
                                            }

                                            // Manually compute expected transcript
                                            let mut manual_transcript =
                                                TranscriptHash::new(hash_algorithm);
                                            manual_transcript
                                                .update(&client_hello_hs_bytes_for_transcript);
                                            manual_transcript.update(&server_hello_hs_bytes);
                                            if let Some(ref ee_bytes) = certificate_bytes {
                                                // Need EncryptedExtensions bytes too
                                                println!("   (Note: EncryptedExtensions not captured for manual check)");
                                            }
                                            if let Some(ref cb) = certificate_bytes {
                                                manual_transcript.update(cb);
                                            }
                                            let manual_hash =
                                                manual_transcript.current_hash(&provider)?;
                                            println!(
                                                "   Manual transcript computation: {}",
                                                hex_encode(&manual_hash)
                                            );
                                            println!(
                                                "   Transcript from handshake: {}",
                                                hex_encode(&transcript_hash_before_cv)
                                            );

                                            if manual_hash == transcript_hash_before_cv {
                                                println!("   ✅ Transcript hashes MATCH");
                                            } else {
                                                println!("   ❌ Transcript hashes DIFFER!");
                                            }

                                            return Err(e);
                                        },
                                    }

                                    // Add CertificateVerify to transcript
                                    handshake.update_transcript(&hs_msg.encode()?)?;
                                    handshake.process_certificate_verify(&cv)?;
                                },
                                HandshakeType::Finished => {
                                    println!("     ✓ Finished");
                                },
                                _ => {},
                            }
                        }
                    }
                },
                Err(e) => {
                    println!("     ⚠ Decryption failed: {}", e);
                },
            }

            encrypted_record_index += 1;
        }
    }

    println!("\n✅ Test completed successfully!");
    Ok(())
}

#[test]
#[ignore]
fn test_debug_aes128_gcm() {
    if !is_server_available() {
        println!("⚠ OpenSSL server not available - skipping test");
        return;
    }

    debug_handshake(CipherSuite::Aes128GcmSha256).expect("AES-128-GCM handshake failed");
}

#[test]
#[ignore]
fn test_debug_chacha20_poly1305() {
    if !is_server_available() {
        println!("⚠ OpenSSL server not available - skipping test");
        return;
    }

    debug_handshake(CipherSuite::ChaCha20Poly1305Sha256)
        .expect("ChaCha20-Poly1305 handshake failed");
}

#[test]
#[ignore]
fn test_compare_both() {
    if !is_server_available() {
        println!("⚠ OpenSSL server not available - skipping test");
        return;
    }

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Comparing AES-128-GCM vs ChaCha20-Poly1305             ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    println!("\n\n## TEST 1: AES-128-GCM ##");
    match debug_handshake(CipherSuite::Aes128GcmSha256) {
        Ok(_) => println!("\n✅ AES-128-GCM: SUCCESS"),
        Err(e) => println!("\n❌ AES-128-GCM: FAILED - {}", e),
    }

    println!("\n\n## TEST 2: ChaCha20-Poly1305 ##");
    match debug_handshake(CipherSuite::ChaCha20Poly1305Sha256) {
        Ok(_) => println!("\n✅ ChaCha20-Poly1305: SUCCESS"),
        Err(e) => println!("\n❌ ChaCha20-Poly1305: FAILED - {}", e),
    }
}
