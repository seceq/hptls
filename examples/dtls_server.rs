//! DTLS 1.3 Server Example
//!
//! This example demonstrates a basic DTLS 1.3 server that:
//! - Listens on UDP port 4433
//! - Performs DTLS handshake with clients
//! - Echoes received data back to clients
//! - Supports cookie-based DoS protection
//!
//! # Usage
//!
//! ```bash
//! # Run the server
//! cargo run --example dtls_server
//!
//! # In another terminal, connect with OpenSSL client
//! openssl-3.2.sh s_client -dtls -connect localhost:4433 -CAfile interop-tests/certs/ca-cert.pem
//! ```
//!
//! # With Cookie Protection
//!
//! ```bash
//! # Always require cookies
//! COOKIE_POLICY=always cargo run --example dtls_server
//!
//! # High load threshold (100 conn/sec)
//! COOKIE_POLICY=onhighload COOKIE_THRESHOLD=100 cargo run --example dtls_server
//! ```

use hptls::dtls::{CookiePolicy, DtlsCookieConfig, DtlsServer, DtlsServerConfig};
use std::env;
use std::fs;
use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 DTLS 1.3 Server Example");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Get port from env or use default
    let port = env::var("PORT").unwrap_or_else(|_| "4433".to_string());
    let addr = format!("0.0.0.0:{}", port);

    // Load certificates
    println!("📜 Loading certificates...");
    let cert_path = env::var("CERT_PATH")
        .unwrap_or_else(|_| "interop-tests/certs/server-cert-p256.pem".to_string());
    let key_path =
        env::var("KEY_PATH").unwrap_or_else(|_| "interop-tests/certs/server-key-p256.pem".to_string());

    let cert_pem = fs::read_to_string(&cert_path)
        .map_err(|e| format!("Failed to read certificate {}: {}", cert_path, e))?;
    let key_pem = fs::read_to_string(&key_path)
        .map_err(|e| format!("Failed to read private key {}: {}", key_path, e))?;

    // Parse PEM to DER
    let cert_der = pem_to_der(&cert_pem)?;
    let key_der = pem_to_der(&key_pem)?;

    println!("   Certificate: {}", cert_path);
    println!("   Private key: {}", key_path);

    // Configure cookie policy
    let cookie_config = get_cookie_config();
    println!("🍪 Cookie Policy: {:?}", cookie_config.policy);

    // Create server configuration
    let config = DtlsServerConfig::builder()
        .with_certificate_chain(vec![cert_der])
        .with_private_key(key_der)
        .with_cookie_config(cookie_config)
        .build()?;

    // Create UDP socket
    println!("🌐 Binding to {}...", addr);
    let socket = UdpSocket::bind(&addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;

    println!("✅ Server listening on {}", addr);
    println!();
    println!("Waiting for client connection...");
    println!("(Press Ctrl+C to stop)");
    println!();

    // Create DTLS server
    let mut server = DtlsServer::new(config, socket)?;

    // Accept client connection
    println!("🤝 Performing DTLS handshake...");
    match server.accept() {
        Ok(result) => {
            println!("✅ Handshake complete: {:?}", result);
        }
        Err(e) => {
            eprintln!("❌ Handshake failed: {}", e);
            return Err(e.into());
        }
    }

    // Get connection stats if available
    let (rate, total, window) = server.connection_stats();
    println!();
    println!("📊 Connection Statistics:");
    println!("   Current rate: {} conn/sec", rate);
    println!("   Total connections: {}", total);
    println!("   Recent connections: {}", window);
    println!();

    // Echo loop
    println!("💬 Echo server ready. Waiting for data...");
    println!();

    let mut buf = [0u8; 4096];
    let mut msg_count = 0;

    loop {
        match server.read(&mut buf) {
            Ok(n) if n > 0 => {
                msg_count += 1;
                let data = &buf[..n];

                // Try to print as UTF-8
                match std::str::from_utf8(data) {
                    Ok(s) => println!("📨 Received ({} bytes): {}", n, s.trim()),
                    Err(_) => println!("📨 Received ({} bytes): {:?}", n, data),
                }

                // Echo back
                match server.write(data) {
                    Ok(_) => println!("📤 Echoed back {} bytes", n),
                    Err(e) => {
                        eprintln!("❌ Failed to send: {}", e);
                        break;
                    }
                }

                println!("   Total messages: {}", msg_count);
                println!();

                // Check if client sent "quit"
                if let Ok(s) = std::str::from_utf8(data) {
                    if s.trim().eq_ignore_ascii_case("quit") {
                        println!("👋 Client requested disconnect");
                        break;
                    }
                }
            }
            Ok(_) => {
                // Empty read, continue
                continue;
            }
            Err(e) => {
                if e.to_string().contains("timed out") {
                    println!("⏱️  Read timeout, waiting for data...");
                    continue;
                }

                // Check if it's close_notify
                if e.to_string().contains("CloseNotify") {
                    println!("📭 Client sent close_notify, shutting down gracefully");
                    break;
                }

                eprintln!("❌ Read error: {}", e);
                break;
            }
        }
    }

    // Send close_notify to client before shutting down
    println!();
    println!("🔐 Sending close_notify to client...");
    if let Err(e) = server.close() {
        eprintln!("⚠️  Failed to send close_notify: {}", e);
    }

    println!();
    println!("✅ Server shutdown complete");
    println!("   Total messages exchanged: {}", msg_count);

    Ok(())
}

/// Get cookie configuration from environment variables
fn get_cookie_config() -> DtlsCookieConfig {
    let policy = match env::var("COOKIE_POLICY")
        .unwrap_or_else(|_| "onhighload".to_string())
        .to_lowercase()
        .as_str()
    {
        "always" => CookiePolicy::Always,
        "never" => CookiePolicy::Never,
        "onhighload" | _ => {
            let threshold = env::var("COOKIE_THRESHOLD")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .unwrap_or(100);
            CookiePolicy::OnHighLoad { threshold }
        }
    };

    DtlsCookieConfig::builder().with_policy(policy).build()
}

/// Simple PEM to DER converter
fn pem_to_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // For EC keys, skip the EC PARAMETERS block and find the PRIVATE KEY block
    // Look for either "BEGIN EC PRIVATE KEY" or "BEGIN PRIVATE KEY"
    let private_key_markers = ["-----BEGIN EC PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"];

    for start_marker in &private_key_markers {
        if let Some(start) = pem.find(start_marker) {
            let end_marker = start_marker.replace("BEGIN", "END");
            let end = pem.find(&end_marker).ok_or("No PEM end marker found")?;

            // Find the actual base64 content (after the first newline after BEGIN)
            let content_start = pem[start..]
                .find('\n')
                .map(|i| start + i + 1)
                .ok_or("Invalid PEM format")?;

            // Extract base64 content
            let base64_content: String = pem[content_start..end]
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect();

            // Decode base64
            let der = base64::decode(&base64_content)
                .map_err(|e| format!("Failed to decode base64: {}", e))?;

            // For EC PRIVATE KEY, extract the raw 32-byte private key from DER structure
            // EC PRIVATE KEY format: SEQUENCE { version INTEGER, privateKey OCTET STRING, ... }
            // We need to find the OCTET STRING (tag 0x04) which contains the actual key
            if start_marker.contains("EC PRIVATE KEY") && der.len() > 10 {
                // Look for OCTET STRING tag (0x04) followed by length
                for i in 0..der.len()-2 {
                    if der[i] == 0x04 && der[i+1] == 0x20 {  // OCTET STRING, length 32
                        let key_start = i + 2;
                        if key_start + 32 <= der.len() {
                            return Ok(der[key_start..key_start + 32].to_vec());
                        }
                    }
                }
            }

            return Ok(der);
        }
    }

    // Fallback to generic BEGIN marker (for certificates, etc.)
    let start_marker = "-----BEGIN";
    let end_marker = "-----END";

    let start = pem
        .find(start_marker)
        .ok_or("No PEM start marker found")?;
    let end = pem.find(end_marker).ok_or("No PEM end marker found")?;

    // Find the actual base64 content (after the first newline after BEGIN)
    let content_start = pem[start..]
        .find('\n')
        .map(|i| start + i + 1)
        .ok_or("Invalid PEM format")?;

    // Extract base64 content
    let base64_content: String = pem[content_start..end]
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();

    // Decode base64
    let der = base64::decode(&base64_content)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    Ok(der)
}

// Add base64 dependency inline for simplicity
mod base64 {
    pub fn decode(input: &str) -> Result<Vec<u8>, String> {
        // Simple base64 decoder (standard alphabet)
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut decode_table = [0xff; 256];
        for (i, &c) in ALPHABET.iter().enumerate() {
            decode_table[c as usize] = i as u8;
        }

        let input: Vec<u8> = input.bytes().filter(|&b| b != b'\r' && b != b'\n').collect();
        let mut output = Vec::with_capacity((input.len() * 3) / 4);

        let mut i = 0;
        while i < input.len() {
            let mut buf = [0u8; 4];
            let mut pad = 0;

            for j in 0..4 {
                if i + j < input.len() && input[i + j] != b'=' {
                    let val = decode_table[input[i + j] as usize];
                    if val == 0xff {
                        return Err(format!("Invalid base64 character at position {}", i + j));
                    }
                    buf[j] = val;
                } else {
                    pad += 1;
                }
            }

            output.push((buf[0] << 2) | (buf[1] >> 4));
            if pad < 2 {
                output.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if pad < 1 {
                output.push((buf[2] << 6) | buf[3]);
            }

            i += 4;
        }

        Ok(output)
    }
}
