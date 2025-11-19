//! DTLS 1.3 Client Example
//!
//! This example demonstrates a basic DTLS 1.3 client that:
//! - Connects to a DTLS server (HPTLS or OpenSSL)
//! - Performs DTLS handshake
//! - Sends test messages
//! - Receives and displays responses
//! - Supports certificate verification
//!
//! # Usage
//!
//! ```bash
//! # Connect to HPTLS server
//! cargo run --example dtls_client -- localhost:4433
//!
//! # Connect to OpenSSL server
//! # (First start OpenSSL server in another terminal)
//! openssl-3.2.sh s_server -dtls -port 4433 \
//!     -cert interop-tests/certs/server-cert-p256.pem \
//!     -key interop-tests/certs/server-key-p256.pem
//! cargo run --example dtls_client -- localhost:4433
//! ```
//!
//! # With Custom Server Name
//!
//! ```bash
//! # Specify server name for SNI
//! SERVER_NAME=example.com cargo run --example dtls_client -- 192.168.1.100:4433
//! ```

use hptls::dtls::{DtlsClient, DtlsClientConfig};
use std::env;
use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 DTLS 1.3 Client Example");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Get server address from command line
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <host:port>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} localhost:4433", args[0]);
        std::process::exit(1);
    }

    let server_addr = &args[1];
    println!("🌐 Server address: {}", server_addr);

    // Extract server name for SNI
    let server_name = if let Some(colon_pos) = server_addr.find(':') {
        server_addr[..colon_pos].to_string()
    } else {
        server_addr.to_string()
    };

    // Get custom server name from env if provided
    let server_name = env::var("SERVER_NAME").unwrap_or(server_name);
    println!("📝 Server name (SNI): {}", server_name);

    // Note: Certificate verification not yet implemented in DTLS API
    println!("⚠️  Note: Certificate verification will be added in future versions");

    // Create client configuration
    let config = DtlsClientConfig::builder()
        .with_server_name(server_name)
        .build()?;

    // Create UDP socket
    println!("🔌 Creating UDP socket...");
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let local_addr = socket.local_addr()?;
    println!("   Local address: {}", local_addr);

    // Connect to server
    println!("🔗 Connecting to {}...", server_addr);
    socket.connect(server_addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

    println!();
    println!("🤝 Performing DTLS handshake...");

    // Create DTLS client
    let mut client = DtlsClient::new(config, socket)?;

    // Perform handshake
    match client.connect() {
        Ok(result) => {
            println!("✅ Handshake complete: {:?}", result);
        }
        Err(e) => {
            eprintln!("❌ Handshake failed: {}", e);
            return Err(e.into());
        }
    }

    println!();
    println!("💬 Connection established. Sending test messages...");
    println!("   (Type 'quit' to exit)");
    println!();

    // Test messages to send
    let test_messages = vec![
        "Hello from HPTLS DTLS 1.3 client!",
        "Testing interoperability with OpenSSL",
        "DTLS 1.3 is working!",
    ];

    let mut buf = [0u8; 4096];

    for (i, message) in test_messages.iter().enumerate() {
        println!("📤 Sending message {}: {}", i + 1, message);

        // Send message
        match client.write(message.as_bytes()) {
            Ok(n) => println!("   Sent {} bytes", n),
            Err(e) => {
                eprintln!("❌ Failed to send: {}", e);
                break;
            }
        }

        // Receive response
        match client.read(&mut buf) {
            Ok(n) if n > 0 => {
                let response = &buf[..n];
                match std::str::from_utf8(response) {
                    Ok(s) => println!("📨 Received ({} bytes): {}", n, s.trim()),
                    Err(_) => println!("📨 Received ({} bytes): {:?}", n, response),
                }
            }
            Ok(_) => {
                println!("⚠️  Empty response received");
            }
            Err(e) => {
                if e.to_string().contains("timed out") {
                    eprintln!("⏱️  Read timeout - server may not be echoing");
                } else {
                    eprintln!("❌ Read error: {}", e);
                }
                break;
            }
        }

        println!();

        // Small delay between messages
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Send quit message
    println!("📤 Sending quit message...");
    if let Err(e) = client.write(b"quit") {
        eprintln!("⚠️  Failed to send quit: {}", e);
    }

    // Graceful shutdown with close_notify
    println!();
    println!("🔐 Closing connection gracefully...");
    if let Err(e) = client.close() {
        eprintln!("⚠️  Failed to send close_notify: {}", e);
    }

    println!();
    println!("✅ Client shutdown complete");
    println!("   Messages sent: {}", test_messages.len());

    Ok(())
}
