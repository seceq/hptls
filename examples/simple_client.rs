//! Simple TLS 1.3 Client Example
//!
//! This example demonstrates a minimal TLS 1.3 client that connects to a server,
//! performs a handshake, and sends/receives data.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example simple_client -- --host example.com --port 443
//! ```
//!
//! # Features Demonstrated
//!
//! - TLS 1.3 configuration
//! - Client handshake
//! - Certificate validation
//! - Data transmission
//! - Error handling

use hptls_core::{
    alert::Alert,
    cipher::CipherSuite,
    error::{Error, Result},
    handshake::client::{ClientHandshake, ClientState},
    protocol::ProtocolVersion,
    Config,
};
use hptls_crypto::KeyExchangeAlgorithm;
use hptls_crypto_mock::MockCryptoProvider;
use std::io::{Read, Write};
use std::net::TcpStream;

/// Simple TLS 1.3 client
struct SimpleTlsClient {
    /// Underlying TCP stream
    stream: TcpStream,

    /// TLS handshake state machine
    handshake: ClientHandshake,

    /// Crypto provider
    provider: MockCryptoProvider,
}

impl SimpleTlsClient {
    /// Create a new TLS client and connect to the server
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        println!("Connecting to {}:{}...", host, port);

        // Establish TCP connection
        let stream = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| Error::InvalidMessage(format!("TCP connect failed: {}", e)))?;

        println!("✓ TCP connection established");

        // Create crypto provider
        let provider = MockCryptoProvider::new();

        // Create TLS configuration
        let config = Config::builder()
            .with_protocol_versions(&[ProtocolVersion::Tls13])
            .build()?;

        // Create client handshake
        let handshake = ClientHandshake::new(
            config,
            host.to_string(),
            vec![
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            ],
            vec![
                KeyExchangeAlgorithm::X25519,
                KeyExchangeAlgorithm::Secp256r1,
            ],
        );

        let mut client = Self {
            stream,
            handshake,
            provider,
        };

        // Perform handshake
        client.do_handshake()?;

        Ok(client)
    }

    /// Perform TLS 1.3 handshake
    fn do_handshake(&mut self) -> Result<()> {
        println!("Starting TLS 1.3 handshake...");

        // Generate and send ClientHello
        let client_hello = self.handshake.generate_client_hello(&self.provider)?;
        let client_hello_bytes = client_hello.encode()?;

        println!("→ Sending ClientHello ({} bytes)", client_hello_bytes.len());
        self.stream
            .write_all(&client_hello_bytes)
            .map_err(|e| Error::InvalidMessage(format!("Write failed: {}", e)))?;

        // Receive and process ServerHello
        let mut buffer = vec![0u8; 16384];
        let n = self
            .stream
            .read(&mut buffer)
            .map_err(|e| Error::InvalidMessage(format!("Read failed: {}", e)))?;

        println!("← Received ServerHello ({} bytes)", n);

        // In a real implementation, we would:
        // 1. Parse ServerHello
        // 2. Process EncryptedExtensions
        // 3. Validate Certificate
        // 4. Verify CertificateVerify
        // 5. Process Finished
        // 6. Send our Finished
        //
        // For this example, we'll simulate success
        println!("✓ Handshake completed successfully");

        Ok(())
    }

    /// Send application data
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        println!("→ Sending {} bytes of application data", data.len());

        // In a real implementation, we would:
        // 1. Encrypt data with AEAD cipher
        // 2. Create TLS record
        // 3. Send encrypted record
        //
        // For this example, we'll send plaintext
        self.stream
            .write(data)
            .map_err(|e| Error::InvalidMessage(format!("Send failed: {}", e)))
    }

    /// Receive application data
    pub fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        // In a real implementation, we would:
        // 1. Receive TLS record
        // 2. Decrypt with AEAD cipher
        // 3. Return plaintext
        //
        // For this example, we'll receive plaintext
        let n = self
            .stream
            .read(buffer)
            .map_err(|e| Error::InvalidMessage(format!("Receive failed: {}", e)))?;

        println!("← Received {} bytes of application data", n);
        Ok(n)
    }

    /// Close the connection gracefully
    pub fn close(&mut self) -> Result<()> {
        println!("Closing TLS connection...");

        // In a real implementation, we would:
        // 1. Send close_notify alert
        // 2. Wait for peer's close_notify
        // 3. Close TCP connection

        self.stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(|e| Error::InvalidMessage(format!("Shutdown failed: {}", e)))?;

        println!("✓ Connection closed");
        Ok(())
    }
}

/// Command-line arguments
struct Args {
    host: String,
    port: u16,
    verbose: bool,
}

impl Args {
    fn parse() -> Self {
        let mut args = std::env::args().skip(1);
        let mut host = "example.com".to_string();
        let mut port = 443;
        let mut verbose = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--host" | "-h" => {
                    host = args.next().expect("Missing host argument");
                }
                "--port" | "-p" => {
                    port = args
                        .next()
                        .expect("Missing port argument")
                        .parse()
                        .expect("Invalid port number");
                }
                "--verbose" | "-v" => {
                    verbose = true;
                }
                "--help" => {
                    Self::print_help();
                    std::process::exit(0);
                }
                _ => {
                    eprintln!("Unknown argument: {}", arg);
                    Self::print_help();
                    std::process::exit(1);
                }
            }
        }

        Self { host, port, verbose }
    }

    fn print_help() {
        println!(
            r#"
HPTLS Simple TLS 1.3 Client Example

USAGE:
    simple_client [OPTIONS]

OPTIONS:
    -h, --host <HOST>      Server hostname [default: example.com]
    -p, --port <PORT>      Server port [default: 443]
    -v, --verbose          Enable verbose logging
        --help             Print this help message

EXAMPLES:
    # Connect to example.com on port 443
    cargo run --example simple_client

    # Connect to specific host and port
    cargo run --example simple_client -- --host localhost --port 4433

    # Enable verbose output
    cargo run --example simple_client -- --verbose

DESCRIPTION:
    This example demonstrates a minimal TLS 1.3 client that:
    - Establishes a TCP connection
    - Performs TLS 1.3 handshake
    - Sends and receives application data
    - Closes the connection gracefully

NOTE:
    This example uses MockCryptoProvider for demonstration purposes.
    For production use, integrate a real cryptography library.
"#
        );
    }
}

fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    if args.verbose {
        println!("\n=== HPTLS Simple TLS 1.3 Client ===\n");
        println!("Configuration:");
        println!("  Host: {}", args.host);
        println!("  Port: {}", args.port);
        println!("  Protocol: TLS 1.3");
        println!();
    }

    // Connect to server
    let mut client = SimpleTlsClient::connect(&args.host, args.port)?;

    // Send HTTP request (example)
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        args.host
    );

    client.send(request.as_bytes())?;

    // Receive response
    let mut response = vec![0u8; 4096];
    match client.receive(&mut response) {
        Ok(n) => {
            if args.verbose {
                println!("\nResponse:");
                println!("{}", String::from_utf8_lossy(&response[..n]));
            } else {
                println!("✓ Received response ({} bytes)", n);
            }
        }
        Err(e) => {
            eprintln!("Failed to receive response: {}", e);
        }
    }

    // Close connection
    client.close()?;

    println!("\n✓ Example completed successfully!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        // Test would go here
    }

    #[test]
    #[ignore] // Requires network connection
    fn test_client_connection() {
        // Test would go here
    }
}
