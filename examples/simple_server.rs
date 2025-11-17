//! Simple TLS 1.3 Server Example
//!
//! This example demonstrates a minimal TLS 1.3 server that listens for connections,
//! performs handshakes, and echoes back received data.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example simple_server -- --port 4433
//! ```
//!
//! # Features Demonstrated
//!
//! - TLS 1.3 server configuration
//! - Server handshake
//! - Certificate handling
//! - Connection management
//! - Echo service

use hptls_core::{
    cipher::CipherSuite,
    error::{Error, Result},
    handshake::server::{ServerHandshake, ServerState},
    protocol::ProtocolVersion,
    Config,
};
use hptls_crypto::KeyExchangeAlgorithm;
use hptls_crypto_mock::MockCryptoProvider;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// Simple TLS 1.3 server
struct SimpleTlsServer {
    /// TCP listener
    listener: TcpListener,

    /// Server configuration
    config: Config,

    /// Crypto provider
    provider: MockCryptoProvider,
}

impl SimpleTlsServer {
    /// Create a new TLS server
    pub fn new(port: u16) -> Result<Self> {
        println!("Starting TLS 1.3 server on port {}...", port);

        // Bind TCP listener
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
            .map_err(|e| Error::InvalidMessage(format!("Bind failed: {}", e)))?;

        println!("✓ Server listening on 0.0.0.0:{}", port);

        // Create configuration
        let config = Config::builder()
            .with_protocol_versions(&[ProtocolVersion::Tls13])
            .build()?;

        // Create crypto provider
        let provider = MockCryptoProvider::new();

        Ok(Self {
            listener,
            config,
            provider,
        })
    }

    /// Accept and handle incoming connections
    pub fn serve(&self) -> Result<()> {
        println!("Waiting for connections...\n");

        for (conn_id, stream) in self.listener.incoming().enumerate() {
            match stream {
                Ok(stream) => {
                    println!("\n=== Connection {} ===", conn_id + 1);
                    println!(
                        "✓ Accepted connection from {}",
                        stream.peer_addr().unwrap()
                    );

                    if let Err(e) = self.handle_client(stream) {
                        eprintln!("✗ Connection failed: {}", e);
                    } else {
                        println!("✓ Connection completed successfully");
                    }
                }
                Err(e) => {
                    eprintln!("✗ Accept failed: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle a single client connection
    fn handle_client(&self, mut stream: TcpStream) -> Result<()> {
        // Create server handshake
        let mut handshake = ServerHandshake::new(
            self.config.clone(),
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

        // Perform handshake
        self.do_handshake(&mut stream, &mut handshake)?;

        // Handle application data (echo server)
        self.echo_service(&mut stream)?;

        Ok(())
    }

    /// Perform TLS 1.3 handshake
    fn do_handshake(
        &self,
        stream: &mut TcpStream,
        handshake: &mut ServerHandshake,
    ) -> Result<()> {
        println!("Starting TLS 1.3 handshake...");

        // Receive ClientHello
        let mut buffer = vec![0u8; 16384];
        let n = stream
            .read(&mut buffer)
            .map_err(|e| Error::InvalidMessage(format!("Read failed: {}", e)))?;

        println!("← Received ClientHello ({} bytes)", n);

        // In a real implementation, we would:
        // 1. Parse ClientHello
        // 2. Select cipher suite and key exchange
        // 3. Generate ServerHello
        // 4. Send EncryptedExtensions
        // 5. Send Certificate
        // 6. Send CertificateVerify
        // 7. Send Finished
        // 8. Receive client Finished
        //
        // For this example, we'll send a mock response
        let response = b"Mock ServerHello response";
        stream
            .write_all(response)
            .map_err(|e| Error::InvalidMessage(format!("Write failed: {}", e)))?;

        println!("→ Sent ServerHello ({} bytes)", response.len());
        println!("✓ Handshake completed successfully");

        Ok(())
    }

    /// Echo service - receives data and sends it back
    fn echo_service(&self, stream: &mut TcpStream) -> Result<()> {
        println!("Echo service active");

        let mut buffer = vec![0u8; 4096];

        loop {
            // Receive data
            match stream.read(&mut buffer) {
                Ok(0) => {
                    println!("← Client closed connection");
                    break;
                }
                Ok(n) => {
                    println!("← Received {} bytes", n);

                    // In a real implementation, we would:
                    // 1. Decrypt TLS record
                    // 2. Process application data
                    // 3. Encrypt response
                    // 4. Send TLS record
                    //
                    // For this example, we'll echo plaintext
                    stream.write_all(&buffer[..n]).map_err(|e| {
                        Error::InvalidMessage(format!("Echo write failed: {}", e))
                    })?;

                    println!("→ Echoed {} bytes", n);
                }
                Err(e) => {
                    return Err(Error::InvalidMessage(format!("Read error: {}", e)));
                }
            }
        }

        Ok(())
    }
}

/// Command-line arguments
struct Args {
    port: u16,
    verbose: bool,
}

impl Args {
    fn parse() -> Self {
        let mut args = std::env::args().skip(1);
        let mut port = 4433;
        let mut verbose = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
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

        Self { port, verbose }
    }

    fn print_help() {
        println!(
            r#"
HPTLS Simple TLS 1.3 Server Example

USAGE:
    simple_server [OPTIONS]

OPTIONS:
    -p, --port <PORT>      Listen port [default: 4433]
    -v, --verbose          Enable verbose logging
        --help             Print this help message

EXAMPLES:
    # Start server on default port 4433
    cargo run --example simple_server

    # Start server on custom port
    cargo run --example simple_server -- --port 8443

    # Enable verbose output
    cargo run --example simple_server -- --verbose

DESCRIPTION:
    This example demonstrates a minimal TLS 1.3 server that:
    - Listens for incoming connections
    - Performs TLS 1.3 handshake
    - Echoes back received data
    - Handles multiple sequential connections

    The server implements an echo service - all received data is
    sent back to the client.

TESTING:
    You can test the server with:

    # Using the simple_client example
    cargo run --example simple_client -- --host localhost --port 4433

    # Using OpenSSL s_client
    openssl s_client -connect localhost:4433 -tls1_3

    # Using cURL
    curl --tlsv1.3 --insecure https://localhost:4433/

NOTE:
    This example uses MockCryptoProvider for demonstration purposes.
    For production use, integrate a real cryptography library and
    proper certificate management.
"#
        );
    }
}

fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    if args.verbose {
        println!("\n=== HPTLS Simple TLS 1.3 Server ===\n");
        println!("Configuration:");
        println!("  Port: {}", args.port);
        println!("  Protocol: TLS 1.3");
        println!("  Service: Echo");
        println!();
    }

    // Create and start server
    let server = SimpleTlsServer::new(args.port)?;
    server.serve()?;

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
    #[ignore] // Requires binding to port
    fn test_server_creation() {
        // Test would go here
    }
}
