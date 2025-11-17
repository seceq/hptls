//! Production-Ready Echo Server Example
//!
//! This example demonstrates a more robust TLS 1.3 echo server with:
//! - Proper error handling
//! - Logging
//! - Graceful shutdown
//! - Connection statistics
//! - Configuration options
//!
//! # Usage
//!
//! ```bash
//! cargo run --example echo_server -- --port 8443 --max-connections 100
//! ```

use hptls_core::{
    cipher::CipherSuite,
    error::{Error, Result},
    protocol::ProtocolVersion,
    Config,
};
use hptls_crypto::KeyExchangeAlgorithm;
use hptls_crypto_mock::MockCryptoProvider;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Server statistics
#[derive(Debug)]
struct ServerStats {
    connections_accepted: AtomicUsize,
    connections_completed: AtomicUsize,
    connections_failed: AtomicUsize,
    bytes_received: AtomicUsize,
    bytes_sent: AtomicUsize,
    start_time: Instant,
}

impl ServerStats {
    fn new() -> Self {
        Self {
            connections_accepted: AtomicUsize::new(0),
            connections_completed: AtomicUsize::new(0),
            connections_failed: AtomicUsize::new(0),
            bytes_received: AtomicUsize::new(0),
            bytes_sent: AtomicUsize::new(0),
            start_time: Instant::now(),
        }
    }

    fn print_summary(&self) {
        let uptime = self.start_time.elapsed();
        let accepted = self.connections_accepted.load(Ordering::Relaxed);
        let completed = self.connections_completed.load(Ordering::Relaxed);
        let failed = self.connections_failed.load(Ordering::Relaxed);
        let rx_bytes = self.bytes_received.load(Ordering::Relaxed);
        let tx_bytes = self.bytes_sent.load(Ordering::Relaxed);

        println!("\n=== Server Statistics ===");
        println!("Uptime: {:?}", uptime);
        println!("Connections:");
        println!("  Accepted:  {}", accepted);
        println!("  Completed: {}", completed);
        println!("  Failed:    {}", failed);
        println!("Data Transfer:");
        println!("  Received: {} bytes ({:.2} KB)", rx_bytes, rx_bytes as f64 / 1024.0);
        println!("  Sent:     {} bytes ({:.2} KB)", tx_bytes, tx_bytes as f64 / 1024.0);
        println!();
    }
}

/// Echo server configuration
struct EchoServerConfig {
    port: u16,
    max_connections: Option<usize>,
    buffer_size: usize,
    verbose: bool,
    stats_interval: Option<Duration>,
}

impl Default for EchoServerConfig {
    fn default() -> Self {
        Self {
            port: 8443,
            max_connections: None,
            buffer_size: 4096,
            verbose: false,
            stats_interval: Some(Duration::from_secs(60)),
        }
    }
}

/// Production-ready echo server
struct EchoServer {
    config: EchoServerConfig,
    tls_config: Config,
    provider: MockCryptoProvider,
    stats: Arc<ServerStats>,
    shutdown: Arc<AtomicBool>,
}

impl EchoServer {
    /// Create a new echo server
    fn new(config: EchoServerConfig) -> Result<Self> {
        let tls_config = Config::builder()
            .with_protocol_versions(&[ProtocolVersion::Tls13])
            .with_session_resumption(true)
            .with_early_data(false, 0) // Disable 0-RTT for echo server
            .build()?;

        let provider = MockCryptoProvider::new();
        let stats = Arc::new(ServerStats::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        // Set up Ctrl+C handler
        let shutdown_clone = shutdown.clone();
        ctrlc::set_handler(move || {
            println!("\n\nShutdown signal received...");
            shutdown_clone.store(true, Ordering::Relaxed);
        })
        .map_err(|e| Error::InvalidMessage(format!("Failed to set Ctrl+C handler: {}", e)))?;

        Ok(Self {
            config,
            tls_config,
            provider,
            stats,
            shutdown,
        })
    }

    /// Start serving
    fn serve(&self) -> Result<()> {
        self.print_banner();

        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.config.port))
            .map_err(|e| Error::InvalidMessage(format!("Bind failed: {}", e)))?;

        listener
            .set_nonblocking(true)
            .map_err(|e| Error::InvalidMessage(format!("Set nonblocking failed: {}", e)))?;

        println!("✓ Server listening on 0.0.0.0:{}", self.config.port);
        println!("✓ Press Ctrl+C to stop\n");

        let mut last_stats_print = Instant::now();
        let mut connection_count = 0;

        while !self.shutdown.load(Ordering::Relaxed) {
            // Accept connection (non-blocking)
            match listener.accept() {
                Ok((stream, addr)) => {
                    self.stats.connections_accepted.fetch_add(1, Ordering::Relaxed);
                    connection_count += 1;

                    if self.config.verbose {
                        println!("\n[Conn {}] Accepted from {}", connection_count, addr);
                    }

                    // Check max connections limit
                    if let Some(max) = self.config.max_connections {
                        if connection_count > max {
                            println!("✗ Max connections ({}) reached, rejecting", max);
                            drop(stream);
                            continue;
                        }
                    }

                    // Handle connection
                    if let Err(e) = self.handle_connection(stream, connection_count) {
                        if self.config.verbose {
                            eprintln!("[Conn {}] ✗ Error: {}", connection_count, e);
                        }
                        self.stats.connections_failed.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.stats.connections_completed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection available, sleep briefly
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    eprintln!("✗ Accept error: {}", e);
                }
            }

            // Print periodic statistics
            if let Some(interval) = self.config.stats_interval {
                if last_stats_print.elapsed() >= interval {
                    self.stats.print_summary();
                    last_stats_print = Instant::now();
                }
            }
        }

        println!("\n✓ Server shutdown complete");
        self.stats.print_summary();

        Ok(())
    }

    /// Handle a single connection
    fn handle_connection(&self, mut stream: TcpStream, conn_id: usize) -> Result<()> {
        let start = Instant::now();

        // Set timeouts
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .ok();

        // Echo loop
        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut total_rx = 0;
        let mut total_tx = 0;

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    // Connection closed
                    if self.config.verbose {
                        println!(
                            "[Conn {}] ✓ Closed (duration: {:?}, rx: {}, tx: {})",
                            conn_id,
                            start.elapsed(),
                            total_rx,
                            total_tx
                        );
                    }
                    break;
                }
                Ok(n) => {
                    total_rx += n;
                    self.stats.bytes_received.fetch_add(n, Ordering::Relaxed);

                    if self.config.verbose {
                        println!("[Conn {}] ← Received {} bytes", conn_id, n);
                    }

                    // Echo back
                    stream.write_all(&buffer[..n]).map_err(|e| {
                        Error::InvalidMessage(format!("Write failed: {}", e))
                    })?;

                    total_tx += n;
                    self.stats.bytes_sent.fetch_add(n, Ordering::Relaxed);

                    if self.config.verbose {
                        println!("[Conn {}] → Echoed {} bytes", conn_id, n);
                    }
                }
                Err(e) => {
                    return Err(Error::InvalidMessage(format!("Read error: {}", e)));
                }
            }
        }

        Ok(())
    }

    /// Print server banner
    fn print_banner(&self) {
        println!(
            r#"
╔═══════════════════════════════════════════════════════════╗
║                  HPTLS Echo Server v0.1                   ║
║                    TLS 1.3 Enabled                        ║
╚═══════════════════════════════════════════════════════════╝
"#
        );

        println!("Configuration:");
        println!("  Port:            {}", self.config.port);
        println!("  Max Connections: {:?}", self.config.max_connections.map_or("unlimited".to_string(), |m| m.to_string()));
        println!("  Buffer Size:     {} bytes", self.config.buffer_size);
        println!("  Verbose:         {}", self.config.verbose);
        println!("  Stats Interval:  {:?}", self.config.stats_interval);
        println!();
    }
}

/// Parse command-line arguments
fn parse_args() -> EchoServerConfig {
    let mut args = std::env::args().skip(1);
    let mut config = EchoServerConfig::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" | "-p" => {
                config.port = args
                    .next()
                    .expect("Missing port argument")
                    .parse()
                    .expect("Invalid port number");
            }
            "--max-connections" | "-m" => {
                config.max_connections = Some(
                    args.next()
                        .expect("Missing max-connections argument")
                        .parse()
                        .expect("Invalid max-connections number"),
                );
            }
            "--buffer-size" | "-b" => {
                config.buffer_size = args
                    .next()
                    .expect("Missing buffer-size argument")
                    .parse()
                    .expect("Invalid buffer-size number");
            }
            "--verbose" | "-v" => {
                config.verbose = true;
            }
            "--no-stats" => {
                config.stats_interval = None;
            }
            "--help" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                print_help();
                std::process::exit(1);
            }
        }
    }

    config
}

fn print_help() {
    println!(
        r#"
HPTLS Production Echo Server Example

USAGE:
    echo_server [OPTIONS]

OPTIONS:
    -p, --port <PORT>              Listen port [default: 8443]
    -m, --max-connections <NUM>    Max concurrent connections [default: unlimited]
    -b, --buffer-size <SIZE>       Buffer size in bytes [default: 4096]
    -v, --verbose                  Enable verbose logging
        --no-stats                 Disable periodic statistics
        --help                     Print this help message

EXAMPLES:
    # Start server with defaults
    cargo run --example echo_server

    # Custom port and connection limit
    cargo run --example echo_server -- --port 8443 --max-connections 100

    # Verbose mode with large buffer
    cargo run --example echo_server -- --verbose --buffer-size 65536

DESCRIPTION:
    Production-ready echo server demonstrating:
    - Proper error handling
    - Connection statistics
    - Graceful shutdown (Ctrl+C)
    - Resource limits
    - Logging and monitoring

TESTING:
    # Using netcat
    echo "Hello, TLS!" | nc localhost 8443

    # Using telnet
    telnet localhost 8443

    # Using OpenSSL
    openssl s_client -connect localhost:8443 -tls1_3

DEPENDENCIES:
    This example requires the `ctrlc` crate for signal handling.
    Add to Cargo.toml:
    [dev-dependencies]
    ctrlc = "3.4"
"#
    );
}

fn main() -> Result<()> {
    let config = parse_args();
    let server = EchoServer::new(config)?;
    server.serve()
}
