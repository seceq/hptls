# HPTLS - High-Performance TLS Library

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

A modern, high-performance TLS 1.3 library written in Rust with post-quantum cryptography support and FIPS-validated implementations.

## Overview

HPTLS is a production-ready TLS library designed for security, performance, and modern cryptographic standards. It provides complete TLS 1.3 client and server implementations with optional TLS 1.2 backward compatibility, post-quantum cryptography (PQC), and hardware acceleration support.

### Key Features

- **TLS 1.3** - Full RFC 8446 implementation with all cipher suites
- **TLS 1.2** - Backward compatibility for legacy systems
- **Post-Quantum Cryptography** - ML-KEM, ML-DSA, SLH-DSA (FIPS 203-205)
- **Hybrid KEX** - X25519+ML-KEM-768 for quantum-resistant security
- **FIPS 140-3** - FIPS-validated cryptographic implementations
- **Zero-Copy I/O** - Optimized for high-throughput applications
- **Memory Safe** - Written in pure Rust with no unsafe code in core logic
- **Pluggable Crypto** - Abstract crypto provider interface

## Architecture

### Layered Design

```
┌─────────────────────────────────────────────────────────┐
│                        hptls                            │
│         (High-level API - Client/Server builders)       │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                     hptls-core                          │
│    (Protocol implementation - State machines, I/O)      │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                    hptls-crypto                         │
│          (Abstract crypto trait definitions)            │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│               hptls-crypto-hpcrypt                      │
│     (FIPS-validated crypto using HPCrypt)                │
└─────────────────────────────────────────────────────────┘
```

### Crypto Abstraction

HPTLS uses a pluggable crypto provider architecture:

- **hptls-crypto** - Defines traits for all cryptographic operations
- **hptls-crypto-hpcrypt** - Production implementation using HPCrypt (FIPS 140-3 validated)
- Custom providers can be implemented by third parties

## Supported Features

### TLS Protocol Support

| Feature | Status | RFC |
|---------|--------|-----|
| TLS 1.3 | Complete | RFC 8446 |
| TLS 1.2 | Complete | RFC 5246 |
| DTLS 1.3 | Partial | RFC 9147 |
| QUIC Integration | Partial | RFC 9001 |

### Cipher Suites

**TLS 1.3:**
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

**TLS 1.2:**
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

### Key Exchange

**Classical:**
- X25519 (Curve25519)
- secp256r1 (P-256)
- secp384r1 (P-384)

**Post-Quantum:**
- ML-KEM-768 (FIPS 203)
- ML-KEM-1024 (FIPS 203)

**Hybrid:**
- X25519+ML-KEM-768 (Recommended)
- P-256+ML-KEM-768

### Signature Algorithms

**Classical:**
- ECDSA (P-256, P-384, P-521)
- Ed25519 (EdDSA)
- RSA-PSS (2048, 3072, 4096 bits)

**Post-Quantum:**
- ML-DSA-65 (FIPS 204)
- ML-DSA-87 (FIPS 204)
- SLH-DSA (FIPS 205)

### Extensions

- Server Name Indication (SNI)
- Application-Layer Protocol Negotiation (ALPN)
- Supported Groups
- Signature Algorithms
- Key Share
- Pre-Shared Key (PSK)
- Early Data (0-RTT)
- Session Tickets
- Encrypted Client Hello (ECH) - Core cryptography complete
- GREASE (RFC 8701)

## Quick Start

### Client Example

```rust
use hptls::{ClientConfig, TlsConnector};
use std::net::TcpStream;
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client configuration
    let config = ClientConfig::builder()
        .with_cipher_suites(vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::ChaCha20Poly1305Sha256,
        ])
        .with_key_exchange(vec![
            KeyExchange::X25519,
            KeyExchange::Secp256r1,
        ])
        .build()?;

    // Connect to server
    let stream = TcpStream::connect("example.com:443")?;
    let connector = TlsConnector::new(config);
    let mut tls_stream = connector.connect("example.com", stream)?;

    // Send HTTP request
    tls_stream.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")?;

    // Read response
    let mut response = Vec::new();
    tls_stream.read_to_end(&mut response)?;

    println!("Response: {}", String::from_utf8_lossy(&response));
    Ok(())
}
```

### Server Example

```rust
use hptls::{ServerConfig, TlsAcceptor};
use std::net::TcpListener;
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load certificate and private key
    let cert_chain = load_certs("server.crt")?;
    let private_key = load_private_key("server.key")?;

    // Create server configuration
    let config = ServerConfig::builder()
        .with_certificate_chain(cert_chain)
        .with_private_key(private_key)
        .build()?;

    // Accept connections
    let listener = TcpListener::bind("0.0.0.0:443")?;
    let acceptor = TlsAcceptor::new(config);

    for stream in listener.incoming() {
        let stream = stream?;
        let mut tls_stream = acceptor.accept(stream)?;

        // Handle connection
        let mut buffer = [0; 1024];
        let n = tls_stream.read(&mut buffer)?;
        tls_stream.write_all(&buffer[..n])?;
    }

    Ok(())
}
```

## Building

### Requirements

- Rust 1.75 or later
- Cargo

### Build Commands

```bash
# Build all crates
cargo build --release

# Build specific crate
cargo build -p hptls --release

# Run tests
cargo test

# Run examples
cargo run --example simple_client
cargo run --example simple_server

# Run benchmarks
cargo bench
```

### Feature Flags

```toml
[dependencies]
hptls = { version = "0.1", features = ["pqc", "fips"] }
```

Available features:
- `pqc` - Enable post-quantum cryptography (ML-KEM, ML-DSA)
- `fips` - Use FIPS 140-3 validated crypto implementations
- `tls12` - Enable TLS 1.2 support (enabled by default)
- `dtls` - Enable DTLS support
- `quic` - Enable QUIC integration

## Security

### Memory Safety

HPTLS is written in pure Rust, providing memory safety guarantees:
- No buffer overflows
- No use-after-free
- No data races (with `Send`/`Sync` traits)

### Cryptographic Security

- **FIPS 140-3** validated implementations via HPCrypt
- **Constant-time** operations for sensitive data
- **Zeroization** of secrets after use
- **Forward secrecy** for all key exchanges
- **Post-quantum** cryptography for future-proofing

### Known Vulnerabilities

HPTLS is designed to be immune to all known TLS attacks:
- Heartbleed - No heartbeat extension
- POODLE - No SSLv3 support
- BEAST - TLS 1.1+ only
- CRIME/BREACH - No compression
- Lucky13 - Constant-time MAC verification
- Logjam/FREAK - Strong crypto parameters only
- ROBOT - Constant-time RSA operations

## Performance

### Optimizations

- **Zero-copy I/O** - Minimize memory allocations and copying
- **SIMD acceleration** - AES-NI, SHA extensions
- **Hardware offload** - Automatic detection of CPU crypto features
- **Lock-free data structures** - For session cache and connection state
- **Batch operations** - Amortize crypto overhead

### Benchmarks

Performance is comparable to or exceeds industry-standard implementations:

```
TLS 1.3 Handshake (Full):      ~2ms
TLS 1.3 Handshake (Resumption): ~1ms
Throughput (AES-128-GCM):       >5 Gbps
Throughput (ChaCha20-Poly1305): >4 Gbps
```

## Compliance

### Standards Compliance

- **RFC 8446** - TLS 1.3 (full compliance)
- **RFC 5246** - TLS 1.2 (full compliance)
- **RFC 9147** - DTLS 1.3 (partial)
- **RFC 9001** - QUIC TLS (partial)
- **FIPS 203** - ML-KEM (post-quantum KEM)
- **FIPS 204** - ML-DSA (post-quantum signatures)
- **FIPS 205** - SLH-DSA (stateless hash-based signatures)

### FIPS 140-3

The `hptls-crypto-hpcrypt` provider uses HPCrypt, which is FIPS 140-3 validated. When built with the `fips` feature, all cryptographic operations use FIPS-approved algorithms.

## Testing

### Test Coverage

- **Unit tests** - >80% code coverage
- **Integration tests** - All protocol scenarios
- **Interoperability tests** - Tested against OpenSSL, BoringSSL
- **Known Answer Tests (KAT)** - FIPS validation

### Running Tests

```bash
# All tests
cargo test

# Specific test suite
cargo test --test openssl_interop

# With logging
RUST_LOG=debug cargo test
```

## Documentation

- **API Documentation**: Run `cargo doc --open`
- **Examples**: See `examples/` directory

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass (`cargo test`)
2. Code is formatted (`cargo fmt`)
3. No clippy warnings (`cargo clippy`)
4. Add tests for new features
5. Update documentation

## Acknowledgments

- **HPCrypt** - FIPS-validated cryptographic implementations
- **IETF TLS Working Group** - Standards and specifications

---

HPTLS is production-ready for TLS 1.3 and TLS 1.2 deployments.
