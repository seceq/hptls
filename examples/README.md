# HPTLS Examples

This directory contains practical examples demonstrating how to use the HPTLS library for various TLS/DTLS/QUIC use cases.

## Quick Start Examples

### Basic TLS 1.3

1. **[simple_client.rs](simple_client.rs)** - Minimal TLS 1.3 client
   - Connects to a server
   - Performs handshake
   - Sends/receives data

2. **[simple_server.rs](simple_server.rs)** - Minimal TLS 1.3 server
   - Listens for connections
   - Handles handshake
   - Echoes data back

### Advanced Features

3. **[psk_client.rs](psk_client.rs)** - Pre-Shared Key client
   - Session resumption
   - 0-RTT early data
   - PSK modes

4. **[psk_server.rs](psk_server.rs)** - Pre-Shared Key server
   - Session ticket issuance
   - 0-RTT acceptance
   - PSK validation

5. **[client_auth.rs](client_auth.rs)** - Client certificate authentication
   - Mutual TLS (mTLS)
   - Certificate validation
   - Client signatures

6. **[post_quantum.rs](post_quantum.rs)** - Post-Quantum cryptography
   - Hybrid key exchange (X25519 + ML-KEM-768)
   - PQC signatures (ML-DSA)
   - Future-proof security

7. **[ech_client.rs](ech_client.rs)** - Encrypted Client Hello
   - SNI privacy
   - ECH configuration
   - GREASE support

### Protocol Variants

8. **[dtls_client.rs](dtls_client.rs)** - DTLS 1.3 over UDP
   - Datagram transport
   - Replay protection
   - Retransmission handling

9. **[quic_integration.rs](quic_integration.rs)** - QUIC-TLS integration
   - QUIC handshake
   - Key derivation
   - Packet protection

### Production Use Cases

10. **[http_client.rs](http_client.rs)** - HTTPS client
    - HTTP/1.1 over TLS
    - ALPN negotiation
    - Connection pooling

11. **[echo_server.rs](echo_server.rs)** - Production echo server
    - Multi-threaded
    - Error handling
    - Logging

12. **[proxy.rs](proxy.rs)** - TLS proxy/load balancer
    - SNI routing
    - Certificate management
    - Connection pooling

## Running Examples

### Prerequisites

```bash
# Build the examples
cargo build --examples

# Or build a specific example
cargo build --example simple_client
```

### Running Specific Examples

#### Simple Client/Server

Terminal 1 (Server):
```bash
cargo run --example simple_server
```

Terminal 2 (Client):
```bash
cargo run --example simple_client
```

#### PSK Resumption

```bash
# Server with PSK enabled
cargo run --example psk_server

# Client with session resumption
cargo run --example psk_client
```

#### Post-Quantum TLS

```bash
# Run with PQC algorithms
cargo run --example post_quantum -- --hybrid
```

#### DTLS over UDP

```bash
# DTLS server
cargo run --example dtls_server

# DTLS client
cargo run --example dtls_client
```

## Example Categories

### 🔰 Beginner

- `simple_client.rs` - Start here!
- `simple_server.rs` - Basic server
- `echo_server.rs` - Practical example

### 🔧 Intermediate

- `psk_client.rs` / `psk_server.rs` - Session resumption
- `client_auth.rs` - Mutual TLS
- `http_client.rs` - Real-world usage

### 🚀 Advanced

- `post_quantum.rs` - Cutting-edge crypto
- `ech_client.rs` - Privacy features
- `quic_integration.rs` - Modern protocols
- `proxy.rs` - Production patterns

## Configuration

Most examples accept command-line arguments for configuration:

```bash
# Specify custom port
cargo run --example simple_server -- --port 8443

# Enable verbose logging
cargo run --example simple_client -- --verbose

# Use specific cipher suite
cargo run --example simple_client -- --cipher TLS_AES_256_GCM_SHA384

# Enable 0-RTT
cargo run --example psk_client -- --early-data
```

## Testing with External Tools

### OpenSSL

Test client against OpenSSL server:
```bash
# Start OpenSSL server
openssl s_server -port 4433 -key server.key -cert server.crt -tls1_3

# Connect with HPTLS client
cargo run --example simple_client -- --host localhost --port 4433
```

Test server against OpenSSL client:
```bash
# Start HPTLS server
cargo run --example simple_server

# Connect with OpenSSL client
openssl s_client -connect localhost:4433 -tls1_3
```

### cURL

```bash
# Start HPTLS server
cargo run --example http_server

# Test with cURL
curl --tlsv1.3 https://localhost:8443/
```

## Certificate Generation

For testing, generate self-signed certificates:

```bash
# Generate CA
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem -days 365 -nodes

# Generate server certificate
openssl req -newkey rsa:4096 -keyout server-key.pem -out server-req.pem -nodes
openssl x509 -req -in server-req.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365

# Generate client certificate (for mTLS)
openssl req -newkey rsa:4096 -keyout client-key.pem -out client-req.pem -nodes
openssl x509 -req -in client-req.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 365
```

## Performance Testing

### Benchmarking

```bash
# Run handshake benchmark
cargo run --example bench_handshake -- --connections 1000

# Throughput benchmark
cargo run --example bench_throughput -- --duration 30s
```

### Load Testing

```bash
# Using Apache Bench
ab -n 10000 -c 100 https://localhost:8443/

# Using wrk
wrk -t4 -c100 -d30s https://localhost:8443/
```

## Troubleshooting

### Common Issues

1. **"Connection refused"**
   - Ensure server is running first
   - Check port number matches

2. **"Certificate verification failed"**
   - Add CA certificate to trust store
   - Or use `--insecure` flag for testing

3. **"Handshake timeout"**
   - Check firewall settings
   - Verify network connectivity

4. **"Unsupported cipher suite"**
   - Ensure both client and server support common cipher
   - Check TLS version compatibility

### Debug Logging

Enable debug output:
```bash
RUST_LOG=debug cargo run --example simple_client
```

Trace-level logging:
```bash
RUST_LOG=trace cargo run --example simple_server
```

## Further Reading

- [HPTLS Documentation](../docs/)
- [API Reference](https://docs.rs/hptls/)
- [RFC 8446 - TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [RFC 9147 - DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147.html)
- [RFC 9001 - QUIC-TLS](https://www.rfc-editor.org/rfc/rfc9001.html)

## Contributing

Found a bug in an example? Want to add a new example?
See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

All examples are provided under the same license as the main HPTLS library.
See [LICENSE](../LICENSE) for details.
