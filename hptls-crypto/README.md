# hptls-crypto

Cryptographic provider interface for HPTLS (High-Performance TLS).

## Overview

This crate defines trait-based interfaces for all cryptographic operations needed by HPTLS. It allows pluggable cryptographic backends, enabling you to:

- Use your custom cryptography library
- Swap crypto implementations without changing TLS code
- Support multiple backends (native, ring, aws-lc-rs, etc.)
- Leverage hardware acceleration automatically

## Architecture

```
CryptoProvider (main trait)
├── Aead        → AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
├── Hash        → Cryptographic hashes (SHA-256, SHA-384, SHA-512)
├── Hmac        → HMAC for message authentication
├── Kdf         → Key derivation (HKDF, TLS PRF)
├── Random      → Cryptographically secure RNG
├── KeyExchange → Key agreement (ECDHE, DHE, ML-KEM, hybrids)
└── Signature   → Digital signatures (ECDSA, EdDSA, RSA-PSS, ML-DSA)
```

## Design Goals

1. **Pluggable**: Support multiple crypto backends
2. **Zero-cost**: Traits compile to static dispatch
3. **Type-safe**: Leverage Rust's type system
4. **Hardware-aware**: Auto-detect AES-NI, SHA extensions, etc.
5. **Constant-time**: Security-critical operations are constant-time
6. **Memory-safe**: Private keys zeroized on drop

## Usage

### Implementing a Crypto Provider

```rust
use hptls_crypto::{CryptoProvider, AeadAlgorithm, Aead, Result};

pub struct MyCryptoProvider {
    hardware_features: HardwareFeatures,
}

impl CryptoProvider for MyCryptoProvider {
    fn new() -> Self {
        Self {
            hardware_features: HardwareFeatures::detect(),
        }
    }

    fn aead(&self, algorithm: AeadAlgorithm) -> Result<Box<dyn Aead>> {
        match algorithm {
            AeadAlgorithm::Aes128Gcm if self.hardware_features.aes_ni => {
                Ok(Box::new(MyAesGcmNi::new()?))
            }
            AeadAlgorithm::Aes128Gcm => {
                Ok(Box::new(MyAesGcmSoft::new()?))
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                Ok(Box::new(MyChaCha20Poly1305::new()?))
            }
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }

    // ... implement other methods
}
```

### Using AEAD Cipher

```rust
let provider = MyCryptoProvider::new();
let aead = provider.aead(AeadAlgorithm::Aes128Gcm)?;

let key = &[0u8; 16];
let nonce = &[0u8; 12];
let aad = b"additional data";
let plaintext = b"secret message";

// Encrypt
let ciphertext = aead.seal(key, nonce, aad, plaintext)?;

// Decrypt
let decrypted = aead.open(key, nonce, aad, &ciphertext)?;
assert_eq!(plaintext, &decrypted[..]);
```

### Using Key Exchange

```rust
let provider = MyCryptoProvider::new();
let kex = provider.key_exchange(KeyExchangeAlgorithm::X25519)?;

// Generate ephemeral key pair
let (private_key, public_key) = kex.generate_keypair()?;

// Exchange with peer
let peer_public_key = /* received from peer */;
let shared_secret = kex.exchange(&private_key, peer_public_key)?;

// Use shared_secret for key derivation
```

## Required Algorithms

### Minimum (for TLS 1.3 MVP)

- **AEAD**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **Hash**: SHA-256, SHA-384, SHA-512
- **KDF**: HKDF-SHA256, HKDF-SHA384
- **KeyExchange**: X25519, P-256, P-384
- **Signature**: ECDSA-P256-SHA256, ECDSA-P384-SHA384, Ed25519, RSA-PSS-SHA256

### For TLS 1.2

- **KDF**: TLS-PRF-SHA256, TLS-PRF-SHA384
- **KeyExchange**: DHE (ffdhe2048, ffdhe3072)

### For Post-Quantum (Phase 4)

- **KeyExchange**: ML-KEM-768, X25519MLKEM768, Secp256r1MLKEM768
- **Signature**: ML-DSA-65 (optional)

## Performance Considerations

### Hardware Acceleration

The provider should detect and use CPU features:

```rust
let features = HardwareFeatures::detect();

if features.aes_ni {
    // Use AES-NI instructions for AES
}
if features.sha_ext {
    // Use SHA extensions for SHA-256/384/512
}
if features.avx2 {
    // Use AVX2 for vectorized operations
}
```

### Zero-Copy Operations

For performance, implement in-place variants:

```rust
impl Aead for MyAead {
    fn seal_in_place(&self, key: &[u8], nonce: &[u8], aad: &[u8],
                     buffer: &mut [u8], plaintext_len: usize) -> Result<usize> {
        // Encrypt in-place without allocations
        // ...
    }
}
```

## Security Requirements

### Constant-Time Operations

All security-critical operations **MUST** be constant-time:

- AEAD tag verification
- HMAC verification
- Signature verification
- Private key operations

Use the `subtle` crate for constant-time comparisons:

```rust
use subtle::ConstantTimeEq;

fn verify_tag(expected: &[u8], actual: &[u8]) -> bool {
    expected.ct_eq(actual).into()
}
```

### Memory Safety

Private keys and shared secrets **MUST** be zeroized on drop:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: Vec<u8>,
}
```

### Random Number Generation

**MUST** use a cryptographically secure RNG:

- Linux: `getrandom()` syscall
- Windows: `BCryptGenRandom()`
- Other: OS-specific secure RNG

**DO NOT** use weak PRNGs like `rand::random()` or `std::random()`.

## Testing

Run tests with:

```bash
cargo test --all-features
```

Run benchmarks:

```bash
cargo bench
```

## Features

- `default`: No crypto implementation (interface only)
- `native`: Use your custom crypto library
- `ring`: Use `ring` as crypto provider
- `aws-lc-rs`: Use `aws-lc-rs` as crypto provider

## License

MIT OR Apache-2.0

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) in the repository root.
