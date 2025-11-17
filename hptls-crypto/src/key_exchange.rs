//! Key exchange algorithms for TLS.

use crate::Result;
use zeroize::Zeroize;

/// Key exchange algorithms supported by HPTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyExchangeAlgorithm {
    // Elliptic Curve Diffie-Hellman
    /// X25519 (Curve25519 ECDHE) - TLS 1.3 preferred
    X25519,
    /// secp256r1 (P-256, NIST curve)
    Secp256r1,
    /// secp384r1 (P-384, NIST curve)
    Secp384r1,
    /// secp521r1 (P-521, NIST curve)
    Secp521r1,
    /// X448 (Curve448)
    X448,

    // Finite Field Diffie-Hellman (TLS 1.2 compatibility)
    /// ffdhe2048 (RFC 7919)
    Ffdhe2048,
    /// ffdhe3072 (RFC 7919)
    Ffdhe3072,
    /// ffdhe4096 (RFC 7919)
    Ffdhe4096,

    // Post-Quantum Key Encapsulation Mechanisms
    /// ML-KEM-512 (FIPS 203)
    MlKem512,
    /// ML-KEM-768 (FIPS 203) - Recommended
    MlKem768,
    /// ML-KEM-1024 (FIPS 203)
    MlKem1024,

    // Hybrid Post-Quantum (most important for TLS)
    /// X25519 + ML-KEM-768 (hybrid)
    X25519MlKem768,
    /// P-256 + ML-KEM-768 (hybrid)
    Secp256r1MlKem768,
}

impl KeyExchangeAlgorithm {
    /// Get the public key size in bytes for this algorithm.
    pub const fn public_key_size(self) -> usize {
        match self {
            KeyExchangeAlgorithm::X25519 => 32,
            KeyExchangeAlgorithm::Secp256r1 => 65, // Uncompressed point
            KeyExchangeAlgorithm::Secp384r1 => 97,
            KeyExchangeAlgorithm::Secp521r1 => 133,
            KeyExchangeAlgorithm::X448 => 56,
            KeyExchangeAlgorithm::Ffdhe2048 => 256,
            KeyExchangeAlgorithm::Ffdhe3072 => 384,
            KeyExchangeAlgorithm::Ffdhe4096 => 512,
            KeyExchangeAlgorithm::MlKem512 => 800,
            KeyExchangeAlgorithm::MlKem768 => 1184,
            KeyExchangeAlgorithm::MlKem1024 => 1568,
            KeyExchangeAlgorithm::X25519MlKem768 => 32 + 1184,
            KeyExchangeAlgorithm::Secp256r1MlKem768 => 65 + 1184,
        }
    }

    /// Get the shared secret size in bytes.
    pub const fn shared_secret_size(self) -> usize {
        match self {
            KeyExchangeAlgorithm::X25519 => 32,
            KeyExchangeAlgorithm::Secp256r1 => 32,
            KeyExchangeAlgorithm::Secp384r1 => 48,
            KeyExchangeAlgorithm::Secp521r1 => 66,
            KeyExchangeAlgorithm::X448 => 56,
            KeyExchangeAlgorithm::Ffdhe2048 => 256,
            KeyExchangeAlgorithm::Ffdhe3072 => 384,
            KeyExchangeAlgorithm::Ffdhe4096 => 512,
            KeyExchangeAlgorithm::MlKem512 => 32,
            KeyExchangeAlgorithm::MlKem768 => 32,
            KeyExchangeAlgorithm::MlKem1024 => 32,
            KeyExchangeAlgorithm::X25519MlKem768 => 64, // Concatenated
            KeyExchangeAlgorithm::Secp256r1MlKem768 => 64,
        }
    }

    /// Get the IANA TLS supported_groups codepoint.
    pub const fn iana_codepoint(self) -> u16 {
        match self {
            KeyExchangeAlgorithm::X25519 => 0x001D,
            KeyExchangeAlgorithm::Secp256r1 => 0x0017,
            KeyExchangeAlgorithm::Secp384r1 => 0x0018,
            KeyExchangeAlgorithm::Secp521r1 => 0x0019,
            KeyExchangeAlgorithm::X448 => 0x001E,
            KeyExchangeAlgorithm::Ffdhe2048 => 0x0100,
            KeyExchangeAlgorithm::Ffdhe3072 => 0x0101,
            KeyExchangeAlgorithm::Ffdhe4096 => 0x0102,
            KeyExchangeAlgorithm::MlKem512 => 0x0200, // Placeholder (not standardized yet)
            KeyExchangeAlgorithm::MlKem768 => 0x0201, // Placeholder
            KeyExchangeAlgorithm::MlKem1024 => 0x0202, // Placeholder
            KeyExchangeAlgorithm::X25519MlKem768 => 0x11EC, // IANA registered
            KeyExchangeAlgorithm::Secp256r1MlKem768 => 0x11EB, // IANA registered
        }
    }

    /// Convert to wire format (u16).
    pub const fn to_u16(self) -> u16 {
        self.iana_codepoint()
    }

    /// Convert from wire format (u16).
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x001D => Some(KeyExchangeAlgorithm::X25519),
            0x0017 => Some(KeyExchangeAlgorithm::Secp256r1),
            0x0018 => Some(KeyExchangeAlgorithm::Secp384r1),
            0x0019 => Some(KeyExchangeAlgorithm::Secp521r1),
            0x001E => Some(KeyExchangeAlgorithm::X448),
            0x0100 => Some(KeyExchangeAlgorithm::Ffdhe2048),
            0x0101 => Some(KeyExchangeAlgorithm::Ffdhe3072),
            0x0102 => Some(KeyExchangeAlgorithm::Ffdhe4096),
            0x0200 => Some(KeyExchangeAlgorithm::MlKem512),
            0x0201 => Some(KeyExchangeAlgorithm::MlKem768),
            0x0202 => Some(KeyExchangeAlgorithm::MlKem1024),
            0x11EC => Some(KeyExchangeAlgorithm::X25519MlKem768),
            0x11EB => Some(KeyExchangeAlgorithm::Secp256r1MlKem768),
            _ => None,
        }
    }

    /// Get the algorithm name.
    pub const fn name(self) -> &'static str {
        match self {
            KeyExchangeAlgorithm::X25519 => "X25519",
            KeyExchangeAlgorithm::Secp256r1 => "secp256r1",
            KeyExchangeAlgorithm::Secp384r1 => "secp384r1",
            KeyExchangeAlgorithm::Secp521r1 => "secp521r1",
            KeyExchangeAlgorithm::X448 => "X448",
            KeyExchangeAlgorithm::Ffdhe2048 => "ffdhe2048",
            KeyExchangeAlgorithm::Ffdhe3072 => "ffdhe3072",
            KeyExchangeAlgorithm::Ffdhe4096 => "ffdhe4096",
            KeyExchangeAlgorithm::MlKem512 => "ML-KEM-512",
            KeyExchangeAlgorithm::MlKem768 => "ML-KEM-768",
            KeyExchangeAlgorithm::MlKem1024 => "ML-KEM-1024",
            KeyExchangeAlgorithm::X25519MlKem768 => "X25519MLKEM768",
            KeyExchangeAlgorithm::Secp256r1MlKem768 => "SecP256r1MLKEM768",
        }
    }

    /// Check if this is a post-quantum algorithm.
    pub const fn is_post_quantum(self) -> bool {
        matches!(
            self,
            KeyExchangeAlgorithm::MlKem512
                | KeyExchangeAlgorithm::MlKem768
                | KeyExchangeAlgorithm::MlKem1024
                | KeyExchangeAlgorithm::X25519MlKem768
                | KeyExchangeAlgorithm::Secp256r1MlKem768
        )
    }
}

/// Private key for key exchange.
///
/// This type wraps the private key material and ensures it's zeroized
/// when dropped.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl PrivateKey {
    /// Create a new private key from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the private key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Public key for key exchange.
#[derive(Debug)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Create a new public key from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to owned bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Shared secret from key exchange.
///
/// This type wraps the shared secret and ensures it's zeroized when dropped.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl SharedSecret {
    /// Create a new shared secret from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the shared secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to owned bytes (consumes the SharedSecret).
    ///
    /// Note: The bytes are NOT zeroized when using this method,
    /// as ownership is transferred to the caller.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

/// Key exchange trait.
///
/// Provides key exchange algorithms for TLS handshakes.
///
/// # Example (ECDHE)
///
/// ```rust,no_run
/// use hptls_crypto::KeyExchange;
///
/// fn key_exchange_example(kex: &dyn KeyExchange) {
///     // Generate ephemeral key pair
///     let (private_key, public_key) = kex.generate_keypair().unwrap();
///
///     // Receive peer's public key
///     let peer_public_key = vec![0u8; 32]; // From peer
///
///     // Compute shared secret
///     let shared_secret = kex.exchange(&private_key, &peer_public_key).unwrap();
/// }
/// ```
pub trait KeyExchange: Send + Sync {
    /// Generate an ephemeral key pair.
    ///
    /// # Returns
    ///
    /// A tuple of (private_key, public_key).
    ///
    /// # Security
    ///
    /// The private key MUST be generated using a CSPRNG.
    /// The private key MUST be zeroized when dropped.
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)>;

    /// Perform key exchange.
    ///
    /// # Arguments
    ///
    /// * `private_key` - Our private key
    /// * `peer_public_key` - Peer's public key bytes
    ///
    /// # Returns
    ///
    /// Shared secret.
    ///
    /// # Errors
    ///
    /// - `InvalidPublicKey` if peer's public key is invalid
    /// - `KeyExchangeFailed` for other errors
    ///
    /// # Security
    ///
    /// The shared secret MUST be zeroized when dropped.
    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret>;

    /// Get the algorithm this key exchange implements.
    fn algorithm(&self) -> KeyExchangeAlgorithm;

    /// Get the expected public key size in bytes.
    fn public_key_size(&self) -> usize {
        self.algorithm().public_key_size()
    }

    /// Get the shared secret size in bytes.
    fn shared_secret_size(&self) -> usize {
        self.algorithm().shared_secret_size()
    }
}
