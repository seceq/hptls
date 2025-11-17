//! Encrypted Client Hello (ECH) Support (draft-ietf-tls-esni)
//!
//! ECH encrypts the ClientHello to prevent passive network observers from
//! learning the server name and other sensitive handshake parameters.
//!
//! # Architecture
//!
//! ```text
//! Client                                     Server
//!
//! 1. DNS Query for _esni.example.com
//!    Retrieves ECHConfig
//!
//! 2. Generate ClientHelloOuter
//!    - public_name (e.g., cloudflare.com)
//!    - encrypted_client_hello extension
//!
//! 3. Generate ClientHelloInner
//!    - real SNI (e.g., secret.example.com)
//!    - encrypted using HPKE
//!
//! ClientHelloOuter          -------->
//! (+ encrypted_client_hello)
//!                                    Decrypt ClientHelloInner
//!                           <--------       ServerHello
//!                                    (+ encrypted_client_hello)
//! ```
//!
//! # Security Properties
//!
//! - SNI privacy: Real server name encrypted
//! - ALPN privacy: Application protocols hidden
//! - Server certificate fingerprinting resistance
//! - Backward compatibility with non-ECH servers
//!
//! # GREASE (Generate Random Extensions And Sustain Extensibility)
//!
//! Clients can send GREASE ECH to test middlebox compatibility:
//! - Random encrypted_client_hello extension
//! - Helps maintain ecosystem compatibility

use crate::error::{Error, Result};
use crate::messages::ClientHello;
use zeroize::Zeroizing;

/// ECH version (0xFE0D for draft-13)
pub const ECH_VERSION: u16 = 0xFE0D;

/// Maximum name length for public_name
pub const MAX_PUBLIC_NAME_LENGTH: usize = 255;

/// ECH configuration mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchMode {
    /// Split mode: ClientHelloOuter and ClientHelloInner are different
    Split = 0,

    /// Shared mode: Most extensions are shared
    Shared = 1,
}

/// ECH configuration
///
/// Retrieved via DNS (HTTPS/SVCB record) or via retry_config in ServerHello
#[derive(Debug, Clone)]
pub struct EchConfig {
    /// ECH version (0xFE0D)
    pub version: u16,

    /// Configuration identifier (8-byte)
    pub config_id: [u8; 8],

    /// Key encapsulation mechanism ID
    pub kem_id: u16,

    /// Public key for key encapsulation
    pub public_key: Vec<u8>,

    /// Cipher suites supported for ECH encryption
    pub cipher_suites: Vec<EchCipherSuite>,

    /// Maximum name length
    pub maximum_name_length: u16,

    /// Public name (cover name)
    pub public_name: String,

    /// Extensions
    pub extensions: Vec<u8>,
}

impl EchConfig {
    /// Create a new ECH config
    pub fn new(
        config_id: [u8; 8],
        kem_id: u16,
        public_key: Vec<u8>,
        cipher_suites: Vec<EchCipherSuite>,
        public_name: String,
    ) -> Result<Self> {
        if public_name.len() > MAX_PUBLIC_NAME_LENGTH {
            return Err(Error::InvalidConfig("Public name too long".into()));
        }

        Ok(Self {
            version: ECH_VERSION,
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length: MAX_PUBLIC_NAME_LENGTH as u16,
            public_name,
            extensions: Vec::new(),
        })
    }

    /// Encode to wire format
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Version (2 bytes)
        buf.extend_from_slice(&self.version.to_be_bytes());

        // Config ID (8 bytes)
        buf.extend_from_slice(&self.config_id);

        // KEM ID (2 bytes)
        buf.extend_from_slice(&self.kem_id.to_be_bytes());

        // Public key length (2 bytes) + public key
        buf.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key);

        // Cipher suites length (2 bytes) + cipher suites
        let cs_len = self.cipher_suites.len() * 4; // Each cipher suite is 4 bytes
        buf.extend_from_slice(&(cs_len as u16).to_be_bytes());
        for cs in &self.cipher_suites {
            buf.extend_from_slice(&cs.encode());
        }

        // Maximum name length (2 bytes)
        buf.extend_from_slice(&self.maximum_name_length.to_be_bytes());

        // Public name length (1 byte) + public name
        buf.push(self.public_name.len() as u8);
        buf.extend_from_slice(self.public_name.as_bytes());

        // Extensions length (2 bytes) + extensions
        buf.extend_from_slice(&(self.extensions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.extensions);

        Ok(buf)
    }

    /// Decode from wire format
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 15 {
            return Err(Error::InvalidMessage("ECH config too short".into()));
        }

        let mut offset = 0;

        // Version
        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Config ID
        let mut config_id = [0u8; 8];
        config_id.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;

        // KEM ID
        let kem_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Public key
        let pk_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let public_key = data[offset..offset + pk_len].to_vec();
        offset += pk_len;

        // Cipher suites
        let cs_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let mut cipher_suites = Vec::new();
        let mut cs_offset = 0;
        while cs_offset < cs_len {
            let cs = EchCipherSuite::decode(&data[offset + cs_offset..])?;
            cipher_suites.push(cs);
            cs_offset += 4;
        }
        offset += cs_len;

        // Maximum name length
        let maximum_name_length = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Public name
        let name_len = data[offset] as usize;
        offset += 1;
        let public_name = String::from_utf8(data[offset..offset + name_len].to_vec())
            .map_err(|_| Error::InvalidMessage("Invalid public name".into()))?;
        offset += name_len;

        // Extensions
        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let extensions = data[offset..offset + ext_len].to_vec();

        Ok(Self {
            version,
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length,
            public_name,
            extensions,
        })
    }
}

/// ECH cipher suite
///
/// Specifies KDF and AEAD for ECH encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchCipherSuite {
    /// KDF ID (HKDF-SHA256 = 0x0001, HKDF-SHA384 = 0x0002)
    pub kdf_id: u16,

    /// AEAD ID (AES-128-GCM = 0x0001, AES-256-GCM = 0x0002, ChaCha20Poly1305 = 0x0003)
    pub aead_id: u16,
}

impl EchCipherSuite {
    /// HKDF-SHA256 + AES-128-GCM
    pub const HKDF_SHA256_AES128GCM: Self = Self {
        kdf_id: 0x0001,
        aead_id: 0x0001,
    };

    /// HKDF-SHA256 + AES-256-GCM
    pub const HKDF_SHA256_AES256GCM: Self = Self {
        kdf_id: 0x0001,
        aead_id: 0x0002,
    };

    /// HKDF-SHA256 + ChaCha20Poly1305
    pub const HKDF_SHA256_CHACHA20POLY1305: Self = Self {
        kdf_id: 0x0001,
        aead_id: 0x0003,
    };

    /// Encode to 4 bytes
    pub fn encode(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&self.kdf_id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.aead_id.to_be_bytes());
        buf
    }

    /// Decode from 4 bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidMessage("ECH cipher suite too short".into()));
        }

        Ok(Self {
            kdf_id: u16::from_be_bytes([data[0], data[1]]),
            aead_id: u16::from_be_bytes([data[2], data[3]]),
        })
    }

    /// Convert to HPKE cipher suite for crypto operations
    ///
    /// # Note
    /// Currently only supports P-256 KEM. X25519 support can be added later.
    pub fn to_hpke_cipher_suite(&self) -> Result<hptls_crypto::HpkeCipherSuite> {
        use hptls_crypto::{HpkeAead, HpkeCipherSuite, HpkeKdf, HpkeKem};

        // Determine KDF
        let kdf = match self.kdf_id {
            0x0001 => HpkeKdf::HkdfSha256,
            0x0002 => HpkeKdf::HkdfSha384,
            0x0003 => HpkeKdf::HkdfSha512,
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "Unsupported KDF ID: 0x{:04X}",
                    self.kdf_id
                )))
            }
        };

        // Determine AEAD
        let aead = match self.aead_id {
            0x0001 => HpkeAead::Aes128Gcm,
            0x0002 => HpkeAead::Aes256Gcm,
            0x0003 => HpkeAead::ChaCha20Poly1305,
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "Unsupported AEAD ID: 0x{:04X}",
                    self.aead_id
                )))
            }
        };

        // Use P-256 KEM (most common for ECH)
        Ok(HpkeCipherSuite::new(
            HpkeKem::DhkemP256HkdfSha256,
            kdf,
            aead,
        ))
    }

    /// Create from HPKE cipher suite
    pub fn from_hpke_cipher_suite(hpke_suite: &hptls_crypto::HpkeCipherSuite) -> Result<Self> {
        use hptls_crypto::{HpkeAead, HpkeKdf};

        // Map KDF
        let kdf_id = match hpke_suite.kdf {
            HpkeKdf::HkdfSha256 => 0x0001,
            HpkeKdf::HkdfSha384 => 0x0002,
            HpkeKdf::HkdfSha512 => 0x0003,
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "Unsupported HPKE KDF: {:?}",
                    hpke_suite.kdf
                )))
            }
        };

        // Map AEAD
        let aead_id = match hpke_suite.aead {
            HpkeAead::Aes128Gcm => 0x0001,
            HpkeAead::Aes256Gcm => 0x0002,
            HpkeAead::ChaCha20Poly1305 => 0x0003,
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "Unsupported HPKE AEAD: {:?}",
                    hpke_suite.aead
                )))
            }
        };

        Ok(Self { kdf_id, aead_id })
    }
}

/// Encrypted Client Hello context
#[derive(Debug)]
pub struct EchContext {
    /// ECH configuration
    pub config: EchConfig,

    /// Selected cipher suite
    pub cipher_suite: EchCipherSuite,

    /// HPKE encryption context (encapsulated key)
    pub enc: Vec<u8>,

    /// Encrypted payload
    pub payload: Zeroizing<Vec<u8>>,
}

impl EchContext {
    /// Create a new ECH context
    pub fn new(
        config: EchConfig,
        cipher_suite: EchCipherSuite,
        enc: Vec<u8>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            config,
            cipher_suite,
            enc,
            payload: Zeroizing::new(payload),
        }
    }
}

/// ClientHello split for ECH
///
/// Separates ClientHello into outer (public) and inner (private) parts
#[derive(Debug, Clone)]
pub struct ClientHelloSplit {
    /// ClientHelloOuter (sent on wire)
    pub outer: ClientHello,

    /// ClientHelloInner (encrypted)
    pub inner: ClientHello,
}

impl ClientHelloSplit {
    /// Create a new split ClientHello
    pub fn new(outer: ClientHello, inner: ClientHello) -> Self {
        Self { outer, inner }
    }

    /// Get the outer ClientHello (to send)
    pub fn outer(&self) -> &ClientHello {
        &self.outer
    }

    /// Get the inner ClientHello (for transcript)
    pub fn inner(&self) -> &ClientHello {
        &self.inner
    }

    /// Create a split ClientHello for ECH
    ///
    /// This separates a ClientHello into:
    /// - **Inner**: Contains the real SNI and sensitive data (encrypted)
    /// - **Outer**: Contains the public_name and encrypted_client_hello extension
    ///
    /// # Arguments
    ///
    /// * `real_sni` - The actual server name the client wants to connect to
    /// * `public_name` - The public cover name from ECH config
    /// * `base_hello` - The base ClientHello with cipher suites and other extensions
    ///
    /// # Returns
    ///
    /// A `ClientHelloSplit` with properly separated Inner/Outer messages
    ///
    /// # Note
    ///
    /// This function assumes the base_hello does NOT already have an SNI extension.
    /// The caller should provide a base ClientHello without SNI, and this function
    /// will add the appropriate SNI to each split.
    pub fn create_for_ech(
        real_sni: &str,
        public_name: &str,
        base_hello: &ClientHello,
    ) -> Result<Self> {
        use crate::extension_types::TypedExtension;

        // Create ClientHelloInner with real SNI
        let mut inner = base_hello.clone();
        inner
            .extensions
            .add_typed(TypedExtension::ServerName(real_sni.to_string()))?;

        // Create ClientHelloOuter with public_name
        let mut outer = base_hello.clone();
        outer
            .extensions
            .add_typed(TypedExtension::ServerName(public_name.to_string()))?;

        Ok(Self { outer, inner })
    }
}

/// Encrypt ClientHelloInner using HPKE
///
/// # Arguments
///
/// * `config` - ECH configuration containing public key
/// * `cipher_suite` - Cipher suite to use for encryption
/// * `client_hello_inner` - The inner ClientHello to encrypt
/// * `provider` - Crypto provider for HPKE operations
///
/// # Returns
///
/// Returns (enc, ciphertext) tuple where:
/// - `enc` is the HPKE encapsulated key
/// - `ciphertext` is the encrypted ClientHelloInner
pub fn encrypt_client_hello_inner(
    config: &EchConfig,
    cipher_suite: &EchCipherSuite,
    client_hello_inner: &[u8],
    provider: &dyn hptls_crypto::CryptoProvider,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Convert ECH cipher suite to HPKE cipher suite
    let hpke_suite = cipher_suite.to_hpke_cipher_suite()?;

    // Get HPKE instance from provider
    let hpke = provider.hpke(hpke_suite)?;

    // info = "tls ech" || 0x00 || config_id
    let mut info = Vec::from(b"tls ech\x00");
    info.extend_from_slice(&config.config_id);

    // aad = empty for ECH (per draft-ietf-tls-esni)
    let aad = b"";

    // Encrypt using HPKE seal_base
    // Returns enc || ciphertext
    let enc_and_ciphertext = hpke.seal_base(&config.public_key, &info, aad, client_hello_inner)?;

    // Split into enc and ciphertext
    let nenc = hpke_suite.nenc();
    if enc_and_ciphertext.len() < nenc {
        return Err(Error::InvalidMessage(
            "HPKE output too short for enc".into(),
        ));
    }

    let enc = enc_and_ciphertext[..nenc].to_vec();
    let ciphertext = enc_and_ciphertext[nenc..].to_vec();

    Ok((enc, ciphertext))
}

/// Decrypt ClientHelloInner using HPKE
///
/// # Arguments
///
/// * `config` - ECH configuration
/// * `cipher_suite` - Cipher suite used for encryption
/// * `enc` - HPKE encapsulated key
/// * `ciphertext` - Encrypted ClientHelloInner
/// * `secret_key` - Server's ECH secret key
/// * `provider` - Crypto provider for HPKE operations
///
/// # Returns
///
/// Decrypted ClientHelloInner as raw bytes
pub fn decrypt_client_hello_inner(
    config: &EchConfig,
    cipher_suite: &EchCipherSuite,
    enc: &[u8],
    ciphertext: &[u8],
    secret_key: &[u8],
    provider: &dyn hptls_crypto::CryptoProvider,
) -> Result<Vec<u8>> {
    // Convert ECH cipher suite to HPKE cipher suite
    let hpke_suite = cipher_suite.to_hpke_cipher_suite()?;

    // Get HPKE instance from provider
    let hpke = provider.hpke(hpke_suite)?;

    // info = "tls ech" || 0x00 || config_id
    let mut info = Vec::from(b"tls ech\x00");
    info.extend_from_slice(&config.config_id);

    // aad = empty for ECH
    let aad = b"";

    // Combine enc || ciphertext for open_base
    let mut enc_and_ciphertext = enc.to_vec();
    enc_and_ciphertext.extend_from_slice(ciphertext);

    // Decrypt using HPKE open_base
    let plaintext = hpke.open_base(&enc_and_ciphertext, secret_key, &info, aad)?;

    Ok(plaintext)
}

/// GREASE ECH (for testing)
///
/// Sends random encrypted_client_hello extension to test compatibility
pub fn generate_grease_ech() -> Vec<u8> {
    // Generate random ECH extension data (minimum viable)
    let mut grease = Vec::new();

    // ECH version (2 bytes) - use GREASE value
    grease.extend_from_slice(&0xFAFA_u16.to_be_bytes());

    // Cipher suite (4 bytes) - GREASE
    grease.extend_from_slice(&0xFAFA_u16.to_be_bytes());
    grease.extend_from_slice(&0xFAFA_u16.to_be_bytes());

    // Config ID (8 bytes) - zeros
    grease.extend_from_slice(&[0u8; 8]);

    // Enc length (2 bytes) + enc (32 bytes of random)
    grease.extend_from_slice(&32_u16.to_be_bytes());
    grease.extend_from_slice(&[0xFA; 32]); // GREASE pattern

    // Payload length (2 bytes) + payload (64 bytes of random)
    grease.extend_from_slice(&64_u16.to_be_bytes());
    grease.extend_from_slice(&[0xFA; 64]); // GREASE pattern

    grease
}

// =============================================================================
// Server-side ECH APIs
// =============================================================================

/// Builder for server-side ECH configuration
///
/// Generates a new ECH configuration with automatic key generation.
///
/// # Example
///
/// ```rust,ignore
/// use hptls_core::ech::{EchConfigBuilder, EchCipherSuite};
/// use hptls_crypto_hpcrypt::HpcryptProvider;
///
/// let provider = HpcryptProvider::new();
/// let (config, secret_key) = EchConfigBuilder::new()
///     .public_name("example.com")
///     .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
///     .add_cipher_suite(EchCipherSuite::HKDF_SHA256_CHACHA20POLY1305)
///     .build(&provider)?;
///
/// // config can be published via DNS (HTTPS/SVCB record)
/// // secret_key must be kept confidential on the server
/// ```
pub struct EchConfigBuilder {
    public_name: Option<String>,
    cipher_suites: Vec<EchCipherSuite>,
    maximum_name_length: u16,
    config_id: Option<[u8; 8]>,
}

impl Default for EchConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EchConfigBuilder {
    /// Create a new ECH config builder
    pub fn new() -> Self {
        Self {
            public_name: None,
            cipher_suites: Vec::new(),
            maximum_name_length: MAX_PUBLIC_NAME_LENGTH as u16,
            config_id: None,
        }
    }

    /// Set the public name (cover name for ECH)
    ///
    /// This is the SNI that will be visible in ClientHelloOuter.
    /// It should be a valid domain that the server also responds to.
    pub fn public_name(mut self, name: impl Into<String>) -> Self {
        self.public_name = Some(name.into());
        self
    }

    /// Add a supported cipher suite
    ///
    /// Clients will choose from this list based on their preferences.
    pub fn add_cipher_suite(mut self, cipher_suite: EchCipherSuite) -> Self {
        self.cipher_suites.push(cipher_suite);
        self
    }

    /// Set multiple cipher suites at once
    pub fn cipher_suites(mut self, cipher_suites: Vec<EchCipherSuite>) -> Self {
        self.cipher_suites = cipher_suites;
        self
    }

    /// Set maximum name length (default: 255)
    pub fn maximum_name_length(mut self, length: u16) -> Self {
        self.maximum_name_length = length;
        self
    }

    /// Set specific config ID (optional, will be randomly generated if not set)
    pub fn config_id(mut self, id: [u8; 8]) -> Self {
        self.config_id = Some(id);
        self
    }

    /// Build the ECH configuration and generate keypair
    ///
    /// Returns (EchConfig, secret_key) where:
    /// - EchConfig should be published via DNS
    /// - secret_key must be kept confidential for decryption
    ///
    /// # Note
    /// Currently only generates P-256 keys (KEM ID 0x0018).
    /// X25519 support can be added when available in hpcrypt-hpke.
    pub fn build(
        self,
        provider: &dyn hptls_crypto::CryptoProvider,
    ) -> Result<(EchConfig, Zeroizing<Vec<u8>>)> {
        // Validate required fields
        let public_name = self
            .public_name
            .ok_or_else(|| Error::InvalidConfig("Public name is required".into()))?;

        if self.cipher_suites.is_empty() {
            return Err(Error::InvalidConfig(
                "At least one cipher suite is required".into(),
            ));
        }

        // Generate config ID if not provided
        let config_id = if let Some(id) = self.config_id {
            id
        } else {
            let mut id = [0u8; 8];
            provider.random().fill(&mut id);
            id
        };

        // Use P-256 KEM (0x0018) - the only one currently supported
        let kem_id = 0x0018_u16; // DHKEM(P-256, HKDF-SHA256)

        // Generate HPKE keypair using the first cipher suite
        let hpke_suite = self.cipher_suites[0].to_hpke_cipher_suite()?;
        let hpke = provider.hpke(hpke_suite)?;
        let (secret_key, public_key) = hpke.generate_keypair()?;

        // Create the config
        let config = EchConfig {
            version: ECH_VERSION,
            config_id,
            kem_id,
            public_key,
            cipher_suites: self.cipher_suites,
            maximum_name_length: self.maximum_name_length,
            public_name,
            extensions: Vec::new(),
        };

        Ok((config, Zeroizing::new(secret_key)))
    }
}

/// ECHConfigList - list of ECH configurations
///
/// Servers may publish multiple ECH configs to support different cipher suites,
/// key rotation, or A/B testing.
#[derive(Debug, Clone)]
pub struct EchConfigList {
    /// List of ECH configurations
    pub configs: Vec<EchConfig>,
}

impl EchConfigList {
    /// Create a new ECHConfigList
    pub fn new(configs: Vec<EchConfig>) -> Self {
        Self { configs }
    }

    /// Create an empty list
    pub fn empty() -> Self {
        Self {
            configs: Vec::new(),
        }
    }

    /// Add a config to the list
    pub fn add(&mut self, config: EchConfig) {
        self.configs.push(config);
    }

    /// Encode ECHConfigList to wire format
    ///
    /// Format: length (2 bytes) || config1 || config2 || ...
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Encode each config
        let mut configs_data = Vec::new();
        for config in &self.configs {
            let encoded = config.encode()?;
            // Each config: length (2 bytes) || config data
            configs_data.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
            configs_data.extend_from_slice(&encoded);
        }

        // Total length (2 bytes) || configs
        buf.extend_from_slice(&(configs_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&configs_data);

        Ok(buf)
    }

    /// Decode ECHConfigList from wire format
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::InvalidMessage("ECHConfigList too short".into()));
        }

        let total_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + total_len {
            return Err(Error::InvalidMessage("ECHConfigList truncated".into()));
        }

        let mut configs = Vec::new();
        let mut offset = 2;

        while offset < 2 + total_len {
            if offset + 2 > data.len() {
                break;
            }

            let config_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + config_len > data.len() {
                return Err(Error::InvalidMessage("ECH config truncated".into()));
            }

            let config = EchConfig::decode(&data[offset..offset + config_len])?;
            configs.push(config);
            offset += config_len;
        }

        Ok(Self { configs })
    }

    /// Select a config by ID
    pub fn find_by_id(&self, config_id: &[u8; 8]) -> Option<&EchConfig> {
        self.configs
            .iter()
            .find(|c| &c.config_id == config_id)
    }

    /// Get the first config (default selection)
    pub fn first(&self) -> Option<&EchConfig> {
        self.configs.first()
    }

    /// Check if list is empty
    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    /// Get number of configs
    pub fn len(&self) -> usize {
        self.configs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ech_cipher_suite_encode_decode() {
        let cs = EchCipherSuite::HKDF_SHA256_AES128GCM;
        let encoded = cs.encode();
        let decoded = EchCipherSuite::decode(&encoded).unwrap();
        assert_eq!(cs, decoded);
    }

    #[test]
    fn test_ech_config_creation() {
        let config = EchConfig::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            0x0020, // X25519
            vec![0x01; 32],
            vec![EchCipherSuite::HKDF_SHA256_AES128GCM],
            "cloudflare.com".to_string(),
        )
        .unwrap();

        assert_eq!(config.version, ECH_VERSION);
        assert_eq!(config.public_name, "cloudflare.com");
    }

    #[test]
    fn test_ech_config_encode_decode() {
        let config = EchConfig::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            0x0020,
            vec![0x01; 32],
            vec![EchCipherSuite::HKDF_SHA256_AES128GCM],
            "example.com".to_string(),
        )
        .unwrap();

        let encoded = config.encode().unwrap();
        let decoded = EchConfig::decode(&encoded).unwrap();

        assert_eq!(config.version, decoded.version);
        assert_eq!(config.config_id, decoded.config_id);
        assert_eq!(config.public_name, decoded.public_name);
    }

    #[test]
    fn test_ech_config_public_name_too_long() {
        let long_name = "a".repeat(300);
        let result = EchConfig::new(
            [1; 8],
            0x0020,
            vec![0x01; 32],
            vec![EchCipherSuite::HKDF_SHA256_AES128GCM],
            long_name,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_grease_ech_generation() {
        let grease = generate_grease_ech();

        // Should have minimum length
        assert!(grease.len() >= 100);

        // Should start with GREASE version
        assert_eq!(u16::from_be_bytes([grease[0], grease[1]]), 0xFAFA);
    }

    #[test]
    fn test_ech_cipher_suite_constants() {
        let cs1 = EchCipherSuite::HKDF_SHA256_AES128GCM;
        assert_eq!(cs1.kdf_id, 0x0001);
        assert_eq!(cs1.aead_id, 0x0001);

        let cs2 = EchCipherSuite::HKDF_SHA256_CHACHA20POLY1305;
        assert_eq!(cs2.kdf_id, 0x0001);
        assert_eq!(cs2.aead_id, 0x0003);
    }

    #[test]
    fn test_ech_to_hpke_cipher_suite_conversion() {
        use hptls_crypto::{HpkeAead, HpkeKdf, HpkeKem};

        // Test AES-128-GCM conversion
        let ech_cs = EchCipherSuite::HKDF_SHA256_AES128GCM;
        let hpke_cs = ech_cs.to_hpke_cipher_suite().unwrap();
        assert_eq!(hpke_cs.kem, HpkeKem::DhkemP256HkdfSha256);
        assert_eq!(hpke_cs.kdf, HpkeKdf::HkdfSha256);
        assert_eq!(hpke_cs.aead, HpkeAead::Aes128Gcm);

        // Test AES-256-GCM conversion
        let ech_cs = EchCipherSuite::HKDF_SHA256_AES256GCM;
        let hpke_cs = ech_cs.to_hpke_cipher_suite().unwrap();
        assert_eq!(hpke_cs.aead, HpkeAead::Aes256Gcm);

        // Test ChaCha20-Poly1305 conversion
        let ech_cs = EchCipherSuite::HKDF_SHA256_CHACHA20POLY1305;
        let hpke_cs = ech_cs.to_hpke_cipher_suite().unwrap();
        assert_eq!(hpke_cs.aead, HpkeAead::ChaCha20Poly1305);
    }

    #[test]
    fn test_hpke_to_ech_cipher_suite_conversion() {
        use hptls_crypto::{HpkeAead, HpkeCipherSuite, HpkeKdf, HpkeKem};

        // Test conversion from HPKE to ECH
        let hpke_cs = HpkeCipherSuite::new(
            HpkeKem::DhkemP256HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        let ech_cs = EchCipherSuite::from_hpke_cipher_suite(&hpke_cs).unwrap();
        assert_eq!(ech_cs.kdf_id, 0x0001);
        assert_eq!(ech_cs.aead_id, 0x0001);

        // Round-trip test
        let hpke_cs2 = ech_cs.to_hpke_cipher_suite().unwrap();
        assert_eq!(hpke_cs2.kdf, hpke_cs.kdf);
        assert_eq!(hpke_cs2.aead, hpke_cs.aead);
    }

    #[test]
    fn test_ech_encrypt_decrypt_round_trip() {
        use hptls_crypto_hpcrypt::HpcryptProvider;
        use hptls_crypto::CryptoProvider;

        let provider = HpcryptProvider::new();

        // Generate HPKE keypair for testing
        let hpke_suite = hptls_crypto::HpkeCipherSuite::ech_default_p256();
        let hpke = provider.hpke(hpke_suite).unwrap();
        let (secret_key, public_key) = hpke.generate_keypair().unwrap();

        // Create ECH config
        let config = EchConfig::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            0x0018, // P-256 KEM ID
            public_key.clone(),
            vec![EchCipherSuite::HKDF_SHA256_AES128GCM],
            "public.example.com".to_string(),
        )
        .unwrap();

        // Test data - simulated ClientHelloInner
        let client_hello_inner = b"This is a secret ClientHello";

        // Encrypt
        let cipher_suite = EchCipherSuite::HKDF_SHA256_AES128GCM;
        let (enc, ciphertext) =
            encrypt_client_hello_inner(&config, &cipher_suite, client_hello_inner, &provider)
                .unwrap();

        // Verify enc has correct length (P-256 point)
        assert_eq!(enc.len(), 65);

        // Decrypt
        let decrypted = decrypt_client_hello_inner(
            &config,
            &cipher_suite,
            &enc,
            &ciphertext,
            &secret_key,
            &provider,
        )
        .unwrap();

        // Verify round-trip
        assert_eq!(decrypted, client_hello_inner);
    }

    #[test]
    fn test_ech_encrypt_decrypt_with_different_cipher_suites() {
        use hptls_crypto_hpcrypt::HpcryptProvider;
        use hptls_crypto::{CryptoProvider, HpkeCipherSuite};

        let provider = HpcryptProvider::new();
        let client_hello_inner = b"Secret ClientHello data";

        // Test with each cipher suite
        let test_cases = vec![
            (
                EchCipherSuite::HKDF_SHA256_AES128GCM,
                HpkeCipherSuite::ech_default_p256(),
            ),
            (
                EchCipherSuite::HKDF_SHA256_AES256GCM,
                HpkeCipherSuite::new(
                    hptls_crypto::HpkeKem::DhkemP256HkdfSha256,
                    hptls_crypto::HpkeKdf::HkdfSha256,
                    hptls_crypto::HpkeAead::Aes256Gcm,
                ),
            ),
            (
                EchCipherSuite::HKDF_SHA256_CHACHA20POLY1305,
                HpkeCipherSuite::new(
                    hptls_crypto::HpkeKem::DhkemP256HkdfSha256,
                    hptls_crypto::HpkeKdf::HkdfSha256,
                    hptls_crypto::HpkeAead::ChaCha20Poly1305,
                ),
            ),
        ];

        for (ech_suite, hpke_suite) in test_cases {
            let hpke = provider.hpke(hpke_suite).unwrap();
            let (secret_key, public_key) = hpke.generate_keypair().unwrap();

            let config = EchConfig::new(
                [1; 8],
                0x0018,
                public_key,
                vec![ech_suite],
                "test.example.com".to_string(),
            )
            .unwrap();

            let (enc, ciphertext) =
                encrypt_client_hello_inner(&config, &ech_suite, client_hello_inner, &provider)
                    .unwrap();

            let decrypted = decrypt_client_hello_inner(
                &config,
                &ech_suite,
                &enc,
                &ciphertext,
                &secret_key,
                &provider,
            )
            .unwrap();

            assert_eq!(
                decrypted, client_hello_inner,
                "Round-trip failed for cipher suite {:?}",
                ech_suite
            );
        }
    }

    #[test]
    fn test_client_hello_splitting() {
        use crate::cipher::CipherSuite;
        use crate::messages::ClientHello;

        // Create a base ClientHello without SNI
        let random = [0u8; 32];
        let cipher_suites = vec![CipherSuite::Aes128GcmSha256];
        let base_hello = ClientHello::new(random, cipher_suites);

        // Split for ECH
        let split = ClientHelloSplit::create_for_ech(
            "secret.example.com",
            "public.example.com",
            &base_hello,
        )
        .unwrap();

        // Verify inner has real SNI
        let inner_sni = split.inner.extensions.get_server_name().unwrap();
        assert_eq!(inner_sni, Some("secret.example.com".to_string()));

        // Verify outer has public name
        let outer_sni = split.outer.extensions.get_server_name().unwrap();
        assert_eq!(outer_sni, Some("public.example.com".to_string()));

        // Verify both have the same cipher suites
        assert_eq!(split.inner.cipher_suites, split.outer.cipher_suites);

        // Verify both have the same random
        assert_eq!(split.inner.random, split.outer.random);
    }

    #[test]
    fn test_ech_decryption_with_wrong_key_fails() {
        use hptls_crypto_hpcrypt::HpcryptProvider;
        use hptls_crypto::CryptoProvider;

        let provider = HpcryptProvider::new();

        let hpke_suite = hptls_crypto::HpkeCipherSuite::ech_default_p256();
        let hpke = provider.hpke(hpke_suite).unwrap();

        // Generate two different keypairs
        let (secret_key1, public_key1) = hpke.generate_keypair().unwrap();
        let (secret_key2, _public_key2) = hpke.generate_keypair().unwrap();

        let config = EchConfig::new(
            [1; 8],
            0x0018,
            public_key1,
            vec![EchCipherSuite::HKDF_SHA256_AES128GCM],
            "test.example.com".to_string(),
        )
        .unwrap();

        let client_hello_inner = b"Secret data";
        let cipher_suite = EchCipherSuite::HKDF_SHA256_AES128GCM;

        let (enc, ciphertext) =
            encrypt_client_hello_inner(&config, &cipher_suite, client_hello_inner, &provider)
                .unwrap();

        // Try to decrypt with wrong key - should fail
        let result = decrypt_client_hello_inner(
            &config,
            &cipher_suite,
            &enc,
            &ciphertext,
            &secret_key2, // Wrong key!
            &provider,
        );

        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_ech_config_builder() {
        use hptls_crypto::CryptoProvider;
        use hptls_crypto_hpcrypt::HpcryptProvider;

        let provider = <HpcryptProvider as CryptoProvider>::new();

        // Build config with builder pattern
        let (config, secret_key) = EchConfigBuilder::new()
            .public_name("example.com")
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_CHACHA20POLY1305)
            .build(&provider)
            .unwrap();

        assert_eq!(config.version, ECH_VERSION);
        assert_eq!(config.public_name, "example.com");
        assert_eq!(config.cipher_suites.len(), 2);
        assert_eq!(config.kem_id, 0x0018); // P-256
        assert!(!config.public_key.is_empty());
        assert!(!secret_key.is_empty());

        // Verify config is valid by encoding/decoding
        let encoded = config.encode().unwrap();
        let decoded = EchConfig::decode(&encoded).unwrap();
        assert_eq!(config.version, decoded.version);
        assert_eq!(config.config_id, decoded.config_id);
    }

    #[test]
    fn test_ech_config_list_encode_decode() {
        use hptls_crypto::CryptoProvider;
        use hptls_crypto_hpcrypt::HpcryptProvider;

        let provider = <HpcryptProvider as CryptoProvider>::new();

        // Create multiple configs
        let (config1, _) = EchConfigBuilder::new()
            .public_name("example.com")
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
            .build(&provider)
            .unwrap();

        let (config2, _) = EchConfigBuilder::new()
            .public_name("example.org")
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_CHACHA20POLY1305)
            .build(&provider)
            .unwrap();

        // Create list
        let list = EchConfigList::new(vec![config1.clone(), config2.clone()]);
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());

        // Encode and decode
        let encoded = list.encode().unwrap();
        let decoded = EchConfigList::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.configs[0].config_id, config1.config_id);
        assert_eq!(decoded.configs[1].config_id, config2.config_id);
    }

    #[test]
    fn test_ech_config_list_find_by_id() {
        use hptls_crypto::CryptoProvider;
        use hptls_crypto_hpcrypt::HpcryptProvider;

        let provider = <HpcryptProvider as CryptoProvider>::new();

        let (config1, _) = EchConfigBuilder::new()
            .public_name("example.com")
            .config_id([1, 2, 3, 4, 5, 6, 7, 8])
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
            .build(&provider)
            .unwrap();

        let (config2, _) = EchConfigBuilder::new()
            .public_name("example.org")
            .config_id([9, 10, 11, 12, 13, 14, 15, 16])
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_CHACHA20POLY1305)
            .build(&provider)
            .unwrap();

        let list = EchConfigList::new(vec![config1.clone(), config2.clone()]);

        // Find by ID
        let found = list.find_by_id(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(found.is_some());
        assert_eq!(found.unwrap().public_name, "example.com");

        let found2 = list.find_by_id(&[9, 10, 11, 12, 13, 14, 15, 16]);
        assert!(found2.is_some());
        assert_eq!(found2.unwrap().public_name, "example.org");

        // Non-existent ID
        let not_found = list.find_by_id(&[99, 99, 99, 99, 99, 99, 99, 99]);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_ech_config_builder_round_trip() {
        use hptls_crypto::CryptoProvider;
        use hptls_crypto_hpcrypt::HpcryptProvider;

        let provider = <HpcryptProvider as CryptoProvider>::new();

        // Build config
        let (config, secret_key) = EchConfigBuilder::new()
            .public_name("secure.example.com")
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
            .build(&provider)
            .unwrap();

        // Test encryption/decryption with generated keys
        let client_hello_inner = b"Test ClientHelloInner data";
        let cipher_suite = EchCipherSuite::HKDF_SHA256_AES128GCM;

        let (enc, ciphertext) =
            encrypt_client_hello_inner(&config, &cipher_suite, client_hello_inner, &provider)
                .unwrap();

        let decrypted = decrypt_client_hello_inner(
            &config,
            &cipher_suite,
            &enc,
            &ciphertext,
            &secret_key,
            &provider,
        )
        .unwrap();

        assert_eq!(decrypted, client_hello_inner);
    }
}
