//! ECH Helper Functions for Handshake Integration
//!
//! This module provides helper functions to use ECH with the handshake state machines.
//! These helpers allow applications to opt-in to ECH without modifying core handshake logic.
//!
//! # Usage Pattern
//!
//! ## Client-Side (with ECH)
//!
//! ```rust,ignore
//! use hptls_core::ech_helpers::{EchClientHelper, prepare_ech_client_hello};
//!
//! // 1. Fetch ECH config from DNS or server
//! let ech_config = fetch_ech_config_from_dns("example.com")?;
//!
//! // 2. Create helper
//! let mut ech_helper = EchClientHelper::new(ech_config);
//!
//! // 3. Generate ClientHello with ECH
//! let (client_hello_outer, ech_context) = ech_helper.prepare_client_hello(
//!     &provider,
//!     &cipher_suites,
//!     "secret.example.com",  // Real SNI (encrypted)
//!     "example.com",         // Public SNI (visible)
//!     alpn_protocols,
//! )?;
//!
//! // 4. Send client_hello_outer
//! connection.send(&client_hello_outer.encode()?)?;
//!
//! // 5. Process server response
//! if let Some(retry_config) = ech_helper.check_for_retry(&server_hello)? {
//!     // Server sent retry config, start over with new config
//!     ech_helper = EchClientHelper::new(retry_config);
//!     // Generate new ClientHello...
//! }
//! ```
//!
//! ## Server-Side (with ECH)
//!
//! ```rust,ignore
//! use hptls_core::ech_helpers::EchServerHelper;
//!
//! // 1. Initialize with server's ECH configs and secret keys
//! let helper = EchServerHelper::new(config_list, secret_keys);
//!
//! // 2. Check if ClientHello has ECH
//! if let Some(decrypted_hello) = helper.try_decrypt_ech(&client_hello, &provider)? {
//!     // Use decrypted ClientHelloInner for handshake
//!     process_client_hello(&decrypted_hello)?;
//! } else {
//!     // No ECH or decryption failed, use outer ClientHello
//!     process_client_hello(&client_hello)?;
//! }
//! ```

use crate::ech::{
    decrypt_client_hello_inner, encrypt_client_hello_inner, ClientHelloSplit, EchCipherSuite,
    EchConfig, EchConfigList,
};
use crate::error::{Error, Result};
use crate::messages::ClientHello;
use hptls_crypto::CryptoProvider;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Client-side ECH helper
///
/// Manages ECH state for a client connection, including retry configuration handling.
pub struct EchClientHelper {
    /// Current ECH configuration
    config: EchConfig,
    /// Whether a retry has been attempted
    retry_attempted: bool,
}

impl EchClientHelper {
    /// Create a new ECH client helper with the given config
    ///
    /// # Arguments
    ///
    /// * `config` - ECH configuration (from DNS or previous retry)
    pub fn new(config: EchConfig) -> Self {
        Self {
            config,
            retry_attempted: false,
        }
    }

    /// Prepare ClientHello with ECH encryption
    ///
    /// This generates both ClientHelloInner (encrypted) and ClientHelloOuter (public).
    /// The outer hello should be sent to the server.
    ///
    /// # Arguments
    ///
    /// * `provider` - Crypto provider for HPKE operations
    /// * `base_hello` - Base ClientHello (without SNI, to be split)
    /// * `real_sni` - Real server name (will be encrypted in ClientHelloInner)
    /// * `public_name` - Public server name (visible in ClientHelloOuter)
    ///
    /// # Returns
    ///
    /// ClientHelloOuter with ECH extension
    pub fn prepare_client_hello(
        &self,
        provider: &dyn CryptoProvider,
        base_hello: &ClientHello,
        real_sni: &str,
        public_name: &str,
    ) -> Result<ClientHello> {
        // Split ClientHello into Inner and Outer
        let split = ClientHelloSplit::create_for_ech(real_sni, public_name, base_hello)?;

        // Encode ClientHelloInner
        let client_hello_inner = split.inner.encode()?;

        // Select cipher suite (use first supported)
        let cipher_suite = self
            .config
            .cipher_suites
            .first()
            .ok_or_else(|| Error::InvalidConfig("No cipher suites in ECH config".into()))?;

        // Encrypt ClientHelloInner
        let (enc, ciphertext) =
            encrypt_client_hello_inner(&self.config, cipher_suite, &client_hello_inner, provider)?;

        // Add ECH extension to Outer ClientHello
        let mut outer = split.outer;
        outer
            .extensions
            .add_ech(*cipher_suite, self.config.config_id, enc, ciphertext)?;

        Ok(outer)
    }

    /// Check if server sent a retry configuration
    ///
    /// If ECH decryption fails on the server, it may send a retry_configs extension
    /// in EncryptedExtensions. This method checks for that and returns the new config.
    ///
    /// # Returns
    ///
    /// `Some(EchConfig)` if retry config was provided, `None` otherwise
    pub fn check_for_retry(&mut self, _retry_config_data: &[u8]) -> Result<Option<EchConfig>> {
        // Check if we've already retried (can only retry once)
        if self.retry_attempted {
            return Ok(None);
        }

        // Decode retry config
        // Note: In a real implementation, this would parse the retry_configs extension
        // from EncryptedExtensions. For now, we assume the data is already ECHConfig encoded.
        let retry_config = EchConfig::decode(_retry_config_data)?;

        self.retry_attempted = true;
        Ok(Some(retry_config))
    }

    /// Get the current ECH config
    pub fn config(&self) -> &EchConfig {
        &self.config
    }

    /// Check if a retry has been attempted
    pub fn has_retried(&self) -> bool {
        self.retry_attempted
    }
}

/// Server-side ECH helper
///
/// Manages ECH decryption for a server, including config lookup and retry generation.
pub struct EchServerHelper {
    /// Available ECH configurations
    config_list: EchConfigList,
    /// Secret keys for decryption (config_id -> secret_key)
    secret_keys: HashMap<[u8; 8], Zeroizing<Vec<u8>>>,
}

impl EchServerHelper {
    /// Create a new ECH server helper
    ///
    /// # Arguments
    ///
    /// * `config_list` - Published ECH configurations
    /// * `secret_keys` - Map of config_id to secret key for decryption
    pub fn new(
        config_list: EchConfigList,
        secret_keys: HashMap<[u8; 8], Zeroizing<Vec<u8>>>,
    ) -> Self {
        Self {
            config_list,
            secret_keys,
        }
    }

    /// Try to decrypt ECH from ClientHello
    ///
    /// If the ClientHello contains an ECH extension, attempts to decrypt it.
    /// Returns the decrypted ClientHelloInner if successful.
    ///
    /// # Arguments
    ///
    /// * `client_hello` - Received ClientHelloOuter
    /// * `provider` - Crypto provider for HPKE operations
    ///
    /// # Returns
    ///
    /// * `Some(ClientHello)` - Decrypted ClientHelloInner (use this for handshake)
    /// * `None` - No ECH extension or decryption failed (use outer hello)
    pub fn try_decrypt_ech(
        &self,
        client_hello: &ClientHello,
        provider: &dyn CryptoProvider,
    ) -> Result<Option<ClientHello>> {
        // Check if ECH extension is present
        let ech_data = match client_hello.extensions.get_ech()? {
            Some(data) => data,
            None => return Ok(None), // No ECH extension
        };

        let (cipher_suite, config_id, enc, payload) = ech_data;

        // Find the corresponding config and secret key
        let config = match self.config_list.find_by_id(&config_id) {
            Some(c) => c,
            None => {
                // Config ID not found - ECH decryption will fail
                // Server should send retry_configs in EncryptedExtensions
                return Ok(None);
            }
        };

        let secret_key = match self.secret_keys.get(&config_id) {
            Some(sk) => sk,
            None => {
                // Secret key not available
                return Ok(None);
            }
        };

        // Decrypt ClientHelloInner
        let decrypted_bytes =
            decrypt_client_hello_inner(config, &cipher_suite, &enc, &payload, secret_key, provider)?;

        // Decode ClientHello from decrypted data
        let inner_hello = ClientHello::decode(&decrypted_bytes)?;

        Ok(Some(inner_hello))
    }

    /// Generate retry configuration for client
    ///
    /// When ECH decryption fails, the server should send a retry_configs extension
    /// containing updated ECH configurations.
    ///
    /// # Returns
    ///
    /// Encoded ECHConfigList for retry_configs extension
    pub fn generate_retry_config(&self) -> Result<Vec<u8>> {
        self.config_list.encode()
    }

    /// Get the config list
    pub fn config_list(&self) -> &EchConfigList {
        &self.config_list
    }
}

/// Convenience function to check if a ClientHello has ECH
///
/// # Arguments
///
/// * `client_hello` - ClientHello to check
///
/// # Returns
///
/// `true` if the ClientHello contains an ECH extension
pub fn has_ech(client_hello: &ClientHello) -> bool {
    client_hello.extensions.has_ech()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::CipherSuite;
    use crate::ech::EchConfigBuilder;
    use hptls_crypto::CryptoProvider;
    use hptls_crypto_hpcrypt::HpcryptProvider;

    #[test]
    fn test_ech_client_helper_prepare() {
        let provider = <HpcryptProvider as CryptoProvider>::new();

        // Generate ECH config
        let (config, _secret_key) = EchConfigBuilder::new()
            .public_name("example.com")
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
            .build(&provider)
            .unwrap();

        // Create helper
        let helper = EchClientHelper::new(config);

        // Create base ClientHello
        let base_hello = ClientHello::new([0u8; 32], vec![CipherSuite::Aes128GcmSha256]);

        // Prepare ECH ClientHello
        let outer_hello = helper
            .prepare_client_hello(&provider, &base_hello, "secret.example.com", "example.com")
            .unwrap();

        // Verify ECH extension is present
        assert!(outer_hello.extensions.has_ech());
    }

    #[test]
    fn test_ech_server_helper_decrypt() {
        let provider = <HpcryptProvider as CryptoProvider>::new();

        // Generate ECH config
        let (config, secret_key) = EchConfigBuilder::new()
            .public_name("example.com")
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
            .build(&provider)
            .unwrap();

        // Create client helper
        let client_helper = EchClientHelper::new(config.clone());

        // Create base ClientHello
        let base_hello = ClientHello::new([0u8; 32], vec![CipherSuite::Aes128GcmSha256]);

        // Prepare ECH ClientHello
        let outer_hello = client_helper
            .prepare_client_hello(&provider, &base_hello, "secret.example.com", "example.com")
            .unwrap();

        // Create server helper
        let config_list = EchConfigList::new(vec![config.clone()]);
        let mut secret_keys = HashMap::new();
        secret_keys.insert(config.config_id, secret_key);
        let server_helper = EchServerHelper::new(config_list, secret_keys);

        // Try to decrypt
        let decrypted = server_helper
            .try_decrypt_ech(&outer_hello, &provider)
            .unwrap();

        assert!(decrypted.is_some());
        let inner_hello = decrypted.unwrap();

        // Verify inner hello has the real SNI
        assert_eq!(
            inner_hello.extensions.get_server_name().unwrap(),
            Some("secret.example.com".to_string())
        );
    }

    #[test]
    fn test_has_ech() {
        let provider = <HpcryptProvider as CryptoProvider>::new();

        // Generate ECH config
        let (config, _) = EchConfigBuilder::new()
            .public_name("example.com")
            .add_cipher_suite(EchCipherSuite::HKDF_SHA256_AES128GCM)
            .build(&provider)
            .unwrap();

        let helper = EchClientHelper::new(config);
        let base_hello = ClientHello::new([0u8; 32], vec![CipherSuite::Aes128GcmSha256]);

        // Without ECH
        assert!(!has_ech(&base_hello));

        // With ECH
        let outer_hello = helper
            .prepare_client_hello(&provider, &base_hello, "secret.example.com", "example.com")
            .unwrap();
        assert!(has_ech(&outer_hello));
    }
}
