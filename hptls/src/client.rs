//! TLS client configuration and implementation.

use hptls_core::{Config, Error, ProtocolVersion, Result};

/// Client-specific configuration for TLS connections.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Base TLS configuration
    pub config: Config,

    /// Trusted root certificates (DER-encoded)
    pub root_certificates: Vec<Vec<u8>>,

    /// Client certificate chain (optional, for mutual TLS)
    pub client_certificate_chain: Option<Vec<Vec<u8>>>,

    /// Client private key (optional, for mutual TLS)
    pub client_private_key: Option<Vec<u8>>,

    /// Enable SNI (Server Name Indication)
    pub enable_sni: bool,

    /// Enable ALPN (Application-Layer Protocol Negotiation)
    pub alpn_protocols: Vec<String>,

    /// Enable session resumption
    pub enable_session_resumption: bool,

    /// Enable OCSP stapling
    pub enable_ocsp_stapling: bool,

    /// Verify server certificate
    pub verify_server_certificate: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            config: Config::default(),
            root_certificates: Vec::new(),
            client_certificate_chain: None,
            client_private_key: None,
            enable_sni: true,
            alpn_protocols: Vec::new(),
            enable_session_resumption: true,
            enable_ocsp_stapling: true,
            verify_server_certificate: true,
        }
    }
}

impl ClientConfig {
    /// Create a new configuration builder.
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::default()
    }
}

/// Builder for client configuration.
#[derive(Debug, Default)]
pub struct ClientConfigBuilder {
    config: ClientConfig,
}

impl ClientConfigBuilder {
    /// Set protocol versions.
    pub fn with_protocol_versions(mut self, versions: &[ProtocolVersion]) -> Self {
        self.config.config.protocol_versions = versions.to_vec();
        self
    }

    /// Add a root certificate (DER-encoded).
    pub fn add_root_certificate(mut self, cert: Vec<u8>) -> Self {
        self.config.root_certificates.push(cert);
        self
    }

    /// Set root certificates (DER-encoded).
    pub fn with_root_certificates(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.config.root_certificates = certs;
        self
    }

    /// Set client certificate chain for mutual TLS.
    pub fn with_client_certificate_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.config.client_certificate_chain = Some(chain);
        self
    }

    /// Set client private key for mutual TLS.
    pub fn with_client_private_key(mut self, key: Vec<u8>) -> Self {
        self.config.client_private_key = Some(key);
        self
    }

    /// Enable or disable SNI.
    pub fn with_sni(mut self, enable: bool) -> Self {
        self.config.enable_sni = enable;
        self
    }

    /// Set ALPN protocols.
    pub fn with_alpn_protocols(mut self, protocols: Vec<String>) -> Self {
        self.config.alpn_protocols = protocols;
        self
    }

    /// Enable session resumption.
    pub fn with_session_resumption(mut self, enable: bool) -> Self {
        self.config.enable_session_resumption = enable;
        self
    }

    /// Enable OCSP stapling.
    pub fn with_ocsp_stapling(mut self, enable: bool) -> Self {
        self.config.enable_ocsp_stapling = enable;
        self
    }

    /// Enable or disable server certificate verification.
    pub fn with_server_certificate_verification(mut self, enable: bool) -> Self {
        self.config.verify_server_certificate = enable;
        self
    }

    /// Build the client configuration.
    pub fn build(self) -> Result<ClientConfig> {
        // Validate configuration
        if self.config.verify_server_certificate && self.config.root_certificates.is_empty() {
            return Err(Error::InvalidConfig(
                "Server certificate verification enabled but no root certificates provided".into(),
            ));
        }

        if self.config.client_certificate_chain.is_some()
            != self.config.client_private_key.is_some()
        {
            return Err(Error::InvalidConfig(
                "Client certificate and private key must both be set or both be unset".into(),
            ));
        }

        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_client_config() {
        let config = ClientConfig::default();
        assert!(config.enable_sni);
        assert!(config.verify_server_certificate);
        assert!(config.enable_session_resumption);
    }

    #[test]
    fn test_client_config_builder() {
        let config = ClientConfig::builder()
            .with_protocol_versions(&[ProtocolVersion::Tls13])
            .with_sni(true)
            .with_alpn_protocols(vec!["h2".to_string(), "http/1.1".to_string()])
            .with_server_certificate_verification(false)
            .build()
            .unwrap();

        assert_eq!(
            config.config.protocol_versions,
            vec![ProtocolVersion::Tls13]
        );
        assert_eq!(config.alpn_protocols, vec!["h2", "http/1.1"]);
        assert!(!config.verify_server_certificate);
    }

    #[test]
    fn test_validation() {
        // Should fail: verification enabled but no root certs
        let result = ClientConfig::builder().with_server_certificate_verification(true).build();
        assert!(result.is_err());

        // Should succeed: verification disabled
        let result = ClientConfig::builder().with_server_certificate_verification(false).build();
        assert!(result.is_ok());
    }
}
