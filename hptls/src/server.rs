//! TLS server configuration and implementation.

use hptls_core::{Config, Error, ProtocolVersion, Result};

/// Server-specific configuration for TLS connections.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Base TLS configuration
    pub config: Config,

    /// Server certificate chain (DER-encoded)
    pub certificate_chain: Vec<Vec<u8>>,

    /// Server private key (DER-encoded)
    pub private_key: Vec<u8>,

    /// Enable ALPN (Application-Layer Protocol Negotiation)
    pub alpn_protocols: Vec<String>,

    /// Require client certificate (mutual TLS)
    pub require_client_certificate: bool,

    /// Trusted client CA certificates (for mutual TLS)
    pub client_ca_certificates: Vec<Vec<u8>>,

    /// Enable session tickets for resumption
    pub enable_session_tickets: bool,

    /// Enable OCSP stapling
    pub enable_ocsp_stapling: bool,

    /// OCSP response (DER-encoded)
    pub ocsp_response: Option<Vec<u8>>,
}

impl ServerConfig {
    /// Create a new configuration builder.
    pub fn builder() -> ServerConfigBuilder {
        ServerConfigBuilder::default()
    }
}

/// Builder for server configuration.
#[derive(Debug, Default)]
pub struct ServerConfigBuilder {
    config: Option<Config>,
    certificate_chain: Option<Vec<Vec<u8>>>,
    private_key: Option<Vec<u8>>,
    alpn_protocols: Vec<String>,
    require_client_certificate: bool,
    client_ca_certificates: Vec<Vec<u8>>,
    enable_session_tickets: bool,
    enable_ocsp_stapling: bool,
    ocsp_response: Option<Vec<u8>>,
}

impl ServerConfigBuilder {
    /// Set protocol versions.
    pub fn with_protocol_versions(mut self, versions: &[ProtocolVersion]) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.protocol_versions = versions.to_vec();
        self.config = Some(config);
        self
    }

    /// Set server certificate chain.
    pub fn with_certificate_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.certificate_chain = Some(chain);
        self
    }

    /// Set server private key.
    pub fn with_private_key(mut self, key: Vec<u8>) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Set ALPN protocols.
    pub fn with_alpn_protocols(mut self, protocols: Vec<String>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Require client certificate (mutual TLS).
    pub fn with_client_certificate_requirement(mut self, require: bool) -> Self {
        self.require_client_certificate = require;
        self
    }

    /// Set trusted client CA certificates (for mutual TLS).
    pub fn with_client_ca_certificates(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.client_ca_certificates = certs;
        self
    }

    /// Enable session tickets.
    pub fn with_session_tickets(mut self, enable: bool) -> Self {
        self.enable_session_tickets = enable;
        self
    }

    /// Enable OCSP stapling.
    pub fn with_ocsp_stapling(mut self, enable: bool) -> Self {
        self.enable_ocsp_stapling = enable;
        self
    }

    /// Set OCSP response.
    pub fn with_ocsp_response(mut self, response: Vec<u8>) -> Self {
        self.ocsp_response = Some(response);
        self
    }

    /// Build the server configuration.
    pub fn build(self) -> Result<ServerConfig> {
        let certificate_chain = self
            .certificate_chain
            .ok_or_else(|| Error::InvalidConfig("Certificate chain not set".into()))?;

        let private_key = self
            .private_key
            .ok_or_else(|| Error::InvalidConfig("Private key not set".into()))?;

        if certificate_chain.is_empty() {
            return Err(Error::InvalidConfig("Certificate chain is empty".into()));
        }

        if private_key.is_empty() {
            return Err(Error::InvalidConfig("Private key is empty".into()));
        }

        if self.require_client_certificate && self.client_ca_certificates.is_empty() {
            return Err(Error::InvalidConfig(
                "Client certificate required but no CA certificates provided".into(),
            ));
        }

        Ok(ServerConfig {
            config: self.config.unwrap_or_default(),
            certificate_chain,
            private_key,
            alpn_protocols: self.alpn_protocols,
            require_client_certificate: self.require_client_certificate,
            client_ca_certificates: self.client_ca_certificates,
            enable_session_tickets: self.enable_session_tickets,
            enable_ocsp_stapling: self.enable_ocsp_stapling,
            ocsp_response: self.ocsp_response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_builder() {
        let config = ServerConfig::builder()
            .with_certificate_chain(vec![vec![1, 2, 3]])
            .with_private_key(vec![4, 5, 6])
            .with_alpn_protocols(vec!["h2".to_string()])
            .with_session_tickets(true)
            .build()
            .unwrap();

        assert_eq!(config.certificate_chain.len(), 1);
        assert_eq!(config.alpn_protocols, vec!["h2"]);
        assert!(config.enable_session_tickets);
    }

    #[test]
    fn test_validation() {
        // Should fail: no certificate
        let result = ServerConfig::builder().with_private_key(vec![1, 2, 3]).build();
        assert!(result.is_err());

        // Should fail: no private key
        let result = ServerConfig::builder().with_certificate_chain(vec![vec![1, 2, 3]]).build();
        assert!(result.is_err());

        // Should fail: require client cert but no CA certs
        let result = ServerConfig::builder()
            .with_certificate_chain(vec![vec![1, 2, 3]])
            .with_private_key(vec![4, 5, 6])
            .with_client_certificate_requirement(true)
            .build();
        assert!(result.is_err());
    }
}
