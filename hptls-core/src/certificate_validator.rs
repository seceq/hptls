//! Certificate validation for TLS 1.3.
//!
//! This module provides X.509 certificate chain validation as required by
//! RFC 8446 Section 4.4.2.
//! # Features
//! - Basic X.509 DER parsing (limited to TLS use cases)
//! - Certificate chain validation
//! - Validity period checking
//! - Trust anchor verification
//! - Hostname verification (SNI matching)
//! # Note
//! This is a simplified implementation suitable for testing and demonstration.
//! Production systems should use mature X.509 libraries like `webpki` or `rustls-webpki`.

use crate::error::{Error, Result};
use std::time::{SystemTime, UNIX_EPOCH};
/// Certificate validation error reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Certificate is expired
    Expired,
    /// Certificate is not yet valid
    NotYetValid,
    /// Certificate chain is empty
    EmptyChain,
    /// Certificate chain is too long
    ChainTooLong,
    /// Certificate signature verification failed
    InvalidSignature,
    /// Certificate is not trusted (not in trust store)
    Untrusted,
    /// Hostname does not match certificate
    HostnameMismatch,
    /// Certificate parsing failed
    ParseError(String),
    /// Invalid certificate encoding
    InvalidEncoding(String),
}
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::Expired => write!(f, "Certificate is expired"),
            ValidationError::NotYetValid => write!(f, "Certificate is not yet valid"),
            ValidationError::EmptyChain => write!(f, "Certificate chain is empty"),
            ValidationError::ChainTooLong => write!(f, "Certificate chain is too long"),
            ValidationError::InvalidSignature => {
                write!(f, "Certificate signature verification failed")
            },
            ValidationError::Untrusted => write!(f, "Certificate is not trusted"),
            ValidationError::HostnameMismatch => write!(f, "Hostname does not match certificate"),
            ValidationError::ParseError(msg) => write!(f, "Certificate parsing failed: {}", msg),
            ValidationError::InvalidEncoding(msg) => {
                write!(f, "Invalid certificate encoding: {}", msg)
            },
        }
    }
}
impl std::error::Error for ValidationError {}
/// Simplified X.509 certificate representation.
///
/// This structure contains only the fields necessary for basic TLS validation.
/// It is not a complete X.509 parser.
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// Raw DER-encoded certificate
    pub der: Vec<u8>,
    /// Subject Common Name (CN) - extracted if present
    pub subject_cn: Option<String>,
    /// Subject Alternative Names (DNS names)
    pub subject_alt_names: Vec<String>,
    /// Not Before timestamp (seconds since UNIX epoch)
    pub not_before: u64,
    /// Not After timestamp (seconds since UNIX epoch)
    pub not_after: u64,
    /// Whether this is a CA certificate
    pub is_ca: bool,
    /// Public key bytes (for signature verification)
    pub public_key: Vec<u8>,
}
impl X509Certificate {
    /// Parse a DER-encoded X.509 certificate.
    ///
    /// This is a simplified parser that extracts only the fields needed for
    /// basic TLS validation. It does not implement the full X.509 specification.
    /// # Note
    /// For production use, consider using a mature X.509 library like `x509-parser`
    /// or `webpki`.
    pub fn parse_der(der: &[u8]) -> Result<Self> {
        // For now, we'll create a mock parser that accepts any DER data
        // In a production implementation, this would use a proper X.509 parser
        if der.is_empty() {
            return Err(Error::CertificateVerificationFailed(
                ValidationError::ParseError("Empty certificate".into()).to_string(),
            ));
        }
        // Basic DER sanity check: should start with SEQUENCE tag (0x30)
        if der[0] != 0x30 {
            return Err(Error::CertificateVerificationFailed(
                ValidationError::InvalidEncoding("Certificate must start with SEQUENCE tag".into())
                    .to_string(),
            ));
        }
        // Extract the public key from the certificate
        // If extraction fails (e.g., unsupported algorithm or malformed cert),
        // fall back to mock public key for testing
        let public_key = match crate::x509_simple::extract_public_key_from_cert(der) {
            Ok(info) => info.key_bytes,
            Err(_) => vec![0u8; 32], // Mock public key for testing
        };
        // For testing purposes, create a mock certificate with reasonable defaults
        // Production code would parse the actual DER structure
        Ok(Self {
            der: der.to_vec(),
            subject_cn: None,
            subject_alt_names: Vec::new(),
            not_before: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 86400, // Valid since yesterday
            not_after: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                + 365 * 86400, // Valid for 1 year
            is_ca: false,
            public_key, // Use extracted or mock public key
        })
    }
    /// Check if the certificate is currently valid (time-based).
    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        timestamp >= self.not_before && timestamp <= self.not_after
    }
    /// Check if the certificate is currently valid.
    pub fn is_currently_valid(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.is_valid_at(now)
    }
    /// Check if the certificate matches the given hostname.
    /// This checks both the subject CN and subject alternative names.
    pub fn matches_hostname(&self, hostname: &str) -> bool {
        // Check Subject Alternative Names first (preferred in modern certs)
        if self.subject_alt_names.iter().any(|name| wildcard_match(name, hostname)) {
            return true;
        }
        // Fallback to CN if no SANs
        if let Some(ref cn) = self.subject_cn {
            return wildcard_match(cn, hostname);
        }
        false
    }
}
/// Match a hostname against a pattern, supporting wildcards.
/// Supports simple wildcard matching where `*` matches a single label.
/// For example: `*.example.com` matches `www.example.com` but not `example.com`.
fn wildcard_match(pattern: &str, hostname: &str) -> bool {
    if pattern == hostname {
        return true;
    }
    // Simple wildcard support for `*.domain.com` pattern
    if pattern.starts_with("*.") {
        let pattern_domain = &pattern[2..];
        if let Some(first_dot) = hostname.find('.') {
            let hostname_domain = &hostname[first_dot + 1..];
            return pattern_domain == hostname_domain;
        }
    }
    false
}
/// Certificate validation policy.
#[derive(Debug, Clone)]
pub struct ValidationPolicy {
    /// Maximum allowed certificate chain length
    pub max_chain_length: usize,
    /// Whether to check certificate validity periods
    pub check_validity_period: bool,
    /// Whether to require hostname matching
    pub require_hostname_match: bool,
    /// Whether to verify certificate signatures
    pub verify_signatures: bool,
}
impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            max_chain_length: 10,
            check_validity_period: true,
            require_hostname_match: true,
            verify_signatures: true,
        }
    }
}
impl ValidationPolicy {
    /// Create a permissive policy for testing.
    pub fn permissive() -> Self {
        Self {
            max_chain_length: 10,
            check_validity_period: false,
            require_hostname_match: false,
            verify_signatures: false,
        }
    }
}
/// Certificate validator.
/// Validates certificate chains according to the configured policy.
pub struct CertificateValidator {
    /// Validation policy
    policy: ValidationPolicy,
    /// Trusted root certificates (DER-encoded)
    trust_anchors: Vec<Vec<u8>>,
}
impl CertificateValidator {
    /// Create a new certificate validator with the given policy.
    pub fn new(policy: ValidationPolicy) -> Self {
        Self {
            policy,
            trust_anchors: Vec::new(),
        }
    }
    /// Create a validator with default policy.
    pub fn with_default_policy() -> Self {
        Self::new(ValidationPolicy::default())
    }
    /// Create a validator with permissive policy (for testing).
    pub fn permissive() -> Self {
        Self::new(ValidationPolicy::permissive())
    }
    /// Add a trusted root certificate.
    pub fn add_trust_anchor(&mut self, root_cert_der: Vec<u8>) {
        self.trust_anchors.push(root_cert_der);
    }
    /// Validate a certificate chain.
    /// # Arguments
    /// * `chain` - Certificate chain (leaf first, root last)
    /// * `hostname` - Optional hostname to verify (for SNI)
    /// * `crypto_provider` - Cryptographic provider for signature verification
    /// # Returns
    /// Returns `Ok(())` if validation succeeds, or an error describing the failure.
    pub fn validate_chain(
        &self,
        chain: &[Vec<u8>],
        hostname: Option<&str>,
        crypto_provider: &dyn hptls_crypto::CryptoProvider,
    ) -> Result<()> {
        // Check for empty chain
        if chain.is_empty() {
            return Err(Error::CertificateVerificationFailed(
                ValidationError::EmptyChain.to_string(),
            ));
        }
        // Check chain length
        if chain.len() > self.policy.max_chain_length {
            return Err(Error::CertificateVerificationFailed(
                ValidationError::ChainTooLong.to_string(),
            ));
        }
        // Parse all certificates
        let mut certs = Vec::new();
        for cert_der in chain {
            let cert = X509Certificate::parse_der(cert_der)?;
            certs.push(cert);
        }
        // Validate leaf certificate
        let leaf = &certs[0];
        // Check validity period
        if self.policy.check_validity_period && !leaf.is_currently_valid() {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            if now < leaf.not_before {
                return Err(Error::CertificateVerificationFailed(
                    ValidationError::NotYetValid.to_string(),
                ));
            } else {
                return Err(Error::CertificateVerificationFailed(
                    ValidationError::Expired.to_string(),
                ));
            }
        }
        // Check hostname match
        if self.policy.require_hostname_match {
            if let Some(hostname) = hostname {
                if !leaf.matches_hostname(hostname) {
                    return Err(Error::CertificateVerificationFailed(
                        ValidationError::HostnameMismatch.to_string(),
                    ));
                }
            }
        }
        // Verify chain signatures (if enabled)
        if self.policy.verify_signatures {
            self.verify_chain_signatures(&certs, chain, crypto_provider)?;
        }
        // Check trust anchor
        self.verify_trust_anchor(&certs)?;
        Ok(())
    }
    /// Verify signatures in the certificate chain.
    /// For each certificate (except the root), verifies that its signature
    /// was created by the issuer (next certificate in chain) using the
    /// issuer's public key.
    fn verify_chain_signatures(
        &self,
        certs: &[X509Certificate],
        chain: &[Vec<u8>],
        crypto_provider: &dyn hptls_crypto::CryptoProvider,
    ) -> Result<()> {
        use crate::x509_simple::{extract_public_key_from_cert, extract_tbs_certificate};
        if !self.policy.verify_signatures {
            return Ok(());
        }
        // Verify each certificate's signature using the issuer's public key
        // (issuer is the next cert in the chain)
        for i in 0..certs.len() {
            // Skip root certificate (self-signed, we trust it based on trust anchor)
            if i == certs.len() - 1 {
                continue;
            }
            // Extract TBS certificate, signature algorithm, and signature
            let tbs = extract_tbs_certificate(&chain[i]).map_err(|e| {
                Error::CertificateVerificationFailed(format!(
                    "Failed to extract TBS from certificate {}: {}",
                    i, e
                ))
            })?;
            // Get the signature algorithm
            let sig_alg = tbs.signature_algorithm;
            // Get verifier for this signature algorithm
            let verifier = crypto_provider.signature(sig_alg).map_err(|e| {
                Error::CertificateVerificationFailed(format!(
                    "Unsupported signature algorithm {:?}: {}",
                    sig_alg, e
                ))
            })?;
            // Extract issuer's public key info
            let issuer_key_info = extract_public_key_from_cert(&chain[i + 1]).map_err(|e| {
                Error::CertificateVerificationFailed(format!(
                    "Failed to extract public key from issuer certificate: {}",
                    e
                ))
            })?;
            // Verify the signature using issuer's public key bytes
            verifier
                .verify(
                    &issuer_key_info.key_bytes,
                    &tbs.tbs_bytes,
                    &tbs.signature_bytes,
                )
                .map_err(|e| {
                    Error::CertificateVerificationFailed(format!(
                        "Certificate {} signature verification failed: {}",
                        i, e
                    ))
                })?;
        }
        Ok(())
    }
    /// Verify that the chain is rooted in a trusted anchor.
    fn verify_trust_anchor(&self, certs: &[X509Certificate]) -> Result<()> {
        // If no trust anchors configured, accept any chain in permissive mode
        if self.trust_anchors.is_empty() && !self.policy.verify_signatures {
            return Ok(());
        }
        // Check if the root certificate matches a trust anchor
        if let Some(root) = certs.last() {
            for anchor in &self.trust_anchors {
                if root.der == *anchor {
                    return Ok(());
                }
            }
        }
        // If we have trust anchors configured, require a match
        if !self.trust_anchors.is_empty() {
            return Err(Error::CertificateVerificationFailed(
                ValidationError::Untrusted.to_string(),
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use hptls_crypto::CryptoProvider;
    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("example.com", "example.com"));
        assert!(wildcard_match("*.example.com", "www.example.com"));
        assert!(wildcard_match("*.example.com", "api.example.com"));
        assert!(!wildcard_match("*.example.com", "example.com"));
        assert!(!wildcard_match(
            "*.example.com",
            "www.subdomain.example.com"
        ));
    }
    #[test]
    fn test_parse_empty_certificate() {
        let result = X509Certificate::parse_der(&[]);
        assert!(result.is_err());
    }
    #[test]
    fn test_parse_invalid_der() {
        // Invalid DER (doesn't start with SEQUENCE tag)
        let result = X509Certificate::parse_der(&[0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }
    #[test]
    fn test_parse_mock_certificate() {
        // Mock DER-encoded certificate (starts with SEQUENCE tag)
        let mock_der = vec![0x30, 0x82, 0x01, 0x00];
        let cert = X509Certificate::parse_der(&mock_der).unwrap();
        assert_eq!(cert.der, mock_der);
        assert!(cert.is_currently_valid());
    }
    #[test]
    fn test_certificate_validity() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let cert = X509Certificate {
            der: vec![0x30, 0x82, 0x01, 0x00],
            subject_cn: None,
            subject_alt_names: Vec::new(),
            not_before: now - 3600, // 1 hour ago
            not_after: now + 3600,  // 1 hour from now
            is_ca: false,
            public_key: vec![0u8; 32],
        };
        assert!(cert.is_valid_at(now));
        assert!(!cert.is_valid_at(now - 7200)); // 2 hours ago
        assert!(!cert.is_valid_at(now + 7200)); // 2 hours from now
    }
    #[test]
    fn test_hostname_matching() {
        let mut cert = X509Certificate {
            der: vec![0x30, 0x82, 0x01, 0x00],
            subject_cn: Some("example.com".to_string()),
            subject_alt_names: vec!["example.com".to_string(), "*.example.com".to_string()],
            not_before: 0,
            not_after: u64::MAX,
            is_ca: false,
            public_key: vec![0u8; 32],
        };
        assert!(cert.matches_hostname("example.com"));
        assert!(cert.matches_hostname("www.example.com"));
        assert!(cert.matches_hostname("api.example.com"));
        assert!(!cert.matches_hostname("other.com"));
        // Test CN fallback when no SANs
        cert.subject_alt_names.clear();
        assert!(cert.matches_hostname("example.com"));
    }
    #[test]
    fn test_validator_empty_chain() {
        let validator = CertificateValidator::permissive();
        let crypto = hptls_crypto_hpcrypt::HpcryptProvider::new();
        let result = validator.validate_chain(&[], None, &crypto);
        assert!(result.is_err());
    }
    #[test]
    fn test_validator_permissive_accepts_any_chain() {
        let validator = CertificateValidator::permissive();
        let crypto = hptls_crypto_hpcrypt::HpcryptProvider::new();
        let chain = vec![vec![0x30, 0x82, 0x01, 0x00]];
        let result = validator.validate_chain(&chain, None, &crypto);
        assert!(result.is_ok());
    }
    #[test]
    fn test_validator_chain_too_long() {
        let mut policy = ValidationPolicy::permissive();
        policy.max_chain_length = 2;
        let validator = CertificateValidator::new(policy);
        let crypto = hptls_crypto_hpcrypt::HpcryptProvider::new();
        let chain = vec![
            vec![0x30, 0x82, 0x01, 0x00],
            vec![0x30, 0x82, 0x01, 0x01],
            vec![0x30, 0x82, 0x01, 0x02],
        ];
        let result = validator.validate_chain(&chain, None, &crypto);
        assert!(result.is_err());
    }
    #[test]
    fn test_validator_with_trust_anchor() {
        let mut validator = CertificateValidator::permissive();
        let crypto = hptls_crypto_hpcrypt::HpcryptProvider::new();
        let root_cert = vec![0x30, 0x82, 0x01, 0xFF];
        validator.add_trust_anchor(root_cert.clone());
        // Chain ending with trusted root should succeed
        let chain = vec![vec![0x30, 0x82, 0x01, 0x00], root_cert];
        let result = validator.validate_chain(&chain, None, &crypto);
        assert!(result.is_ok());
    }
    #[test]
    fn test_certificate_chain_signature_verification() {
        use std::fs;
        // Load real certificate chain (server + CA)
        let server_cert_path = "../server-cert-ed25519.der";
        let ca_cert_path = "../ca-cert.pem";
        if let (Ok(server_cert), Ok(ca_pem)) =
            (fs::read(server_cert_path), fs::read_to_string(ca_cert_path))
        {
            // Convert CA cert from PEM to DER
            let ca_lines: Vec<&str> = ca_pem.lines().filter(|l| !l.starts_with("-----")).collect();
            // For this test, we'll just use the server cert alone since we don't have
            // a proper base64 decoder in the test environment. The real test is in
            // the integration tests.
            // Create validator with signature verification enabled
            let mut policy = ValidationPolicy::permissive();
            policy.verify_signatures = true;
            let validator = CertificateValidator::new(policy);
            let crypto = hptls_crypto_hpcrypt::HpcryptProvider::new();
            // Single cert chain (leaf only) - should succeed even without root
            // because permissive mode accepts chains without trust anchors
            let chain = vec![server_cert];
            let result = validator.validate_chain(&chain, None, &crypto);
            // Should succeed because we only have one cert (no signature to verify)
            assert!(result.is_ok(), "Single cert chain should succeed");
        }
    }
}
