//! CertificateRequest message (RFC 8446 Section 4.3.2)
//!
//! The CertificateRequest message is sent by the server when it wants to
//! authenticate the client. The client must respond with a Certificate
//! message (possibly empty) and a CertificateVerify message if a certificate
//! was sent.
//!
//! # Protocol Flow
//!
//! ```text
//! Server                                           Client
//!
//! ServerHello
//! EncryptedExtensions
//! {CertificateRequest}      -------->
//! {Certificate}
//! {CertificateVerify}
//! {Finished}
//!                           <--------  {Certificate}
//!                                      {CertificateVerify}
//!                                      {Finished}
//! ```

use crate::error::{Error, Result};
use crate::extension_types::SignatureScheme;
use crate::extensions::Extensions;
use bytes::{Buf, BufMut, BytesMut};

/// CertificateRequest message.
///
/// Sent by server to request client certificate authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    /// Certificate request context (opaque)
    pub certificate_request_context: Vec<u8>,

    /// Extensions (signature_algorithms, certificate_authorities, etc.)
    pub extensions: Extensions,
}

impl CertificateRequest {
    /// Create a new CertificateRequest
    pub fn new(certificate_request_context: Vec<u8>, extensions: Extensions) -> Self {
        Self {
            certificate_request_context,
            extensions,
        }
    }

    /// Encode to wire format
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Certificate request context length (1 byte)
        if self.certificate_request_context.len() > 255 {
            return Err(Error::InvalidMessage(
                "Certificate request context too long".into(),
            ));
        }
        buf.put_u8(self.certificate_request_context.len() as u8);

        // Certificate request context
        buf.put_slice(&self.certificate_request_context);

        // Extensions
        buf.put_slice(&self.extensions.encode());

        Ok(buf.to_vec())
    }

    /// Decode from wire format
    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidMessage("CertificateRequest too short".into()));
        }

        // Certificate request context length
        let context_len = data.get_u8() as usize;

        if data.len() < context_len {
            return Err(Error::InvalidMessage(
                "Incomplete certificate request context".into(),
            ));
        }

        // Certificate request context
        let certificate_request_context = data[..context_len].to_vec();
        data.advance(context_len);

        // Extensions
        let extensions = Extensions::decode(data)?;

        Ok(Self {
            certificate_request_context,
            extensions,
        })
    }

    /// Get supported signature algorithms from extensions
    pub fn signature_algorithms(&self) -> Result<Option<Vec<SignatureScheme>>> {
        if let Some(typed_ext) =
            self.extensions.get_typed(crate::protocol::ExtensionType::SignatureAlgorithms)?
        {
            if let crate::extension_types::TypedExtension::SignatureAlgorithms(algorithms) =
                typed_ext
            {
                return Ok(Some(algorithms));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_request_encode_decode() {
        let cert_req = CertificateRequest::new(vec![1, 2, 3, 4], Extensions::new());

        let encoded = cert_req.encode().unwrap();
        let decoded = CertificateRequest::decode(&encoded).unwrap();

        assert_eq!(cert_req, decoded);
    }

    #[test]
    fn test_certificate_request_empty_context() {
        let cert_req = CertificateRequest::new(vec![], Extensions::new());

        let encoded = cert_req.encode().unwrap();
        let decoded = CertificateRequest::decode(&encoded).unwrap();

        assert_eq!(cert_req, decoded);
        assert!(decoded.certificate_request_context.is_empty());
    }

    #[test]
    fn test_certificate_request_with_extensions() {
        use crate::extension_types::{SignatureScheme, TypedExtension};

        let mut extensions = Extensions::new();
        extensions
            .add_typed(TypedExtension::SignatureAlgorithms(vec![
                SignatureScheme::EcdsaSecp256r1Sha256,
                SignatureScheme::RsaPssRsaeSha256,
            ]))
            .unwrap();

        let cert_req = CertificateRequest::new(vec![1, 2], extensions);

        let encoded = cert_req.encode().unwrap();
        let decoded = CertificateRequest::decode(&encoded).unwrap();

        assert_eq!(cert_req, decoded);

        // Verify signature algorithms are preserved
        let sig_algs = decoded.signature_algorithms().unwrap();
        assert!(sig_algs.is_some());
        assert_eq!(sig_algs.unwrap().len(), 2);
    }

    #[test]
    fn test_certificate_request_context_too_long() {
        let cert_req = CertificateRequest::new(
            vec![0u8; 300], // > 255 bytes
            Extensions::new(),
        );

        let result = cert_req.encode();
        assert!(result.is_err());
    }
}
