//! TLS 1.2 Certificate Message (RFC 5246 Section 7.4.2)
//!
//! The Certificate message format for TLS 1.2 is simpler than TLS 1.3:
//! - No certificate_request_context
//! - No per-certificate extensions
//! - Just a list of DER-encoded certificates

use crate::error::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// TLS 1.2 Certificate message.
///
/// ```text
/// opaque ASN.1Cert<1..2^24-1>;
///
/// struct {
///     ASN.1Cert certificate_list<0..2^24-1>;
/// } Certificate;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls12Certificate {
    /// Certificate chain (DER-encoded X.509 certificates)
    /// First certificate is the leaf (server/client) certificate
    /// Following certificates are intermediates, up to the root
    pub certificate_list: Vec<Vec<u8>>,
}

impl Tls12Certificate {
    /// Create a new TLS 1.2 Certificate message.
    ///
    /// # Arguments
    /// * `certificate_list` - List of DER-encoded certificates (leaf first)
    pub fn new(certificate_list: Vec<Vec<u8>>) -> Self {
        Self { certificate_list }
    }

    /// Encode the Certificate message to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Calculate total certificate list length
        let mut cert_list_buf = BytesMut::new();
        for cert in &self.certificate_list {
            // Each certificate: 3-byte length + data
            if cert.len() > 0xFFFFFF {
                return Err(Error::InvalidMessage("Certificate too large".into()));
            }
            cert_list_buf.put_uint(cert.len() as u64, 3);
            cert_list_buf.put_slice(cert);
        }

        // Write certificate list length (3 bytes)
        if cert_list_buf.len() > 0xFFFFFF {
            return Err(Error::InvalidMessage("Certificate list too large".into()));
        }
        buf.put_uint(cert_list_buf.len() as u64, 3);
        buf.put_slice(&cert_list_buf);

        Ok(buf.to_vec())
    }

    /// Decode a Certificate message from bytes.
    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(Error::InvalidMessage("Certificate message too short".into()));
        }

        // Read certificate list length (3 bytes)
        let list_len = ((data.get_u8() as usize) << 16)
            | ((data.get_u8() as usize) << 8)
            | (data.get_u8() as usize);

        if data.len() < list_len {
            return Err(Error::InvalidMessage("Incomplete certificate list".into()));
        }

        let mut certificate_list = Vec::new();
        let mut remaining = list_len;

        while remaining > 0 {
            if remaining < 3 {
                return Err(Error::InvalidMessage(
                    "Incomplete certificate length".into(),
                ));
            }

            // Read certificate length (3 bytes)
            let cert_len = ((data.get_u8() as usize) << 16)
                | ((data.get_u8() as usize) << 8)
                | (data.get_u8() as usize);
            remaining -= 3;

            if remaining < cert_len {
                return Err(Error::InvalidMessage("Incomplete certificate data".into()));
            }

            // Read certificate data
            let cert_data = data[..cert_len].to_vec();
            data.advance(cert_len);
            remaining -= cert_len;

            certificate_list.push(cert_data);
        }

        Ok(Self { certificate_list })
    }

    /// Get the leaf certificate (first in the chain).
    pub fn leaf_certificate(&self) -> Option<&[u8]> {
        self.certificate_list.first().map(|c| c.as_slice())
    }

    /// Get the number of certificates in the chain.
    pub fn chain_length(&self) -> usize {
        self.certificate_list.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls12_certificate_encode_decode() {
        // Create a certificate chain with dummy data
        let cert1 = vec![0x30, 0x82, 0x01, 0x00]; // Dummy DER-encoded cert
        let cert2 = vec![0x30, 0x82, 0x02, 0x00]; // Dummy intermediate cert

        let cert_msg = Tls12Certificate::new(vec![cert1.clone(), cert2.clone()]);

        // Encode
        let encoded = cert_msg.encode().expect("Failed to encode");

        // Decode
        let decoded = Tls12Certificate::decode(&encoded).expect("Failed to decode");

        assert_eq!(decoded.certificate_list.len(), 2);
        assert_eq!(decoded.certificate_list[0], cert1);
        assert_eq!(decoded.certificate_list[1], cert2);
        assert_eq!(decoded.leaf_certificate(), Some(cert1.as_slice()));
    }

    #[test]
    fn test_tls12_certificate_empty() {
        let cert_msg = Tls12Certificate::new(vec![]);
        let encoded = cert_msg.encode().expect("Failed to encode");

        // Should just be 3 bytes of zeros (empty list)
        assert_eq!(encoded.len(), 3);
        assert_eq!(encoded, vec![0, 0, 0]);

        let decoded = Tls12Certificate::decode(&encoded).expect("Failed to decode");
        assert_eq!(decoded.certificate_list.len(), 0);
        assert_eq!(decoded.leaf_certificate(), None);
    }

    #[test]
    fn test_tls12_certificate_single() {
        let cert = vec![0x30, 0x82, 0x03, 0x00, 0xAA, 0xBB, 0xCC];
        let cert_msg = Tls12Certificate::new(vec![cert.clone()]);

        let encoded = cert_msg.encode().expect("Failed to encode");
        let decoded = Tls12Certificate::decode(&encoded).expect("Failed to decode");

        assert_eq!(decoded.chain_length(), 1);
        assert_eq!(decoded.certificate_list[0], cert);
    }

    #[test]
    fn test_tls12_certificate_invalid() {
        // Too short
        let result = Tls12Certificate::decode(&[1, 2]);
        assert!(result.is_err());

        // Invalid length
        let result = Tls12Certificate::decode(&[0, 0, 10, 0x30, 0x82]); // Says 10 bytes but only has 2
        assert!(result.is_err());
    }
}
