//! Certificate message (RFC 8446 Section 4.4.2).

use crate::error::{Error, Result};
use crate::extensions::Extensions;
use bytes::{Buf, BufMut, BytesMut};

/// Certificate entry with extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEntry {
    /// Certificate data (DER-encoded X.509)
    pub cert_data: Vec<u8>,

    /// Extensions for this certificate
    pub extensions: Extensions,
}

/// Certificate message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// Certificate request context (0-length for server auth)
    pub certificate_request_context: Vec<u8>,

    /// Certificate chain
    pub certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    /// Create a new Certificate message.
    pub fn new(cert_list: Vec<Vec<u8>>) -> Self {
        let certificate_list = cert_list
            .into_iter()
            .map(|cert_data| CertificateEntry {
                cert_data,
                extensions: Extensions::new(),
            })
            .collect();

        Self {
            certificate_request_context: Vec::new(),
            certificate_list,
        }
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Certificate request context
        if self.certificate_request_context.len() > 255 {
            return Err(Error::InvalidMessage("Context too long".into()));
        }
        buf.put_u8(self.certificate_request_context.len() as u8);
        buf.put_slice(&self.certificate_request_context);

        // Certificate list length (3 bytes)
        let mut cert_list_buf = BytesMut::new();
        for entry in &self.certificate_list {
            // Cert data length (3 bytes)
            if entry.cert_data.len() > 0xFFFFFF {
                return Err(Error::InvalidMessage("Certificate too large".into()));
            }
            cert_list_buf.put_uint(entry.cert_data.len() as u64, 3);
            cert_list_buf.put_slice(&entry.cert_data);

            // Extensions
            let ext_bytes = entry.extensions.encode();
            cert_list_buf.put_slice(&ext_bytes);
        }

        if cert_list_buf.len() > 0xFFFFFF {
            return Err(Error::InvalidMessage("Certificate list too large".into()));
        }
        buf.put_uint(cert_list_buf.len() as u64, 3);
        buf.put_slice(&cert_list_buf);

        Ok(buf.to_vec())
    }

    /// Decode from bytes.
    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidMessage("Certificate too short".into()));
        }

        // Certificate request context
        let ctx_len = data.get_u8() as usize;
        if data.len() < ctx_len {
            return Err(Error::InvalidMessage("Incomplete context".into()));
        }
        let certificate_request_context = data[..ctx_len].to_vec();
        data.advance(ctx_len);

        // Certificate list
        if data.len() < 3 {
            return Err(Error::InvalidMessage("Missing cert list length".into()));
        }
        let list_len = ((data.get_u8() as usize) << 16)
            | ((data.get_u8() as usize) << 8)
            | (data.get_u8() as usize);

        if data.len() < list_len {
            return Err(Error::InvalidMessage("Incomplete cert list".into()));
        }

        let mut certificate_list = Vec::new();
        let mut remaining = list_len;

        while remaining > 0 {
            if data.len() < 3 {
                return Err(Error::InvalidMessage("Missing cert length".into()));
            }
            let cert_len = ((data.get_u8() as usize) << 16)
                | ((data.get_u8() as usize) << 8)
                | (data.get_u8() as usize);
            remaining -= 3;

            if data.len() < cert_len {
                return Err(Error::InvalidMessage("Incomplete cert data".into()));
            }
            let cert_data = data[..cert_len].to_vec();
            data.advance(cert_len);
            remaining -= cert_len;

            // Extensions
            let extensions = Extensions::decode(data)?;
            let ext_len = extensions.encode().len();
            remaining -= ext_len;

            certificate_list.push(CertificateEntry {
                cert_data,
                extensions,
            });
        }

        Ok(Self {
            certificate_request_context,
            certificate_list,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate() {
        let cert = Certificate::new(vec![vec![1, 2, 3, 4]]);
        let encoded = cert.encode().unwrap();
        // Basic smoke test - full test requires proper X.509 certs
        assert!(!encoded.is_empty());
    }
}
