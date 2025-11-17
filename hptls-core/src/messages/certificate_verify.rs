//! CertificateVerify message (RFC 8446 Section 4.4.3).

use crate::error::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};
use hptls_crypto::SignatureAlgorithm;

/// CertificateVerify message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    /// Signature algorithm
    pub algorithm: SignatureAlgorithm,

    /// Signature
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn new(algorithm: SignatureAlgorithm, signature: Vec<u8>) -> Self {
        Self {
            algorithm,
            signature,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        buf.put_u16(self.algorithm as u16);
        if self.signature.len() > 65535 {
            return Err(Error::InvalidMessage("Signature too large".into()));
        }
        buf.put_u16(self.signature.len() as u16);
        buf.put_slice(&self.signature);
        Ok(buf.to_vec())
    }

    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidMessage("CertificateVerify too short".into()));
        }
        let alg_raw = data.get_u16();
        let algorithm = SignatureAlgorithm::from_u16(alg_raw)
            .ok_or_else(|| Error::InvalidMessage("Unknown signature algorithm".into()))?;
        let sig_len = data.get_u16() as usize;
        if data.len() < sig_len {
            return Err(Error::InvalidMessage("Incomplete signature".into()));
        }
        let signature = data[..sig_len].to_vec();
        Ok(Self {
            algorithm,
            signature,
        })
    }
}
