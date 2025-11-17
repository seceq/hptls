//! EncryptedExtensions message (RFC 8446 Section 4.3.1).

use crate::error::Result;
use crate::extensions::Extensions;

/// EncryptedExtensions message.
///
/// Sent by the server immediately after ServerHello.
/// Contains extensions that are not needed for cryptographic negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedExtensions {
    /// Extensions
    pub extensions: Extensions,
}

impl EncryptedExtensions {
    /// Create a new EncryptedExtensions message.
    pub fn new(extensions: Extensions) -> Self {
        Self { extensions }
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(self.extensions.encode())
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let extensions = Extensions::decode(data)?;
        Ok(Self { extensions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_extensions() {
        let ee = EncryptedExtensions::new(Extensions::new());
        let encoded = ee.encode().unwrap();
        let decoded = EncryptedExtensions::decode(&encoded).unwrap();
        assert_eq!(decoded.extensions.len(), 0);
    }
}
