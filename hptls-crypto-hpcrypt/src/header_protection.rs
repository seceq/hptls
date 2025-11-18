//! QUIC Header Protection implementation using hpcrypt-kdf.

use hptls_crypto::{Error, HeaderProtection, HeaderProtectionAlgorithm, Result};
// Import hpcrypt-kdf's HeaderProtection trait to access generate_mask method
use hpcrypt_kdf::HeaderProtection as HpcryptHeaderProtection;

/// Create a header protection instance.
pub fn create_header_protection(
    algorithm: HeaderProtectionAlgorithm,
    key: &[u8],
) -> Result<Box<dyn HeaderProtection>> {
    match algorithm {
        HeaderProtectionAlgorithm::Aes128 => {
            if key.len() != 16 {
                return Err(Error::InvalidKeySize {
                    expected: 16,
                    actual: key.len(),
                });
            }
            Ok(Box::new(HeaderProtectionAes128::new(key)))
        }
        HeaderProtectionAlgorithm::Aes256 => {
            if key.len() != 32 {
                return Err(Error::InvalidKeySize {
                    expected: 32,
                    actual: key.len(),
                });
            }
            Ok(Box::new(HeaderProtectionAes256::new(key)))
        }
        HeaderProtectionAlgorithm::ChaCha20 => {
            if key.len() != 32 {
                return Err(Error::InvalidKeySize {
                    expected: 32,
                    actual: key.len(),
                });
            }
            Ok(Box::new(HeaderProtectionChaCha20::new(key)))
        }
    }
}

/// AES-128 header protection implementation.
struct HeaderProtectionAes128 {
    inner: hpcrypt_kdf::HeaderProtectionAes128,
}

impl HeaderProtectionAes128 {
    fn new(key: &[u8]) -> Self {
        Self {
            inner: hpcrypt_kdf::HeaderProtectionAes128::new(key),
        }
    }
}

impl HeaderProtection for HeaderProtectionAes128 {
    fn generate_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() < 16 {
            return Err(Error::Internal(format!(
                "Sample must be at least 16 bytes, got {}",
                sample.len()
            )));
        }
        Ok(self.inner.generate_mask(&sample[..16]))
    }

    fn algorithm(&self) -> HeaderProtectionAlgorithm {
        HeaderProtectionAlgorithm::Aes128
    }
}

/// AES-256 header protection implementation.
struct HeaderProtectionAes256 {
    inner: hpcrypt_kdf::HeaderProtectionAes256,
}

impl HeaderProtectionAes256 {
    fn new(key: &[u8]) -> Self {
        Self {
            inner: hpcrypt_kdf::HeaderProtectionAes256::new(key),
        }
    }
}

impl HeaderProtection for HeaderProtectionAes256 {
    fn generate_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() < 16 {
            return Err(Error::Internal(format!(
                "Sample must be at least 16 bytes, got {}",
                sample.len()
            )));
        }
        Ok(self.inner.generate_mask(&sample[..16]))
    }

    fn algorithm(&self) -> HeaderProtectionAlgorithm {
        HeaderProtectionAlgorithm::Aes256
    }
}

/// ChaCha20 header protection implementation.
struct HeaderProtectionChaCha20 {
    inner: hpcrypt_kdf::HeaderProtectionChaCha20,
}

impl HeaderProtectionChaCha20 {
    fn new(key: &[u8]) -> Self {
        Self {
            inner: hpcrypt_kdf::HeaderProtectionChaCha20::new(key),
        }
    }
}

impl HeaderProtection for HeaderProtectionChaCha20 {
    fn generate_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() < 16 {
            return Err(Error::Internal(format!(
                "Sample must be at least 16 bytes, got {}",
                sample.len()
            )));
        }
        Ok(self.inner.generate_mask(&sample[..16]))
    }

    fn algorithm(&self) -> HeaderProtectionAlgorithm {
        HeaderProtectionAlgorithm::ChaCha20
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_header_protection() {
        let key = [0u8; 16];
        let hp = create_header_protection(HeaderProtectionAlgorithm::Aes128, &key).unwrap();
        let sample = [0u8; 16];
        let mask = hp.generate_mask(&sample).unwrap();
        assert_eq!(mask.len(), 5);
    }

    #[test]
    fn test_aes256_header_protection() {
        let key = [0u8; 32];
        let hp = create_header_protection(HeaderProtectionAlgorithm::Aes256, &key).unwrap();
        let sample = [0u8; 16];
        let mask = hp.generate_mask(&sample).unwrap();
        assert_eq!(mask.len(), 5);
    }

    #[test]
    fn test_chacha20_header_protection() {
        let key = [0u8; 32];
        let hp = create_header_protection(HeaderProtectionAlgorithm::ChaCha20, &key).unwrap();
        let sample = [0u8; 16];
        let mask = hp.generate_mask(&sample).unwrap();
        assert_eq!(mask.len(), 5);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0u8; 10];
        let result = create_header_protection(HeaderProtectionAlgorithm::Aes128, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_sample_length() {
        let key = [0u8; 16];
        let hp = create_header_protection(HeaderProtectionAlgorithm::Aes128, &key).unwrap();
        let sample = [0u8; 8]; // Too short
        let result = hp.generate_mask(&sample);
        assert!(result.is_err());
    }
}
