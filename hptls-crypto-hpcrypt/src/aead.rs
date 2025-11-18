//! AEAD cipher implementations using hpcrypt-aead.

use hptls_crypto::{Aead, AeadAlgorithm, Error, Result};

/// Create an AEAD cipher instance for the specified algorithm.
pub fn create_aead(algorithm: AeadAlgorithm) -> Result<Box<dyn Aead>> {
    match algorithm {
        AeadAlgorithm::Aes128Gcm => Ok(Box::new(Aes128GcmImpl)),
        AeadAlgorithm::Aes256Gcm => Ok(Box::new(Aes256GcmImpl)),
        AeadAlgorithm::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Impl)),
        AeadAlgorithm::Aes128Ccm => Ok(Box::new(Aes128CcmImpl)),
        AeadAlgorithm::Aes128Ccm8 => Ok(Box::new(Aes128Ccm8Impl)),
    }
}

/// AES-128-GCM implementation.
#[derive(Debug)]
struct Aes128GcmImpl;

impl Aead for Aes128GcmImpl {
    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 16 {
            return Err(Error::InvalidKeySize {
                expected: 16,
                actual: key.len(),
            });
        }

        // Validate nonce size
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size arrays
        let key_array: [u8; 16] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();

        // Encrypt using hpcrypt
        let ciphertext_with_tag =
            hpcrypt_aead::Aes128Gcm::encrypt(&key_array, &nonce_array, plaintext, aad);

        Ok(ciphertext_with_tag)
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 16 {
            return Err(Error::InvalidKeySize {
                expected: 16,
                actual: key.len(),
            });
        }

        // Validate nonce size
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size arrays
        let key_array: [u8; 16] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();

        // Decrypt using hpcrypt
        hpcrypt_aead::Aes128Gcm::decrypt(&key_array, &nonce_array, ciphertext, aad)
            .map_err(|_| Error::AuthenticationFailed)
    }

    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::Aes128Gcm
    }
}

/// AES-256-GCM implementation.
#[derive(Debug)]
struct Aes256GcmImpl;

impl Aead for Aes256GcmImpl {
    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key.len(),
            });
        }

        // Validate nonce size
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size arrays
        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();

        // Encrypt using hpcrypt
        let ciphertext_with_tag =
            hpcrypt_aead::Aes256Gcm::encrypt(&key_array, &nonce_array, plaintext, aad);

        Ok(ciphertext_with_tag)
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key.len(),
            });
        }

        // Validate nonce size
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size arrays
        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();

        // Decrypt using hpcrypt
        hpcrypt_aead::Aes256Gcm::decrypt(&key_array, &nonce_array, ciphertext, aad)
            .map_err(|_| Error::AuthenticationFailed)
    }

    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::Aes256Gcm
    }
}

/// ChaCha20-Poly1305 implementation.
#[derive(Debug)]
struct ChaCha20Poly1305Impl;

impl Aead for ChaCha20Poly1305Impl {
    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key.len(),
            });
        }

        // Validate nonce size
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size arrays
        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();

        // Encrypt using hpcrypt
        let ciphertext_with_tag =
            hpcrypt_aead::ChaCha20Poly1305::encrypt(&key_array, &nonce_array, plaintext, aad);

        Ok(ciphertext_with_tag)
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key.len(),
            });
        }

        // Validate nonce size
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size arrays
        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();

        // Decrypt using hpcrypt
        hpcrypt_aead::ChaCha20Poly1305::decrypt(&key_array, &nonce_array, ciphertext, aad)
            .ok_or(Error::AuthenticationFailed)
    }

    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::ChaCha20Poly1305
    }
}

/// AES-128-CCM implementation (16-byte tag).
#[derive(Debug)]
struct Aes128CcmImpl;

impl Aead for Aes128CcmImpl {
    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 16 {
            return Err(Error::InvalidKeySize {
                expected: 16,
                actual: key.len(),
            });
        }

        // Validate nonce size (TLS 1.3 uses 12-byte nonces)
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size array
        let key_array: [u8; 16] = key.try_into().unwrap();

        // Encrypt using hpcrypt with 16-byte tag
        let ciphertext_with_tag = hpcrypt_aead::Aes128Ccm::encrypt(&key_array, nonce, plaintext, aad, 16)
            .map_err(|e| Error::CryptoError(format!("AES-128-CCM encryption failed: {:?}", e)))?;

        Ok(ciphertext_with_tag)
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 16 {
            return Err(Error::InvalidKeySize {
                expected: 16,
                actual: key.len(),
            });
        }

        // Validate nonce size
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size array
        let key_array: [u8; 16] = key.try_into().unwrap();

        // Decrypt using hpcrypt with 16-byte tag
        hpcrypt_aead::Aes128Ccm::decrypt(&key_array, nonce, ciphertext, aad, 16)
            .map_err(|_| Error::AuthenticationFailed)
    }

    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::Aes128Ccm
    }
}

/// AES-128-CCM implementation with 8-byte tag (truncated).
#[derive(Debug)]
struct Aes128Ccm8Impl;

impl Aead for Aes128Ccm8Impl {
    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 16 {
            return Err(Error::InvalidKeySize {
                expected: 16,
                actual: key.len(),
            });
        }

        // Validate nonce size
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size array
        let key_array: [u8; 16] = key.try_into().unwrap();

        // Encrypt using hpcrypt with 8-byte tag
        let ciphertext_with_tag = hpcrypt_aead::Aes128Ccm::encrypt(&key_array, nonce, plaintext, aad, 8)
            .map_err(|e| Error::CryptoError(format!("AES-128-CCM-8 encryption failed: {:?}", e)))?;

        Ok(ciphertext_with_tag)
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if key.len() != 16 {
            return Err(Error::InvalidKeySize {
                expected: 16,
                actual: key.len(),
            });
        }

        // Validate nonce size
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceSize {
                expected: 12,
                actual: nonce.len(),
            });
        }

        // Convert to fixed-size array
        let key_array: [u8; 16] = key.try_into().unwrap();

        // Decrypt using hpcrypt with 8-byte tag
        hpcrypt_aead::Aes128Ccm::decrypt(&key_array, nonce, ciphertext, aad, 8)
            .map_err(|_| Error::AuthenticationFailed)
    }

    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::Aes128Ccm8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128gcm_basic() {
        let aead = create_aead(AeadAlgorithm::Aes128Gcm).unwrap();

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"secret message";

        let ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for tag

        let decrypted = aead.open(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256gcm_basic() {
        let aead = create_aead(AeadAlgorithm::Aes256Gcm).unwrap();

        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"secret message";

        let ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for tag

        let decrypted = aead.open(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_basic() {
        let aead = create_aead(AeadAlgorithm::ChaCha20Poly1305).unwrap();

        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"secret message";

        let ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for tag

        let decrypted = aead.open(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_authentication_failure() {
        let aead = create_aead(AeadAlgorithm::Aes128Gcm).unwrap();

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"secret message";

        let mut ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();

        // Corrupt the tag
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 1;

        let result = aead.open(&key, &nonce, aad, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_size() {
        let aead = create_aead(AeadAlgorithm::Aes128Gcm).unwrap();

        let key = [0u8; 32]; // Wrong size
        let nonce = [0u8; 12];
        let plaintext = b"test";

        let result = aead.seal(&key, &nonce, &[], plaintext);
        assert!(matches!(result, Err(Error::InvalidKeySize { .. })));
    }

    #[test]
    fn test_invalid_nonce_size() {
        let aead = create_aead(AeadAlgorithm::Aes128Gcm).unwrap();

        let key = [0u8; 16];
        let nonce = [0u8; 16]; // Wrong size
        let plaintext = b"test";

        let result = aead.seal(&key, &nonce, &[], plaintext);
        assert!(matches!(result, Err(Error::InvalidNonceSize { .. })));
    }

    #[test]
    fn test_aes128ccm_basic() {
        let aead = create_aead(AeadAlgorithm::Aes128Ccm).unwrap();

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"secret message for CCM";

        let ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for tag

        let decrypted = aead.open(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128ccm8_basic() {
        let aead = create_aead(AeadAlgorithm::Aes128Ccm8).unwrap();

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"secret message for CCM-8";

        let ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 8); // +8 for tag

        let decrypted = aead.open(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ccm_authentication_failure() {
        let aead = create_aead(AeadAlgorithm::Aes128Ccm).unwrap();

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"secret message";

        let mut ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();

        // Corrupt the tag
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 1;

        let result = aead.open(&key, &nonce, aad, &ciphertext);
        assert!(result.is_err());
    }
}
