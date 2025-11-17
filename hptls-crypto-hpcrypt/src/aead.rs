//! AEAD cipher implementations using hpcrypt-aead.

use hptls_crypto::{Aead, AeadAlgorithm, Error, Result};

/// Create an AEAD cipher instance for the specified algorithm.
pub fn create_aead(algorithm: AeadAlgorithm) -> Result<Box<dyn Aead>> {
    match algorithm {
        AeadAlgorithm::Aes128Gcm => Ok(Box::new(Aes128GcmImpl)),
        AeadAlgorithm::Aes256Gcm => Ok(Box::new(Aes256GcmImpl)),
        AeadAlgorithm::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Impl)),
        AeadAlgorithm::Aes128Ccm | AeadAlgorithm::Aes128Ccm8 => Err(Error::UnsupportedAlgorithm(
            format!("AEAD algorithm {:?} not supported by hpcrypt", algorithm),
        )),
    }
}

/// AES-128-GCM AEAD cipher implementation using hpcrypt.
///
/// Provides authenticated encryption with associated data (AEAD) using AES-128-GCM.
/// - Key size: 16 bytes (128 bits)
/// - Nonce size: 12 bytes (96 bits)
/// - Authentication tag: 16 bytes (128 bits)
///
/// # Security
///
/// AES-128-GCM is a NIST-approved AEAD cipher and is mandatory for TLS 1.3 compliance (RFC 8446).
/// The implementation uses hardware acceleration (AES-NI) when available.
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

/// AES-256-GCM AEAD cipher implementation using hpcrypt.
///
/// Provides authenticated encryption with associated data (AEAD) using AES-256-GCM.
/// - Key size: 32 bytes (256 bits)
/// - Nonce size: 12 bytes (96 bits)
/// - Authentication tag: 16 bytes (128 bits)
///
/// # Security
///
/// AES-256-GCM provides stronger security than AES-128-GCM and is recommended for
/// high-security applications. Uses hardware acceleration (AES-NI) when available.
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

/// ChaCha20-Poly1305 AEAD cipher implementation using hpcrypt.
///
/// Provides authenticated encryption with associated data (AEAD) using ChaCha20-Poly1305.
/// - Key size: 32 bytes (256 bits)
/// - Nonce size: 12 bytes (96 bits)
/// - Authentication tag: 16 bytes (128 bits)
///
/// # Security
///
/// ChaCha20-Poly1305 is an alternative to AES-GCM, particularly useful on platforms
/// without AES hardware acceleration. It is mandatory for TLS 1.3 compliance (RFC 8446).
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
}
