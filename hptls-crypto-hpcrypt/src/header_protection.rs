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

/// AES-128 header protection for QUIC packets.
///
/// Provides header protection using AES-128 in ECB mode for QUIC packet headers.
/// - Algorithm: AES-128-ECB
/// - Key size: 16 bytes (128 bits)
/// - Sample size: 16 bytes (128 bits)
/// - Mask size: 5 bytes (first 5 bytes of AES output)
///
/// # Algorithm
///
/// Header protection uses AES-ECB to generate a mask:
/// ```text
/// mask = AES-ECB(header_protection_key, sample)[0..5]
/// ```
/// The mask is XORed with packet number and first byte of header.
///
/// # Security
///
/// Header protection is not encryption - it only obfuscates packet metadata:
/// - Protects packet number from passive observers
/// - Prevents correlation of packets in a connection
/// - Does NOT provide confidentiality (packets are separately encrypted)
/// - Uses ECB mode safely (each sample is unique and random)
///
/// # Usage Context
///
/// Used exclusively in QUIC protocol (not TLS):
/// - Required by RFC 9001 for QUIC-TLS integration
/// - Applied after packet payload encryption
/// - Protects both long and short header packets
///
/// # Standards
///
/// - RFC 9001: Using TLS to Secure QUIC (Section 5.4: Header Protection)
/// - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
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

/// AES-256 header protection for QUIC packets.
///
/// Provides header protection using AES-256 in ECB mode for QUIC packet headers.
/// - Algorithm: AES-256-ECB
/// - Key size: 32 bytes (256 bits)
/// - Sample size: 16 bytes (128 bits)
/// - Mask size: 5 bytes (first 5 bytes of AES output)
///
/// # Algorithm
///
/// Header protection uses AES-ECB to generate a mask:
/// ```text
/// mask = AES-ECB(header_protection_key, sample)[0..5]
/// ```
/// The mask is XORed with packet number and first byte of header.
///
/// # Security
///
/// Header protection is not encryption - it only obfuscates packet metadata:
/// - Protects packet number from passive observers
/// - Prevents correlation of packets in a connection
/// - Does NOT provide confidentiality (packets are separately encrypted)
/// - Uses ECB mode safely (each sample is unique and random)
/// - Provides stronger key security than AES-128 variant
///
/// # Usage Context
///
/// Used exclusively in QUIC protocol with AES-256-GCM cipher suites:
/// - Required by RFC 9001 for QUIC-TLS integration
/// - Applied after packet payload encryption
/// - Commonly paired with AES-256-GCM for payload encryption
///
/// # Standards
///
/// - RFC 9001: Using TLS to Secure QUIC (Section 5.4: Header Protection)
/// - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
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

/// ChaCha20 header protection for QUIC packets.
///
/// Provides header protection using ChaCha20 stream cipher for QUIC packet headers.
/// - Algorithm: ChaCha20
/// - Key size: 32 bytes (256 bits)
/// - Sample size: 16 bytes (used as counter || nonce)
/// - Mask size: 5 bytes (first 5 bytes of ChaCha20 output)
///
/// # Algorithm
///
/// Header protection uses ChaCha20 to generate a mask:
/// ```text
/// counter = sample[0..4] (little-endian)
/// nonce = sample[4..16]
/// mask = ChaCha20(key, counter, nonce)[0..5]
/// ```
/// The mask is XORed with packet number and first byte of header.
///
/// # Security
///
/// Header protection is not encryption - it only obfuscates packet metadata:
/// - Protects packet number from passive observers
/// - Prevents correlation of packets in a connection
/// - Does NOT provide confidentiality (packets are separately encrypted)
/// - ChaCha20 provides constant-time operation (resistant to timing attacks)
/// - Performs well on platforms without AES hardware acceleration
///
/// # Usage Context
///
/// Used exclusively in QUIC protocol with ChaCha20-Poly1305 cipher suites:
/// - Required by RFC 9001 for QUIC-TLS integration
/// - Applied after packet payload encryption
/// - Commonly paired with ChaCha20-Poly1305 for payload encryption
/// - Preferred on mobile devices and embedded systems
///
/// # Standards
///
/// - RFC 9001: Using TLS to Secure QUIC (Section 5.4: Header Protection)
/// - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
/// - RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
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
