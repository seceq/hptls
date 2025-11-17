//! HMAC implementations using hpcrypt-mac.

use hptls_crypto::{HashAlgorithm, Hmac, Result};
use hpcrypt_mac::{HmacSha256, HmacSha384, HmacSha512};

/// Create an HMAC instance for the specified hash algorithm.
pub fn create_hmac(algorithm: HashAlgorithm, key: &[u8]) -> Result<Box<dyn Hmac>> {
    match algorithm {
        HashAlgorithm::Sha256 => Ok(Box::new(HmacSha256Impl::new(key))),
        HashAlgorithm::Sha384 => Ok(Box::new(HmacSha384Impl::new(key))),
        HashAlgorithm::Sha512 => Ok(Box::new(HmacSha512Impl::new(key))),
    }
}

/// HMAC-SHA256 implementation with incremental updates.
///
/// Provides keyed-hash message authentication using SHA-256.
/// - Key size: Any length (recommended: 32 bytes)
/// - Output size: 32 bytes (256 bits)
/// - Hash function: SHA-256
///
/// # Security
///
/// HMAC-SHA256 is a FIPS 198-1 approved MAC widely used in TLS 1.2 and TLS 1.3
/// for record authentication and key derivation. Unlike plain hash functions,
/// HMAC is resistant to length extension attacks.
///
/// # Standards
///
/// - FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)
/// - RFC 2104: HMAC: Keyed-Hashing for Message Authentication
/// - RFC 5246: TLS 1.2 (uses HMAC-SHA256 for PRF and record authentication)
/// - RFC 8446: TLS 1.3 (uses HMAC-SHA256 in HKDF)
struct HmacSha256Impl {
    hmac: HmacSha256,
    buffer: Vec<u8>,
}

impl HmacSha256Impl {
    fn new(key: &[u8]) -> Self {
        Self {
            hmac: HmacSha256::new(key),
            buffer: Vec::new(),
        }
    }
}

impl Hmac for HmacSha256Impl {
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.hmac.compute(&self.buffer).to_vec()
    }

    fn output_size(&self) -> usize {
        32
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
}

/// HMAC-SHA384 implementation with incremental updates.
///
/// Provides keyed-hash message authentication using SHA-384.
/// - Key size: Any length (recommended: 48 bytes)
/// - Output size: 48 bytes (384 bits)
/// - Hash function: SHA-384
///
/// # Security
///
/// HMAC-SHA384 is a FIPS 198-1 approved message authentication code. It provides
/// stronger security than HMAC-SHA256 and is used in TLS cipher suites that require
/// higher security levels. Commonly paired with AES-256 and ECDHE-384.
///
/// # Standards
///
/// - FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)
/// - RFC 2104: HMAC: Keyed-Hashing for Message Authentication
/// - RFC 5246: TLS 1.2 (uses HMAC-SHA384 for certain cipher suites)
/// - RFC 8446: TLS 1.3 (uses HMAC-SHA384 in HKDF-SHA384)
struct HmacSha384Impl {
    hmac: HmacSha384,
    buffer: Vec<u8>,
}

impl HmacSha384Impl {
    fn new(key: &[u8]) -> Self {
        Self {
            hmac: HmacSha384::new(key),
            buffer: Vec::new(),
        }
    }
}

impl Hmac for HmacSha384Impl {
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.hmac.compute(&self.buffer).to_vec()
    }

    fn output_size(&self) -> usize {
        48
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha384
    }
}

/// HMAC-SHA512 implementation with incremental updates.
///
/// Provides keyed-hash message authentication using SHA-512.
/// - Key size: Any length (recommended: 64 bytes)
/// - Output size: 64 bytes (512 bits)
/// - Hash function: SHA-512
///
/// # Security
///
/// HMAC-SHA512 is a FIPS 198-1 approved message authentication code. It provides
/// the highest security level among the SHA-2 family and is suitable for applications
/// requiring maximum cryptographic strength. Used in high-security TLS configurations.
///
/// # Standards
///
/// - FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)
/// - RFC 2104: HMAC: Keyed-Hashing for Message Authentication
/// - RFC 5246: TLS 1.2 (uses HMAC-SHA512 for certain cipher suites)
struct HmacSha512Impl {
    hmac: HmacSha512,
    buffer: Vec<u8>,
}

impl HmacSha512Impl {
    fn new(key: &[u8]) -> Self {
        Self {
            hmac: HmacSha512::new(key),
            buffer: Vec::new(),
        }
    }
}

impl Hmac for HmacSha512Impl {
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.hmac.compute(&self.buffer).to_vec()
    }

    fn output_size(&self) -> usize {
        64
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha512
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_basic() {
        let key = b"secret key";
        let mut hmac = create_hmac(HashAlgorithm::Sha256, key).unwrap();
        hmac.update(b"message");
        let tag = hmac.finalize();
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_incremental() {
        let key = b"secret key";

        let mut hmac1 = create_hmac(HashAlgorithm::Sha256, key).unwrap();
        hmac1.update(b"hello ");
        hmac1.update(b"world");
        let tag1 = hmac1.finalize();

        let mut hmac2 = create_hmac(HashAlgorithm::Sha256, key).unwrap();
        hmac2.update(b"hello world");
        let tag2 = hmac2.finalize();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_hmac_sha256_verify() {
        let key = b"secret key";
        let message = b"message";

        let mut hmac1 = create_hmac(HashAlgorithm::Sha256, key).unwrap();
        hmac1.update(message);
        let tag = hmac1.finalize();

        let mut hmac2 = create_hmac(HashAlgorithm::Sha256, key).unwrap();
        hmac2.update(message);
        assert!(hmac2.verify(&tag));
    }

    #[test]
    fn test_hmac_sha384_basic() {
        let key = b"secret key";
        let mut hmac = create_hmac(HashAlgorithm::Sha384, key).unwrap();
        hmac.update(b"message");
        let tag = hmac.finalize();
        assert_eq!(tag.len(), 48);
    }

    #[test]
    fn test_hmac_sha512_basic() {
        let key = b"secret key";
        let mut hmac = create_hmac(HashAlgorithm::Sha512, key).unwrap();
        hmac.update(b"message");
        let tag = hmac.finalize();
        assert_eq!(tag.len(), 64);
    }

    #[test]
    fn test_hmac_different_keys() {
        let key1 = b"key1";
        let key2 = b"key2";
        let message = b"message";

        let mut hmac1 = create_hmac(HashAlgorithm::Sha256, key1).unwrap();
        hmac1.update(message);
        let tag1 = hmac1.finalize();

        let mut hmac2 = create_hmac(HashAlgorithm::Sha256, key2).unwrap();
        hmac2.update(message);
        let tag2 = hmac2.finalize();

        assert_ne!(tag1, tag2);
    }
}
