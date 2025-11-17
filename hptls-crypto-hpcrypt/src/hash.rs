//! Hash function implementations using hpcrypt-hash.

use hptls_crypto::{Hash, HashAlgorithm, Result};

/// Create a hash instance for the specified algorithm.
pub fn create_hash(algorithm: HashAlgorithm) -> Result<Box<dyn Hash>> {
    match algorithm {
        HashAlgorithm::Sha256 => Ok(Box::new(Sha256Hash::new())),
        HashAlgorithm::Sha384 => Ok(Box::new(Sha384Hash::new())),
        HashAlgorithm::Sha512 => Ok(Box::new(Sha512Hash::new())),
    }
}

/// SHA-256 cryptographic hash function implementation using hpcrypt.
///
/// Provides the SHA-256 hash algorithm as defined in FIPS 180-4.
/// - Output size: 32 bytes (256 bits)
/// - Block size: 64 bytes
///
/// # Security
///
/// SHA-256 is part of the SHA-2 family and is widely used in TLS for HMAC, HKDF,
/// and transcript hashing. Uses hardware acceleration (SHA extensions) when available.
struct Sha256Hash {
    hasher: hpcrypt_hash::Sha256,
}

impl Sha256Hash {
    fn new() -> Self {
        Self {
            hasher: hpcrypt_hash::Sha256::new(),
        }
    }
}

impl Hash for Sha256Hash {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.hasher.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        32
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
}

/// SHA-384 cryptographic hash function implementation using hpcrypt.
///
/// Provides the SHA-384 hash algorithm as defined in FIPS 180-4.
/// - Output size: 48 bytes (384 bits)
/// - Block size: 128 bytes
///
/// # Security
///
/// SHA-384 is a truncated version of SHA-512, providing higher security margins
/// than SHA-256. Used in TLS cipher suites requiring stronger hash functions.
struct Sha384Hash {
    hasher: hpcrypt_hash::Sha384,
}

impl Sha384Hash {
    fn new() -> Self {
        Self {
            hasher: hpcrypt_hash::Sha384::new(),
        }
    }
}

impl Hash for Sha384Hash {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.hasher.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        48
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha384
    }
}

/// SHA-512 cryptographic hash function implementation using hpcrypt.
///
/// Provides the SHA-512 hash algorithm as defined in FIPS 180-4.
/// - Output size: 64 bytes (512 bits)
/// - Block size: 128 bytes
///
/// # Security
///
/// SHA-512 provides the highest security level of the SHA-2 family. While not
/// commonly used in standard TLS cipher suites, it may be used in custom configurations
/// or for signature algorithms.
struct Sha512Hash {
    hasher: hpcrypt_hash::Sha512,
}

impl Sha512Hash {
    fn new() -> Self {
        Self {
            hasher: hpcrypt_hash::Sha512::new(),
        }
    }
}

impl Hash for Sha512Hash {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.hasher.finalize().to_vec()
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
    fn test_sha256_basic() {
        let mut hash = create_hash(HashAlgorithm::Sha256).unwrap();
        hash.update(b"hello world");
        let digest = hash.finalize();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_sha256_incremental() {
        let mut hash1 = create_hash(HashAlgorithm::Sha256).unwrap();
        hash1.update(b"hello ");
        hash1.update(b"world");
        let digest1 = hash1.finalize();

        let mut hash2 = create_hash(HashAlgorithm::Sha256).unwrap();
        hash2.update(b"hello world");
        let digest2 = hash2.finalize();

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_sha384_basic() {
        let mut hash = create_hash(HashAlgorithm::Sha384).unwrap();
        hash.update(b"hello world");
        let digest = hash.finalize();
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn test_sha512_basic() {
        let mut hash = create_hash(HashAlgorithm::Sha512).unwrap();
        hash.update(b"hello world");
        let digest = hash.finalize();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_sha256_empty() {
        let mut hash = create_hash(HashAlgorithm::Sha256).unwrap();
        hash.update(b"");
        let digest = hash.finalize();

        // Known SHA-256 of empty string
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha256_known_vector() {
        let mut hash = create_hash(HashAlgorithm::Sha256).unwrap();
        hash.update(b"abc");
        let digest = hash.finalize();

        // Known SHA-256 of "abc"
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(digest, expected);
    }
}
