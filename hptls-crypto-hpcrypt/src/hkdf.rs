//! HKDF implementations using hpcrypt-kdf.

use hptls_crypto::{Error, Kdf, KdfAlgorithm, Result};

/// Create a KDF instance for the specified algorithm.
pub fn create_kdf(algorithm: KdfAlgorithm) -> Result<Box<dyn Kdf>> {
    match algorithm {
        KdfAlgorithm::HkdfSha256 => Ok(Box::new(HkdfSha256Impl)),
        KdfAlgorithm::HkdfSha384 => Ok(Box::new(HkdfSha384Impl)),
        KdfAlgorithm::HkdfSha512 => Ok(Box::new(HkdfSha512Impl)),
        KdfAlgorithm::TlsPrfSha256 => Ok(Box::new(TlsPrfSha256Impl)),
        KdfAlgorithm::TlsPrfSha384 => Ok(Box::new(TlsPrfSha384Impl)),
    }
}

/// HKDF-SHA256 key derivation function implementation.
///
/// HMAC-based Key Derivation Function using SHA-256 as the underlying hash.
/// - Hash function: SHA-256
/// - PRK size: 32 bytes (256 bits)
/// - Max output length: 8160 bytes (255 * 32)
///
/// # Algorithm
///
/// HKDF is a two-step key derivation function:
/// 1. Extract: HKDF-Extract(salt, IKM) -> PRK (pseudorandom key)
/// 2. Expand: HKDF-Expand(PRK, info, L) -> OKM (output keying material)
///
/// # Security
///
/// HKDF-SHA256 is cryptographically strong and suitable for deriving multiple keys
/// from a single shared secret. It is mandatory for TLS 1.3 (RFC 8446) and provides
/// forward secrecy when used with ephemeral key exchange.
///
/// # Standards
///
/// - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
/// - RFC 8446: TLS 1.3 (mandatory KDF for all cipher suites)
/// - NIST SP 800-56C: Recommendation for Key-Derivation Methods
#[derive(Debug, Clone, Copy)]
struct HkdfSha256Impl;

impl Kdf for HkdfSha256Impl {
    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        // Use hpcrypt-kdf's new extract() method that returns fixed-size array
        hpcrypt_kdf::HkdfSha256::extract(salt, ikm).to_vec()
    }

    fn expand(&self, prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        // Use hpcrypt-kdf's from_prk() and expand() methods
        let hkdf = hpcrypt_kdf::HkdfSha256::from_prk(prk);
        let mut output = vec![0u8; length];
        hkdf.expand(info, &mut output)
            .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(output)
    }

    fn algorithm(&self) -> KdfAlgorithm {
        KdfAlgorithm::HkdfSha256
    }
}

/// HKDF-SHA384 key derivation function implementation.
///
/// HMAC-based Key Derivation Function using SHA-384 as the underlying hash.
/// - Hash function: SHA-384
/// - PRK size: 48 bytes (384 bits)
/// - Max output length: 12240 bytes (255 * 48)
///
/// # Algorithm
///
/// HKDF is a two-step key derivation function:
/// 1. Extract: HKDF-Extract(salt, IKM) -> PRK (pseudorandom key)
/// 2. Expand: HKDF-Expand(PRK, info, L) -> OKM (output keying material)
///
/// # Security
///
/// HKDF-SHA384 provides stronger security than HKDF-SHA256 and is recommended
/// for high-security applications. Used in TLS 1.3 cipher suites with AES-256-GCM
/// and stronger curve groups (P-384, P-521).
///
/// # Standards
///
/// - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
/// - RFC 8446: TLS 1.3 (used with SHA-384 cipher suites)
/// - NIST SP 800-56C: Recommendation for Key-Derivation Methods
#[derive(Debug, Clone, Copy)]
struct HkdfSha384Impl;

impl Kdf for HkdfSha384Impl {
    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        // Use hpcrypt-kdf's new extract() method that returns fixed-size array
        hpcrypt_kdf::HkdfSha384::extract(salt, ikm).to_vec()
    }

    fn expand(&self, prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        // Use hpcrypt-kdf's from_prk() and expand() methods
        let hkdf = hpcrypt_kdf::HkdfSha384::from_prk(prk);
        let mut output = vec![0u8; length];
        hkdf.expand(info, &mut output)
            .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(output)
    }

    fn algorithm(&self) -> KdfAlgorithm {
        KdfAlgorithm::HkdfSha384
    }
}

/// HKDF-SHA512 key derivation function implementation.
///
/// HMAC-based Key Derivation Function using SHA-512 as the underlying hash.
/// - Hash function: SHA-512
/// - PRK size: 64 bytes (512 bits)
/// - Max output length: 16320 bytes (255 * 64)
///
/// # Algorithm
///
/// HKDF is a two-step key derivation function:
/// 1. Extract: HKDF-Extract(salt, IKM) -> PRK (pseudorandom key)
/// 2. Expand: HKDF-Expand(PRK, info, L) -> OKM (output keying material)
///
/// # Security
///
/// HKDF-SHA512 provides the highest security level among SHA-2 family and is
/// suitable for applications requiring maximum cryptographic strength. Can be used
/// in custom protocols or high-security TLS extensions.
///
/// # Standards
///
/// - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
/// - NIST SP 800-56C: Recommendation for Key-Derivation Methods
#[derive(Debug, Clone, Copy)]
struct HkdfSha512Impl;

impl Kdf for HkdfSha512Impl {
    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        // Use hpcrypt-kdf's new extract() method that returns fixed-size array
        hpcrypt_kdf::HkdfSha512::extract(salt, ikm).to_vec()
    }

    fn expand(&self, prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        // Use hpcrypt-kdf's from_prk() and expand() methods
        let hkdf = hpcrypt_kdf::HkdfSha512::from_prk(prk);
        let mut output = vec![0u8; length];
        hkdf.expand(info, &mut output)
            .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(output)
    }

    fn algorithm(&self) -> KdfAlgorithm {
        KdfAlgorithm::HkdfSha512
    }
}

/// TLS 1.2 Pseudorandom Function (PRF) with SHA-256.
///
/// Legacy key derivation function used exclusively in TLS 1.2.
/// - Hash function: SHA-256
/// - Algorithm: P_SHA256 (HMAC-based expansion)
/// - Output: Variable length (up to practical limits)
///
/// # Algorithm
///
/// The TLS 1.2 PRF uses P_hash defined as:
/// ```text
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                        HMAC_hash(secret, A(2) + seed) + ...
/// where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
/// ```
///
/// # Security
///
/// The TLS 1.2 PRF is specific to TLS 1.2 and has been superseded by HKDF in TLS 1.3.
/// It is still widely used for backward compatibility with TLS 1.2 connections.
/// Note: TLS 1.3 uses HKDF instead for improved security properties.
///
/// # Standards
///
/// - RFC 5246: TLS 1.2 (Section 5: HMAC and the Pseudorandom Function)
/// - RFC 2246: TLS 1.0 (original PRF definition)
#[derive(Debug, Clone, Copy)]
struct TlsPrfSha256Impl;

impl Kdf for TlsPrfSha256Impl {
    fn extract(&self, _salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        // TLS 1.2 PRF doesn't use extract/expand pattern
        // Return IKM as-is for compatibility
        ikm.to_vec()
    }

    fn expand(&self, secret: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        // info is expected to be label + seed for TLS 1.2
        let mut output = vec![0u8; length];
        hpcrypt_kdf::tls12::prf_sha256(secret, "", info, &mut output);
        Ok(output)
    }

    fn algorithm(&self) -> KdfAlgorithm {
        KdfAlgorithm::TlsPrfSha256
    }
}

/// TLS 1.2 Pseudorandom Function (PRF) with SHA-384.
///
/// Legacy key derivation function used exclusively in TLS 1.2 with SHA-384 cipher suites.
/// - Hash function: SHA-384
/// - Algorithm: P_SHA384 (HMAC-based expansion)
/// - Output: Variable length (up to practical limits)
///
/// # Algorithm
///
/// The TLS 1.2 PRF uses P_hash defined as:
/// ```text
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                        HMAC_hash(secret, A(2) + seed) + ...
/// where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
/// ```
///
/// # Security
///
/// The TLS 1.2 PRF with SHA-384 provides stronger security than the SHA-256 variant
/// and is used with high-security TLS 1.2 cipher suites. TLS 1.3 supersedes this
/// with HKDF-SHA384 for improved security properties.
///
/// # Standards
///
/// - RFC 5246: TLS 1.2 (Section 5: HMAC and the Pseudorandom Function)
/// - Used with TLS 1.2 cipher suites that specify SHA-384
#[derive(Debug, Clone, Copy)]
struct TlsPrfSha384Impl;

impl Kdf for TlsPrfSha384Impl {
    fn extract(&self, _salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        // TLS 1.2 PRF doesn't use extract/expand pattern
        // Return IKM as-is for compatibility
        ikm.to_vec()
    }

    fn expand(&self, secret: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        // info is expected to be label + seed for TLS 1.2
        let mut output = vec![0u8; length];
        hpcrypt_kdf::tls12::prf_sha384(secret, "", info, &mut output);
        Ok(output)
    }

    fn algorithm(&self) -> KdfAlgorithm {
        KdfAlgorithm::TlsPrfSha384
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_extract() {
        let kdf = create_kdf(KdfAlgorithm::HkdfSha256).unwrap();
        let salt = b"salt";
        let ikm = b"input key material";

        let prk = kdf.extract(salt, ikm);
        assert_eq!(prk.len(), 32);
    }

    #[test]
    fn test_hkdf_sha256_expand() {
        let kdf = create_kdf(KdfAlgorithm::HkdfSha256).unwrap();
        let prk = vec![0u8; 32];
        let info = b"application info";

        let okm = kdf.expand(&prk, info, 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_hkdf_sha256_derive() {
        let kdf = create_kdf(KdfAlgorithm::HkdfSha256).unwrap();
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";

        let okm = kdf.derive(salt, ikm, info, 48).unwrap();
        assert_eq!(okm.len(), 48);
    }

    #[test]
    fn test_hkdf_sha384_basic() {
        let kdf = create_kdf(KdfAlgorithm::HkdfSha384).unwrap();
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";

        let okm = kdf.derive(salt, ikm, info, 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_hkdf_sha512_basic() {
        let kdf = create_kdf(KdfAlgorithm::HkdfSha512).unwrap();
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";

        let okm = kdf.derive(salt, ikm, info, 80).unwrap();
        assert_eq!(okm.len(), 80);
    }

    #[test]
    fn test_hkdf_empty_salt() {
        let kdf = create_kdf(KdfAlgorithm::HkdfSha256).unwrap();
        let ikm = b"input key material";

        let prk = kdf.extract(&[], ikm);
        assert_eq!(prk.len(), 32);
    }

    #[test]
    fn test_hkdf_expand_multiple_blocks() {
        let kdf = create_kdf(KdfAlgorithm::HkdfSha256).unwrap();
        let prk = vec![1u8; 32];
        let info = b"test";

        // Request more than one block (32 bytes)
        let okm = kdf.expand(&prk, info, 100).unwrap();
        assert_eq!(okm.len(), 100);
    }

    #[test]
    fn test_hkdf_expand_too_long() {
        let kdf = create_kdf(KdfAlgorithm::HkdfSha256).unwrap();
        let prk = vec![0u8; 32];

        // Request > 255 * 32 bytes
        let result = kdf.expand(&prk, b"", 8200);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_deterministic() {
        let kdf = create_kdf(KdfAlgorithm::HkdfSha256).unwrap();
        let salt = b"salt";
        let ikm = b"ikm";
        let info = b"info";

        let okm1 = kdf.derive(salt, ikm, info, 32).unwrap();
        let okm2 = kdf.derive(salt, ikm, info, 32).unwrap();

        assert_eq!(okm1, okm2);
    }
}
