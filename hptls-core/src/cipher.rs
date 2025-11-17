//! Cipher suite definitions and operations.

use hptls_crypto::{AeadAlgorithm, HashAlgorithm};

/// Cipher suite for TLS 1.2 and TLS 1.3.
///
/// TLS 1.3 simplified cipher suites to only specify the AEAD and hash algorithm.
/// Key exchange and signature algorithms are negotiated separately via extensions.
///
/// TLS 1.2 cipher suites specify the complete cryptographic suite including
/// key exchange and authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CipherSuite {
    // TLS 1.3 cipher suites (0x13xx)
    /// TLS_AES_128_GCM_SHA256 (mandatory to implement)
    Aes128GcmSha256 = 0x1301,

    /// TLS_AES_256_GCM_SHA384
    Aes256GcmSha384 = 0x1302,

    /// TLS_CHACHA20_POLY1305_SHA256
    ChaCha20Poly1305Sha256 = 0x1303,

    /// TLS_AES_128_CCM_SHA256
    Aes128CcmSha256 = 0x1304,

    /// TLS_AES_128_CCM_8_SHA256
    Aes128Ccm8Sha256 = 0x1305,

    // TLS 1.2 cipher suites (0xC0xx, 0xCCxx)
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    Tls12EcdheRsaWithAes128GcmSha256 = 0xC02F,

    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    Tls12EcdheRsaWithAes256GcmSha384 = 0xC030,

    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    Tls12EcdheRsaWithChacha20Poly1305Sha256 = 0xCCA8,

    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    Tls12EcdheEcdsaWithAes128GcmSha256 = 0xC02B,

    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    Tls12EcdheEcdsaWithAes256GcmSha384 = 0xC02C,

    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    Tls12EcdheEcdsaWithChacha20Poly1305Sha256 = 0xCCA9,
}

impl CipherSuite {
    /// Create from wire format (u16).
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            // TLS 1.3 cipher suites
            0x1301 => Some(CipherSuite::Aes128GcmSha256),
            0x1302 => Some(CipherSuite::Aes256GcmSha384),
            0x1303 => Some(CipherSuite::ChaCha20Poly1305Sha256),
            0x1304 => Some(CipherSuite::Aes128CcmSha256),
            0x1305 => Some(CipherSuite::Aes128Ccm8Sha256),
            // TLS 1.2 cipher suites
            0xC02F => Some(CipherSuite::Tls12EcdheRsaWithAes128GcmSha256),
            0xC030 => Some(CipherSuite::Tls12EcdheRsaWithAes256GcmSha384),
            0xCCA8 => Some(CipherSuite::Tls12EcdheRsaWithChacha20Poly1305Sha256),
            0xC02B => Some(CipherSuite::Tls12EcdheEcdsaWithAes128GcmSha256),
            0xC02C => Some(CipherSuite::Tls12EcdheEcdsaWithAes256GcmSha384),
            0xCCA9 => Some(CipherSuite::Tls12EcdheEcdsaWithChacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Convert to wire format (u16).
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Get the AEAD algorithm for this cipher suite.
    pub const fn aead_algorithm(self) -> AeadAlgorithm {
        match self {
            CipherSuite::Aes128GcmSha256 => AeadAlgorithm::Aes128Gcm,
            CipherSuite::Aes256GcmSha384 => AeadAlgorithm::Aes256Gcm,
            CipherSuite::ChaCha20Poly1305Sha256 => AeadAlgorithm::ChaCha20Poly1305,
            CipherSuite::Aes128CcmSha256 => AeadAlgorithm::Aes128Ccm,
            CipherSuite::Aes128Ccm8Sha256 => AeadAlgorithm::Aes128Ccm8,
            CipherSuite::Tls12EcdheRsaWithAes128GcmSha256
            | CipherSuite::Tls12EcdheEcdsaWithAes128GcmSha256 => AeadAlgorithm::Aes128Gcm,
            CipherSuite::Tls12EcdheRsaWithAes256GcmSha384
            | CipherSuite::Tls12EcdheEcdsaWithAes256GcmSha384 => AeadAlgorithm::Aes256Gcm,
            CipherSuite::Tls12EcdheRsaWithChacha20Poly1305Sha256
            | CipherSuite::Tls12EcdheEcdsaWithChacha20Poly1305Sha256 => {
                AeadAlgorithm::ChaCha20Poly1305
            }
        }
    }

    /// Get the hash algorithm for this cipher suite.
    pub const fn hash_algorithm(self) -> HashAlgorithm {
        match self {
            CipherSuite::Aes128GcmSha256
            | CipherSuite::ChaCha20Poly1305Sha256
            | CipherSuite::Aes128CcmSha256
            | CipherSuite::Aes128Ccm8Sha256 => HashAlgorithm::Sha256,
            CipherSuite::Aes256GcmSha384 => HashAlgorithm::Sha384,
            CipherSuite::Tls12EcdheRsaWithAes128GcmSha256
            | CipherSuite::Tls12EcdheEcdsaWithAes128GcmSha256
            | CipherSuite::Tls12EcdheRsaWithChacha20Poly1305Sha256
            | CipherSuite::Tls12EcdheEcdsaWithChacha20Poly1305Sha256 => HashAlgorithm::Sha256,
            CipherSuite::Tls12EcdheRsaWithAes256GcmSha384
            | CipherSuite::Tls12EcdheEcdsaWithAes256GcmSha384 => HashAlgorithm::Sha384,
        }
    }

    /// Get the key length for this cipher suite.
    pub const fn key_length(self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256
            | CipherSuite::Aes128CcmSha256
            | CipherSuite::Aes128Ccm8Sha256 => 16,
            CipherSuite::Aes256GcmSha384 => 32,
            CipherSuite::ChaCha20Poly1305Sha256 => 32,
            CipherSuite::Tls12EcdheRsaWithAes128GcmSha256
            | CipherSuite::Tls12EcdheEcdsaWithAes128GcmSha256 => 16,
            CipherSuite::Tls12EcdheRsaWithAes256GcmSha384
            | CipherSuite::Tls12EcdheEcdsaWithAes256GcmSha384 => 32,
            CipherSuite::Tls12EcdheRsaWithChacha20Poly1305Sha256
            | CipherSuite::Tls12EcdheEcdsaWithChacha20Poly1305Sha256 => 32,
        }
    }

    /// Get the IV length for this cipher suite.
    pub const fn iv_length(self) -> usize {
        12 // All TLS 1.3 AEAD ciphers use 12-byte nonces
    }

    /// Get the cipher suite name.
    pub const fn name(self) -> &'static str {
        match self {
            CipherSuite::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            CipherSuite::ChaCha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
            CipherSuite::Aes128CcmSha256 => "TLS_AES_128_CCM_SHA256",
            CipherSuite::Aes128Ccm8Sha256 => "TLS_AES_128_CCM_8_SHA256",
            CipherSuite::Tls12EcdheRsaWithAes128GcmSha256 => {
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            }
            CipherSuite::Tls12EcdheRsaWithAes256GcmSha384 => {
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            }
            CipherSuite::Tls12EcdheRsaWithChacha20Poly1305Sha256 => {
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            CipherSuite::Tls12EcdheEcdsaWithAes128GcmSha256 => {
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            }
            CipherSuite::Tls12EcdheEcdsaWithAes256GcmSha384 => {
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            }
            CipherSuite::Tls12EcdheEcdsaWithChacha20Poly1305Sha256 => {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            }
        }
    }
}

/// Default cipher suite preference order for TLS 1.3.
pub const DEFAULT_CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::Aes128GcmSha256,
    CipherSuite::ChaCha20Poly1305Sha256,
    CipherSuite::Aes256GcmSha384,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_conversion() {
        assert_eq!(
            CipherSuite::from_u16(0x1301),
            Some(CipherSuite::Aes128GcmSha256)
        );
        assert_eq!(CipherSuite::Aes128GcmSha256.to_u16(), 0x1301);
    }

    #[test]
    fn test_cipher_suite_properties() {
        let suite = CipherSuite::Aes128GcmSha256;
        assert_eq!(suite.aead_algorithm(), AeadAlgorithm::Aes128Gcm);
        assert_eq!(suite.hash_algorithm(), HashAlgorithm::Sha256);
        assert_eq!(suite.key_length(), 16);
        assert_eq!(suite.iv_length(), 12);
        assert_eq!(suite.name(), "TLS_AES_128_GCM_SHA256");
    }
}
