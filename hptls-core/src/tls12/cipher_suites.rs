//! TLS 1.2 Cipher Suite Definitions
//!
//! TLS 1.2 cipher suites specify the complete cryptographic suite:
//! - Key exchange algorithm (ECDHE, RSA)
//! - Authentication/signature algorithm (RSA, ECDSA)
//! - Encryption algorithm (AES-GCM, ChaCha20-Poly1305)
//! - Hash/PRF algorithm (SHA256, SHA384)
//!
//! Format: TLS_{KeyExchange}_{Authentication}_WITH_{Encryption}_{Hash}
//!
//! ## Modern Cipher Suites Only
//!
//! This implementation only supports modern, secure cipher suites:
//! - ECDHE for forward secrecy
//! - AEAD ciphers only (no CBC)
//! - SHA256/SHA384 (no MD5/SHA1)

use crate::error::{Error, Result};
use hptls_crypto::{AeadAlgorithm, HashAlgorithm, KeyExchangeAlgorithm, SignatureAlgorithm};

/// TLS 1.2 Cipher Suite
///
/// Unlike TLS 1.3 which only specifies AEAD+Hash, TLS 1.2 cipher suites
/// specify the complete cryptographic suite including key exchange and authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Tls12CipherSuite {
    // ECDHE-RSA cipher suites
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F) - RFC 5289
    EcdheRsaWithAes128GcmSha256 = 0xC02F,

    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030) - RFC 5289
    EcdheRsaWithAes256GcmSha384 = 0xC030,

    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8) - RFC 7905
    EcdheRsaWithChacha20Poly1305Sha256 = 0xCCA8,

    // ECDHE-ECDSA cipher suites
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B) - RFC 5289
    EcdheEcdsaWithAes128GcmSha256 = 0xC02B,

    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C) - RFC 5289
    EcdheEcdsaWithAes256GcmSha384 = 0xC02C,

    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9) - RFC 7905
    EcdheEcdsaWithChacha20Poly1305Sha256 = 0xCCA9,
}

impl Tls12CipherSuite {
    /// Create from wire format (u16 big-endian).
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0xC02F => Some(Tls12CipherSuite::EcdheRsaWithAes128GcmSha256),
            0xC030 => Some(Tls12CipherSuite::EcdheRsaWithAes256GcmSha384),
            0xCCA8 => Some(Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256),
            0xC02B => Some(Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256),
            0xC02C => Some(Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384),
            0xCCA9 => Some(Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Convert to wire format (u16 big-endian).
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Get the key exchange algorithm for this cipher suite.
    pub const fn key_exchange(&self) -> KeyExchangeAlgorithm {
        // All supported cipher suites use ECDHE
        KeyExchangeAlgorithm::Secp256r1
    }

    /// Get the signature algorithm for this cipher suite.
    pub const fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            Tls12CipherSuite::EcdheRsaWithAes128GcmSha256
            | Tls12CipherSuite::EcdheRsaWithAes256GcmSha384 => SignatureAlgorithm::RsaPssRsaeSha256,
            Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256 => {
                SignatureAlgorithm::RsaPssRsaeSha256
            }
            Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256
            | Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256 => {
                SignatureAlgorithm::EcdsaSecp256r1Sha256
            }
            Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384 => {
                SignatureAlgorithm::EcdsaSecp384r1Sha384
            }
        }
    }

    /// Get the AEAD algorithm for this cipher suite.
    pub const fn aead_algorithm(&self) -> AeadAlgorithm {
        match self {
            Tls12CipherSuite::EcdheRsaWithAes128GcmSha256
            | Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256 => AeadAlgorithm::Aes128Gcm,
            Tls12CipherSuite::EcdheRsaWithAes256GcmSha384
            | Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384 => AeadAlgorithm::Aes256Gcm,
            Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256
            | Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256 => {
                AeadAlgorithm::ChaCha20Poly1305
            }
        }
    }

    /// Get the hash/PRF algorithm for this cipher suite.
    pub const fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Tls12CipherSuite::EcdheRsaWithAes128GcmSha256
            | Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256
            | Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256
            | Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256 => HashAlgorithm::Sha256,
            Tls12CipherSuite::EcdheRsaWithAes256GcmSha384
            | Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384 => HashAlgorithm::Sha384,
        }
    }

    /// Get cipher suite name as a string.
    pub const fn name(&self) -> &'static str {
        match self {
            Tls12CipherSuite::EcdheRsaWithAes128GcmSha256 => {
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            }
            Tls12CipherSuite::EcdheRsaWithAes256GcmSha384 => {
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            }
            Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256 => {
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256 => {
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            }
            Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384 => {
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            }
            Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256 => {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            }
        }
    }

    /// Check if this cipher suite uses RSA for authentication.
    pub const fn uses_rsa(&self) -> bool {
        matches!(
            self,
            Tls12CipherSuite::EcdheRsaWithAes128GcmSha256
                | Tls12CipherSuite::EcdheRsaWithAes256GcmSha384
                | Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256
        )
    }

    /// Check if this cipher suite uses ECDSA for authentication.
    pub const fn uses_ecdsa(&self) -> bool {
        matches!(
            self,
            Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256
                | Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384
                | Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256
        )
    }

    /// Get the key block length required for this cipher suite.
    ///
    /// For TLS 1.2 with AEAD ciphers:
    /// - client_write_key: key_length
    /// - server_write_key: key_length
    /// - client_write_IV: fixed_iv_length
    /// - server_write_IV: fixed_iv_length
    ///
    /// Total: 2 * (key_length + fixed_iv_length)
    pub const fn key_block_length(&self) -> usize {
        match self.aead_algorithm() {
            AeadAlgorithm::Aes128Gcm => {
                // AES-128: 16 byte key, 4 byte fixed IV
                2 * (16 + 4) // = 40 bytes
            }
            AeadAlgorithm::Aes256Gcm => {
                // AES-256: 32 byte key, 4 byte fixed IV
                2 * (32 + 4) // = 72 bytes
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                // ChaCha20: 32 byte key, 12 byte IV (but only 4 bytes in key_block for TLS 1.2)
                2 * (32 + 12) // = 88 bytes
            }
            AeadAlgorithm::Aes128Ccm | AeadAlgorithm::Aes128Ccm8 => {
                // CCM not supported in TLS 1.2 implementation
                // (not included in cipher suite list, but need to handle for exhaustiveness)
                2 * (16 + 4) // = 40 bytes
            }
        }
    }

    /// Convert to generic CipherSuite enum for use in messages.
    pub const fn to_cipher_suite(self) -> crate::cipher::CipherSuite {
        use crate::cipher::CipherSuite;
        match self {
            Tls12CipherSuite::EcdheRsaWithAes128GcmSha256 => {
                CipherSuite::Tls12EcdheRsaWithAes128GcmSha256
            }
            Tls12CipherSuite::EcdheRsaWithAes256GcmSha384 => {
                CipherSuite::Tls12EcdheRsaWithAes256GcmSha384
            }
            Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256 => {
                CipherSuite::Tls12EcdheRsaWithChacha20Poly1305Sha256
            }
            Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256 => {
                CipherSuite::Tls12EcdheEcdsaWithAes128GcmSha256
            }
            Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384 => {
                CipherSuite::Tls12EcdheEcdsaWithAes256GcmSha384
            }
            Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256 => {
                CipherSuite::Tls12EcdheEcdsaWithChacha20Poly1305Sha256
            }
        }
    }

    /// Convert from generic CipherSuite enum.
    pub const fn from_cipher_suite(cs: crate::cipher::CipherSuite) -> Option<Self> {
        use crate::cipher::CipherSuite;
        match cs {
            CipherSuite::Tls12EcdheRsaWithAes128GcmSha256 => {
                Some(Tls12CipherSuite::EcdheRsaWithAes128GcmSha256)
            }
            CipherSuite::Tls12EcdheRsaWithAes256GcmSha384 => {
                Some(Tls12CipherSuite::EcdheRsaWithAes256GcmSha384)
            }
            CipherSuite::Tls12EcdheRsaWithChacha20Poly1305Sha256 => {
                Some(Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256)
            }
            CipherSuite::Tls12EcdheEcdsaWithAes128GcmSha256 => {
                Some(Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256)
            }
            CipherSuite::Tls12EcdheEcdsaWithAes256GcmSha384 => {
                Some(Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384)
            }
            CipherSuite::Tls12EcdheEcdsaWithChacha20Poly1305Sha256 => {
                Some(Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256)
            }
            _ => None, // TLS 1.3 cipher suites
        }
    }
}

/// Get the default/recommended TLS 1.2 cipher suites.
///
/// Prioritized by:
/// 1. ChaCha20-Poly1305 (fastest, best for mobile)
/// 2. AES-256-GCM (strongest AES)
/// 3. AES-128-GCM (good balance)
pub fn default_cipher_suites() -> Vec<Tls12CipherSuite> {
    vec![
        // ECDSA (preferred - faster)
        Tls12CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256,
        Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384,
        Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256,
        // RSA (fallback for compatibility)
        Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256,
        Tls12CipherSuite::EcdheRsaWithAes256GcmSha384,
        Tls12CipherSuite::EcdheRsaWithAes128GcmSha256,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_conversion() {
        assert_eq!(
            Tls12CipherSuite::from_u16(0xC02F),
            Some(Tls12CipherSuite::EcdheRsaWithAes128GcmSha256)
        );
        assert_eq!(
            Tls12CipherSuite::EcdheRsaWithAes128GcmSha256.to_u16(),
            0xC02F
        );
    }

    #[test]
    fn test_cipher_suite_properties() {
        let cs = Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384;
        assert_eq!(cs.aead_algorithm(), AeadAlgorithm::Aes256Gcm);
        assert_eq!(cs.hash_algorithm(), HashAlgorithm::Sha384);
        assert!(cs.uses_ecdsa());
        assert!(!cs.uses_rsa());
        assert_eq!(cs.key_block_length(), 72);
    }

    #[test]
    fn test_default_cipher_suites() {
        let suites = default_cipher_suites();
        assert_eq!(suites.len(), 6);
        // ECDSA should come first
        assert!(suites[0].uses_ecdsa());
    }

    #[test]
    fn test_cipher_suite_names() {
        assert_eq!(
            Tls12CipherSuite::EcdheRsaWithChacha20Poly1305Sha256.name(),
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        );
    }
}
