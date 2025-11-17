//! QUIC Header Protection interface (RFC 9001 Section 5.4)
//!
//! Header protection is used to encrypt QUIC packet headers to prevent
//! ossification and protect metadata. It uses a sample from the packet
//! payload to generate a 5-byte mask that is XORed with the header.

use crate::Result;

/// QUIC Header Protection trait.
///
/// Provides header protection/unprotection for QUIC packets.
/// Different cipher suites use different algorithms:
/// - AES-GCM: AES-ECB
/// - ChaCha20-Poly1305: ChaCha20
pub trait HeaderProtection: Send + Sync {
    /// Generate a 5-byte mask from a 16-byte sample.
    ///
    /// # Arguments
    /// * `sample` - 16-byte sample from packet payload
    ///
    /// # Returns
    /// 5-byte mask to XOR with header
    fn generate_mask(&self, sample: &[u8]) -> Result<[u8; 5]>;

    /// Get the algorithm this header protection uses.
    fn algorithm(&self) -> HeaderProtectionAlgorithm;
}

/// Header protection algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderProtectionAlgorithm {
    /// AES-128-ECB for AES-128-GCM cipher suites
    Aes128,
    /// AES-256-ECB for AES-256-GCM cipher suites
    Aes256,
    /// ChaCha20 for ChaCha20-Poly1305 cipher suites
    ChaCha20,
}

impl HeaderProtectionAlgorithm {

    /// Get the key length for this algorithm.
    pub const fn key_length(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
            Self::ChaCha20 => 32,
        }
    }

    /// Get the name of this algorithm.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128 => "AES-128-ECB",
            Self::Aes256 => "AES-256-ECB",
            Self::ChaCha20 => "ChaCha20",
        }
    }
}
