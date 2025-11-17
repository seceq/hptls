//! Cryptographically secure random number generation using hpcrypt-rng.

use hptls_crypto::{Random, Result};

/// Random number generator implementation using hpcrypt-rng.
///
/// This uses the OS-provided entropy source via `getrandom` crate.
#[derive(Debug, Clone, Copy)]
pub struct HpcryptRandom;

impl Random for HpcryptRandom {
    fn fill(&self, dest: &mut [u8]) -> Result<()> {
        hpcrypt_rng::fill_random(dest)
            .map_err(|e| hptls_crypto::Error::CryptoError(format!("RNG error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_generation() {
        let rng = HpcryptRandom;

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rng.fill(&mut buf1).unwrap();
        rng.fill(&mut buf2).unwrap();

        // Should not be all zeros
        assert_ne!(&buf1[..], &[0u8; 32][..]);

        // Should generate different values
        assert_ne!(&buf1[..], &buf2[..]);
    }

    #[test]
    fn test_random_u64() {
        let rng = HpcryptRandom;
        let n1 = rng.next_u64().unwrap();
        let n2 = rng.next_u64().unwrap();

        // Should generate different values
        assert_ne!(n1, n2);
    }
}
