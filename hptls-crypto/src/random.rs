//! Cryptographically Secure Random Number Generator (CSPRNG) interface.

use crate::Result;

/// Random number generator trait.
///
/// Provides a cryptographically secure random number generator (CSPRNG)
/// for use in TLS.
///
/// # Security Requirements
///
/// - MUST be cryptographically secure
/// - MUST be properly seeded from OS entropy source
/// - MUST be thread-safe (Send + Sync)
/// - MUST NOT use weak PRNGs (like rand::random())
///
/// # Example
///
/// ```rust,no_run
/// use hptls_crypto::Random;
///
/// fn generate_nonce(rng: &dyn Random) -> Vec<u8> {
///     let mut nonce = vec![0u8; 12];
///     rng.fill(&mut nonce).unwrap();
///     nonce
/// }
/// ```
pub trait Random: Send + Sync {
    /// Fill a buffer with random bytes.
    ///
    /// # Arguments
    ///
    /// * `dest` - Buffer to fill with random bytes
    ///
    /// # Errors
    ///
    /// Returns error if random generation fails (e.g., OS RNG unavailable).
    ///
    /// # Security
    ///
    /// This MUST use a CSPRNG. Do not use weak PRNGs like `rand::random()`.
    fn fill(&self, dest: &mut [u8]) -> Result<()>;

    /// Generate a random byte vector of specified length.
    ///
    /// # Arguments
    ///
    /// * `len` - Number of random bytes to generate
    ///
    /// # Returns
    ///
    /// Vector of `len` random bytes
    fn generate(&self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.fill(&mut buf)?;
        Ok(buf)
    }

    /// Generate a random u64.
    ///
    /// Convenience method for generating random numbers.
    fn next_u64(&self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.fill(&mut buf)?;
        Ok(u64::from_ne_bytes(buf))
    }

    /// Generate a random u32.
    fn next_u32(&self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.fill(&mut buf)?;
        Ok(u32::from_ne_bytes(buf))
    }
}
