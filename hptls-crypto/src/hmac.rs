//! HMAC (Hash-based Message Authentication Code) interface.

use crate::HashAlgorithm;

/// HMAC trait.
///
/// Provides HMAC computation for message authentication.
///
/// # Example
///
/// ```rust,ignore
/// use hptls_crypto::Hmac;
///
/// fn hmac_example(hmac: &mut dyn Hmac) -> Vec<u8> {
///     hmac.update(b"message");
///     hmac.finalize()
/// }
/// ```
pub trait Hmac: Send {
    /// Update the HMAC state with more data.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to authenticate
    fn update(&mut self, data: &[u8]);

    /// Finalize the HMAC and return the authentication tag.
    ///
    /// This consumes the HMAC state. After calling finalize(),
    /// the HMAC object should not be used again.
    ///
    /// # Returns
    ///
    /// The HMAC tag (size depends on hash algorithm).
    fn finalize(self: Box<Self>) -> Vec<u8>;

    /// Verify an HMAC tag in constant time.
    ///
    /// # Arguments
    ///
    /// * `tag` - Expected HMAC tag to verify against
    ///
    /// # Returns
    ///
    /// `true` if the tag matches, `false` otherwise.
    ///
    /// # Security
    ///
    /// This function MUST use constant-time comparison to prevent
    /// timing attacks.
    fn verify(self: Box<Self>, tag: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        let computed = self.finalize();
        computed.ct_eq(tag).into()
    }

    /// Get the output size in bytes for this HMAC.
    fn output_size(&self) -> usize;

    /// Get the hash algorithm used by this HMAC.
    fn algorithm(&self) -> HashAlgorithm;

    /// Reset the HMAC state (optional, for reusable HMAC objects).
    fn reset(&mut self) {
        // Default: no-op
    }
}
