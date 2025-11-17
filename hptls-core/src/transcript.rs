//! Transcript hash management for TLS 1.3 handshakes.
//!
//! The transcript hash is a running hash of all handshake messages exchanged
//! between client and server. It's used for:
//! - Deriving handshake traffic secrets
//! - Computing Finished message verify data
//! - Deriving application traffic secrets
//! - PSK binders
//! Per RFC 8446 Section 4.4.1:
//! "The transcript hash is computed as Hash(Handshake Context)"

use crate::error::{Error, Result};
use hptls_crypto::{CryptoProvider, HashAlgorithm};
/// Transcript hash manager.
///
/// Maintains a running hash of all handshake messages for use in
/// key derivation and Finished message verification.
/// # Example
/// ```rust,ignore
/// use hptls_core::transcript::TranscriptHash;
/// use hptls_crypto::HashAlgorithm;
/// let mut transcript = TranscriptHash::new(HashAlgorithm::Sha256);
/// transcript.update_message(&provider, &client_hello)?;
/// transcript.update_message(&provider, &server_hello)?;
/// let hash = transcript.current_hash(&provider)?;
/// ```
#[derive(Debug, Clone)]
pub struct TranscriptHash {
    /// Hash algorithm being used
    algorithm: HashAlgorithm,
    /// All messages in order
    messages: Vec<Vec<u8>>,
    /// Cached hash (computed lazily)
    cached_hash: Option<Vec<u8>>,
}
impl TranscriptHash {
    /// Create a new transcript hash with the specified algorithm.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            messages: Vec::new(),
            cached_hash: None,
        }
    }
    /// Get the hash algorithm being used.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Add a raw message to the transcript.
    ///
    /// # Arguments
    /// * `message` - The encoded handshake message bytes (including 4-byte header)
    pub fn update(&mut self, message: &[u8]) {
        self.messages.push(message.to_vec());
        self.cached_hash = None; // Invalidate cache
    }

    /// Compute the current transcript hash.
    /// * `provider` - Crypto provider for hashing
    /// # Returns
    /// The hash of all messages added so far.
    pub fn current_hash(&mut self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        // Return cached value if available
        if let Some(ref hash) = self.cached_hash {
            return Ok(hash.clone());
        }
        // Compute hash of all messages
        let mut hasher = provider.hash(self.algorithm)?;
        for msg in &self.messages {
            hasher.update(msg);
        }
        let hash = hasher.finalize();
        // Cache the result
        self.cached_hash = Some(hash.clone());
        Ok(hash)
    }
    /// Get the current hash without updating the cache.
    /// This is useful for debugging or when you need the hash
    /// but don't want to affect the cached value.
    pub fn peek_hash(&self, provider: &dyn CryptoProvider) -> Result<Vec<u8>> {
        let mut hasher = provider.hash(self.algorithm)?;
        for msg in &self.messages {
            hasher.update(msg);
        }
        Ok(hasher.finalize())
    }

    /// Reset the transcript to empty.
    pub fn reset(&mut self) {
        self.messages.clear();
        self.cached_hash = None;
    }

    /// Get the number of messages in the transcript.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Check if the transcript is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Get the total size of all messages in bytes.
    pub fn total_size(&self) -> usize {
        self.messages.iter().map(|m| m.len()).sum()
    }

    /// Create a snapshot of the transcript at this point.
    /// This is useful for computing hashes at specific points in the handshake
    /// (e.g., for PSK binders or early data).
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    /// Compute hash up to but not including the last N messages.
    /// This is used for PSK binders where we need the hash of the ClientHello
    /// up to (but not including) the binders themselves.
    pub fn hash_excluding_last(&self, provider: &dyn CryptoProvider, n: usize) -> Result<Vec<u8>> {
        if n > self.messages.len() {
            return Err(Error::InternalError(
                "Cannot exclude more messages than exist".to_string(),
            ));
        }
        let count = self.messages.len() - n;
        let mut hasher = provider.hash(self.algorithm)?;
        for msg in &self.messages[..count] {
            hasher.update(msg);
        }
        Ok(hasher.finalize())
    }

    /// Compute hash of a specific range of messages.
    pub fn hash_range(
        &self,
        provider: &dyn CryptoProvider,
        start: usize,
        end: usize,
    ) -> Result<Vec<u8>> {
        if end > self.messages.len() {
            return Err(Error::InternalError(
                "Range end exceeds message count".to_string(),
            ));
        }
        if start > end {
            return Err(Error::InternalError(
                "Invalid range: start > end".to_string(),
            ));
        }
        let mut hasher = provider.hash(self.algorithm)?;
        for msg in &self.messages[start..end] {
            hasher.update(msg);
        }
        Ok(hasher.finalize())
    }

    /// Get a reference to all messages (for debugging).
    #[cfg(test)]
    pub(crate) fn messages(&self) -> &[Vec<u8>] {
        &self.messages
    }
}

/// Helper for computing Finished message verify data.
/// Per RFC 8446 Section 4.4.4:
/// ```text
/// finished_key =
///     HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// verify_data =
///     HMAC(finished_key, Transcript-Hash(Handshake Context))
pub fn compute_verify_data(
    provider: &dyn CryptoProvider,
    algorithm: HashAlgorithm,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    // Derive finished_key using HKDF-Expand-Label
    let hash_len = match algorithm {
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha384 => 48,
        _ => {
            return Err(Error::InternalError(
                "Unsupported hash algorithm".to_string(),
            ))
        },
    };
    let finished_key =
        hkdf_expand_label(provider, algorithm, base_key, b"finished", &[], hash_len)?;
    // Compute HMAC of transcript hash
    let mut hmac = provider.hmac(algorithm, &finished_key)?;
    hmac.update(transcript_hash);
    Ok(hmac.finalize())
}

/// HKDF-Expand-Label implementation per RFC 8446 Section 7.1.
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
pub fn hkdf_expand_label(
    _provider: &dyn CryptoProvider,
    algorithm: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    // Check if this is a QUIC label (starts with "quic ")
    if label.starts_with(b"quic ") {
        // Use QUIC-specific implementation
        return quic_hkdf_expand_label(algorithm, secret, label, context, length);
    }

    // Convert label bytes to string for hpcrypt-kdf (TLS 1.3)
    let label_str = std::str::from_utf8(label)
        .map_err(|_| Error::InternalError("Label is not valid UTF-8".to_string()))?;

    // Validate length fits in u16
    if length > 0xFFFF {
        return Err(Error::InternalError("Length too large".to_string()));
    }
    let length_u16 = length as u16;

    // Use hpcrypt-kdf's TLS 1.3 HKDF-Expand-Label implementation
    // It handles the "tls13 " prefix and encoding internally
    let result = match algorithm {
        HashAlgorithm::Sha256 => {
            hpcrypt_kdf::tls13::hkdf_expand_label_sha256(secret, label_str, context, length_u16)
        }
        HashAlgorithm::Sha384 => {
            hpcrypt_kdf::tls13::hkdf_expand_label_sha384(secret, label_str, context, length_u16)
        }
        HashAlgorithm::Sha512 => {
            hpcrypt_kdf::tls13::hkdf_expand_label_sha512(secret, label_str, context, length_u16)
        }
    };

    Ok(result)
}

/// QUIC-specific HKDF-Expand-Label (RFC 9001)
///
/// Similar to TLS 1.3's HKDF-Expand-Label but with "quic " prefix instead of "tls13 "
fn quic_hkdf_expand_label(
    algorithm: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    // Remove "quic " prefix from label (hpcrypt-kdf adds it back)
    let label_without_prefix = if label.starts_with(b"quic ") {
        &label[5..]
    } else {
        label
    };

    // Convert label bytes to string for hpcrypt-kdf
    let label_str = std::str::from_utf8(label_without_prefix)
        .map_err(|_| Error::InternalError("Label is not valid UTF-8".to_string()))?;

    // Validate length fits in u16
    if length > 0xFFFF {
        return Err(Error::InternalError("Length too large".to_string()));
    }
    let length_u16 = length as u16;

    // Use hpcrypt-kdf's QUIC HKDF-Expand-Label implementation
    let result = match algorithm {
        HashAlgorithm::Sha256 => {
            hpcrypt_kdf::quic::hkdf_expand_label_sha256(secret, label_str, context, length_u16)
        }
        HashAlgorithm::Sha384 => {
            hpcrypt_kdf::quic::hkdf_expand_label_sha384(secret, label_str, context, length_u16)
        }
        HashAlgorithm::Sha512 => {
            hpcrypt_kdf::quic::hkdf_expand_label_sha512(secret, label_str, context, length_u16)
        }
    };

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hptls_crypto::CryptoProvider;
    use hptls_crypto_hpcrypt::HpcryptProvider;
    #[test]
    fn test_transcript_basic() {
        let mut transcript = TranscriptHash::new(HashAlgorithm::Sha256);
        assert!(transcript.is_empty());
        assert_eq!(transcript.message_count(), 0);
        transcript.update(b"message1");
        assert!(!transcript.is_empty());
        assert_eq!(transcript.message_count(), 1);
        transcript.update(b"message2");
        assert_eq!(transcript.message_count(), 2);
    }

    #[test]
    fn test_transcript_hash() {
        let provider = HpcryptProvider::new();
        let mut transcript = TranscriptHash::new(HashAlgorithm::Sha256);
        transcript.update(b"message1");
        transcript.update(b"message2");
        let hash1 = transcript.current_hash(&provider).unwrap();
        assert_eq!(hash1.len(), 32); // SHA-256 produces 32 bytes
                                     // Hash should be cached
        let hash2 = transcript.current_hash(&provider).unwrap();
        assert_eq!(hash1, hash2);
        // Adding new message should invalidate cache
        transcript.update(b"message3");
        let hash3 = transcript.current_hash(&provider).unwrap();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_transcript_snapshot() {
        let provider = HpcryptProvider::new();
        let mut transcript = TranscriptHash::new(HashAlgorithm::Sha256);
        transcript.update(b"message1");
        let snapshot = transcript.snapshot();
        let hash1 = transcript.current_hash(&provider).unwrap();
        // Add message to original transcript
        transcript.update(b"message2");
        let hash2 = transcript.current_hash(&provider).unwrap();
        // Original hash should differ after adding message
        assert_ne!(hash1, hash2);
        // Snapshot should have original hash
        let mut snapshot_copy = snapshot;
        let snapshot_hash = snapshot_copy.current_hash(&provider).unwrap();
        assert_eq!(hash1, snapshot_hash);
    }

    #[test]
    fn test_hkdf_expand_label() {
        let provider = HpcryptProvider::new();
        let secret = vec![0x42u8; 32];
        let result = hkdf_expand_label(
            &provider,
            HashAlgorithm::Sha256,
            &secret,
            b"test label",
            b"context",
            32,
        )
        .unwrap();
        assert_eq!(result.len(), 32);
        // Same inputs should produce same output
        let result2 = hkdf_expand_label(
            &provider,
            HashAlgorithm::Sha256,
            &secret,
            b"test label",
            b"context",
            32,
        )
        .unwrap();
        assert_eq!(result, result2);
        // Different label should produce different output
        let result3 = hkdf_expand_label(
            &provider,
            HashAlgorithm::Sha256,
            &secret,
            b"different",
            b"context",
            32,
        )
        .unwrap();
        assert_ne!(result, result3);
    }

    #[test]
    fn test_compute_verify_data() {
        let provider = HpcryptProvider::new();
        let base_key = vec![0x42u8; 32];
        let transcript_hash = vec![0x55u8; 32];
        let verify_data = compute_verify_data(
            &provider,
            HashAlgorithm::Sha256,
            &base_key,
            &transcript_hash,
        )
        .unwrap();
        assert_eq!(verify_data.len(), 32); // HMAC-SHA256 produces 32 bytes
                                           // Should be deterministic
        let verify_data2 = compute_verify_data(
            &provider,
            HashAlgorithm::Sha256,
            &base_key,
            &transcript_hash,
        )
        .unwrap();
        assert_eq!(verify_data, verify_data2);
    }

    #[test]
    fn test_hash_excluding_last() {
        let provider = HpcryptProvider::new();
        let mut transcript = TranscriptHash::new(HashAlgorithm::Sha256);
        transcript.update(b"message1");
        transcript.update(b"message2");
        transcript.update(b"message3");
        // Hash excluding last message
        let hash_excl = transcript.hash_excluding_last(&provider, 1).unwrap();
        // Should equal hash of first 2 messages
        let mut transcript2 = TranscriptHash::new(HashAlgorithm::Sha256);
        transcript2.update(b"message1");
        transcript2.update(b"message2");
        let hash2 = transcript2.current_hash(&provider).unwrap();
        assert_eq!(hash_excl, hash2);
    }

    #[test]
    fn test_hash_range() {
        let provider = HpcryptProvider::new();
        let mut transcript = TranscriptHash::new(HashAlgorithm::Sha256);
        transcript.update(b"message1");
        transcript.update(b"message2");
        transcript.update(b"message3");
        transcript.update(b"message4");
        // Hash messages 1 and 2 (indices 1 and 2)
        let hash_range = transcript.hash_range(&provider, 1, 3).unwrap();
        // Should equal hash of just those messages
        let mut transcript2 = TranscriptHash::new(HashAlgorithm::Sha256);
        transcript2.update(b"message2");
        transcript2.update(b"message3");
        let hash2 = transcript2.current_hash(&provider).unwrap();
        assert_eq!(hash_range, hash2);
    }
}
