//! TLS 1.2 PRF (Pseudorandom Function) - RFC 5246 Section 5
//!
//! The TLS 1.2 PRF is used for key derivation and is based on HMAC.
//! It replaces the TLS 1.0/1.1 PRF which used MD5/SHA1.
//!
//! PRF(secret, label, seed) = P_<hash>(secret, label + seed)
//!
//! Where P_hash is defined as:
//! P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//!                         HMAC_hash(secret, A(2) + seed) +
//!                         HMAC_hash(secret, A(3) + seed) + ...
//!
//! A(0) = seed
//! A(i) = HMAC_hash(secret, A(i-1))

use hptls_crypto::{CryptoProvider, HashAlgorithm};

use crate::error::{Error, Result};

/// TLS 1.2 PRF implementation
pub struct Tls12Prf<'a> {
    provider: &'a dyn CryptoProvider,
    hash_algorithm: HashAlgorithm,
}

impl<'a> Tls12Prf<'a> {
    /// Create a new TLS 1.2 PRF with the specified hash algorithm.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider for HMAC operations
    /// * `hash_algorithm` - Hash algorithm (typically SHA256 or SHA384)
    pub fn new(provider: &'a dyn CryptoProvider, hash_algorithm: HashAlgorithm) -> Self {
        Self {
            provider,
            hash_algorithm,
        }
    }

    /// Compute the TLS 1.2 PRF.
    ///
    /// # Arguments
    /// * `secret` - The secret key material
    /// * `label` - ASCII string label (e.g., "master secret", "key expansion")
    /// * `seed` - Random seed data
    /// * `output_len` - Desired output length in bytes
    ///
    /// # Returns
    /// Output bytes of specified length
    pub fn compute(
        &self,
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>> {
        // Get the appropriate TLS 1.2 PRF KDF from the provider
        let kdf_algorithm = match self.hash_algorithm {
            HashAlgorithm::Sha256 => hptls_crypto::KdfAlgorithm::TlsPrfSha256,
            HashAlgorithm::Sha384 => hptls_crypto::KdfAlgorithm::TlsPrfSha384,
            HashAlgorithm::Sha512 => {
                // SHA512 is not commonly used in TLS 1.2, fall back to custom implementation
                return self.p_hash_manual(secret, label, seed, output_len);
            }
        };

        let kdf = self
            .provider
            .kdf(kdf_algorithm)
            .map_err(|e| Error::CryptoError(format!("Failed to get TLS PRF KDF: {}", e)))?;

        // Concatenate label + seed (this is the "info" parameter for the KDF)
        let mut label_seed = Vec::with_capacity(label.len() + seed.len());
        label_seed.extend_from_slice(label);
        label_seed.extend_from_slice(seed);

        // Use the provider's TLS PRF implementation (via hpcrypt-kdf)
        // Note: extract() is a no-op for TLS PRF, it just returns the secret
        let _prk = kdf.extract(&[], secret);

        // expand() does the actual PRF computation
        kdf.expand(secret, &label_seed, output_len)
            .map_err(|e| Error::CryptoError(format!("TLS PRF expansion failed: {}", e)))
    }

    /// Manual P_hash implementation for algorithms not supported by hpcrypt-kdf.
    ///
    /// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
    ///                         HMAC_hash(secret, A(2) + seed) +
    ///                         HMAC_hash(secret, A(3) + seed) + ...
    ///
    /// A(0) = seed
    /// A(i) = HMAC_hash(secret, A(i-1))
    fn p_hash_manual(
        &self,
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>> {
        // Concatenate label + seed
        let mut label_seed = Vec::with_capacity(label.len() + seed.len());
        label_seed.extend_from_slice(label);
        label_seed.extend_from_slice(seed);

        let mut output = Vec::with_capacity(output_len);
        let hash_len = self.hash_algorithm.output_size();

        // A(0) = label + seed
        let mut a = label_seed.clone();

        while output.len() < output_len {
            // A(i) = HMAC_hash(secret, A(i-1))
            a = self.hmac(secret, &a)?;

            // HMAC_hash(secret, A(i) + label_seed)
            let mut a_seed = Vec::with_capacity(a.len() + label_seed.len());
            a_seed.extend_from_slice(&a);
            a_seed.extend_from_slice(&label_seed);

            let hmac_result = self.hmac(secret, &a_seed)?;

            // Append to output
            let remaining = output_len - output.len();
            if remaining >= hash_len {
                output.extend_from_slice(&hmac_result);
            } else {
                // Last iteration - only take what we need
                output.extend_from_slice(&hmac_result[..remaining]);
            }
        }

        Ok(output)
    }

    /// Compute HMAC using the configured hash algorithm.
    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut hmac = self
            .provider
            .hmac(self.hash_algorithm, key)
            .map_err(|e| Error::CryptoError(format!("Failed to create HMAC: {}", e)))?;

        hmac.update(data);
        Ok(hmac.finalize().to_vec())
    }
}

/// Compute TLS 1.2 master secret from premaster secret.
///
/// master_secret = PRF(pre_master_secret, "master secret",
///                     ClientHello.random + ServerHello.random)[0..47]
///
/// # Arguments
/// * `provider` - Crypto provider
/// * `hash_algorithm` - Hash algorithm (from cipher suite)
/// * `premaster_secret` - Premaster secret (from key exchange)
/// * `client_random` - Client random (32 bytes)
/// * `server_random` - Server random (32 bytes)
///
/// # Returns
/// Master secret (48 bytes)
pub fn compute_master_secret(
    provider: &dyn CryptoProvider,
    hash_algorithm: HashAlgorithm,
    premaster_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Result<Vec<u8>> {
    if client_random.len() != 32 {
        return Err(Error::InvalidMessage(format!(
            "Client random must be 32 bytes, got {}",
            client_random.len()
        )));
    }

    if server_random.len() != 32 {
        return Err(Error::InvalidMessage(format!(
            "Server random must be 32 bytes, got {}",
            server_random.len()
        )));
    }

    let prf = Tls12Prf::new(provider, hash_algorithm);

    // Seed = ClientHello.random + ServerHello.random
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    prf.compute(premaster_secret, b"master secret", &seed, 48)
}

/// Compute TLS 1.2 key material from master secret.
///
/// key_block = PRF(SecurityParameters.master_secret, "key expansion",
///                 SecurityParameters.server_random +
///                 SecurityParameters.client_random);
///
/// # Arguments
/// * `provider` - Crypto provider
/// * `hash_algorithm` - Hash algorithm (from cipher suite)
/// * `master_secret` - Master secret (48 bytes)
/// * `server_random` - Server random (32 bytes)
/// * `client_random` - Client random (32 bytes)
/// * `key_block_len` - Length of key block to generate
///
/// # Returns
/// Key block bytes
pub fn compute_key_block(
    provider: &dyn CryptoProvider,
    hash_algorithm: HashAlgorithm,
    master_secret: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    key_block_len: usize,
) -> Result<Vec<u8>> {
    if master_secret.len() != 48 {
        return Err(Error::InvalidMessage(format!(
            "Master secret must be 48 bytes, got {}",
            master_secret.len()
        )));
    }

    if server_random.len() != 32 {
        return Err(Error::InvalidMessage(format!(
            "Server random must be 32 bytes, got {}",
            server_random.len()
        )));
    }

    if client_random.len() != 32 {
        return Err(Error::InvalidMessage(format!(
            "Client random must be 32 bytes, got {}",
            client_random.len()
        )));
    }

    let prf = Tls12Prf::new(provider, hash_algorithm);

    // Seed = ServerHello.random + ClientHello.random (note: reversed from master_secret)
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    prf.compute(master_secret, b"key expansion", &seed, key_block_len)
}

/// Compute TLS 1.2 verify data for Finished message.
///
/// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length]
///
/// # Arguments
/// * `provider` - Crypto provider
/// * `hash_algorithm` - Hash algorithm (from cipher suite)
/// * `master_secret` - Master secret (48 bytes)
/// * `finished_label` - "client finished" or "server finished"
/// * `handshake_hash` - Hash of all handshake messages
///
/// # Returns
/// Verify data (12 bytes)
pub fn compute_verify_data(
    provider: &dyn CryptoProvider,
    hash_algorithm: HashAlgorithm,
    master_secret: &[u8],
    finished_label: &[u8],
    handshake_hash: &[u8],
) -> Result<Vec<u8>> {
    let prf = Tls12Prf::new(provider, hash_algorithm);
    prf.compute(master_secret, finished_label, handshake_hash, 12)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hptls_crypto_hpcrypt::HpcryptProvider;

    #[test]
    fn test_tls12_prf_basic() {
        let provider = HpcryptProvider::new();
        let prf = Tls12Prf::new(&provider, HashAlgorithm::Sha256);

        let secret = b"secret";
        let label = b"label";
        let seed = b"seed";

        let result = prf.compute(secret, label, seed, 32).unwrap();
        assert_eq!(result.len(), 32);

        // PRF should be deterministic
        let result2 = prf.compute(secret, label, seed, 32).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_tls12_prf_different_lengths() {
        let provider = HpcryptProvider::new();
        let prf = Tls12Prf::new(&provider, HashAlgorithm::Sha256);

        let secret = b"secret";
        let label = b"label";
        let seed = b"seed";

        // Test various output lengths
        for len in [12, 32, 48, 64, 100, 256] {
            let result = prf.compute(secret, label, seed, len).unwrap();
            assert_eq!(result.len(), len);
        }
    }

    #[test]
    fn test_compute_master_secret() {
        let provider = HpcryptProvider::new();
        let premaster_secret = vec![0u8; 48];
        let client_random = vec![1u8; 32];
        let server_random = vec![2u8; 32];

        let master_secret = compute_master_secret(
            &provider,
            HashAlgorithm::Sha256,
            &premaster_secret,
            &client_random,
            &server_random,
        )
        .unwrap();

        assert_eq!(master_secret.len(), 48);
    }

    #[test]
    fn test_compute_key_block() {
        let provider = HpcryptProvider::new();
        let master_secret = vec![0u8; 48];
        let client_random = vec![1u8; 32];
        let server_random = vec![2u8; 32];

        // AES-128-GCM: 2*(16 byte key + 4 byte IV) = 40 bytes
        let key_block = compute_key_block(
            &provider,
            HashAlgorithm::Sha256,
            &master_secret,
            &server_random,
            &client_random,
            40,
        )
        .unwrap();

        assert_eq!(key_block.len(), 40);
    }

    #[test]
    fn test_compute_verify_data() {
        let provider = HpcryptProvider::new();
        let master_secret = vec![0u8; 48];
        let handshake_hash = vec![0u8; 32]; // SHA256 hash

        let verify_data = compute_verify_data(
            &provider,
            HashAlgorithm::Sha256,
            &master_secret,
            b"client finished",
            &handshake_hash,
        )
        .unwrap();

        assert_eq!(verify_data.len(), 12);
    }

    #[test]
    fn test_prf_with_sha384() {
        let provider = HpcryptProvider::new();
        let prf = Tls12Prf::new(&provider, HashAlgorithm::Sha384);

        let secret = b"secret";
        let label = b"label";
        let seed = b"seed";

        let result = prf.compute(secret, label, seed, 64).unwrap();
        assert_eq!(result.len(), 64);
    }

    /// RFC 5246 test vector (Appendix hasn't published official test vectors,
    /// but we validate consistency)
    #[test]
    fn test_prf_consistency() {
        let provider = HpcryptProvider::new();

        // Test that different inputs produce different outputs
        let prf = Tls12Prf::new(&provider, HashAlgorithm::Sha256);

        let result1 = prf.compute(b"secret1", b"label", b"seed", 32).unwrap();
        let result2 = prf.compute(b"secret2", b"label", b"seed", 32).unwrap();
        assert_ne!(result1, result2);

        let result3 = prf.compute(b"secret", b"label1", b"seed", 32).unwrap();
        let result4 = prf.compute(b"secret", b"label2", b"seed", 32).unwrap();
        assert_ne!(result3, result4);
    }
}
