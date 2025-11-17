//! TLS 1.2 Key Exchange
//!
//! This module implements ECDHE key exchange for TLS 1.2.
//! The key exchange produces a premaster secret which is then used to derive the master secret.
//!
//! ECDHE Flow:
//! 1. Server generates ephemeral key pair, sends public key in ServerKeyExchange
//! 2. Client generates ephemeral key pair, sends public key in ClientKeyExchange
//! 3. Both sides compute shared secret (premaster secret) using ECDH
//! 4. Premaster secret is used with PRF to derive master secret

use crate::error::{Error, Result};
use hptls_crypto::{CryptoProvider, KeyExchangeAlgorithm};

/// Compute the premaster secret from ECDHE.
///
/// # Arguments
/// * `provider` - Crypto provider
/// * `algorithm` - Key exchange algorithm (e.g., X25519, P-256)
/// * `private_key` - Our private key bytes
/// * `peer_public_key` - Peer's public key bytes
///
/// # Returns
/// Premaster secret (shared secret from ECDH)
pub fn compute_premaster_secret(
    provider: &dyn CryptoProvider,
    algorithm: KeyExchangeAlgorithm,
    private_key: &[u8],
    peer_public_key: &[u8],
) -> Result<Vec<u8>> {
    use hptls_crypto::key_exchange::PrivateKey;

    let kex = provider
        .key_exchange(algorithm)
        .map_err(|e| Error::CryptoError(format!("Failed to get key exchange: {}", e)))?;

    let priv_key = PrivateKey::from_bytes(private_key.to_vec());
    let shared_secret = kex
        .exchange(&priv_key, peer_public_key)
        .map_err(|e| Error::CryptoError(format!("Failed to compute shared secret: {}", e)))?;

    Ok(shared_secret.into_bytes())
}

/// Generate an ephemeral key pair for ECDHE.
///
/// # Arguments
/// * `provider` - Crypto provider
/// * `algorithm` - Key exchange algorithm (e.g., X25519, P-256)
///
/// # Returns
/// (private_key, public_key) as byte vectors
pub fn generate_key_pair(
    provider: &dyn CryptoProvider,
    algorithm: KeyExchangeAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let kex = provider
        .key_exchange(algorithm)
        .map_err(|e| Error::CryptoError(format!("Failed to get key exchange: {}", e)))?;

    let (private_key, public_key) = kex
        .generate_keypair()
        .map_err(|e| Error::CryptoError(format!("Failed to generate keypair: {}", e)))?;

    Ok((private_key.as_bytes().to_vec(), public_key.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hptls_crypto_hpcrypt::HpcryptProvider;

    #[test]
    fn test_ecdhe_key_exchange_x25519() {
        let provider = HpcryptProvider::new();

        // Generate key pairs for both sides
        let (client_private, client_public) =
            generate_key_pair(&provider, KeyExchangeAlgorithm::X25519).unwrap();
        let (server_private, server_public) =
            generate_key_pair(&provider, KeyExchangeAlgorithm::X25519).unwrap();

        // Compute shared secrets
        let client_secret = compute_premaster_secret(
            &provider,
            KeyExchangeAlgorithm::X25519,
            &client_private,
            &server_public,
        )
        .unwrap();

        let server_secret = compute_premaster_secret(
            &provider,
            KeyExchangeAlgorithm::X25519,
            &server_private,
            &client_public,
        )
        .unwrap();

        // Both should compute the same shared secret
        assert_eq!(client_secret, server_secret);
        assert_eq!(client_secret.len(), 32); // X25519 shared secret is 32 bytes
    }

    #[test]
    #[ignore] // P-256 not yet fully supported in hpcrypt
    fn test_ecdhe_key_exchange_p256() {
        let provider = HpcryptProvider::new();

        // Generate key pairs
        let (client_private, client_public) =
            generate_key_pair(&provider, KeyExchangeAlgorithm::Secp256r1).unwrap();
        let (server_private, server_public) =
            generate_key_pair(&provider, KeyExchangeAlgorithm::Secp256r1).unwrap();

        // Compute shared secrets
        let client_secret = compute_premaster_secret(
            &provider,
            KeyExchangeAlgorithm::Secp256r1,
            &client_private,
            &server_public,
        )
        .unwrap();

        let server_secret = compute_premaster_secret(
            &provider,
            KeyExchangeAlgorithm::Secp256r1,
            &server_private,
            &client_public,
        )
        .unwrap();

        // Both should compute the same shared secret
        assert_eq!(client_secret, server_secret);
        assert_eq!(client_secret.len(), 32); // P-256 shared secret is 32 bytes
    }
}
