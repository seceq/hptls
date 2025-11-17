//! Key exchange implementations using hpcrypt-curves.

use hptls_crypto::{
    key_exchange::{KeyExchangeAlgorithm, PrivateKey, PublicKey, SharedSecret},
    Error, KeyExchange, Random, Result,
};

use crate::random::HpcryptRandom;

/// Create a key exchange instance for the specified algorithm.
pub fn create_key_exchange(algorithm: KeyExchangeAlgorithm) -> Result<Box<dyn KeyExchange>> {
    match algorithm {
        // Classical key exchange
        KeyExchangeAlgorithm::X25519 => Ok(Box::new(X25519Kex)),
        KeyExchangeAlgorithm::Secp256r1 => Ok(Box::new(EcdhP256)),

        // Post-Quantum key exchange - ML-KEM
        KeyExchangeAlgorithm::MlKem512 => Ok(Box::new(crate::mlkem::MlKem512Kex)),
        KeyExchangeAlgorithm::MlKem768 => Ok(Box::new(crate::mlkem::MlKem768Kex)),
        KeyExchangeAlgorithm::MlKem1024 => Ok(Box::new(crate::mlkem::MlKem1024Kex)),

        // Hybrid key exchange (classical + PQC)
        KeyExchangeAlgorithm::X25519MlKem768 => Ok(Box::new(crate::hybrid_kem::X25519MlKem768Kex)),
        KeyExchangeAlgorithm::Secp256r1MlKem768 => Ok(Box::new(crate::hybrid_kem::Secp256r1MlKem768Kex)),

        // Not yet implemented
        KeyExchangeAlgorithm::X448
        | KeyExchangeAlgorithm::Secp384r1
        | KeyExchangeAlgorithm::Secp521r1
        | KeyExchangeAlgorithm::Ffdhe2048
        | KeyExchangeAlgorithm::Ffdhe3072
        | KeyExchangeAlgorithm::Ffdhe4096 => Err(Error::UnsupportedAlgorithm(format!(
            "Key exchange algorithm {:?} not yet implemented",
            algorithm
        ))),
    }
}

/// X25519 Elliptic Curve Diffie-Hellman (ECDH) key exchange.
///
/// Implements key exchange using Curve25519 (a Montgomery curve).
/// - Curve: Curve25519
/// - Key size: 32 bytes (256 bits)
/// - Shared secret size: 32 bytes (256 bits)
/// - Security level: ~128 bits
///
/// # Algorithm
///
/// X25519 performs scalar multiplication on Curve25519:
/// ```text
/// shared_secret = private_key * peer_public_key
/// ```
///
/// The curve equation is: y^2 = x^3 + 486662x^2 + x (mod 2^255 - 19)
///
/// # Security
///
/// X25519 is a secure and efficient elliptic curve key exchange algorithm, mandatory
/// for TLS 1.3 compliance. The constant-time implementation provides strong protection
/// against timing and side-channel attacks.
///
/// Key properties:
/// - Constant-time operation (timing attack resistant)
/// - Safe handling of curve cofactor (no invalid point attacks)
/// - Efficient computation with CPU optimizations
/// - Compact 32-byte keys
///
/// # Standards
///
/// - RFC 7748: Elliptic Curves for Security (X25519 and X448)
/// - RFC 8446: TLS 1.3 (mandatory supported group)
/// - FIPS 186-5: Digital Signature Standard (Curve25519 approved)
#[derive(Debug)]
struct X25519Kex;

impl KeyExchange for X25519Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        // Generate random private key
        let rng = HpcryptRandom;
        let mut private_key_bytes = [0u8; 32];
        rng.fill(&mut private_key_bytes)?;

        // Derive public key
        let public_key_bytes = hpcrypt_curves::X25519::public_key(&private_key_bytes);

        Ok((
            PrivateKey::from_bytes(private_key_bytes.to_vec()),
            PublicKey::from_bytes(public_key_bytes.to_vec()),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        // Validate peer public key size
        if peer_public_key.len() != 32 {
            return Err(Error::CryptoError(format!(
                "X25519 public key must be 32 bytes, got {}",
                peer_public_key.len()
            )));
        }

        // Convert to fixed-size arrays
        let private_key_array: [u8; 32] = private_key
            .as_bytes()
            .try_into()
            .map_err(|_| Error::Internal("Invalid private key size".to_string()))?;
        let peer_public_key_array: [u8; 32] = peer_public_key.try_into().unwrap();

        // Perform X25519 ECDH
        let shared_secret =
            hpcrypt_curves::X25519::shared_secret(&private_key_array, &peer_public_key_array)
                .map_err(|e| Error::CryptoError(format!("X25519 exchange failed: {}", e)))?;

        Ok(SharedSecret::from_bytes(shared_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::X25519
    }
}

/// ECDH P-256 key exchange implementation.
///
/// Note: This is a placeholder implementation using low-level P-256 operations.
/// hpcrypt provides P-256 point arithmetic, but we need to implement ECDH ourselves.
#[derive(Debug)]
struct EcdhP256;

impl KeyExchange for EcdhP256 {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        // P-256 ECDH is not yet fully implemented
        Err(Error::UnsupportedAlgorithm(
            "P-256 ECDH temporarily unavailable - hpcrypt API incomplete".to_string(),
        ))
    }

    fn exchange(&self, _private_key: &PrivateKey, _peer_public_key: &[u8]) -> Result<SharedSecret> {
        // P-256 ECDH is not yet fully implemented
        // The hpcrypt-curves API for P-256 point serialization is incomplete
        Err(Error::UnsupportedAlgorithm(
            "P-256 ECDH temporarily unavailable - hpcrypt API incomplete".to_string(),
        ))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::Secp256r1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_keypair_generation() {
        let kex = create_key_exchange(KeyExchangeAlgorithm::X25519).unwrap();

        let (private_key, public_key) = kex.generate_keypair().unwrap();

        assert_eq!(private_key.as_bytes().len(), 32);
        assert_eq!(public_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_x25519_key_exchange() {
        let kex = create_key_exchange(KeyExchangeAlgorithm::X25519).unwrap();

        // Alice generates keypair
        let (alice_private, alice_public) = kex.generate_keypair().unwrap();

        // Bob generates keypair
        let (bob_private, bob_public) = kex.generate_keypair().unwrap();

        // Compute shared secrets
        let alice_shared = kex.exchange(&alice_private, bob_public.as_bytes()).unwrap();
        let bob_shared = kex.exchange(&bob_private, alice_public.as_bytes()).unwrap();

        // Should be equal
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.as_bytes().len(), 32);
    }

    #[test]
    fn test_x25519_invalid_public_key_size() {
        let kex = create_key_exchange(KeyExchangeAlgorithm::X25519).unwrap();
        let (private_key, _) = kex.generate_keypair().unwrap();

        let invalid_public_key = vec![0u8; 16]; // Wrong size

        let result = kex.exchange(&private_key, &invalid_public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_p256_placeholder() {
        // P-256 ECDH is temporarily unavailable due to incomplete hpcrypt API
        let kex = create_key_exchange(KeyExchangeAlgorithm::Secp256r1).unwrap();

        // Should return unsupported error
        let result = kex.generate_keypair();
        assert!(matches!(result, Err(Error::UnsupportedAlgorithm(_))));
    }
}
