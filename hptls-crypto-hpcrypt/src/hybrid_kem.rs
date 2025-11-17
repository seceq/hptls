//! Hybrid key exchange combining classical and post-quantum algorithms.
//!
//! Hybrid key exchange provides a smooth transition to post-quantum
//! cryptography by combining:
//! - Classical algorithms (X25519, P-256) for backward compatibility
//! - PQC algorithms (ML-KEM) for quantum resistance
//!
//! The shared secret is the concatenation of both algorithms' outputs.

use hptls_crypto::{
    key_exchange::{KeyExchange, KeyExchangeAlgorithm, PrivateKey, PublicKey, SharedSecret},
    Error, Result,
};
use hpcrypt_mlkem::{KeyPair as MlKemKeyPair, MlKem768};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use x25519_dalek::x25519;
use zeroize::Zeroizing;

/// X25519 + ML-KEM-768 hybrid key exchange.
///
/// This is the recommended hybrid algorithm for most use cases,
/// combining the widely-deployed X25519 with ML-KEM-768.
#[derive(Debug, Clone, Copy)]
pub struct X25519MlKem768Kex;

impl KeyExchange for X25519MlKem768Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        // Generate X25519 keypair using raw bytes
        let mut x25519_secret = [0u8; 32];
        rand::Rng::fill(&mut rand::rngs::OsRng, &mut x25519_secret);
        let x25519_public_bytes = x25519(x25519_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

        // Generate ML-KEM-768 keypair
        let mlkem_keypair = MlKemKeyPair::generate::<MlKem768>();

        // Concatenate private keys: X25519 (32) || ML-KEM-768 decaps key
        let mut private_bytes = Vec::new();
        private_bytes.extend_from_slice(&x25519_secret);
        private_bytes.extend_from_slice(mlkem_keypair.decapsulation_key());

        // Concatenate public keys: X25519 (32) || ML-KEM-768 encaps key (1184)
        let mut public_bytes = Vec::new();
        public_bytes.extend_from_slice(&x25519_public_bytes);
        public_bytes.extend_from_slice(mlkem_keypair.encapsulation_key());

        Ok((
            PrivateKey::from_bytes(private_bytes),
            PublicKey::from_bytes(public_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        // Split peer's public key: X25519 (32) || ML-KEM-768 ciphertext (1088)
        if peer_public_key.len() < 32 {
            return Err(Error::InvalidPublicKey);
        }

        let (x25519_peer_public, mlkem_ciphertext) = peer_public_key.split_at(32);

        // Split our private key: X25519 (32) || ML-KEM-768 decaps key
        let private_bytes = private_key.as_bytes();
        if private_bytes.len() < 32 {
            return Err(Error::InvalidPrivateKey);
        }

        let (x25519_private, mlkem_decaps_bytes) = private_bytes.split_at(32);

        // Perform X25519 exchange using raw function
        let x25519_secret_bytes = <[u8; 32]>::try_from(x25519_private)
            .map_err(|_| Error::InvalidPrivateKey)?;
        let x25519_peer_bytes = <[u8; 32]>::try_from(x25519_peer_public)
            .map_err(|_| Error::InvalidPublicKey)?;
        let x25519_shared = x25519(x25519_secret_bytes, x25519_peer_bytes);

        // Perform ML-KEM-768 decapsulation using hpcrypt
        let mlkem_shared = hpcrypt_mlkem::decapsulate::<MlKem768>(
            mlkem_decaps_bytes,
            mlkem_ciphertext
        );

        // Concatenate shared secrets: X25519 (32) || ML-KEM-768 (32) = 64 bytes total
        let mut combined_secret = Zeroizing::new(Vec::with_capacity(64));
        combined_secret.extend_from_slice(&x25519_shared);
        combined_secret.extend_from_slice(&mlkem_shared);

        Ok(SharedSecret::from_bytes(combined_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::X25519MlKem768
    }
}

/// P-256 + ML-KEM-768 hybrid key exchange.
///
/// This combines NIST P-256 with ML-KEM-768 for environments
/// that require NIST-standardized classical algorithms.
#[derive(Debug, Clone, Copy)]
pub struct Secp256r1MlKem768Kex;

impl KeyExchange for Secp256r1MlKem768Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        // Generate P-256 keypair
        let p256_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let p256_public = p256_secret.public_key();

        // Generate ML-KEM-768 keypair
        let mlkem_keypair = MlKemKeyPair::generate::<MlKem768>();

        // Concatenate private keys: P-256 (32) || ML-KEM-768 decaps key
        let mut private_bytes = Vec::new();
        private_bytes.extend_from_slice(&p256_secret.to_bytes());
        private_bytes.extend_from_slice(mlkem_keypair.decapsulation_key());

        // Concatenate public keys: P-256 uncompressed (65) || ML-KEM-768 encaps key (1184)
        let mut public_bytes = Vec::new();
        let p256_public_uncompressed = p256_public.to_encoded_point(false);
        public_bytes.extend_from_slice(p256_public_uncompressed.as_bytes());
        public_bytes.extend_from_slice(mlkem_keypair.encapsulation_key());

        Ok((
            PrivateKey::from_bytes(private_bytes),
            PublicKey::from_bytes(public_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        // Split peer's public key: P-256 (65) || ML-KEM-768 ciphertext (1088)
        if peer_public_key.len() < 65 {
            return Err(Error::InvalidPublicKey);
        }

        let (p256_peer_public, mlkem_ciphertext) = peer_public_key.split_at(65);

        // Split our private key: P-256 (32) || ML-KEM-768 decaps key
        let private_bytes = private_key.as_bytes();
        if private_bytes.len() < 32 {
            return Err(Error::InvalidPrivateKey);
        }

        let (p256_private, mlkem_decaps_bytes) = private_bytes.split_at(32);

        // Perform P-256 ECDH
        let p256_secret = p256::SecretKey::from_slice(p256_private)
            .map_err(|_| Error::InvalidPrivateKey)?;

        let p256_peer_pk = p256::PublicKey::from_sec1_bytes(p256_peer_public)
            .map_err(|_| Error::InvalidPublicKey)?;

        let p256_shared = p256::ecdh::diffie_hellman(
            p256_secret.to_nonzero_scalar(),
            p256_peer_pk.as_affine(),
        );

        // Perform ML-KEM-768 decapsulation using hpcrypt
        let mlkem_shared = hpcrypt_mlkem::decapsulate::<MlKem768>(
            mlkem_decaps_bytes,
            mlkem_ciphertext
        );

        // Concatenate shared secrets: P-256 (32) || ML-KEM-768 (32) = 64 bytes total
        let mut combined_secret = Zeroizing::new(Vec::with_capacity(64));
        combined_secret.extend_from_slice(p256_shared.raw_secret_bytes());
        combined_secret.extend_from_slice(&mlkem_shared);

        Ok(SharedSecret::from_bytes(combined_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::Secp256r1MlKem768
    }
}

/// Helper to encapsulate for X25519+ML-KEM-768 hybrid.
///
/// Takes a hybrid public key (X25519 || ML-KEM-768 encaps key) and
/// produces a hybrid ciphertext (X25519 public || ML-KEM-768 ciphertext).
pub fn encapsulate_x25519_mlkem768(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if public_key.len() < 32 + 1184 {
        return Err(Error::InvalidPublicKey);
    }

    let (x25519_peer, mlkem_encaps_bytes) = public_key.split_at(32);

    // X25519 encapsulation (generate ephemeral keypair using raw bytes)
    let mut x25519_ephemeral = [0u8; 32];
    rand::Rng::fill(&mut rand::rngs::OsRng, &mut x25519_ephemeral);
    let x25519_ephemeral_public = x25519(x25519_ephemeral, x25519_dalek::X25519_BASEPOINT_BYTES);

    let x25519_peer_bytes = <[u8; 32]>::try_from(x25519_peer)
        .map_err(|_| Error::InvalidPublicKey)?;
    let x25519_shared = x25519(x25519_ephemeral, x25519_peer_bytes);

    // ML-KEM-768 encapsulation using hpcrypt
    let (mlkem_ciphertext, mlkem_shared) = hpcrypt_mlkem::encapsulate::<MlKem768>(mlkem_encaps_bytes);

    // Build hybrid ciphertext: X25519 public (32) || ML-KEM-768 ciphertext (1088)
    let mut ciphertext = Vec::new();
    ciphertext.extend_from_slice(&x25519_ephemeral_public);
    ciphertext.extend_from_slice(&mlkem_ciphertext);

    // Build combined shared secret: X25519 (32) || ML-KEM-768 (32)
    let mut shared_secret = Zeroizing::new(Vec::new());
    shared_secret.extend_from_slice(&x25519_shared);
    shared_secret.extend_from_slice(&mlkem_shared);

    Ok((ciphertext, shared_secret.to_vec()))
}

/// Helper to encapsulate for P-256+ML-KEM-768 hybrid.
pub fn encapsulate_secp256r1_mlkem768(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if public_key.len() < 65 + 1184 {
        return Err(Error::InvalidPublicKey);
    }

    let (p256_peer, mlkem_encaps_bytes) = public_key.split_at(65);

    // P-256 encapsulation (generate ephemeral keypair)
    let p256_ephemeral = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let p256_ephemeral_public = p256_ephemeral.public_key();

    let p256_peer_pk = p256::PublicKey::from_sec1_bytes(p256_peer)
        .map_err(|_| Error::InvalidPublicKey)?;

    let p256_shared = p256::ecdh::diffie_hellman(
        p256_ephemeral.to_nonzero_scalar(),
        p256_peer_pk.as_affine(),
    );

    // ML-KEM-768 encapsulation using hpcrypt
    let (mlkem_ciphertext, mlkem_shared) = hpcrypt_mlkem::encapsulate::<MlKem768>(mlkem_encaps_bytes);

    // Build hybrid ciphertext: P-256 public (65) || ML-KEM-768 ciphertext (1088)
    let mut ciphertext = Vec::new();
    let p256_ephemeral_encoded = p256_ephemeral_public.to_encoded_point(false);
    ciphertext.extend_from_slice(p256_ephemeral_encoded.as_bytes());
    ciphertext.extend_from_slice(&mlkem_ciphertext);

    // Build combined shared secret: P-256 (32) || ML-KEM-768 (32)
    let mut shared_secret = Zeroizing::new(Vec::new());
    shared_secret.extend_from_slice(p256_shared.raw_secret_bytes());
    shared_secret.extend_from_slice(&mlkem_shared);

    Ok((ciphertext, shared_secret.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_mlkem768_roundtrip() {
        let kex = X25519MlKem768Kex;

        // Generate keypair
        let (private_key, public_key) = kex.generate_keypair().unwrap();

        // Encapsulate
        let (ciphertext, expected_secret) =
            encapsulate_x25519_mlkem768(public_key.as_bytes()).unwrap();

        // Decapsulate
        let shared_secret = kex.exchange(&private_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), expected_secret.as_slice());
        assert_eq!(shared_secret.as_bytes().len(), 64); // 32 + 32
    }

    #[test]
    fn test_secp256r1_mlkem768_roundtrip() {
        let kex = Secp256r1MlKem768Kex;

        let (private_key, public_key) = kex.generate_keypair().unwrap();
        let (ciphertext, expected_secret) =
            encapsulate_secp256r1_mlkem768(public_key.as_bytes()).unwrap();
        let shared_secret = kex.exchange(&private_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), expected_secret.as_slice());
        assert_eq!(shared_secret.as_bytes().len(), 64); // 32 + 32
    }

    #[test]
    fn test_hybrid_public_key_sizes() {
        let x25519_kex = X25519MlKem768Kex;
        let (_, x25519_pk) = x25519_kex.generate_keypair().unwrap();
        assert_eq!(x25519_pk.as_bytes().len(), 32 + 1184);

        let p256_kex = Secp256r1MlKem768Kex;
        let (_, p256_pk) = p256_kex.generate_keypair().unwrap();
        assert_eq!(p256_pk.as_bytes().len(), 65 + 1184);
    }
}
