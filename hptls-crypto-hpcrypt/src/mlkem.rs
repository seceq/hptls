//! ML-KEM (FIPS 203) key encapsulation mechanism implementation using hpcrypt.
//!
//! ML-KEM provides post-quantum secure key encapsulation with three security levels:
//! - ML-KEM-512: 128-bit classical security equivalent
//! - ML-KEM-768: 192-bit classical security equivalent (recommended)
//! - ML-KEM-1024: 256-bit classical security equivalent

use hptls_crypto::{
    key_exchange::{KeyExchange, KeyExchangeAlgorithm, PrivateKey, PublicKey, SharedSecret},
    Result,
};
use hpcrypt_mlkem::{KeyPair, MlKem512, MlKem768, MlKem1024};

/// ML-KEM-512 key exchange (128-bit security).
#[derive(Debug, Clone, Copy)]
pub struct MlKem512Kex;

impl KeyExchange for MlKem512Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        let keypair = KeyPair::generate::<MlKem512>();

        let private_bytes = keypair.decapsulation_key().to_vec();
        let public_bytes = keypair.encapsulation_key().to_vec();

        Ok((
            PrivateKey::from_bytes(private_bytes),
            PublicKey::from_bytes(public_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        // Decapsulate using hpcrypt's decapsulate function
        let shared_secret = hpcrypt_mlkem::decapsulate::<MlKem512>(
            private_key.as_bytes(),
            peer_public_key
        );

        Ok(SharedSecret::from_bytes(shared_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::MlKem512
    }
}

/// ML-KEM-768 key exchange (192-bit security, recommended).
#[derive(Debug, Clone, Copy)]
pub struct MlKem768Kex;

impl KeyExchange for MlKem768Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        let keypair = KeyPair::generate::<MlKem768>();

        let private_bytes = keypair.decapsulation_key().to_vec();
        let public_bytes = keypair.encapsulation_key().to_vec();

        Ok((
            PrivateKey::from_bytes(private_bytes),
            PublicKey::from_bytes(public_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        let shared_secret = hpcrypt_mlkem::decapsulate::<MlKem768>(
            private_key.as_bytes(),
            peer_public_key
        );

        Ok(SharedSecret::from_bytes(shared_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::MlKem768
    }
}

/// ML-KEM-1024 key exchange (256-bit security).
#[derive(Debug, Clone, Copy)]
pub struct MlKem1024Kex;

impl KeyExchange for MlKem1024Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        let keypair = KeyPair::generate::<MlKem1024>();

        let private_bytes = keypair.decapsulation_key().to_vec();
        let public_bytes = keypair.encapsulation_key().to_vec();

        Ok((
            PrivateKey::from_bytes(private_bytes),
            PublicKey::from_bytes(public_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        let shared_secret = hpcrypt_mlkem::decapsulate::<MlKem1024>(
            private_key.as_bytes(),
            peer_public_key
        );

        Ok(SharedSecret::from_bytes(shared_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::MlKem1024
    }
}

/// Helper to create a KEM encapsulation for the peer.
///
/// In TLS, the client generates a keypair and sends the public key,
/// then the server encapsulates using that public key to generate
/// the ciphertext and shared secret.
pub fn encapsulate_mlkem512(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (ciphertext, shared_secret) = hpcrypt_mlkem::encapsulate::<MlKem512>(public_key);

    Ok((
        ciphertext,
        shared_secret.to_vec(),
    ))
}

/// Helper to create a KEM encapsulation for ML-KEM-768.
pub fn encapsulate_mlkem768(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (ciphertext, shared_secret) = hpcrypt_mlkem::encapsulate::<MlKem768>(public_key);

    Ok((
        ciphertext,
        shared_secret.to_vec(),
    ))
}

/// Helper to create a KEM encapsulation for ML-KEM-1024.
pub fn encapsulate_mlkem1024(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (ciphertext, shared_secret) = hpcrypt_mlkem::encapsulate::<MlKem1024>(public_key);

    Ok((
        ciphertext,
        shared_secret.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem512_roundtrip() {
        let kex = MlKem512Kex;

        // Generate keypair
        let (private_key, public_key) = kex.generate_keypair().unwrap();

        // Encapsulate
        let (ciphertext, expected_secret) = encapsulate_mlkem512(public_key.as_bytes()).unwrap();

        // Decapsulate
        let shared_secret = kex.exchange(&private_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), expected_secret.as_slice());
    }

    #[test]
    fn test_mlkem768_roundtrip() {
        let kex = MlKem768Kex;

        let (private_key, public_key) = kex.generate_keypair().unwrap();
        let (ciphertext, expected_secret) = encapsulate_mlkem768(public_key.as_bytes()).unwrap();
        let shared_secret = kex.exchange(&private_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), expected_secret.as_slice());
    }

    #[test]
    fn test_mlkem1024_roundtrip() {
        let kex = MlKem1024Kex;

        let (private_key, public_key) = kex.generate_keypair().unwrap();
        let (ciphertext, expected_secret) = encapsulate_mlkem1024(public_key.as_bytes()).unwrap();
        let shared_secret = kex.exchange(&private_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), expected_secret.as_slice());
    }

    #[test]
    fn test_public_key_sizes() {
        let kex512 = MlKem512Kex;
        let (_, pk512) = kex512.generate_keypair().unwrap();
        assert_eq!(pk512.as_bytes().len(), 800);

        let kex768 = MlKem768Kex;
        let (_, pk768) = kex768.generate_keypair().unwrap();
        assert_eq!(pk768.as_bytes().len(), 1184);

        let kex1024 = MlKem1024Kex;
        let (_, pk1024) = kex1024.generate_keypair().unwrap();
        assert_eq!(pk1024.as_bytes().len(), 1568);
    }
}
