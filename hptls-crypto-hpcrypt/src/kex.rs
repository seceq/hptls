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
        KeyExchangeAlgorithm::X448MlKem1024 => Ok(Box::new(crate::hybrid_kem::X448MlKem1024Kex)),
        KeyExchangeAlgorithm::Secp384r1MlKem1024 => Ok(Box::new(crate::hybrid_kem::Secp384r1MlKem1024Kex)),
        KeyExchangeAlgorithm::Secp521r1MlKem1024 => Ok(Box::new(crate::hybrid_kem::Secp521r1MlKem1024Kex)),

        // Additional curves
        KeyExchangeAlgorithm::X448 => Ok(Box::new(X448Kex)),
        KeyExchangeAlgorithm::Secp384r1 => Ok(Box::new(EcdhP384)),
        KeyExchangeAlgorithm::Secp521r1 => Ok(Box::new(EcdhP521)),

        // FFDHE not yet implemented
        KeyExchangeAlgorithm::Ffdhe2048
        | KeyExchangeAlgorithm::Ffdhe3072
        | KeyExchangeAlgorithm::Ffdhe4096 => Err(Error::UnsupportedAlgorithm(format!(
            "Key exchange algorithm {:?} - FFDHE not yet implemented",
            algorithm
        ))),
    }
}

/// X25519 key exchange implementation.
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

/// X448 key exchange implementation.
#[derive(Debug)]
struct X448Kex;

impl KeyExchange for X448Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        // Generate random private key
        let rng = HpcryptRandom;
        let mut private_key_bytes = [0u8; 56];
        rng.fill(&mut private_key_bytes)?;

        // Derive public key
        let public_key_bytes = hpcrypt_curves::X448::public_key(&private_key_bytes);

        Ok((
            PrivateKey::from_bytes(private_key_bytes.to_vec()),
            PublicKey::from_bytes(public_key_bytes.to_vec()),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        // Validate peer public key size
        if peer_public_key.len() != 56 {
            return Err(Error::CryptoError(format!(
                "X448 public key must be 56 bytes, got {}",
                peer_public_key.len()
            )));
        }

        // Convert to fixed-size arrays
        let private_key_array: [u8; 56] = private_key
            .as_bytes()
            .try_into()
            .map_err(|_| Error::Internal("Invalid private key size".to_string()))?;
        let peer_public_key_array: [u8; 56] = peer_public_key.try_into().unwrap();

        // Perform X448 ECDH
        let shared_secret =
            hpcrypt_curves::X448::shared_secret(&private_key_array, &peer_public_key_array)
                .map_err(|e| Error::CryptoError(format!("X448 exchange failed: {}", e)))?;

        Ok(SharedSecret::from_bytes(shared_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::X448
    }
}

/// ECDH P-384 key exchange implementation.
#[derive(Debug)]
struct EcdhP384;

impl KeyExchange for EcdhP384 {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        use hpcrypt_curves::p384::Point;

        // Generate random private key (384 bits = 48 bytes)
        let rng = HpcryptRandom;
        let mut private_key_bytes = [0u8; 48];
        rng.fill(&mut private_key_bytes)?;

        // Derive public key: Q = d * G
        let generator = Point::generator();
        let public_point = generator.scalar_mul(&private_key_bytes);

        // Convert to uncompressed SEC1 format (0x04 || x || y)
        let affine = public_point.to_affine().ok_or(Error::CryptoError(
            "P-384 key generation resulted in point at infinity".to_string(),
        ))?;

        let mut public_key_bytes = vec![0x04]; // Uncompressed point prefix
        public_key_bytes.extend_from_slice(&affine.x.to_bytes());
        public_key_bytes.extend_from_slice(&affine.y.to_bytes());

        Ok((
            PrivateKey::from_bytes(private_key_bytes.to_vec()),
            PublicKey::from_bytes(public_key_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        use hpcrypt_curves::p384::{AffinePoint, FieldElement, Point};

        // Validate peer public key size (1 + 48 + 48 = 97 bytes for uncompressed)
        if peer_public_key.len() != 97 {
            return Err(Error::CryptoError(format!(
                "P-384 public key must be 97 bytes (uncompressed), got {}",
                peer_public_key.len()
            )));
        }

        // Validate uncompressed format
        if peer_public_key[0] != 0x04 {
            return Err(Error::CryptoError(
                "P-384 public key must be uncompressed (0x04 prefix)".to_string(),
            ));
        }

        // Parse peer public key (FieldElement::from_bytes returns Option)
        let x_bytes: [u8; 48] = peer_public_key[1..49].try_into().unwrap();
        let y_bytes: [u8; 48] = peer_public_key[49..97].try_into().unwrap();

        let x = FieldElement::from_bytes(&x_bytes).ok_or(Error::CryptoError(
            "P-384 peer public key x-coordinate is invalid".to_string(),
        ))?;
        let y = FieldElement::from_bytes(&y_bytes).ok_or(Error::CryptoError(
            "P-384 peer public key y-coordinate is invalid".to_string(),
        ))?;

        let affine_peer = AffinePoint { x, y };
        let peer_point = Point::from_affine(&affine_peer);

        // Convert private key to scalar
        let private_key_array: [u8; 48] = private_key
            .as_bytes()
            .try_into()
            .map_err(|_| Error::Internal("Invalid private key size".to_string()))?;

        // Compute shared secret: S = d * Q
        let shared_point = peer_point.scalar_mul(&private_key_array);
        let shared_affine = shared_point.to_affine().ok_or(Error::CryptoError(
            "P-384 key exchange resulted in point at infinity".to_string(),
        ))?;

        // Use x-coordinate as shared secret (standard ECDH)
        let shared_secret = shared_affine.x.to_bytes();

        Ok(SharedSecret::from_bytes(shared_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::Secp384r1
    }
}

/// ECDH P-521 key exchange implementation.
#[derive(Debug)]
struct EcdhP521;

impl KeyExchange for EcdhP521 {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        use hpcrypt_curves::p521::{Point, Scalar};

        // Generate random private key (521 bits = 66 bytes)
        let rng = HpcryptRandom;
        let mut private_key_bytes = [0u8; 66];
        rng.fill(&mut private_key_bytes)?;

        // Derive public key: Q = d * G
        let generator = Point::generator();
        let scalar = Scalar::from_bytes(&private_key_bytes);
        let public_point = generator.scalar_mul(&scalar);

        // Convert to uncompressed SEC1 format (0x04 || x || y)
        let affine = public_point.to_affine().ok_or(Error::CryptoError(
            "P-521 key generation resulted in point at infinity".to_string(),
        ))?;

        let mut public_key_bytes = vec![0x04]; // Uncompressed point prefix
        public_key_bytes.extend_from_slice(&affine.x.to_bytes());
        public_key_bytes.extend_from_slice(&affine.y.to_bytes());

        Ok((
            PrivateKey::from_bytes(private_key_bytes.to_vec()),
            PublicKey::from_bytes(public_key_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        use hpcrypt_curves::p521::{FieldElement, Point, Scalar};

        // Validate peer public key size (1 + 66 + 66 = 133 bytes for uncompressed)
        if peer_public_key.len() != 133 {
            return Err(Error::CryptoError(format!(
                "P-521 public key must be 133 bytes (uncompressed), got {}",
                peer_public_key.len()
            )));
        }

        // Validate uncompressed format
        if peer_public_key[0] != 0x04 {
            return Err(Error::CryptoError(
                "P-521 public key must be uncompressed (0x04 prefix)".to_string(),
            ));
        }

        // Parse peer public key - P-521 uses Point::from_affine(&x, &y) not AffinePoint struct
        let x_bytes: [u8; 66] = peer_public_key[1..67].try_into().unwrap();
        let y_bytes: [u8; 66] = peer_public_key[67..133].try_into().unwrap();

        let x = FieldElement::from_bytes(&x_bytes).ok_or(Error::CryptoError(
            "P-521 peer public key x-coordinate is invalid".to_string(),
        ))?;
        let y = FieldElement::from_bytes(&y_bytes).ok_or(Error::CryptoError(
            "P-521 peer public key y-coordinate is invalid".to_string(),
        ))?;

        // P-521 Point::from_affine takes (&FieldElement, &FieldElement) and returns Option<Point>
        let peer_point = Point::from_affine(&x, &y).ok_or(Error::CryptoError(
            "P-521 peer public key is not a valid curve point".to_string(),
        ))?;

        // Convert private key to scalar
        let private_key_array: [u8; 66] = private_key
            .as_bytes()
            .try_into()
            .map_err(|_| Error::Internal("Invalid private key size".to_string()))?;
        let scalar = Scalar::from_bytes(&private_key_array);

        // Compute shared secret: S = d * Q
        let shared_point = peer_point.scalar_mul(&scalar);
        let shared_affine = shared_point.to_affine().ok_or(Error::CryptoError(
            "P-521 key exchange resulted in point at infinity".to_string(),
        ))?;

        // Use x-coordinate as shared secret (standard ECDH)
        let shared_secret = shared_affine.x.to_bytes();

        Ok(SharedSecret::from_bytes(shared_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::Secp521r1
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
