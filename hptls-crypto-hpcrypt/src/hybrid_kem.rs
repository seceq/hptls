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
use hpcrypt_mlkem::{KeyPair as MlKemKeyPair, MlKem768, MlKem1024};
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

/// Helper to encapsulate for X448+ML-KEM-1024 hybrid.
pub fn encapsulate_x448_mlkem1024(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if public_key.len() < 56 + 1568 {
        return Err(Error::InvalidPublicKey);
    }

    let (x448_peer, mlkem_encaps_bytes) = public_key.split_at(56);

    // X448 encapsulation (generate ephemeral keypair)
    let mut x448_ephemeral = [0u8; 56];
    hpcrypt_rng::fill_random(&mut x448_ephemeral)
        .map_err(|e| Error::CryptoError(format!("RNG error: {}", e)))?;
    let x448_ephemeral_public = hpcrypt_curves::X448::public_key(&x448_ephemeral);

    let x448_peer_bytes = <[u8; 56]>::try_from(x448_peer)
        .map_err(|_| Error::InvalidPublicKey)?;
    let x448_shared = hpcrypt_curves::X448::shared_secret(&x448_ephemeral, &x448_peer_bytes)
        .map_err(|e| Error::CryptoError(format!("X448 exchange failed: {}", e)))?;

    // ML-KEM-1024 encapsulation using hpcrypt
    let (mlkem_ciphertext, mlkem_shared) = hpcrypt_mlkem::encapsulate::<MlKem1024>(mlkem_encaps_bytes);

    // Build hybrid ciphertext: X448 public (56) || ML-KEM-1024 ciphertext (1568)
    let mut ciphertext = Vec::new();
    ciphertext.extend_from_slice(&x448_ephemeral_public);
    ciphertext.extend_from_slice(&mlkem_ciphertext);

    // Build combined shared secret: X448 (56) || ML-KEM-1024 (32) = 88 bytes
    let mut shared_secret = Zeroizing::new(Vec::new());
    shared_secret.extend_from_slice(&x448_shared);
    shared_secret.extend_from_slice(&mlkem_shared);

    Ok((ciphertext, shared_secret.to_vec()))
}

/// Helper to encapsulate for P-384+ML-KEM-1024 hybrid.
pub fn encapsulate_secp384r1_mlkem1024(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if public_key.len() < 97 + 1568 {
        return Err(Error::InvalidPublicKey);
    }

    let (p384_peer, mlkem_encaps_bytes) = public_key.split_at(97);

    // P-384 encapsulation (generate ephemeral keypair)
    let mut p384_ephemeral = [0u8; 48];
    hpcrypt_rng::fill_random(&mut p384_ephemeral)
        .map_err(|e| Error::CryptoError(format!("RNG error: {}", e)))?;

    use hpcrypt_curves::p384::{Point, FieldElement};
    let ephemeral_point = Point::generator().scalar_mul(&p384_ephemeral);
    let ephemeral_affine = ephemeral_point.to_affine()
        .ok_or_else(|| Error::CryptoError("P-384 ephemeral key generation failed".to_string()))?;

    // SEC1 uncompressed public key
    let mut p384_ephemeral_public = vec![0x04];
    p384_ephemeral_public.extend_from_slice(&ephemeral_affine.x.to_bytes());
    p384_ephemeral_public.extend_from_slice(&ephemeral_affine.y.to_bytes());

    // Parse peer's public key
    if p384_peer[0] != 0x04 || p384_peer.len() != 97 {
        return Err(Error::InvalidPublicKey);
    }

    let x_bytes: [u8; 48] = p384_peer[1..49].try_into().unwrap();
    let y_bytes: [u8; 48] = p384_peer[49..97].try_into().unwrap();

    let x = FieldElement::from_bytes(&x_bytes)
        .ok_or_else(|| Error::InvalidPublicKey)?;
    let y = FieldElement::from_bytes(&y_bytes)
        .ok_or_else(|| Error::InvalidPublicKey)?;

    let peer_point = Point::from_affine(&hpcrypt_curves::p384::AffinePoint { x, y });

    // Perform ECDH
    let shared_point = peer_point.scalar_mul(&p384_ephemeral);
    let shared_affine = shared_point.to_affine()
        .ok_or_else(|| Error::CryptoError("P-384 ECDH resulted in point at infinity".to_string()))?;

    let p384_shared = shared_affine.x.to_bytes();

    // ML-KEM-1024 encapsulation using hpcrypt
    let (mlkem_ciphertext, mlkem_shared) = hpcrypt_mlkem::encapsulate::<MlKem1024>(mlkem_encaps_bytes);

    // Build hybrid ciphertext: P-384 public (97) || ML-KEM-1024 ciphertext (1568)
    let mut ciphertext = Vec::new();
    ciphertext.extend_from_slice(&p384_ephemeral_public);
    ciphertext.extend_from_slice(&mlkem_ciphertext);

    // Build combined shared secret: P-384 (48) || ML-KEM-1024 (32) = 80 bytes
    let mut shared_secret = Zeroizing::new(Vec::new());
    shared_secret.extend_from_slice(&p384_shared);
    shared_secret.extend_from_slice(&mlkem_shared);

    Ok((ciphertext, shared_secret.to_vec()))
}

/// Helper to encapsulate for P-521+ML-KEM-1024 hybrid.
pub fn encapsulate_secp521r1_mlkem1024(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if public_key.len() < 133 + 1568 {
        return Err(Error::InvalidPublicKey);
    }

    let (p521_peer, mlkem_encaps_bytes) = public_key.split_at(133);

    // P-521 encapsulation (generate ephemeral keypair)
    let mut p521_ephemeral = [0u8; 66];
    hpcrypt_rng::fill_random(&mut p521_ephemeral)
        .map_err(|e| Error::CryptoError(format!("RNG error: {}", e)))?;

    use hpcrypt_curves::p521::{Point, Scalar, FieldElement};
    let scalar = Scalar::from_bytes(&p521_ephemeral);
    let ephemeral_point = Point::generator().scalar_mul(&scalar);
    let ephemeral_affine = ephemeral_point.to_affine()
        .ok_or_else(|| Error::CryptoError("P-521 ephemeral key generation failed".to_string()))?;

    // SEC1 uncompressed public key
    let mut p521_ephemeral_public = vec![0x04];
    p521_ephemeral_public.extend_from_slice(&ephemeral_affine.x.to_bytes());
    p521_ephemeral_public.extend_from_slice(&ephemeral_affine.y.to_bytes());

    // Parse peer's public key
    if p521_peer[0] != 0x04 || p521_peer.len() != 133 {
        return Err(Error::InvalidPublicKey);
    }

    let x_bytes: [u8; 66] = p521_peer[1..67].try_into().unwrap();
    let y_bytes: [u8; 66] = p521_peer[67..133].try_into().unwrap();

    let x = FieldElement::from_bytes(&x_bytes)
        .ok_or_else(|| Error::InvalidPublicKey)?;
    let y = FieldElement::from_bytes(&y_bytes)
        .ok_or_else(|| Error::InvalidPublicKey)?;

    let peer_point = Point::from_affine(&x, &y)
        .ok_or_else(|| Error::InvalidPublicKey)?;

    // Perform ECDH
    let ephemeral_scalar = Scalar::from_bytes(&p521_ephemeral);
    let shared_point = peer_point.scalar_mul(&ephemeral_scalar);
    let shared_affine = shared_point.to_affine()
        .ok_or_else(|| Error::CryptoError("P-521 ECDH resulted in point at infinity".to_string()))?;

    let p521_shared = shared_affine.x.to_bytes();

    // ML-KEM-1024 encapsulation using hpcrypt
    let (mlkem_ciphertext, mlkem_shared) = hpcrypt_mlkem::encapsulate::<MlKem1024>(mlkem_encaps_bytes);

    // Build hybrid ciphertext: P-521 public (133) || ML-KEM-1024 ciphertext (1568)
    let mut ciphertext = Vec::new();
    ciphertext.extend_from_slice(&p521_ephemeral_public);
    ciphertext.extend_from_slice(&mlkem_ciphertext);

    // Build combined shared secret: P-521 (66) || ML-KEM-1024 (32) = 98 bytes
    let mut shared_secret = Zeroizing::new(Vec::new());
    shared_secret.extend_from_slice(&p521_shared);
    shared_secret.extend_from_slice(&mlkem_shared);

    Ok((ciphertext, shared_secret.to_vec()))
}

/// X448 + ML-KEM-1024 hybrid key exchange.
///
/// This provides the highest security level hybrid, combining X448 (224-bit security)
/// with ML-KEM-1024 (256-bit post-quantum security).
#[derive(Debug, Clone, Copy)]
pub struct X448MlKem1024Kex;

impl KeyExchange for X448MlKem1024Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        // Generate X448 keypair
        let mut x448_secret = [0u8; 56];
        hpcrypt_rng::fill_random(&mut x448_secret)
            .map_err(|e| Error::CryptoError(format!("RNG error: {}", e)))?;
        let x448_public_bytes = hpcrypt_curves::X448::public_key(&x448_secret);

        // Generate ML-KEM-1024 keypair
        let mlkem_keypair = MlKemKeyPair::generate::<MlKem1024>();

        // Concatenate private keys: X448 (56) || ML-KEM-1024 decaps key
        let mut private_bytes = Vec::new();
        private_bytes.extend_from_slice(&x448_secret);
        private_bytes.extend_from_slice(mlkem_keypair.decapsulation_key());

        // Concatenate public keys: X448 (56) || ML-KEM-1024 encaps key (1568)
        let mut public_bytes = Vec::new();
        public_bytes.extend_from_slice(&x448_public_bytes);
        public_bytes.extend_from_slice(mlkem_keypair.encapsulation_key());

        Ok((
            PrivateKey::from_bytes(private_bytes),
            PublicKey::from_bytes(public_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        // Split peer's public key: X448 (56) || ML-KEM-1024 ciphertext (1568)
        if peer_public_key.len() < 56 {
            return Err(Error::InvalidPublicKey);
        }

        let (x448_peer_public, mlkem_ciphertext) = peer_public_key.split_at(56);

        // Split our private key: X448 (56) || ML-KEM-1024 decaps key
        let private_bytes = private_key.as_bytes();
        if private_bytes.len() < 56 {
            return Err(Error::InvalidPrivateKey);
        }

        let (x448_private, mlkem_decaps_bytes) = private_bytes.split_at(56);

        // Perform X448 exchange
        let x448_secret_bytes = <[u8; 56]>::try_from(x448_private)
            .map_err(|_| Error::InvalidPrivateKey)?;
        let x448_peer_bytes = <[u8; 56]>::try_from(x448_peer_public)
            .map_err(|_| Error::InvalidPublicKey)?;

        let x448_shared = hpcrypt_curves::X448::shared_secret(&x448_secret_bytes, &x448_peer_bytes)
            .map_err(|e| Error::CryptoError(format!("X448 exchange failed: {}", e)))?;

        // Perform ML-KEM-1024 decapsulation
        let mlkem_shared = hpcrypt_mlkem::decapsulate::<MlKem1024>(
            mlkem_decaps_bytes,
            mlkem_ciphertext
        );

        // Concatenate shared secrets: X448 (56) || ML-KEM-1024 (32) = 88 bytes total
        let mut combined_secret = Zeroizing::new(Vec::with_capacity(88));
        combined_secret.extend_from_slice(&x448_shared);
        combined_secret.extend_from_slice(&mlkem_shared);

        Ok(SharedSecret::from_bytes(combined_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::X448MlKem1024
    }
}

/// P-384 + ML-KEM-1024 hybrid key exchange.
///
/// Combines NIST P-384 (192-bit security) with ML-KEM-1024 (256-bit PQ security)
/// for high-security NIST-compliant environments.
#[derive(Debug, Clone, Copy)]
pub struct Secp384r1MlKem1024Kex;

impl KeyExchange for Secp384r1MlKem1024Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        // Generate P-384 keypair using hpcrypt
        let mut p384_secret = [0u8; 48];
        hpcrypt_rng::fill_random(&mut p384_secret)
            .map_err(|e| Error::CryptoError(format!("RNG error: {}", e)))?;

        use hpcrypt_curves::p384::Point;
        let public_point = Point::generator().scalar_mul(&p384_secret);
        let affine = public_point.to_affine()
            .ok_or_else(|| Error::CryptoError("P-384 key generation failed".to_string()))?;

        // SEC1 uncompressed format: 0x04 || x || y
        let mut p384_public = vec![0x04];
        p384_public.extend_from_slice(&affine.x.to_bytes());
        p384_public.extend_from_slice(&affine.y.to_bytes());

        // Generate ML-KEM-1024 keypair
        let mlkem_keypair = MlKemKeyPair::generate::<MlKem1024>();

        // Concatenate private keys: P-384 (48) || ML-KEM-1024 decaps key
        let mut private_bytes = Vec::new();
        private_bytes.extend_from_slice(&p384_secret);
        private_bytes.extend_from_slice(mlkem_keypair.decapsulation_key());

        // Concatenate public keys: P-384 uncompressed (97) || ML-KEM-1024 encaps key (1568)
        let mut public_bytes = Vec::new();
        public_bytes.extend_from_slice(&p384_public);
        public_bytes.extend_from_slice(mlkem_keypair.encapsulation_key());

        Ok((
            PrivateKey::from_bytes(private_bytes),
            PublicKey::from_bytes(public_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        // Split peer's public key: P-384 (97) || ML-KEM-1024 ciphertext (1568)
        if peer_public_key.len() < 97 {
            return Err(Error::InvalidPublicKey);
        }

        let (p384_peer_public, mlkem_ciphertext) = peer_public_key.split_at(97);

        // Split our private key: P-384 (48) || ML-KEM-1024 decaps key
        let private_bytes = private_key.as_bytes();
        if private_bytes.len() < 48 {
            return Err(Error::InvalidPrivateKey);
        }

        let (p384_private, mlkem_decaps_bytes) = private_bytes.split_at(48);

        // Perform P-384 ECDH
        use hpcrypt_curves::p384::{Point, FieldElement};

        // Parse peer public key
        if p384_peer_public[0] != 0x04 || p384_peer_public.len() != 97 {
            return Err(Error::InvalidPublicKey);
        }

        let x_bytes: [u8; 48] = p384_peer_public[1..49].try_into().unwrap();
        let y_bytes: [u8; 48] = p384_peer_public[49..97].try_into().unwrap();

        let x = FieldElement::from_bytes(&x_bytes)
            .ok_or_else(|| Error::InvalidPublicKey)?;
        let y = FieldElement::from_bytes(&y_bytes)
            .ok_or_else(|| Error::InvalidPublicKey)?;

        let peer_point = Point::from_affine(&hpcrypt_curves::p384::AffinePoint { x, y });

        // Perform scalar multiplication
        let p384_secret_array: [u8; 48] = p384_private.try_into()
            .map_err(|_| Error::InvalidPrivateKey)?;

        let shared_point = peer_point.scalar_mul(&p384_secret_array);
        let shared_affine = shared_point.to_affine()
            .ok_or_else(|| Error::CryptoError("P-384 ECDH resulted in point at infinity".to_string()))?;

        let p384_shared = shared_affine.x.to_bytes();

        // Perform ML-KEM-1024 decapsulation
        let mlkem_shared = hpcrypt_mlkem::decapsulate::<MlKem1024>(
            mlkem_decaps_bytes,
            mlkem_ciphertext
        );

        // Concatenate shared secrets: P-384 (48) || ML-KEM-1024 (32) = 80 bytes total
        let mut combined_secret = Zeroizing::new(Vec::with_capacity(80));
        combined_secret.extend_from_slice(&p384_shared);
        combined_secret.extend_from_slice(&mlkem_shared);

        Ok(SharedSecret::from_bytes(combined_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::Secp384r1MlKem1024
    }
}

/// P-521 + ML-KEM-1024 hybrid key exchange.
///
/// Maximum security hybrid combining P-521 (260-bit security) with ML-KEM-1024 (256-bit PQ security).
#[derive(Debug, Clone, Copy)]
pub struct Secp521r1MlKem1024Kex;

impl KeyExchange for Secp521r1MlKem1024Kex {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey)> {
        // Generate P-521 keypair using hpcrypt
        let mut p521_secret = [0u8; 66];
        hpcrypt_rng::fill_random(&mut p521_secret)
            .map_err(|e| Error::CryptoError(format!("RNG error: {}", e)))?;

        use hpcrypt_curves::p521::{Point, Scalar};
        let scalar = Scalar::from_bytes(&p521_secret);
        let public_point = Point::generator().scalar_mul(&scalar);
        let affine = public_point.to_affine()
            .ok_or_else(|| Error::CryptoError("P-521 key generation failed".to_string()))?;

        // SEC1 uncompressed format: 0x04 || x || y
        let mut p521_public = vec![0x04];
        p521_public.extend_from_slice(&affine.x.to_bytes());
        p521_public.extend_from_slice(&affine.y.to_bytes());

        // Generate ML-KEM-1024 keypair
        let mlkem_keypair = MlKemKeyPair::generate::<MlKem1024>();

        // Concatenate private keys: P-521 (66) || ML-KEM-1024 decaps key
        let mut private_bytes = Vec::new();
        private_bytes.extend_from_slice(&p521_secret);
        private_bytes.extend_from_slice(mlkem_keypair.decapsulation_key());

        // Concatenate public keys: P-521 uncompressed (133) || ML-KEM-1024 encaps key (1568)
        let mut public_bytes = Vec::new();
        public_bytes.extend_from_slice(&p521_public);
        public_bytes.extend_from_slice(mlkem_keypair.encapsulation_key());

        Ok((
            PrivateKey::from_bytes(private_bytes),
            PublicKey::from_bytes(public_bytes),
        ))
    }

    fn exchange(&self, private_key: &PrivateKey, peer_public_key: &[u8]) -> Result<SharedSecret> {
        // Split peer's public key: P-521 (133) || ML-KEM-1024 ciphertext (1568)
        if peer_public_key.len() < 133 {
            return Err(Error::InvalidPublicKey);
        }

        let (p521_peer_public, mlkem_ciphertext) = peer_public_key.split_at(133);

        // Split our private key: P-521 (66) || ML-KEM-1024 decaps key
        let private_bytes = private_key.as_bytes();
        if private_bytes.len() < 66 {
            return Err(Error::InvalidPrivateKey);
        }

        let (p521_private, mlkem_decaps_bytes) = private_bytes.split_at(66);

        // Perform P-521 ECDH
        use hpcrypt_curves::p521::{Point, Scalar, FieldElement};

        // Parse peer public key
        if p521_peer_public[0] != 0x04 || p521_peer_public.len() != 133 {
            return Err(Error::InvalidPublicKey);
        }

        let x_bytes: [u8; 66] = p521_peer_public[1..67].try_into().unwrap();
        let y_bytes: [u8; 66] = p521_peer_public[67..133].try_into().unwrap();

        let x = FieldElement::from_bytes(&x_bytes)
            .ok_or_else(|| Error::InvalidPublicKey)?;
        let y = FieldElement::from_bytes(&y_bytes)
            .ok_or_else(|| Error::InvalidPublicKey)?;

        let peer_point = Point::from_affine(&x, &y)
            .ok_or_else(|| Error::InvalidPublicKey)?;

        // Perform scalar multiplication
        let p521_secret_array: [u8; 66] = p521_private.try_into()
            .map_err(|_| Error::InvalidPrivateKey)?;
        let scalar = Scalar::from_bytes(&p521_secret_array);

        let shared_point = peer_point.scalar_mul(&scalar);
        let shared_affine = shared_point.to_affine()
            .ok_or_else(|| Error::CryptoError("P-521 ECDH resulted in point at infinity".to_string()))?;

        let p521_shared = shared_affine.x.to_bytes();

        // Perform ML-KEM-1024 decapsulation
        let mlkem_shared = hpcrypt_mlkem::decapsulate::<MlKem1024>(
            mlkem_decaps_bytes,
            mlkem_ciphertext
        );

        // Concatenate shared secrets: P-521 (66) || ML-KEM-1024 (32) = 98 bytes total
        let mut combined_secret = Zeroizing::new(Vec::with_capacity(98));
        combined_secret.extend_from_slice(&p521_shared);
        combined_secret.extend_from_slice(&mlkem_shared);

        Ok(SharedSecret::from_bytes(combined_secret.to_vec()))
    }

    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::Secp521r1MlKem1024
    }
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

        let x448_kex = X448MlKem1024Kex;
        let (_, x448_pk) = x448_kex.generate_keypair().unwrap();
        assert_eq!(x448_pk.as_bytes().len(), 56 + 1568); // 1624 bytes

        let p384_kex = Secp384r1MlKem1024Kex;
        let (_, p384_pk) = p384_kex.generate_keypair().unwrap();
        assert_eq!(p384_pk.as_bytes().len(), 97 + 1568); // 1665 bytes

        let p521_kex = Secp521r1MlKem1024Kex;
        let (_, p521_pk) = p521_kex.generate_keypair().unwrap();
        assert_eq!(p521_pk.as_bytes().len(), 133 + 1568); // 1701 bytes
    }

    #[test]
    fn test_x448_mlkem1024_roundtrip() {
        let kex = X448MlKem1024Kex;

        // Generate keypair
        let (private_key, public_key) = kex.generate_keypair().unwrap();

        // Encapsulate
        let (ciphertext, expected_secret) =
            encapsulate_x448_mlkem1024(public_key.as_bytes()).unwrap();

        // Decapsulate
        let shared_secret = kex.exchange(&private_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), expected_secret.as_slice());
        assert_eq!(shared_secret.as_bytes().len(), 88); // 56 + 32
    }

    #[test]
    fn test_secp384r1_mlkem1024_roundtrip() {
        let kex = Secp384r1MlKem1024Kex;

        let (private_key, public_key) = kex.generate_keypair().unwrap();
        let (ciphertext, expected_secret) =
            encapsulate_secp384r1_mlkem1024(public_key.as_bytes()).unwrap();
        let shared_secret = kex.exchange(&private_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), expected_secret.as_slice());
        assert_eq!(shared_secret.as_bytes().len(), 80); // 48 + 32
    }

    #[test]
    fn test_secp521r1_mlkem1024_roundtrip() {
        let kex = Secp521r1MlKem1024Kex;

        let (private_key, public_key) = kex.generate_keypair().unwrap();
        let (ciphertext, expected_secret) =
            encapsulate_secp521r1_mlkem1024(public_key.as_bytes()).unwrap();
        let shared_secret = kex.exchange(&private_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), expected_secret.as_slice());
        assert_eq!(shared_secret.as_bytes().len(), 98); // 66 + 32
    }
}
