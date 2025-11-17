//! Digital signature implementations using hpcrypt.

use hptls_crypto::signature::{SigningKey, VerifyingKey};
use hptls_crypto::{Error, Result, Signature, SignatureAlgorithm};

// RSA PSS support
use hpcrypt_rsa::RsaPrivateKey;

/// Hash adapter for RSA-PSS using hpcrypt SHA-256
#[allow(dead_code)]
struct PssHashSha256;

impl hpcrypt_rsa::pss::PssHash for PssHashSha256 {
    fn output_size() -> usize {
        32
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        hpcrypt_hash::sha256::sha256(input).to_vec()
    }
}

/// Hash adapter for RSA-PSS using hpcrypt SHA-384
#[allow(dead_code)]
struct PssHashSha384;

impl hpcrypt_rsa::pss::PssHash for PssHashSha384 {
    fn output_size() -> usize {
        48
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        hpcrypt_hash::sha384::sha384(input).to_vec()
    }
}

/// Hash adapter for RSA-PSS using hpcrypt SHA-512
#[allow(dead_code)]
struct PssHashSha512;

impl hpcrypt_rsa::pss::PssHash for PssHashSha512 {
    fn output_size() -> usize {
        64
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        hpcrypt_hash::sha512::sha512(input).to_vec()
    }
}

/// Create a signature instance for the specified algorithm.
pub fn create_signature(algorithm: SignatureAlgorithm) -> Result<Box<dyn Signature>> {
    match algorithm {
        // Classical signatures
        SignatureAlgorithm::Ed25519 => Ok(Box::new(Ed25519Sig)),
        SignatureAlgorithm::EcdsaSecp256r1Sha256 => Ok(Box::new(EcdsaP256Sig)),
        SignatureAlgorithm::EcdsaSecp384r1Sha384 => Ok(Box::new(EcdsaP384Sig)),
        SignatureAlgorithm::RsaPssRsaeSha256 => Ok(Box::new(RsaPssSha256Sig)),
        SignatureAlgorithm::RsaPssRsaeSha384 => Ok(Box::new(RsaPssSha384Sig)),
        SignatureAlgorithm::RsaPssRsaeSha512 => Ok(Box::new(RsaPssSha512Sig)),

        // Post-Quantum signatures - ML-DSA
        SignatureAlgorithm::MlDsa44 => Ok(Box::new(crate::mldsa::MlDsa44Sig)),
        SignatureAlgorithm::MlDsa65 => Ok(Box::new(crate::mldsa::MlDsa65Sig)),
        SignatureAlgorithm::MlDsa87 => Ok(Box::new(crate::mldsa::MlDsa87Sig)),

        // Post-Quantum signatures - SLH-DSA
        SignatureAlgorithm::SlhDsaSha2_128f => Ok(Box::new(crate::slhdsa::SlhDsaSha2_128f)),
        SignatureAlgorithm::SlhDsaSha2_192f => Ok(Box::new(crate::slhdsa::SlhDsaSha2_192f)),
        SignatureAlgorithm::SlhDsaSha2_256f => Ok(Box::new(crate::slhdsa::SlhDsaSha2_256f)),

        // Not yet implemented
        SignatureAlgorithm::Ed448
        | SignatureAlgorithm::EcdsaSecp521r1Sha512
        | SignatureAlgorithm::RsaPkcs1Sha256
        | SignatureAlgorithm::RsaPkcs1Sha384
        | SignatureAlgorithm::RsaPkcs1Sha512 => Err(Error::UnsupportedAlgorithm(format!(
            "Signature algorithm {:?} not yet implemented",
            algorithm
        ))),
    }
}

/// Ed25519 digital signature algorithm implementation.
///
/// Edwards-curve Digital Signature Algorithm using Curve25519 (EdDSA).
/// - Curve: Edwards25519 (twisted Edwards form of Curve25519)
/// - Private key size: 32 bytes (256 bits)
/// - Public key size: 32 bytes (256 bits)
/// - Signature size: 64 bytes (512 bits)
/// - Security level: ~128 bits
///
/// # Algorithm
///
/// Ed25519 is a deterministic signature scheme based on the EdDSA algorithm:
/// - Signature: (R, s) where R is a curve point and s is a scalar
/// - No hash function parameter needed (uses SHA-512 internally)
/// - Deterministic (same message + key always produces same signature)
///
/// # Security
///
/// Ed25519 provides strong security guarantees:
/// - Deterministic signatures (resistant to bad RNG attacks)
/// - Constant-time implementation (timing attack resistant)
/// - Uses SHA-512 internally for collision resistance
/// - Compact 32-byte keys and 64-byte signatures
/// - NIST FIPS 186-5 approved
///
/// # Standards
///
/// - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
/// - RFC 8446: TLS 1.3 (supported signature algorithm)
/// - FIPS 186-5: Digital Signature Standard (Ed25519 approved)
#[derive(Debug)]
struct Ed25519Sig;

impl Signature for Ed25519Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if signing_key.len() != 32 {
            return Err(Error::CryptoError(format!(
                "Ed25519 signing key must be 32 bytes, got {}",
                signing_key.len()
            )));
        }

        let signing_key_array: [u8; 32] = signing_key.try_into().unwrap();

        // Sign using hpcrypt Ed25519
        let signature = hpcrypt_curves::Ed25519::sign(&signing_key_array, message);

        Ok(signature.to_vec())
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        // Validate key size
        if verifying_key.len() != 32 {
            return Err(Error::CryptoError(format!(
                "Ed25519 verifying key must be 32 bytes, got {}",
                verifying_key.len()
            )));
        }

        // Validate signature size
        if signature.len() != 64 {
            return Err(Error::CryptoError(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            )));
        }

        let verifying_key_array: [u8; 32] = verifying_key.try_into().unwrap();
        let signature_array: [u8; 64] = signature.try_into().unwrap();

        // Verify using hpcrypt Ed25519
        if hpcrypt_curves::Ed25519::verify(&verifying_key_array, message, &signature_array) {
            Ok(())
        } else {
            Err(Error::CryptoError(
                "Ed25519 signature verification failed".to_string(),
            ))
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        // Generate a random 32-byte key
        let mut key = vec![0u8; 32];
        hpcrypt_rng::generate_random_bytes(&mut key)
            .map_err(|_| Error::CryptoError("Failed to generate random Ed25519 key".to_string()))?;

        // Derive public key
        let signing_key_array: [u8; 32] = key.clone().try_into().unwrap();
        let verifying_key = hpcrypt_curves::Ed25519::public_key(&signing_key_array);

        Ok((
            SigningKey::from_bytes(key),
            VerifyingKey::from_bytes(verifying_key.to_vec()),
        ))
    }
}

/// ECDSA P-256 (secp256r1) with SHA-256 signature algorithm.
///
/// Elliptic Curve Digital Signature Algorithm using NIST P-256 curve.
/// - Curve: NIST P-256 (secp256r1, prime256v1)
/// - Private key size: 32 bytes (256 bits)
/// - Public key size: 65 bytes (uncompressed SEC1 format: 0x04 || x || y)
/// - Signature size: Variable (DER-encoded, typically 70-72 bytes)
/// - Hash function: SHA-256
/// - Security level: ~128 bits
///
/// # Algorithm
///
/// ECDSA generates signatures using elliptic curve arithmetic:
/// - Signature: (r, s) where r and s are scalars mod curve order
/// - Uses SHA-256 to hash the message before signing
/// - Encoded in DER format for TLS compatibility
///
/// # Security
///
/// ECDSA P-256 is a FIPS-approved signature algorithm widely used in TLS:
/// - NIST-standardized curve with broad hardware support
/// - Strong security with efficient computation
/// - Requires good randomness for signature generation (vulnerable to bad RNG)
/// - Note: Ed25519 is generally preferred for new applications due to better security properties
///
/// # Standards
///
/// - FIPS 186-5: Digital Signature Standard (ECDSA approved)
/// - RFC 6979: Deterministic Usage of DSA and ECDSA (optional)
/// - RFC 8446: TLS 1.3 (supported signature algorithm)
/// - SEC 1: Elliptic Curve Cryptography (curve specification)
#[derive(Debug)]
struct EcdsaP256Sig;

impl Signature for EcdsaP256Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        // For ECDSA, signing_key is the raw 32-byte private scalar
        if signing_key.len() != 32 {
            return Err(Error::CryptoError(format!(
                "ECDSA P-256 signing key must be 32 bytes, got {}",
                signing_key.len()
            )));
        }

        let signing_key_array: [u8; 32] = signing_key.try_into().unwrap();

        // Create SigningKey from bytes
        let sk = hpcrypt_signatures::ecdsa::SigningKey::from_bytes(&signing_key_array)
            .map_err(|e| Error::CryptoError(format!("Invalid P-256 signing key: {:?}", e)))?;

        // TLS passes pre-hashed messages, but hpcrypt's sign() expects unhashed
        // We need to hash it with SHA-256 for ECDSA
        // Actually, for TLS the message is already the hash we need to sign
        // But ECDSA SigningKey.sign() will hash again. We need raw signing.
        // Let me check if message is already hashed...
        // For TLS 1.3, the signature is over a constructed message that includes
        // the hash. The signing implementation should hash it.
        // So we can just pass it to sign() which will SHA-256 hash it.

        let signature = sk.sign(message);

        // Convert to DER encoding for TLS
        let (der_bytes, len) = signature.to_der();
        Ok(der_bytes[..len].to_vec())
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        // Verifying key is in SEC1 uncompressed format (65 bytes: 0x04 || x || y)
        if verifying_key.len() != 65 {
            return Err(Error::CryptoError(format!(
                "ECDSA P-256 verifying key must be 65 bytes (uncompressed), got {}",
                verifying_key.len()
            )));
        }

        let verifying_key_array: [u8; 65] = verifying_key.try_into().unwrap();

        // Parse verifying key from SEC1 uncompressed format
        let vk = hpcrypt_signatures::ecdsa::VerifyingKey::from_bytes_uncompressed(&verifying_key_array)
            .map_err(|e| Error::CryptoError(format!("Invalid P-256 verifying key: {:?}", e)))?;

        // Parse signature from DER encoding
        let sig = hpcrypt_signatures::ecdsa::Signature::from_der(signature)
            .map_err(|e| Error::CryptoError(format!("Invalid P-256 signature DER: {:?}", e)))?;

        // Verify (will hash message with SHA-256 internally)
        if vk.verify(message, &sig) {
            Ok(())
        } else {
            Err(Error::CryptoError(
                "ECDSA P-256 signature verification failed".to_string(),
            ))
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaSecp256r1Sha256
    }

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        // Generate random 32-byte private key
        let mut key_bytes = [0u8; 32];
        hpcrypt_rng::generate_random_bytes(&mut key_bytes)
            .map_err(|_| Error::CryptoError("Failed to generate random P-256 key".to_string()))?;

        // Validate and create signing key
        let sk = hpcrypt_signatures::ecdsa::SigningKey::from_bytes(&key_bytes)
            .map_err(|e| Error::CryptoError(format!("Generated invalid P-256 key: {:?}", e)))?;

        // Derive public key
        let vk = sk.verifying_key();

        Ok((
            SigningKey::from_bytes(key_bytes.to_vec()),
            VerifyingKey::from_bytes(vk.to_bytes_uncompressed().to_vec()),
        ))
    }
}

/// ECDSA P-384 (secp384r1) with SHA-384 signature algorithm.
///
/// Elliptic Curve Digital Signature Algorithm using NIST P-384 curve.
/// - Curve: NIST P-384 (secp384r1)
/// - Private key size: 48 bytes (384 bits)
/// - Public key size: 97 bytes (uncompressed SEC1 format: 0x04 || x || y)
/// - Signature size: Variable (DER-encoded, typically 102-104 bytes)
/// - Hash function: SHA-384
/// - Security level: ~192 bits
///
/// # Algorithm
///
/// ECDSA generates signatures using elliptic curve arithmetic:
/// - Signature: (r, s) where r and s are scalars mod curve order
/// - Uses SHA-384 to hash the message before signing
/// - Encoded in DER format for TLS compatibility
///
/// # Security
///
/// ECDSA P-384 provides stronger security than P-256 and is recommended for
/// high-security applications:
/// - NIST-standardized curve with NSA Suite B approval
/// - Suitable for TOP SECRET information (per NSA guidelines)
/// - Requires good randomness for signature generation
/// - Commonly paired with AES-256-GCM in TLS
///
/// # Standards
///
/// - FIPS 186-5: Digital Signature Standard (ECDSA approved)
/// - RFC 6979: Deterministic Usage of DSA and ECDSA (optional)
/// - RFC 8446: TLS 1.3 (supported signature algorithm)
/// - SEC 1: Elliptic Curve Cryptography (curve specification)
/// - NSA Suite B Cryptography
#[derive(Debug)]
struct EcdsaP384Sig;

impl Signature for EcdsaP384Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        // For P-384, signing key is 48 bytes
        if signing_key.len() != 48 {
            return Err(Error::CryptoError(format!(
                "ECDSA P-384 signing key must be 48 bytes, got {}",
                signing_key.len()
            )));
        }

        let signing_key_array: [u8; 48] = signing_key.try_into().unwrap();

        // Create SigningKey from bytes
        let sk = hpcrypt_signatures::ecdsa_p384::SigningKey::from_bytes(&signing_key_array)
            .map_err(|e| Error::CryptoError(format!("Invalid P-384 signing key: {:?}", e)))?;

        // Sign (will hash with SHA-384 internally)
        let signature = sk.sign(message);

        // Convert to DER encoding for TLS
        let (der_bytes, len) = signature.to_der();
        Ok(der_bytes[..len].to_vec())
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        // Verifying key is in SEC1 uncompressed format (97 bytes: 0x04 || x || y)
        if verifying_key.len() != 97 {
            return Err(Error::CryptoError(format!(
                "ECDSA P-384 verifying key must be 97 bytes (uncompressed), got {}",
                verifying_key.len()
            )));
        }

        let verifying_key_array: [u8; 97] = verifying_key.try_into().unwrap();

        // Parse verifying key from SEC1 uncompressed format
        let vk = hpcrypt_signatures::ecdsa_p384::VerifyingKey::from_bytes_uncompressed(&verifying_key_array)
            .map_err(|e| Error::CryptoError(format!("Invalid P-384 verifying key: {:?}", e)))?;

        // Parse signature from DER encoding
        let sig = hpcrypt_signatures::ecdsa_p384::Signature::from_der(signature)
            .map_err(|e| Error::CryptoError(format!("Invalid P-384 signature DER: {:?}", e)))?;

        // Verify (will hash message with SHA-384 internally)
        if vk.verify(message, &sig) {
            Ok(())
        } else {
            Err(Error::CryptoError(
                "ECDSA P-384 signature verification failed".to_string(),
            ))
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaSecp384r1Sha384
    }

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        // Generate random 48-byte private key
        let mut key_bytes = [0u8; 48];
        hpcrypt_rng::generate_random_bytes(&mut key_bytes)
            .map_err(|_| Error::CryptoError("Failed to generate random P-384 key".to_string()))?;

        // Validate and create signing key
        let sk = hpcrypt_signatures::ecdsa_p384::SigningKey::from_bytes(&key_bytes)
            .map_err(|e| Error::CryptoError(format!("Generated invalid P-384 key: {:?}", e)))?;

        // Derive public key
        let vk = sk.verifying_key();

        Ok((
            SigningKey::from_bytes(key_bytes.to_vec()),
            VerifyingKey::from_bytes(vk.to_bytes_uncompressed().to_vec()),
        ))
    }
}

/// RSA-PSS with SHA-256 signature algorithm.
///
/// RSA Probabilistic Signature Scheme using SHA-256 hash function.
/// - Key size: Variable (typically 2048, 3072, or 4096 bits)
/// - Signature size: Same as key size (256, 384, or 512 bytes)
/// - Hash function: SHA-256
/// - Salt length: 32 bytes (equal to hash output)
/// - Security level: Depends on key size (2048-bit ~ 112 bits)
///
/// # Algorithm
///
/// RSA-PSS is a probabilistic signature scheme with provable security:
/// - Uses randomized padding (PSS = Probabilistic Signature Scheme)
/// - MGF1 (Mask Generation Function) with SHA-256
/// - Salt length equals hash length for maximum security
/// - More secure than older RSA PKCS#1 v1.5 signatures
///
/// # Security
///
/// RSA-PSS is the modern RSA signature standard with stronger security guarantees:
/// - Provable security in the random oracle model
/// - Resistant to forgery attacks that affect PKCS#1 v1.5
/// - Randomized signatures (different signatures for same message)
/// - Recommended over RSA PKCS#1 v1.5 for new applications
///
/// Key size recommendations:
/// - 2048-bit: Minimum for TLS 1.3, secure until ~2030
/// - 3072-bit: Recommended for high-security, secure beyond 2030
/// - 4096-bit: Maximum security, but slower performance
///
/// # Standards
///
/// - FIPS 186-5: Digital Signature Standard (RSA-PSS approved)
/// - RFC 8017: PKCS#1 v2.2 - RSA Cryptography Specifications
/// - RFC 8446: TLS 1.3 (mandatory-to-implement signature algorithm)
///
/// # Note
///
/// Keys are expected in PKCS#8 (private) or X.509 SubjectPublicKeyInfo (public) DER format.
#[derive(Debug)]
struct RsaPssSha256Sig;

impl Signature for RsaPssSha256Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        use crate::der::parse_rsa_private_key_pkcs8;
        use crate::rsa_bridge::private_key_from_components;

        // Parse PKCS#8 DER-encoded private key
        let key_components = parse_rsa_private_key_pkcs8(signing_key)
            .map_err(|e| Error::CryptoError(format!("Failed to parse RSA private key: {}", e)))?;

        // Construct RsaPrivateKey from components using bridge
        let private_key = private_key_from_components(key_components)?;

        // Sign with RSA-PSS using SHA-256, salt length = hash length (32 bytes)
        let signature = hpcrypt_rsa::pss::sign_pss::<PssHashSha256>(&private_key, message, 32)
            .map_err(|e| Error::CryptoError(format!("RSA-PSS signing failed: {:?}", e)))?;

        Ok(signature)
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        use crate::der::parse_rsa_public_key_spki;
        use crate::rsa_bridge::public_key_from_components;

        // Parse X.509 SubjectPublicKeyInfo DER-encoded public key
        let key_components = parse_rsa_public_key_spki(verifying_key)
            .map_err(|e| Error::CryptoError(format!("Failed to parse RSA public key: {}", e)))?;

        // Construct RsaPublicKey from components using bridge
        let public_key = public_key_from_components(key_components)?;

        // Verify with RSA-PSS using SHA-256, salt length = hash length (32 bytes)
        hpcrypt_rsa::pss::verify_pss::<PssHashSha256>(&public_key, message, signature, 32)
            .map_err(|e| Error::CryptoError(format!("RSA-PSS verification failed: {:?}", e)))?;

        Ok(())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RsaPssRsaeSha256
    }

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        // Generate a 2048-bit RSA key
        let _private_key = RsaPrivateKey::generate(2048)
            .map_err(|e| Error::CryptoError(format!("Failed to generate RSA key: {:?}", e)))?;

        // For now, we can't easily serialize the key to bytes without DER encoding
        // This is a limitation that should be addressed for production use
        Err(Error::CryptoError(
            "RSA keypair generation successful but serialization not yet implemented. \
             Use ECDSA or Ed25519 for now."
                .to_string(),
        ))
    }
}

/// RSA-PSS with SHA-384 signature algorithm.
///
/// RSA Probabilistic Signature Scheme using SHA-384 hash function.
/// - Key size: Variable (typically 2048, 3072, or 4096 bits)
/// - Signature size: Same as key size (256, 384, or 512 bytes)
/// - Hash function: SHA-384
/// - Salt length: 48 bytes (equal to hash output)
/// - Security level: Depends on key size (2048-bit ~ 112 bits)
///
/// # Algorithm
///
/// RSA-PSS is a probabilistic signature scheme with provable security:
/// - Uses randomized padding (PSS = Probabilistic Signature Scheme)
/// - MGF1 (Mask Generation Function) with SHA-384
/// - Salt length equals hash length for maximum security
/// - More secure than older RSA PKCS#1 v1.5 signatures
///
/// # Security
///
/// RSA-PSS is the modern RSA signature standard with stronger security guarantees:
/// - Provable security in the random oracle model
/// - Resistant to forgery attacks that affect PKCS#1 v1.5
/// - Randomized signatures (different signatures for same message)
/// - Recommended over RSA PKCS#1 v1.5 for new applications
///
/// Key size recommendations:
/// - 2048-bit: Minimum for TLS 1.3, secure until ~2030
/// - 3072-bit: Recommended for high-security, secure beyond 2030
/// - 4096-bit: Maximum security, but slower performance
///
/// # Standards
///
/// - FIPS 186-5: Digital Signature Standard (RSA-PSS approved)
/// - RFC 8017: PKCS#1 v2.2 - RSA Cryptography Specifications
/// - RFC 8446: TLS 1.3 (mandatory-to-implement signature algorithm)
#[derive(Debug)]
struct RsaPssSha384Sig;

impl Signature for RsaPssSha384Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        use crate::der::parse_rsa_private_key_pkcs8;
        use crate::rsa_bridge::private_key_from_components;

        // Parse PKCS#8 DER-encoded private key
        let key_components = parse_rsa_private_key_pkcs8(signing_key)
            .map_err(|e| Error::CryptoError(format!("Failed to parse RSA private key: {}", e)))?;

        // Construct RsaPrivateKey from components using bridge
        let private_key = private_key_from_components(key_components)?;

        // Sign with RSA-PSS using SHA-384, salt length = hash length (48 bytes)
        let signature = hpcrypt_rsa::pss::sign_pss::<PssHashSha384>(&private_key, message, 48)
            .map_err(|e| Error::CryptoError(format!("RSA-PSS signing failed: {:?}", e)))?;

        Ok(signature)
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        use crate::der::parse_rsa_public_key_spki;
        use crate::rsa_bridge::public_key_from_components;

        // Parse X.509 SubjectPublicKeyInfo DER-encoded public key
        let key_components = parse_rsa_public_key_spki(verifying_key)
            .map_err(|e| Error::CryptoError(format!("Failed to parse RSA public key: {}", e)))?;

        // Construct RsaPublicKey from components using bridge
        let public_key = public_key_from_components(key_components)?;

        // Verify with RSA-PSS using SHA-384, salt length = hash length (48 bytes)
        hpcrypt_rsa::pss::verify_pss::<PssHashSha384>(&public_key, message, signature, 48)
            .map_err(|e| Error::CryptoError(format!("RSA-PSS verification failed: {:?}", e)))?;

        Ok(())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RsaPssRsaeSha384
    }
}

/// RSA-PSS with SHA-512 signature algorithm.
///
/// RSA Probabilistic Signature Scheme using SHA-512 hash function.
/// - Key size: Variable (typically 2048, 3072, or 4096 bits)
/// - Signature size: Same as key size (256, 384, or 512 bytes)
/// - Hash function: SHA-512
/// - Salt length: 64 bytes (equal to hash output)
/// - Security level: Depends on key size (2048-bit ~ 112 bits)
///
/// # Algorithm
///
/// RSA-PSS is a probabilistic signature scheme with provable security:
/// - Uses randomized padding (PSS = Probabilistic Signature Scheme)
/// - MGF1 (Mask Generation Function) with SHA-512
/// - Salt length equals hash length for maximum security
/// - More secure than older RSA PKCS#1 v1.5 signatures
///
/// # Security
///
/// RSA-PSS with SHA-512 provides the highest security level for RSA signatures:
/// - Provable security in the random oracle model
/// - Resistant to forgery attacks that affect PKCS#1 v1.5
/// - Strongest hash function in the SHA-2 family
/// - Suitable for long-term security and high-value transactions
/// - Recommended for applications requiring maximum cryptographic strength
///
/// Key size recommendations:
/// - 2048-bit: Minimum for TLS 1.3, secure until ~2030
/// - 3072-bit: Recommended for high-security, secure beyond 2030
/// - 4096-bit: Maximum security, but slower performance
///
/// # Standards
///
/// - FIPS 186-5: Digital Signature Standard (RSA-PSS approved)
/// - RFC 8017: PKCS#1 v2.2 - RSA Cryptography Specifications
/// - RFC 8446: TLS 1.3 (supported signature algorithm)
#[derive(Debug)]
struct RsaPssSha512Sig;

impl Signature for RsaPssSha512Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        use crate::der::parse_rsa_private_key_pkcs8;
        use crate::rsa_bridge::private_key_from_components;

        // Parse PKCS#8 DER-encoded private key
        let key_components = parse_rsa_private_key_pkcs8(signing_key)
            .map_err(|e| Error::CryptoError(format!("Failed to parse RSA private key: {}", e)))?;

        // Construct RsaPrivateKey from components using bridge
        let private_key = private_key_from_components(key_components)?;

        // Sign with RSA-PSS using SHA-512, salt length = hash length (64 bytes)
        let signature = hpcrypt_rsa::pss::sign_pss::<PssHashSha512>(&private_key, message, 64)
            .map_err(|e| Error::CryptoError(format!("RSA-PSS signing failed: {:?}", e)))?;

        Ok(signature)
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        use crate::der::parse_rsa_public_key_spki;
        use crate::rsa_bridge::public_key_from_components;

        // Parse X.509 SubjectPublicKeyInfo DER-encoded public key
        let key_components = parse_rsa_public_key_spki(verifying_key)
            .map_err(|e| Error::CryptoError(format!("Failed to parse RSA public key: {}", e)))?;

        // Construct RsaPublicKey from components using bridge
        let public_key = public_key_from_components(key_components)?;

        // Verify with RSA-PSS using SHA-512, salt length = hash length (64 bytes)
        hpcrypt_rsa::pss::verify_pss::<PssHashSha512>(&public_key, message, signature, 64)
            .map_err(|e| Error::CryptoError(format!("RSA-PSS verification failed: {:?}", e)))?;

        Ok(())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RsaPssRsaeSha512
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_roundtrip() {
        let sig = Ed25519Sig;

        // Generate a keypair
        let (signing_key, verifying_key) = sig.generate_keypair().unwrap();
        assert_eq!(signing_key.as_bytes().len(), 32);
        assert_eq!(verifying_key.as_bytes().len(), 32);

        // Sign a message
        let message = b"test message";
        let signature = sig.sign(signing_key.as_bytes(), message).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify the signature
        sig.verify(verifying_key.as_bytes(), message, &signature)
            .unwrap();
    }

    #[test]
    fn test_ecdsa_p256_roundtrip() {
        let sig = EcdsaP256Sig;

        // Generate a keypair
        let (signing_key, verifying_key) = sig.generate_keypair().unwrap();
        assert_eq!(signing_key.as_bytes().len(), 32);
        assert_eq!(verifying_key.as_bytes().len(), 65); // Uncompressed SEC1 format

        // Sign a message
        let message = b"test message for P-256";
        let signature = sig.sign(signing_key.as_bytes(), message).unwrap();

        // Verify the signature
        sig.verify(verifying_key.as_bytes(), message, &signature)
            .unwrap();
    }

    #[test]
    fn test_ecdsa_p384_roundtrip() {
        let sig = EcdsaP384Sig;

        // Generate a keypair
        let (signing_key, verifying_key) = sig.generate_keypair().unwrap();
        assert_eq!(signing_key.as_bytes().len(), 48);
        assert_eq!(verifying_key.as_bytes().len(), 97); // Uncompressed SEC1 format

        // Sign a message
        let message = b"test message for P-384";
        let signature = sig.sign(signing_key.as_bytes(), message).unwrap();

        // Verify the signature
        sig.verify(verifying_key.as_bytes(), message, &signature)
            .unwrap();
    }

    #[test]
    fn test_rsa_pss_sha256_basic() {
        // This test verifies that RSA-PSS implementation compiles and the API works.
        // For now, we cannot test the full roundtrip without DER encoding support.
        //
        // TODO: Add full roundtrip test once we implement DER encoding or when
        // hpcrypt-rsa provides from_components constructor.

        let sig = RsaPssSha256Sig;

        // Verify we get the correct algorithm
        assert_eq!(sig.algorithm(), SignatureAlgorithm::RsaPssRsaeSha256);
    }

    #[test]
    fn test_rsa_pss_sha384_basic() {
        let sig = RsaPssSha384Sig;
        assert_eq!(sig.algorithm(), SignatureAlgorithm::RsaPssRsaeSha384);
    }

    #[test]
    fn test_rsa_pss_sha512_basic() {
        let sig = RsaPssSha512Sig;
        assert_eq!(sig.algorithm(), SignatureAlgorithm::RsaPssRsaeSha512);
    }
}
