//! Digital signature implementations using hpcrypt.

use hptls_crypto::signature::{SigningKey, VerifyingKey};
use hptls_crypto::{Error, Result, Signature, SignatureAlgorithm};

// RSA PSS support
use hpcrypt_rsa::RsaPrivateKey;
use num_bigint::BigUint;

/// Helper function to encode a BigUint as DER INTEGER
fn encode_der_integer(value: &BigUint) -> Vec<u8> {
    let mut result = Vec::new();
    let bytes = value.to_bytes_be();

    // DER INTEGER tag
    result.push(0x02);

    // Length
    if bytes.len() < 128 {
        result.push(bytes.len() as u8);
    } else {
        let len_bytes = bytes.len().to_be_bytes();
        let mut first_non_zero = 0;
        for (i, &b) in len_bytes.iter().enumerate() {
            if b != 0 {
                first_non_zero = i;
                break;
            }
        }
        let len_of_len = len_bytes.len() - first_non_zero;
        result.push(0x80 | len_of_len as u8);
        result.extend_from_slice(&len_bytes[first_non_zero..]);
    }

    // Value (add leading zero if high bit is set)
    if bytes[0] & 0x80 != 0 {
        result.push(0);
    }
    result.extend_from_slice(&bytes);

    result
}

/// Helper function to encode DER SEQUENCE
fn encode_der_sequence(contents: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE tag

    // Length
    if contents.len() < 128 {
        result.push(contents.len() as u8);
    } else {
        let len_bytes = contents.len().to_be_bytes();
        let mut first_non_zero = 0;
        for (i, &b) in len_bytes.iter().enumerate() {
            if b != 0 {
                first_non_zero = i;
                break;
            }
        }
        let len_of_len = len_bytes.len() - first_non_zero;
        result.push(0x80 | len_of_len as u8);
        result.extend_from_slice(&len_bytes[first_non_zero..]);
    }

    result.extend_from_slice(contents);
    result
}

/// Encode an RSA public key as PKCS#1 DER format
fn encode_rsa_public_key_pkcs1(n: &BigUint, e: &BigUint) -> Vec<u8> {
    let mut contents = Vec::new();
    contents.extend_from_slice(&encode_der_integer(n));
    contents.extend_from_slice(&encode_der_integer(e));
    encode_der_sequence(&contents)
}

/// Encode an RSA public key as X.509 SubjectPublicKeyInfo DER format
fn encode_rsa_public_key_spki(n: &BigUint, e: &BigUint) -> Vec<u8> {
    // RSA OID: 1.2.840.113549.1.1.1
    let rsa_oid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    // AlgorithmIdentifier: SEQUENCE { OID, NULL }
    let mut alg_id = Vec::new();
    alg_id.extend_from_slice(&rsa_oid);
    alg_id.push(0x05); // NULL tag
    alg_id.push(0x00); // NULL length
    let alg_id_seq = encode_der_sequence(&alg_id);

    // RSAPublicKey: SEQUENCE { n, e }
    let rsa_pub_key = encode_rsa_public_key_pkcs1(n, e);

    // BIT STRING wrapping the public key (add 0x00 for unused bits)
    let mut bit_string_contents = vec![0x00];
    bit_string_contents.extend_from_slice(&rsa_pub_key);
    let mut bit_string = vec![0x03]; // BIT STRING tag
    if bit_string_contents.len() < 128 {
        bit_string.push(bit_string_contents.len() as u8);
    } else {
        let len_bytes = bit_string_contents.len().to_be_bytes();
        let mut first_non_zero = 0;
        for (i, &b) in len_bytes.iter().enumerate() {
            if b != 0 {
                first_non_zero = i;
                break;
            }
        }
        let len_of_len = len_bytes.len() - first_non_zero;
        bit_string.push(0x80 | len_of_len as u8);
        bit_string.extend_from_slice(&len_bytes[first_non_zero..]);
    }
    bit_string.extend_from_slice(&bit_string_contents);

    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    let mut spki_contents = Vec::new();
    spki_contents.extend_from_slice(&alg_id_seq);
    spki_contents.extend_from_slice(&bit_string);
    encode_der_sequence(&spki_contents)
}

/// Encode an RSA private key as PKCS#1 DER format
/// Note: We can only encode n, e, d (missing p, q, dp, dq, qinv from public RsaPrivateKey)
fn encode_rsa_private_key_pkcs1_simple(n: &BigUint, e: &BigUint, d: &BigUint) -> Vec<u8> {
    // For simplicity, encode only the public components and private exponent
    // A proper PKCS#1 RSA private key would include p, q, dp, dq, qinv for CRT optimization
    // But since those aren't exposed, we'll encode with version, n, e, d and zeros for the rest
    let mut contents = Vec::new();

    // Version (0)
    contents.extend_from_slice(&[0x02, 0x01, 0x00]);

    // modulus
    contents.extend_from_slice(&encode_der_integer(n));

    // publicExponent
    contents.extend_from_slice(&encode_der_integer(e));

    // privateExponent
    contents.extend_from_slice(&encode_der_integer(d));

    // We omit p, q, dp, dq, qinv which are required for proper PKCS#1
    // This will only work for signing, not for decryption-based operations

    encode_der_sequence(&contents)
}

/// Encode an RSA private key as PKCS#8 DER format
fn encode_rsa_private_key_pkcs8(n: &BigUint, e: &BigUint, d: &BigUint) -> Vec<u8> {
    // RSA OID: 1.2.840.113549.1.1.1
    let rsa_oid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    // AlgorithmIdentifier: SEQUENCE { OID, NULL }
    let mut alg_id = Vec::new();
    alg_id.extend_from_slice(&rsa_oid);
    alg_id.push(0x05); // NULL tag
    alg_id.push(0x00); // NULL length
    let alg_id_seq = encode_der_sequence(&alg_id);

    // RSAPrivateKey: PKCS#1 structure
    let rsa_priv_key = encode_rsa_private_key_pkcs1_simple(n, e, d);

    // PrivateKeyInfo: SEQUENCE {
    //   version INTEGER (0),
    //   algorithm AlgorithmIdentifier,
    //   privateKey OCTET STRING (containing RSAPrivateKey)
    // }
    let mut pkcs8_contents = Vec::new();

    // Version (0)
    pkcs8_contents.extend_from_slice(&[0x02, 0x01, 0x00]);

    // AlgorithmIdentifier
    pkcs8_contents.extend_from_slice(&alg_id_seq);

    // OCTET STRING wrapping the RSA private key
    let mut octet_string = vec![0x04]; // OCTET STRING tag
    if rsa_priv_key.len() < 128 {
        octet_string.push(rsa_priv_key.len() as u8);
    } else {
        let len_bytes = rsa_priv_key.len().to_be_bytes();
        let mut first_non_zero = 0;
        for (i, &b) in len_bytes.iter().enumerate() {
            if b != 0 {
                first_non_zero = i;
                break;
            }
        }
        let len_of_len = len_bytes.len() - first_non_zero;
        octet_string.push(0x80 | len_of_len as u8);
        octet_string.extend_from_slice(&len_bytes[first_non_zero..]);
    }
    octet_string.extend_from_slice(&rsa_priv_key);
    pkcs8_contents.extend_from_slice(&octet_string);

    encode_der_sequence(&pkcs8_contents)
}

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

        // Post-Quantum signatures - SLH-DSA (SHA2 variants)
        SignatureAlgorithm::SlhDsaSha2_128f => Ok(Box::new(crate::slhdsa::SlhDsaSha2_128f)),
        SignatureAlgorithm::SlhDsaSha2_192f => Ok(Box::new(crate::slhdsa::SlhDsaSha2_192f)),
        SignatureAlgorithm::SlhDsaSha2_256f => Ok(Box::new(crate::slhdsa::SlhDsaSha2_256f)),

        // Post-Quantum signatures - SLH-DSA (SHAKE variants)
        SignatureAlgorithm::SlhDsaShake128f => Ok(Box::new(crate::slhdsa::SlhDsaShake128f)),
        SignatureAlgorithm::SlhDsaShake256f => Ok(Box::new(crate::slhdsa::SlhDsaShake256f)),

        // Additional EdDSA
        SignatureAlgorithm::Ed448 => Ok(Box::new(Ed448Sig)),

        // Additional ECDSA
        SignatureAlgorithm::EcdsaSecp521r1Sha512 => Ok(Box::new(EcdsaP521Sig)),

        // RSA PKCS#1 v1.5 not implemented (forbidden in TLS 1.3)
        SignatureAlgorithm::RsaPkcs1Sha256
        | SignatureAlgorithm::RsaPkcs1Sha384
        | SignatureAlgorithm::RsaPkcs1Sha512 => Err(Error::UnsupportedAlgorithm(format!(
            "Signature algorithm {:?} - RSA PKCS#1 v1.5 is forbidden in TLS 1.3",
            algorithm
        ))),
    }
}

/// Ed25519 signature implementation.
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

/// ECDSA P-256 (secp256r1) with SHA-256 signature implementation.
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
        let sk = hpcrypt_signatures::ecdsa_p256::SigningKey::from_bytes(&signing_key_array)
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
        let vk = hpcrypt_signatures::ecdsa_p256::VerifyingKey::from_bytes_uncompressed(&verifying_key_array)
            .map_err(|e| Error::CryptoError(format!("Invalid P-256 verifying key: {:?}", e)))?;

        // Parse signature from DER encoding
        let sig = hpcrypt_signatures::ecdsa_p256::Signature::from_der(signature)
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
        let sk = hpcrypt_signatures::ecdsa_p256::SigningKey::from_bytes(&key_bytes)
            .map_err(|e| Error::CryptoError(format!("Generated invalid P-256 key: {:?}", e)))?;

        // Derive public key
        let vk = sk.verifying_key();

        Ok((
            SigningKey::from_bytes(key_bytes.to_vec()),
            VerifyingKey::from_bytes(vk.to_bytes_uncompressed().to_vec()),
        ))
    }
}

/// ECDSA P-384 (secp384r1) with SHA-384 signature implementation.
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

/// ECDSA P-521 (secp521r1) with SHA-512 signature implementation.
#[derive(Debug)]
struct EcdsaP521Sig;

impl Signature for EcdsaP521Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        // For P-521, signing key is 66 bytes
        if signing_key.len() != 66 {
            return Err(Error::CryptoError(format!(
                "ECDSA P-521 signing key must be 66 bytes, got {}",
                signing_key.len()
            )));
        }

        let signing_key_array: [u8; 66] = signing_key.try_into().unwrap();

        // Create SigningKey from bytes
        let sk = hpcrypt_signatures::ecdsa_p521::SigningKey::from_bytes(&signing_key_array)
            .ok_or_else(|| Error::CryptoError("Invalid P-521 signing key".to_string()))?;

        // Sign (will hash with SHA-512 internally)
        let signature = sk.sign(message);

        // Convert to DER encoding for TLS
        let (der_bytes, len) = signature.to_der();
        Ok(der_bytes[..len].to_vec())
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        // Verifying key is in SEC1 uncompressed format (133 bytes: 0x04 || x || y)
        if verifying_key.len() != 133 {
            return Err(Error::CryptoError(format!(
                "ECDSA P-521 verifying key must be 133 bytes (uncompressed), got {}",
                verifying_key.len()
            )));
        }

        let verifying_key_array: [u8; 133] = verifying_key.try_into().unwrap();

        // Parse verifying key from SEC1 uncompressed format
        let vk = hpcrypt_signatures::ecdsa_p521::VerifyingKey::from_sec1_uncompressed(&verifying_key_array)
            .map_err(|e| Error::CryptoError(format!("Invalid P-521 verifying key: {:?}", e)))?;

        // Parse signature from DER encoding
        let sig = hpcrypt_signatures::ecdsa_p521::Signature::from_der(signature)
            .ok_or_else(|| Error::CryptoError("Invalid P-521 signature DER".to_string()))?;

        // Verify (will hash message with SHA-512 internally)
        if vk.verify(message, &sig) {
            Ok(())
        } else {
            Err(Error::CryptoError(
                "ECDSA P-521 signature verification failed".to_string(),
            ))
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaSecp521r1Sha512
    }

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        // Generate a signing key using hpcrypt-signatures
        let sk = hpcrypt_signatures::ecdsa_p521::SigningKey::generate();

        // Derive public key
        let vk = sk.verifying_key();

        Ok((
            SigningKey::from_bytes(sk.to_bytes().to_vec()),
            VerifyingKey::from_bytes(vk.to_sec1_uncompressed().to_vec()),
        ))
    }
}

/// RSA-PSS with SHA-256 signature implementation.
///
/// Note: This implementation expects keys in a simple serialized format for now.
/// For production TLS use, proper PKCS#8/PKCS#1 DER parsing should be added.
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
        // Generate a 2048-bit RSA keypair
        let private_key = RsaPrivateKey::generate(2048)
            .map_err(|e| Error::CryptoError(format!("Failed to generate RSA key: {:?}", e)))?;

        let n = private_key.n().clone();
        let e = private_key.e().clone();
        let d = private_key.d().clone();

        // Encode keys in the formats expected by sign/verify methods
        // Sign/verify expect PKCS#8 for private and SPKI for public
        let private_key_pkcs8 = encode_rsa_private_key_pkcs8(&n, &e, &d);
        let public_key_spki = encode_rsa_public_key_spki(&n, &e);

        Ok((
            SigningKey::from_bytes(private_key_pkcs8),
            VerifyingKey::from_bytes(public_key_spki),
        ))
    }
}

/// RSA-PSS with SHA-384 signature implementation.
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

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        // Generate a 2048-bit RSA keypair
        let private_key = RsaPrivateKey::generate(2048)
            .map_err(|e| Error::CryptoError(format!("Failed to generate RSA key: {:?}", e)))?;

        let n = private_key.n().clone();
        let e = private_key.e().clone();
        let d = private_key.d().clone();

        // Encode keys in the formats expected by sign/verify methods
        // Sign/verify expect PKCS#8 for private and SPKI for public
        let private_key_pkcs8 = encode_rsa_private_key_pkcs8(&n, &e, &d);
        let public_key_spki = encode_rsa_public_key_spki(&n, &e);

        Ok((
            SigningKey::from_bytes(private_key_pkcs8),
            VerifyingKey::from_bytes(public_key_spki),
        ))
    }
}

/// RSA-PSS with SHA-512 signature implementation.
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

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        // Generate a 2048-bit RSA keypair
        let private_key = RsaPrivateKey::generate(2048)
            .map_err(|e| Error::CryptoError(format!("Failed to generate RSA key: {:?}", e)))?;

        let n = private_key.n().clone();
        let e = private_key.e().clone();
        let d = private_key.d().clone();

        // Encode keys in the formats expected by sign/verify methods
        // Sign/verify expect PKCS#8 for private and SPKI for public
        let private_key_pkcs8 = encode_rsa_private_key_pkcs8(&n, &e, &d);
        let public_key_spki = encode_rsa_public_key_spki(&n, &e);

        Ok((
            SigningKey::from_bytes(private_key_pkcs8),
            VerifyingKey::from_bytes(public_key_spki),
        ))
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
    fn test_ecdsa_p521_roundtrip() {
        let sig = EcdsaP521Sig;

        // Generate a keypair
        let (signing_key, verifying_key) = sig.generate_keypair().unwrap();
        assert_eq!(signing_key.as_bytes().len(), 66);
        assert_eq!(verifying_key.as_bytes().len(), 133); // Uncompressed SEC1 format

        // Sign a message
        let message = b"test message for P-521";
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

/// Ed448 signature implementation.
#[derive(Debug)]
struct Ed448Sig;

impl Signature for Ed448Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        // Validate key size
        if signing_key.len() != 57 {
            return Err(Error::CryptoError(format!(
                "Ed448 signing key must be 57 bytes, got {}",
                signing_key.len()
            )));
        }

        let signing_key_array: [u8; 57] = signing_key.try_into().unwrap();

        // Sign using hpcrypt Ed448
        let signature = hpcrypt_curves::ed448::sign(&signing_key_array, message);

        Ok(signature.to_vec())
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        // Validate key size
        if verifying_key.len() != 57 {
            return Err(Error::CryptoError(format!(
                "Ed448 verifying key must be 57 bytes, got {}",
                verifying_key.len()
            )));
        }

        // Validate signature size
        if signature.len() != 114 {
            return Err(Error::CryptoError(format!(
                "Ed448 signature must be 114 bytes, got {}",
                signature.len()
            )));
        }

        let verifying_key_array: [u8; 57] = verifying_key.try_into().unwrap();
        let signature_array: [u8; 114] = signature.try_into().unwrap();

        // Verify using hpcrypt Ed448
        if hpcrypt_curves::ed448::verify(&verifying_key_array, message, &signature_array) {
            Ok(())
        } else {
            Err(Error::CryptoError(
                "Ed448 signature verification failed".to_string(),
            ))
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed448
    }

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        // Generate a random 57-byte key
        let mut key = vec![0u8; 57];
        hpcrypt_rng::generate_random_bytes(&mut key)
            .map_err(|_| Error::CryptoError("Failed to generate random Ed448 key".to_string()))?;

        // Derive public key
        let signing_key_array: [u8; 57] = key.clone().try_into().unwrap();
        let verifying_key = hpcrypt_curves::ed448::public_key(&signing_key_array);

        Ok((
            SigningKey::from_bytes(key),
            VerifyingKey::from_bytes(verifying_key.to_vec()),
        ))
    }
}

