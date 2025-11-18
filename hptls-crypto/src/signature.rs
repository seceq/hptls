//! Digital signature algorithms for TLS.

use crate::{Error, Result};
use zeroize::Zeroize;

/// Signature algorithms supported by HPTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    // ECDSA
    /// ECDSA with P-256 and SHA-256
    EcdsaSecp256r1Sha256,
    /// ECDSA with P-384 and SHA-384
    EcdsaSecp384r1Sha384,
    /// ECDSA with P-521 and SHA-512
    EcdsaSecp521r1Sha512,

    // EdDSA
    /// Ed25519 (EdDSA with Curve25519)
    Ed25519,
    /// Ed448 (EdDSA with Curve448)
    Ed448,

    // RSA-PSS (modern RSA signatures)
    /// RSA-PSS with SHA-256
    RsaPssRsaeSha256,
    /// RSA-PSS with SHA-384
    RsaPssRsaeSha384,
    /// RSA-PSS with SHA-512
    RsaPssRsaeSha512,

    // RSA PKCS#1 v1.5 (legacy, TLS 1.2 only)
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512
    RsaPkcs1Sha512,

    // Post-Quantum Signatures
    /// ML-DSA-44 (FIPS 204, formerly Dilithium2)
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, formerly Dilithium3)
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, formerly Dilithium5)
    MlDsa87,

    // SLH-DSA (FIPS 205, hash-based signatures) - SHA2 variants
    /// SLH-DSA-SHA2-128f (FIPS 205, 128-bit security, fast variant)
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192f (FIPS 205, 192-bit security, fast variant)
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-256f (FIPS 205, 256-bit security, fast variant)
    SlhDsaSha2_256f,

    // SLH-DSA (FIPS 205, hash-based signatures) - SHAKE variants
    /// SLH-DSA-SHAKE-128f (FIPS 205, 128-bit security, fast variant, SHAKE-based)
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-256f (FIPS 205, 256-bit security, fast variant, SHAKE-based)
    SlhDsaShake256f,
}

impl SignatureAlgorithm {
    /// Get the IANA TLS SignatureScheme codepoint.
    pub const fn iana_codepoint(self) -> u16 {
        match self {
            SignatureAlgorithm::EcdsaSecp256r1Sha256 => 0x0403,
            SignatureAlgorithm::EcdsaSecp384r1Sha384 => 0x0503,
            SignatureAlgorithm::EcdsaSecp521r1Sha512 => 0x0603,
            SignatureAlgorithm::Ed25519 => 0x0807,
            SignatureAlgorithm::Ed448 => 0x0808,
            SignatureAlgorithm::RsaPssRsaeSha256 => 0x0804,
            SignatureAlgorithm::RsaPssRsaeSha384 => 0x0805,
            SignatureAlgorithm::RsaPssRsaeSha512 => 0x0806,
            SignatureAlgorithm::RsaPkcs1Sha256 => 0x0401,
            SignatureAlgorithm::RsaPkcs1Sha384 => 0x0501,
            SignatureAlgorithm::RsaPkcs1Sha512 => 0x0601,
            SignatureAlgorithm::MlDsa44 => 0x0900, // Placeholder (not standardized)
            SignatureAlgorithm::MlDsa65 => 0x0901, // Placeholder
            SignatureAlgorithm::MlDsa87 => 0x0902, // Placeholder
            SignatureAlgorithm::SlhDsaSha2_128f => 0x0A00, // Placeholder (not standardized)
            SignatureAlgorithm::SlhDsaSha2_192f => 0x0A01, // Placeholder
            SignatureAlgorithm::SlhDsaSha2_256f => 0x0A02, // Placeholder
            SignatureAlgorithm::SlhDsaShake128f => 0x0A10, // Placeholder (not standardized)
            SignatureAlgorithm::SlhDsaShake256f => 0x0A12, // Placeholder
        }
    }

    /// Get the algorithm name.
    pub const fn name(self) -> &'static str {
        match self {
            SignatureAlgorithm::EcdsaSecp256r1Sha256 => "ecdsa_secp256r1_sha256",
            SignatureAlgorithm::EcdsaSecp384r1Sha384 => "ecdsa_secp384r1_sha384",
            SignatureAlgorithm::EcdsaSecp521r1Sha512 => "ecdsa_secp521r1_sha512",
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::Ed448 => "ed448",
            SignatureAlgorithm::RsaPssRsaeSha256 => "rsa_pss_rsae_sha256",
            SignatureAlgorithm::RsaPssRsaeSha384 => "rsa_pss_rsae_sha384",
            SignatureAlgorithm::RsaPssRsaeSha512 => "rsa_pss_rsae_sha512",
            SignatureAlgorithm::RsaPkcs1Sha256 => "rsa_pkcs1_sha256",
            SignatureAlgorithm::RsaPkcs1Sha384 => "rsa_pkcs1_sha384",
            SignatureAlgorithm::RsaPkcs1Sha512 => "rsa_pkcs1_sha512",
            SignatureAlgorithm::MlDsa44 => "ml_dsa_44",
            SignatureAlgorithm::MlDsa65 => "ml_dsa_65",
            SignatureAlgorithm::MlDsa87 => "ml_dsa_87",
            SignatureAlgorithm::SlhDsaSha2_128f => "slh_dsa_sha2_128f",
            SignatureAlgorithm::SlhDsaSha2_192f => "slh_dsa_sha2_192f",
            SignatureAlgorithm::SlhDsaSha2_256f => "slh_dsa_sha2_256f",
            SignatureAlgorithm::SlhDsaShake128f => "slh_dsa_shake_128f",
            SignatureAlgorithm::SlhDsaShake256f => "slh_dsa_shake_256f",
        }
    }

    /// Check if this is a post-quantum signature algorithm.
    pub const fn is_post_quantum(self) -> bool {
        matches!(
            self,
            SignatureAlgorithm::MlDsa44
            | SignatureAlgorithm::MlDsa65
            | SignatureAlgorithm::MlDsa87
            | SignatureAlgorithm::SlhDsaSha2_128f
            | SignatureAlgorithm::SlhDsaSha2_192f
            | SignatureAlgorithm::SlhDsaSha2_256f
            | SignatureAlgorithm::SlhDsaShake128f
            | SignatureAlgorithm::SlhDsaShake256f
        )
    }

    /// Check if this algorithm is allowed in TLS 1.3.
    ///
    /// TLS 1.3 forbids RSA PKCS#1 v1.5 signatures.
    pub const fn allowed_in_tls13(self) -> bool {
        !matches!(
            self,
            SignatureAlgorithm::RsaPkcs1Sha256
                | SignatureAlgorithm::RsaPkcs1Sha384
                | SignatureAlgorithm::RsaPkcs1Sha512
        )
    }

    /// Create from IANA codepoint.
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0403 => Some(SignatureAlgorithm::EcdsaSecp256r1Sha256),
            0x0503 => Some(SignatureAlgorithm::EcdsaSecp384r1Sha384),
            0x0603 => Some(SignatureAlgorithm::EcdsaSecp521r1Sha512),
            0x0807 => Some(SignatureAlgorithm::Ed25519),
            0x0808 => Some(SignatureAlgorithm::Ed448),
            0x0804 => Some(SignatureAlgorithm::RsaPssRsaeSha256),
            0x0805 => Some(SignatureAlgorithm::RsaPssRsaeSha384),
            0x0806 => Some(SignatureAlgorithm::RsaPssRsaeSha512),
            0x0401 => Some(SignatureAlgorithm::RsaPkcs1Sha256),
            0x0501 => Some(SignatureAlgorithm::RsaPkcs1Sha384),
            0x0601 => Some(SignatureAlgorithm::RsaPkcs1Sha512),
            0x0900 => Some(SignatureAlgorithm::MlDsa44),
            0x0901 => Some(SignatureAlgorithm::MlDsa65),
            0x0902 => Some(SignatureAlgorithm::MlDsa87),
            0x0A00 => Some(SignatureAlgorithm::SlhDsaSha2_128f),
            0x0A01 => Some(SignatureAlgorithm::SlhDsaSha2_192f),
            0x0A02 => Some(SignatureAlgorithm::SlhDsaSha2_256f),
            0x0A10 => Some(SignatureAlgorithm::SlhDsaShake128f),
            0x0A12 => Some(SignatureAlgorithm::SlhDsaShake256f),
            _ => None,
        }
    }
}

/// Signing key (private key).
///
/// This type wraps the private signing key and ensures it's zeroized
/// when dropped.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SigningKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl SigningKey {
    /// Create a new signing key from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the signing key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Verification key (public key).
#[derive(Debug)]
pub struct VerifyingKey {
    bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Create a new verifying key from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the verifying key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Digital signature trait.
///
/// Provides signature generation and verification for TLS.
///
/// # Example (Signing)
///
/// ```rust,no_run
/// use hptls_crypto::Signature;
///
/// fn sign_example(sig: &dyn Signature, signing_key: &[u8], message: &[u8]) -> Vec<u8> {
///     sig.sign(signing_key, message).unwrap()
/// }
/// ```
///
/// # Example (Verification)
///
/// ```rust,no_run
/// use hptls_crypto::Signature;
///
/// fn verify_example(sig: &dyn Signature, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
///     sig.verify(verifying_key, message, signature).is_ok()
/// }
/// ```
pub trait Signature: Send + Sync {
    /// Sign a message.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - Private signing key
    /// * `message` - Message to sign
    ///
    /// # Returns
    ///
    /// Signature bytes.
    ///
    /// # Errors
    ///
    /// - `InvalidPrivateKey` if signing key is invalid
    /// - `CryptoError` for other errors
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - Public verifying key
    /// * `message` - Message that was signed
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if signature is valid.
    ///
    /// # Errors
    ///
    /// - `InvalidPublicKey` if verifying key is invalid
    /// - `SignatureVerificationFailed` if signature doesn't match
    /// - `InvalidSignature` if signature format is invalid
    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()>;

    /// Get the algorithm this signature implements.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Generate a key pair for this signature algorithm.
    ///
    /// Optional: Not all signature providers support key generation.
    /// Returns `UnsupportedAlgorithm` if not supported.
    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        Err(Error::UnsupportedAlgorithm("Not implemented".into()))
    }
}
