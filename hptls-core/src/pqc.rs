//! Post-Quantum Cryptography Support
//!
//! This module provides the architectural foundation for post-quantum cryptographic
//! algorithms in TLS 1.3, including:
//! - NIST PQC standard algorithms (ML-KEM, ML-DSA, SLH-DSA)
//! - Hybrid key exchange (classical + PQC)
//! - PQC signature schemes
//! - Integration points for external crypto libraries
//!
//! # NIST Post-Quantum Standards
//!
//! ## Key Encapsulation Mechanisms (KEM)
//! - **ML-KEM** (FIPS 203): Module-Lattice-based Key Encapsulation Mechanism
//!   - Formerly known as CRYSTALS-Kyber
//!   - Variants: ML-KEM-512, ML-KEM-768, ML-KEM-1024
//!
//! ## Digital Signatures
//! - **ML-DSA** (FIPS 204): Module-Lattice-based Digital Signature Algorithm
//!   - Formerly known as CRYSTALS-Dilithium
//!   - Variants: ML-DSA-44, ML-DSA-65, ML-DSA-87
//!
//! - **SLH-DSA** (FIPS 205): Stateless Hash-based Digital Signature Algorithm
//!   - Formerly known as SPHINCS+
//!   - Variants: SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-256f, etc.
//!
//! # Hybrid Key Exchange
//!
//! Hybrid schemes combine classical and PQC algorithms for defense-in-depth:
//! ```text
//! X25519 + ML-KEM-768  (classical ECDH + PQC KEM)
//! P-256 + ML-KEM-768   (NIST curve + PQC KEM)
//! ```
//!
//! # TLS Integration
//!
//! PQC algorithms are negotiated via:
//! - `supported_groups` extension (for hybrid KEMs)
//! - `signature_algorithms` extension (for PQC signatures)
//! - Custom extensions for algorithm parameters
//!
//! # Security Considerations
//!
//! - Larger key sizes (ML-KEM-768 public key: 1184 bytes)
//! - Larger signatures (ML-DSA-65 signature: ~3293 bytes)
//! - Hybrid mode recommended during transition period
//! - Side-channel resistance required for implementations

use crate::error::{Error, Result};
use zeroize::Zeroizing;

/// Post-Quantum Key Encapsulation Mechanism (KEM) algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PqcKemAlgorithm {
    /// ML-KEM-512 (FIPS 203) - 128-bit security level
    /// - Public key: 800 bytes
    /// - Ciphertext: 768 bytes
    /// - Shared secret: 32 bytes
    MlKem512 = 0x0512,

    /// ML-KEM-768 (FIPS 203) - 192-bit security level (recommended)
    /// - Public key: 1184 bytes
    /// - Ciphertext: 1088 bytes
    /// - Shared secret: 32 bytes
    MlKem768 = 0x0768,

    /// ML-KEM-1024 (FIPS 203) - 256-bit security level
    /// - Public key: 1568 bytes
    /// - Ciphertext: 1568 bytes
    /// - Shared secret: 32 bytes
    MlKem1024 = 0x1024,
}

impl PqcKemAlgorithm {
    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            PqcKemAlgorithm::MlKem512 => 800,
            PqcKemAlgorithm::MlKem768 => 1184,
            PqcKemAlgorithm::MlKem1024 => 1568,
        }
    }

    /// Get the ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            PqcKemAlgorithm::MlKem512 => 768,
            PqcKemAlgorithm::MlKem768 => 1088,
            PqcKemAlgorithm::MlKem1024 => 1568,
        }
    }

    /// Get the shared secret size in bytes (always 32 for ML-KEM)
    pub fn shared_secret_size(&self) -> usize {
        32
    }

    /// Get the security level in bits
    pub fn security_level(&self) -> u16 {
        match self {
            PqcKemAlgorithm::MlKem512 => 128,
            PqcKemAlgorithm::MlKem768 => 192,
            PqcKemAlgorithm::MlKem1024 => 256,
        }
    }
}

/// Post-Quantum Digital Signature Algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PqcSignatureAlgorithm {
    /// ML-DSA-44 (FIPS 204) - 128-bit security level
    /// - Public key: 1312 bytes
    /// - Signature: ~2420 bytes
    MlDsa44 = 0x0E01,

    /// ML-DSA-65 (FIPS 204) - 192-bit security level (recommended)
    /// - Public key: 1952 bytes
    /// - Signature: ~3293 bytes
    MlDsa65 = 0x0E02,

    /// ML-DSA-87 (FIPS 204) - 256-bit security level
    /// - Public key: 2592 bytes
    /// - Signature: ~4595 bytes
    MlDsa87 = 0x0E03,

    /// SLH-DSA-SHA2-128s (FIPS 205) - 128-bit, small signature
    /// - Public key: 32 bytes
    /// - Signature: 7856 bytes
    SlhDsaSha2_128s = 0x0E10,

    /// SLH-DSA-SHA2-128f (FIPS 205) - 128-bit, fast verification
    /// - Public key: 32 bytes
    /// - Signature: 17088 bytes
    SlhDsaSha2_128f = 0x0E11,

    /// SLH-DSA-SHAKE-256s (FIPS 205) - 256-bit, small signature
    /// - Public key: 64 bytes
    /// - Signature: 29792 bytes
    SlhDsaShake256s = 0x0E20,
}

impl PqcSignatureAlgorithm {
    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            PqcSignatureAlgorithm::MlDsa44 => 1312,
            PqcSignatureAlgorithm::MlDsa65 => 1952,
            PqcSignatureAlgorithm::MlDsa87 => 2592,
            PqcSignatureAlgorithm::SlhDsaSha2_128s => 32,
            PqcSignatureAlgorithm::SlhDsaSha2_128f => 32,
            PqcSignatureAlgorithm::SlhDsaShake256s => 64,
        }
    }

    /// Get the maximum signature size in bytes
    pub fn max_signature_size(&self) -> usize {
        match self {
            PqcSignatureAlgorithm::MlDsa44 => 2420,
            PqcSignatureAlgorithm::MlDsa65 => 3293,
            PqcSignatureAlgorithm::MlDsa87 => 4595,
            PqcSignatureAlgorithm::SlhDsaSha2_128s => 7856,
            PqcSignatureAlgorithm::SlhDsaSha2_128f => 17088,
            PqcSignatureAlgorithm::SlhDsaShake256s => 29792,
        }
    }

    /// Get the security level in bits
    pub fn security_level(&self) -> u16 {
        match self {
            PqcSignatureAlgorithm::MlDsa44 => 128,
            PqcSignatureAlgorithm::MlDsa65 => 192,
            PqcSignatureAlgorithm::MlDsa87 => 256,
            PqcSignatureAlgorithm::SlhDsaSha2_128s => 128,
            PqcSignatureAlgorithm::SlhDsaSha2_128f => 128,
            PqcSignatureAlgorithm::SlhDsaShake256s => 256,
        }
    }
}

/// Hybrid key exchange combining classical and PQC algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HybridKemGroup {
    /// X25519 + ML-KEM-768 (recommended)
    /// - Total public key: 32 + 1184 = 1216 bytes
    /// - Total shared secret: 32 + 32 = 64 bytes (concatenated)
    X25519MlKem768,

    /// X25519 + ML-KEM-1024
    /// - Total public key: 32 + 1568 = 1600 bytes
    /// - Total shared secret: 64 bytes
    X25519MlKem1024,

    /// P-256 + ML-KEM-768
    /// - Total public key: 65 + 1184 = 1249 bytes
    /// - Total shared secret: 64 bytes
    P256MlKem768,

    /// P-384 + ML-KEM-1024
    /// - Total public key: 97 + 1568 = 1665 bytes
    /// - Total shared secret: 64 bytes
    P384MlKem1024,
}

impl HybridKemGroup {
    /// Get the IANA code point for this hybrid group
    pub fn code_point(&self) -> u16 {
        match self {
            HybridKemGroup::X25519MlKem768 => 0x6399,
            HybridKemGroup::X25519MlKem1024 => 0x639A,
            HybridKemGroup::P256MlKem768 => 0x639B,
            HybridKemGroup::P384MlKem1024 => 0x639C,
        }
    }

    /// Get the classical algorithm component
    pub fn classical_algorithm(&self) -> &str {
        match self {
            HybridKemGroup::X25519MlKem768 | HybridKemGroup::X25519MlKem1024 => "X25519",
            HybridKemGroup::P256MlKem768 => "P-256",
            HybridKemGroup::P384MlKem1024 => "P-384",
        }
    }

    /// Get the PQC algorithm component
    pub fn pqc_algorithm(&self) -> PqcKemAlgorithm {
        match self {
            HybridKemGroup::X25519MlKem768 | HybridKemGroup::P256MlKem768 => {
                PqcKemAlgorithm::MlKem768
            },
            HybridKemGroup::X25519MlKem1024 | HybridKemGroup::P384MlKem1024 => {
                PqcKemAlgorithm::MlKem1024
            },
        }
    }

    /// Get the total public key size
    pub fn public_key_size(&self) -> usize {
        let classical_size = match self {
            HybridKemGroup::X25519MlKem768 | HybridKemGroup::X25519MlKem1024 => 32,
            HybridKemGroup::P256MlKem768 => 65,
            HybridKemGroup::P384MlKem1024 => 97,
        };
        classical_size + self.pqc_algorithm().public_key_size()
    }

    /// Get the total shared secret size (always 64 bytes for hybrid)
    pub fn shared_secret_size(&self) -> usize {
        64 // 32 bytes classical + 32 bytes PQC
    }
}

/// Hybrid public key (classical + PQC components)
#[derive(Debug, Clone)]
pub struct HybridPublicKey {
    /// Classical key component (X25519 or P-256/P-384)
    pub classical_key: Vec<u8>,

    /// Post-quantum key component (ML-KEM)
    pub pqc_key: Vec<u8>,

    /// Hybrid group identifier
    pub group: HybridKemGroup,
}

impl HybridPublicKey {
    /// Create a new hybrid public key
    pub fn new(classical_key: Vec<u8>, pqc_key: Vec<u8>, group: HybridKemGroup) -> Result<Self> {
        // Validate sizes
        let expected_classical_size = match group {
            HybridKemGroup::X25519MlKem768 | HybridKemGroup::X25519MlKem1024 => 32,
            HybridKemGroup::P256MlKem768 => 65,
            HybridKemGroup::P384MlKem1024 => 97,
        };

        if classical_key.len() != expected_classical_size {
            return Err(Error::InvalidMessage("Invalid classical key size".into()));
        }

        let expected_pqc_size = group.pqc_algorithm().public_key_size();
        if pqc_key.len() != expected_pqc_size {
            return Err(Error::InvalidMessage("Invalid PQC key size".into()));
        }

        Ok(Self {
            classical_key,
            pqc_key,
            group,
        })
    }

    /// Encode to wire format (classical || pqc)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.group.public_key_size());
        buf.extend_from_slice(&self.classical_key);
        buf.extend_from_slice(&self.pqc_key);
        buf
    }

    /// Decode from wire format
    pub fn decode(data: &[u8], group: HybridKemGroup) -> Result<Self> {
        let expected_classical_size = match group {
            HybridKemGroup::X25519MlKem768 | HybridKemGroup::X25519MlKem1024 => 32,
            HybridKemGroup::P256MlKem768 => 65,
            HybridKemGroup::P384MlKem1024 => 97,
        };

        let expected_pqc_size = group.pqc_algorithm().public_key_size();
        let expected_total_size = expected_classical_size + expected_pqc_size;

        if data.len() != expected_total_size {
            return Err(Error::InvalidMessage("Invalid hybrid key size".into()));
        }

        let classical_key = data[..expected_classical_size].to_vec();
        let pqc_key = data[expected_classical_size..].to_vec();

        Ok(Self {
            classical_key,
            pqc_key,
            group,
        })
    }
}

/// Hybrid shared secret (classical || PQC)
#[derive(Debug, Clone)]
pub struct HybridSharedSecret {
    /// Classical shared secret (32 bytes)
    pub classical_secret: Zeroizing<Vec<u8>>,

    /// Post-quantum shared secret (32 bytes)
    pub pqc_secret: Zeroizing<Vec<u8>>,
}

impl HybridSharedSecret {
    /// Create a new hybrid shared secret
    pub fn new(classical_secret: Vec<u8>, pqc_secret: Vec<u8>) -> Result<Self> {
        if classical_secret.len() != 32 {
            return Err(Error::InvalidMessage(
                "Classical secret must be 32 bytes".into(),
            ));
        }

        if pqc_secret.len() != 32 {
            return Err(Error::InvalidMessage("PQC secret must be 32 bytes".into()));
        }

        Ok(Self {
            classical_secret: Zeroizing::new(classical_secret),
            pqc_secret: Zeroizing::new(pqc_secret),
        })
    }

    /// Combine into a single shared secret (classical || PQC)
    pub fn combine(&self) -> Zeroizing<Vec<u8>> {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&self.classical_secret);
        combined.extend_from_slice(&self.pqc_secret);
        Zeroizing::new(combined)
    }
}

/// PQC Key Encapsulation output
#[derive(Debug, Clone)]
pub struct PqcKemOutput {
    /// Ciphertext (encapsulated key)
    pub ciphertext: Vec<u8>,

    /// Shared secret
    pub shared_secret: Zeroizing<Vec<u8>>,
}

/// PQC signature output
#[derive(Debug, Clone)]
pub struct PqcSignature {
    /// Signature algorithm
    pub algorithm: PqcSignatureAlgorithm,

    /// Signature bytes
    pub signature: Vec<u8>,
}

impl PqcSignature {
    /// Create a new PQC signature
    pub fn new(algorithm: PqcSignatureAlgorithm, signature: Vec<u8>) -> Result<Self> {
        if signature.len() > algorithm.max_signature_size() {
            return Err(Error::InvalidMessage("Signature too large".into()));
        }

        Ok(Self {
            algorithm,
            signature,
        })
    }

    /// Encode to wire format
    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    /// Get signature size
    pub fn size(&self) -> usize {
        self.signature.len()
    }
}

/// Integration point for external PQC crypto provider
///
/// This trait defines the interface that external PQC libraries must implement.
/// Implementations will be provided by libraries like:
/// - `pqcrypto` (Rust PQC library)
/// - `liboqs` (Open Quantum Safe)
/// - Hardware security modules with PQC support
pub trait PqcCryptoProvider: Send + Sync {
    // === KEM Operations ===

    /// Generate a KEM keypair
    fn kem_keygen(&self, algorithm: PqcKemAlgorithm) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)>;

    /// Encapsulate a shared secret (sender side)
    fn kem_encapsulate(
        &self,
        algorithm: PqcKemAlgorithm,
        public_key: &[u8],
    ) -> Result<PqcKemOutput>;

    /// Decapsulate a shared secret (receiver side)
    fn kem_decapsulate(
        &self,
        algorithm: PqcKemAlgorithm,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;

    // === Signature Operations ===

    /// Generate a signature keypair
    fn sign_keygen(
        &self,
        algorithm: PqcSignatureAlgorithm,
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)>;

    /// Sign a message
    fn sign(
        &self,
        algorithm: PqcSignatureAlgorithm,
        secret_key: &[u8],
        message: &[u8],
    ) -> Result<PqcSignature>;

    /// Verify a signature
    fn verify(
        &self,
        algorithm: PqcSignatureAlgorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool>;

    // === Hybrid Operations ===

    /// Generate a hybrid keypair
    fn hybrid_keygen(&self, group: HybridKemGroup)
        -> Result<(HybridPublicKey, Zeroizing<Vec<u8>>)>;

    /// Perform hybrid key exchange (encapsulation)
    fn hybrid_encapsulate(
        &self,
        public_key: &HybridPublicKey,
    ) -> Result<(Vec<u8>, HybridSharedSecret)>;

    /// Perform hybrid key exchange (decapsulation)
    fn hybrid_decapsulate(
        &self,
        group: HybridKemGroup,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<HybridSharedSecret>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_kem_algorithm_sizes() {
        let ml_kem_512 = PqcKemAlgorithm::MlKem512;
        assert_eq!(ml_kem_512.public_key_size(), 800);
        assert_eq!(ml_kem_512.ciphertext_size(), 768);
        assert_eq!(ml_kem_512.shared_secret_size(), 32);
        assert_eq!(ml_kem_512.security_level(), 128);

        let ml_kem_768 = PqcKemAlgorithm::MlKem768;
        assert_eq!(ml_kem_768.public_key_size(), 1184);
        assert_eq!(ml_kem_768.ciphertext_size(), 1088);
        assert_eq!(ml_kem_768.shared_secret_size(), 32);
        assert_eq!(ml_kem_768.security_level(), 192);

        let ml_kem_1024 = PqcKemAlgorithm::MlKem1024;
        assert_eq!(ml_kem_1024.public_key_size(), 1568);
        assert_eq!(ml_kem_1024.ciphertext_size(), 1568);
        assert_eq!(ml_kem_1024.shared_secret_size(), 32);
        assert_eq!(ml_kem_1024.security_level(), 256);
    }

    #[test]
    fn test_pqc_signature_algorithm_sizes() {
        let ml_dsa_44 = PqcSignatureAlgorithm::MlDsa44;
        assert_eq!(ml_dsa_44.public_key_size(), 1312);
        assert_eq!(ml_dsa_44.max_signature_size(), 2420);
        assert_eq!(ml_dsa_44.security_level(), 128);

        let ml_dsa_65 = PqcSignatureAlgorithm::MlDsa65;
        assert_eq!(ml_dsa_65.public_key_size(), 1952);
        assert_eq!(ml_dsa_65.max_signature_size(), 3293);
        assert_eq!(ml_dsa_65.security_level(), 192);

        let slh_dsa_shake_256s = PqcSignatureAlgorithm::SlhDsaShake256s;
        assert_eq!(slh_dsa_shake_256s.public_key_size(), 64);
        assert_eq!(slh_dsa_shake_256s.max_signature_size(), 29792);
        assert_eq!(slh_dsa_shake_256s.security_level(), 256);
    }

    #[test]
    fn test_hybrid_kem_group_properties() {
        let x25519_mlkem768 = HybridKemGroup::X25519MlKem768;
        assert_eq!(x25519_mlkem768.code_point(), 0x6399);
        assert_eq!(x25519_mlkem768.classical_algorithm(), "X25519");
        assert_eq!(x25519_mlkem768.pqc_algorithm(), PqcKemAlgorithm::MlKem768);
        assert_eq!(x25519_mlkem768.public_key_size(), 32 + 1184);
        assert_eq!(x25519_mlkem768.shared_secret_size(), 64);

        let p256_mlkem768 = HybridKemGroup::P256MlKem768;
        assert_eq!(p256_mlkem768.code_point(), 0x639B);
        assert_eq!(p256_mlkem768.classical_algorithm(), "P-256");
        assert_eq!(p256_mlkem768.public_key_size(), 65 + 1184);
    }

    #[test]
    fn test_hybrid_public_key_encode_decode() {
        let classical_key = vec![0x42; 32]; // X25519 key
        let pqc_key = vec![0x99; 1184]; // ML-KEM-768 key
        let group = HybridKemGroup::X25519MlKem768;

        let hybrid_key =
            HybridPublicKey::new(classical_key.clone(), pqc_key.clone(), group).unwrap();

        let encoded = hybrid_key.encode();
        assert_eq!(encoded.len(), 32 + 1184);

        let decoded = HybridPublicKey::decode(&encoded, group).unwrap();
        assert_eq!(decoded.classical_key, classical_key);
        assert_eq!(decoded.pqc_key, pqc_key);
        assert_eq!(decoded.group, group);
    }

    #[test]
    fn test_hybrid_public_key_invalid_sizes() {
        // Classical key too short
        let result = HybridPublicKey::new(
            vec![0x42; 16],
            vec![0x99; 1184],
            HybridKemGroup::X25519MlKem768,
        );
        assert!(result.is_err());

        // PQC key too short
        let result = HybridPublicKey::new(
            vec![0x42; 32],
            vec![0x99; 800],
            HybridKemGroup::X25519MlKem768,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_shared_secret_combine() {
        let classical_secret = vec![0x11; 32];
        let pqc_secret = vec![0x22; 32];

        let hybrid_secret =
            HybridSharedSecret::new(classical_secret.clone(), pqc_secret.clone()).unwrap();

        let combined = hybrid_secret.combine();
        assert_eq!(combined.len(), 64);
        assert_eq!(&combined[..32], &classical_secret[..]);
        assert_eq!(&combined[32..], &pqc_secret[..]);
    }

    #[test]
    fn test_hybrid_shared_secret_invalid_sizes() {
        // Classical secret wrong size
        let result = HybridSharedSecret::new(vec![0x11; 16], vec![0x22; 32]);
        assert!(result.is_err());

        // PQC secret wrong size
        let result = HybridSharedSecret::new(vec![0x11; 32], vec![0x22; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pqc_signature_creation() {
        let algorithm = PqcSignatureAlgorithm::MlDsa65;
        let signature_bytes = vec![0xAB; 3000];

        let sig = PqcSignature::new(algorithm, signature_bytes.clone()).unwrap();
        assert_eq!(sig.algorithm, algorithm);
        assert_eq!(sig.size(), 3000);
        assert_eq!(sig.encode(), signature_bytes);
    }

    #[test]
    fn test_pqc_signature_too_large() {
        let algorithm = PqcSignatureAlgorithm::MlDsa44;
        let signature_bytes = vec![0xAB; 5000]; // Exceeds max size of 2420

        let result = PqcSignature::new(algorithm, signature_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_hybrid_groups() {
        let groups = vec![
            HybridKemGroup::X25519MlKem768,
            HybridKemGroup::X25519MlKem1024,
            HybridKemGroup::P256MlKem768,
            HybridKemGroup::P384MlKem1024,
        ];

        for group in groups {
            // All hybrid groups should have 64-byte shared secret
            assert_eq!(group.shared_secret_size(), 64);

            // Code points should be unique
            assert!(group.code_point() >= 0x6399 && group.code_point() <= 0x639C);

            // Public key size should be classical + PQC
            let expected_size = match group.classical_algorithm() {
                "X25519" => 32,
                "P-256" => 65,
                "P-384" => 97,
                _ => unreachable!(),
            } + group.pqc_algorithm().public_key_size();

            assert_eq!(group.public_key_size(), expected_size);
        }
    }
}
