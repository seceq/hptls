//! ML-DSA (FIPS 204) digital signature implementation using hpcrypt.
//!
//! ML-DSA provides post-quantum secure digital signatures with three security levels:
//! - ML-DSA-44: 128-bit classical security equivalent
//! - ML-DSA-65: 192-bit classical security equivalent (recommended)
//! - ML-DSA-87: 256-bit classical security equivalent

use hptls_crypto::{
    signature::{Signature, SignatureAlgorithm, SigningKey, VerifyingKey},
    Error, Result,
};
use hpcrypt_mldsa::{
    keygen::keygen,
    params::{MlDsa44, MlDsa65, MlDsa87},
    sign::sign,
    verify::verify,
};

/// ML-DSA-44 signature algorithm (128-bit security).
#[derive(Debug, Clone, Copy)]
pub struct MlDsa44Sig;

impl Signature for MlDsa44Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        // Deserialize secret key
        let sk = hpcrypt_mldsa::serialize::deserialize_secret_key::<MlDsa44>(signing_key)
            .map_err(|_| Error::InvalidSignature)?;

        // Sign the message
        let signature = sign(&sk, message)
            .ok_or(Error::SignatureVerificationFailed)?;

        // Serialize signature
        Ok(hpcrypt_mldsa::serialize::serialize_signature(&signature))
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        // Deserialize public key
        let pk = hpcrypt_mldsa::serialize::deserialize_public_key::<MlDsa44>(verifying_key)
            .map_err(|_| Error::InvalidPublicKey)?;

        // Deserialize signature
        let sig = hpcrypt_mldsa::serialize::deserialize_signature::<MlDsa44>(signature)
            .map_err(|_| Error::InvalidSignature)?;

        // Verify
        if verify(&pk, message, &sig) {
            Ok(())
        } else {
            Err(Error::SignatureVerificationFailed)
        }
    }

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        let (pk, sk) = keygen::<MlDsa44>();

        Ok((
            SigningKey::from_bytes(hpcrypt_mldsa::serialize::serialize_secret_key(&sk)),
            VerifyingKey::from_bytes(hpcrypt_mldsa::serialize::serialize_public_key(&pk)),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::MlDsa44
    }
}

/// ML-DSA-65 signature algorithm (192-bit security, recommended).
#[derive(Debug, Clone, Copy)]
pub struct MlDsa65Sig;

impl Signature for MlDsa65Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sk = hpcrypt_mldsa::serialize::deserialize_secret_key::<MlDsa65>(signing_key)
            .map_err(|_| Error::InvalidSignature)?;

        let signature = sign(&sk, message)
            .ok_or(Error::SignatureVerificationFailed)?;

        Ok(hpcrypt_mldsa::serialize::serialize_signature(&signature))
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        let pk = hpcrypt_mldsa::serialize::deserialize_public_key::<MlDsa65>(verifying_key)
            .map_err(|_| Error::InvalidPublicKey)?;

        let sig = hpcrypt_mldsa::serialize::deserialize_signature::<MlDsa65>(signature)
            .map_err(|_| Error::InvalidSignature)?;

        if verify(&pk, message, &sig) {
            Ok(())
        } else {
            Err(Error::SignatureVerificationFailed)
        }
    }

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        let (pk, sk) = keygen::<MlDsa65>();

        Ok((
            SigningKey::from_bytes(hpcrypt_mldsa::serialize::serialize_secret_key(&sk)),
            VerifyingKey::from_bytes(hpcrypt_mldsa::serialize::serialize_public_key(&pk)),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::MlDsa65
    }
}

/// ML-DSA-87 signature algorithm (256-bit security).
#[derive(Debug, Clone, Copy)]
pub struct MlDsa87Sig;

impl Signature for MlDsa87Sig {
    fn sign(&self, signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sk = hpcrypt_mldsa::serialize::deserialize_secret_key::<MlDsa87>(signing_key)
            .map_err(|_| Error::InvalidSignature)?;

        let signature = sign(&sk, message)
            .ok_or(Error::SignatureVerificationFailed)?;

        Ok(hpcrypt_mldsa::serialize::serialize_signature(&signature))
    }

    fn verify(&self, verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        let pk = hpcrypt_mldsa::serialize::deserialize_public_key::<MlDsa87>(verifying_key)
            .map_err(|_| Error::InvalidPublicKey)?;

        let sig = hpcrypt_mldsa::serialize::deserialize_signature::<MlDsa87>(signature)
            .map_err(|_| Error::InvalidSignature)?;

        if verify(&pk, message, &sig) {
            Ok(())
        } else {
            Err(Error::SignatureVerificationFailed)
        }
    }

    fn generate_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        let (pk, sk) = keygen::<MlDsa87>();

        Ok((
            SigningKey::from_bytes(hpcrypt_mldsa::serialize::serialize_secret_key(&sk)),
            VerifyingKey::from_bytes(hpcrypt_mldsa::serialize::serialize_public_key(&pk)),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::MlDsa87
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa44_sign_verify() {
        let sig_algo = MlDsa44Sig;
        let (signing_key, verifying_key) = sig_algo.generate_keypair().unwrap();

        let message = b"Hello, post-quantum world!";
        let signature = sig_algo.sign(signing_key.as_bytes(), message).unwrap();

        sig_algo.verify(verifying_key.as_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn test_mldsa44_verify_fails_wrong_message() {
        let sig_algo = MlDsa44Sig;
        let (signing_key, verifying_key) = sig_algo.generate_keypair().unwrap();

        let message = b"Hello, post-quantum world!";
        let signature = sig_algo.sign(signing_key.as_bytes(), message).unwrap();

        let wrong_message = b"Different message";
        assert!(sig_algo.verify(verifying_key.as_bytes(), wrong_message, &signature).is_err());
    }

    #[test]
    fn test_mldsa65_sign_verify() {
        let sig_algo = MlDsa65Sig;
        let (signing_key, verifying_key) = sig_algo.generate_keypair().unwrap();

        let message = b"Testing ML-DSA-65";
        let signature = sig_algo.sign(signing_key.as_bytes(), message).unwrap();

        sig_algo.verify(verifying_key.as_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn test_mldsa87_sign_verify() {
        let sig_algo = MlDsa87Sig;
        let (signing_key, verifying_key) = sig_algo.generate_keypair().unwrap();

        let message = b"Testing ML-DSA-87";
        let signature = sig_algo.sign(signing_key.as_bytes(), message).unwrap();

        sig_algo.verify(verifying_key.as_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn test_signature_sizes() {
        let sig44 = MlDsa44Sig;
        let (sk44, _) = sig44.generate_keypair().unwrap();
        let sig44_bytes = sig44.sign(sk44.as_bytes(), b"test").unwrap();
        println!("ML-DSA-44 signature size: {} bytes", sig44_bytes.len());

        let sig65 = MlDsa65Sig;
        let (sk65, _) = sig65.generate_keypair().unwrap();
        let sig65_bytes = sig65.sign(sk65.as_bytes(), b"test").unwrap();
        println!("ML-DSA-65 signature size: {} bytes", sig65_bytes.len());

        let sig87 = MlDsa87Sig;
        let (sk87, _) = sig87.generate_keypair().unwrap();
        let sig87_bytes = sig87.sign(sk87.as_bytes(), b"test").unwrap();
        println!("ML-DSA-87 signature size: {} bytes", sig87_bytes.len());
    }
}
