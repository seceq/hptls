//! ECDH Known Answer Tests (KAT)
//!
//! Test vectors for X25519 and X448 key exchange.
//! These tests verify that the ECDH implementation produces correct shared secrets.

use hptls_crypto::Result;

/// Run all ECDH Known Answer Tests
pub(crate) fn run_ecdh_kats() -> Result<()> {
    kat_x25519()?;
    kat_x448()?;
    kat_p256()?;
    Ok(())
}

/// X25519 Known Answer Test
///
/// Test vector from RFC 7748 Section 5.2
fn kat_x25519() -> Result<()> {
    use crate::kex::X25519Kex;

    // RFC 7748 Test Vector
    // Alice's private key
    let alice_private = hex::decode(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    ).unwrap();

    // Alice's public key
    let expected_alice_public = hex::decode(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    ).unwrap();

    // Bob's public key
    let bob_public = hex::decode(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    ).unwrap();

    // Expected shared secret
    let expected_shared_secret = hex::decode(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    ).unwrap();

    // Generate Alice's public key from private key
    let alice_public = X25519Kex::public_key(&alice_private)
        .map_err(|e| hptls_crypto::Error::CryptoError(format!("X25519 public key: {}", e)))?;

    // Verify Alice's public key
    if alice_public != expected_alice_public.as_slice() {
        return Err(hptls_crypto::Error::CryptoError(
            "X25519 KAT: Alice's public key mismatch".to_string()
        ));
    }

    // Compute shared secret (Alice's perspective)
    let shared_secret = X25519Kex::shared_secret(&alice_private, &bob_public)
        .map_err(|e| hptls_crypto::Error::CryptoError(format!("X25519 shared secret: {}", e)))?;

    // Verify shared secret
    if shared_secret.as_slice() != expected_shared_secret.as_slice() {
        return Err(hptls_crypto::Error::CryptoError(
            "X25519 KAT: Shared secret mismatch".to_string()
        ));
    }

    Ok(())
}

/// X448 Known Answer Test
///
/// Test vector from RFC 7748 Section 5.2
fn kat_x448() -> Result<()> {
    use crate::kex::X448Kex;

    // RFC 7748 Test Vector
    // Alice's private key
    let alice_private = hex::decode(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5\
         74a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
    ).unwrap();

    // Alice's public key
    let expected_alice_public = hex::decode(
        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bb\
         c836647241d953d40c5b12da88120d53177f80e532c41fa0"
    ).unwrap();

    // Bob's public key
    let bob_public = hex::decode(
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972\
         fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
    ).unwrap();

    // Expected shared secret
    let expected_shared_secret = hex::decode(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56\
         fd2464c335543936521c24403085d59a449a5037514a879d"
    ).unwrap();

    // Generate Alice's public key from private key
    let alice_public = X448Kex::public_key(&alice_private)
        .map_err(|e| hptls_crypto::Error::CryptoError(format!("X448 public key: {}", e)))?;

    // Verify Alice's public key
    if alice_public != expected_alice_public.as_slice() {
        return Err(hptls_crypto::Error::CryptoError(
            "X448 KAT: Alice's public key mismatch".to_string()
        ));
    }

    // Compute shared secret (Alice's perspective)
    let shared_secret = X448Kex::shared_secret(&alice_private, &bob_public)
        .map_err(|e| hptls_crypto::Error::CryptoError(format!("X448 shared secret: {}", e)))?;

    // Verify shared secret
    if shared_secret.as_slice() != expected_shared_secret.as_slice() {
        return Err(hptls_crypto::Error::CryptoError(
            "X448 KAT: Shared secret mismatch".to_string()
        ));
    }

    Ok(())
}

/// P-256 ECDH Known Answer Test
///
/// Basic functionality test for P-256 key exchange
fn kat_p256() -> Result<()> {
    use crate::kex::EcdhP256;

    // Generate a keypair and verify the operation works
    let private1 = vec![0x42; 32]; // Simple test private key
    let public1 = EcdhP256::public_key(&private1)
        .map_err(|e| hptls_crypto::Error::CryptoError(format!("P-256 public key 1: {}", e)))?;

    let private2 = vec![0x24; 32]; // Different test private key
    let public2 = EcdhP256::public_key(&private2)
        .map_err(|e| hptls_crypto::Error::CryptoError(format!("P-256 public key 2: {}", e)))?;

    // Compute shared secrets from both sides
    let shared1 = EcdhP256::shared_secret(&private1, &public2)
        .map_err(|e| hptls_crypto::Error::CryptoError(format!("P-256 shared secret 1: {}", e)))?;

    let shared2 = EcdhP256::shared_secret(&private2, &public1)
        .map_err(|e| hptls_crypto::Error::CryptoError(format!("P-256 shared secret 2: {}", e)))?;

    // Verify shared secrets match
    if shared1.as_slice() != shared2.as_slice() {
        return Err(hptls_crypto::Error::CryptoError(
            "P-256 KAT: Shared secrets don't match".to_string()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_kat() {
        let result = kat_x25519();
        assert!(result.is_ok(), "X25519 KAT should pass: {:?}", result);
    }

    #[test]
    fn test_x448_kat() {
        let result = kat_x448();
        assert!(result.is_ok(), "X448 KAT should pass: {:?}", result);
    }

    #[test]
    fn test_p256_kat() {
        let result = kat_p256();
        assert!(result.is_ok(), "P-256 KAT should pass: {:?}", result);
    }

    #[test]
    fn test_all_ecdh_kats() {
        let result = run_ecdh_kats();
        assert!(result.is_ok(), "ECDH KATs should pass: {:?}", result);
    }
}
