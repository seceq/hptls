//! ChaCha20-Poly1305 Known Answer Tests (KAT)
//!
//! Test vectors for ChaCha20-Poly1305 AEAD cipher from RFC 8439.

use hptls_crypto::{AeadAlgorithm, CryptoProvider, Result};
use crate::HpcryptProvider;

/// Run all ChaCha20-Poly1305 Known Answer Tests
pub(crate) fn run_chacha20_kats() -> Result<()> {
    kat_chacha20_poly1305_rfc8439()?;
    Ok(())
}

/// ChaCha20-Poly1305 Known Answer Test
///
/// Test vector from RFC 8439 Section 2.8.2
fn kat_chacha20_poly1305_rfc8439() -> Result<()> {
    let provider = HpcryptProvider::new();
    let aead = provider.aead(AeadAlgorithm::ChaCha20Poly1305)?;

    // RFC 8439 Test Vector
    // Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    let plaintext = hex::decode(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
         73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
         6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
         637265656e20776f756c642062652069742e"
    ).unwrap();

    // AAD: 50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

    // Key: 256-bit key
    let key = hex::decode(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    ).unwrap();

    // Nonce: 12 bytes (96 bits)
    let nonce = hex::decode("070000004041424344454647").unwrap();

    // Expected ciphertext + tag
    let expected_ciphertext_and_tag = hex::decode(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116\
         1ae10b594f09e26a7e902ecbd0600691"
    ).unwrap();

    // Split expected result into ciphertext and tag
    let expected_ciphertext = &expected_ciphertext_and_tag[..plaintext.len()];
    let expected_tag = &expected_ciphertext_and_tag[plaintext.len()..];

    // Encrypt
    let ciphertext_with_tag = aead.seal(&key, &nonce, &aad, &plaintext)?;

    // Split into ciphertext and tag
    let (ciphertext, tag) = ciphertext_with_tag.split_at(plaintext.len());

    // Verify ciphertext matches
    if ciphertext != expected_ciphertext {
        return Err(hptls_crypto::Error::CryptoError(
            "ChaCha20-Poly1305 KAT: Ciphertext mismatch".to_string()
        ));
    }

    // Verify tag matches
    if tag != expected_tag {
        return Err(hptls_crypto::Error::CryptoError(
            "ChaCha20-Poly1305 KAT: Tag mismatch".to_string()
        ));
    }

    // Decrypt and verify
    let mut ciphertext_with_tag_vec = ciphertext.to_vec();
    ciphertext_with_tag_vec.extend_from_slice(tag);

    let decrypted = aead.open(&key, &nonce, &aad, &ciphertext_with_tag_vec)?;

    // Verify decrypted plaintext matches
    if decrypted != plaintext {
        return Err(hptls_crypto::Error::CryptoError(
            "ChaCha20-Poly1305 KAT: Decrypted plaintext mismatch".to_string()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_kat() {
        let result = kat_chacha20_poly1305_rfc8439();
        assert!(result.is_ok(), "ChaCha20-Poly1305 KAT should pass: {:?}", result);
    }

    #[test]
    fn test_all_chacha20_kats() {
        let result = run_chacha20_kats();
        assert!(result.is_ok(), "ChaCha20 KATs should pass: {:?}", result);
    }
}
