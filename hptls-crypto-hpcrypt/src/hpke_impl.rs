//! HPKE implementation using hpcrypt-hpke

use hpcrypt_hpke::HpkeP256;
use hptls_crypto::{
    Error, Hpke, HpkeAead, HpkeCipherSuite, HpkeContext as HpkeContextTrait, HpkeKdf, HpkeKem,
    Result,
};
use std::sync::Mutex;

/// Create an HPKE instance with the given cipher suite
pub fn create_hpke(cipher_suite: HpkeCipherSuite) -> Result<Box<dyn Hpke>> {
    Ok(Box::new(HpcryptHpke::new(cipher_suite)?))
}

/// Wrapper for hpcrypt-hpke context to implement our trait
struct HpcryptHpkeContext {
    inner: Mutex<hpcrypt_hpke::context::HpkeContext>,
}

impl HpkeContextTrait for HpcryptHpkeContext {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ctx = self.inner.lock().unwrap();
        ctx.seal(aad, plaintext)
            .map_err(|e| Error::CryptoError(format!("HPKE seal failed: {:?}", e)))
    }

    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut ctx = self.inner.lock().unwrap();
        ctx.open(aad, ciphertext)
            .map_err(|e| Error::CryptoError(format!("HPKE open failed: {:?}", e)))
    }

    fn export(&self, context: &[u8], length: usize) -> Vec<u8> {
        let ctx = self.inner.lock().unwrap();
        ctx.export(context, length)
    }
}

/// HPKE implementation using hpcrypt
pub struct HpcryptHpke {
    cipher_suite: HpkeCipherSuite,
    hpke: HpkeP256,
}

impl HpcryptHpke {
    /// Create a new HPKE instance with the given cipher suite
    pub fn new(cipher_suite: HpkeCipherSuite) -> Result<Self> {
        // Validate the cipher suite is supported
        if cipher_suite.kem != HpkeKem::DhkemP256HkdfSha256 {
            return Err(Error::UnsupportedAlgorithm(format!(
                "KEM {:?} not supported, only P-256 is available",
                cipher_suite.kem
            )));
        }

        if cipher_suite.kdf != HpkeKdf::HkdfSha256 {
            return Err(Error::UnsupportedAlgorithm(format!(
                "KDF {:?} not supported, only HKDF-SHA256 is available",
                cipher_suite.kdf
            )));
        }

        // Create the appropriate hpcrypt HPKE instance based on AEAD
        let hpke = match cipher_suite.aead {
            HpkeAead::Aes128Gcm => HpkeP256::new(),
            HpkeAead::Aes256Gcm => HpkeP256::with_aes256(),
            HpkeAead::ChaCha20Poly1305 => HpkeP256::with_chacha(),
            // Handle any future AEADs that might be added
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "AEAD {:?} not supported",
                    cipher_suite.aead
                )))
            }
        };

        Ok(Self { cipher_suite, hpke })
    }
}

impl Hpke for HpcryptHpke {
    fn cipher_suite(&self) -> HpkeCipherSuite {
        self.cipher_suite
    }

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = rand::thread_rng();
        HpkeP256::generate_keypair(&mut rng).map_err(|e| {
            Error::CryptoError(format!("HPKE keypair generation failed: {:?}", e))
        })
    }

    fn setup_base_sender(
        &self,
        pk_r: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, Box<dyn HpkeContextTrait>)> {
        let mut rng = rand::thread_rng();
        let (enc, ctx) = self
            .hpke
            .setup_base_sender(pk_r, info, &mut rng)
            .map_err(|e| {
                Error::CryptoError(format!("HPKE setup_base_sender failed: {:?}", e))
            })?;

        Ok((
            enc,
            Box::new(HpcryptHpkeContext {
                inner: Mutex::new(ctx),
            }),
        ))
    }

    fn setup_base_recipient(
        &self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
    ) -> Result<Box<dyn HpkeContextTrait>> {
        let ctx = self
            .hpke
            .setup_base_recipient(enc, sk_r, info)
            .map_err(|e| {
                Error::CryptoError(format!("HPKE setup_base_recipient failed: {:?}", e))
            })?;

        Ok(Box::new(HpcryptHpkeContext {
            inner: Mutex::new(ctx),
        }))
    }

    fn seal_base(
        &self,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        self.hpke
            .seal_base(pk_r, info, aad, plaintext, &mut rng)
            .map_err(|e| Error::CryptoError(format!("HPKE seal_base failed: {:?}", e)))
    }

    fn open_base(
        &self,
        enc_and_ciphertext: &[u8],
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        self.hpke
            .open_base(enc_and_ciphertext, sk_r, info, aad)
            .map_err(|e| Error::CryptoError(format!("HPKE open_base failed: {:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpke_round_trip() {
        let suite = HpkeCipherSuite::ech_default_p256();
        let hpke = HpcryptHpke::new(suite).unwrap();

        // Generate recipient keypair
        let (sk_r, pk_r) = hpke.generate_keypair().unwrap();

        let info = b"test application";
        let aad = b"associated data";
        let plaintext = b"secret message for ECH";

        // Encrypt
        let enc_and_ct = hpke.seal_base(&pk_r, info, aad, plaintext).unwrap();

        // Decrypt
        let decrypted = hpke.open_base(&enc_and_ct, &sk_r, info, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hpke_context() {
        let suite = HpkeCipherSuite::ech_default_p256();
        let hpke = HpcryptHpke::new(suite).unwrap();

        let (sk_r, pk_r) = hpke.generate_keypair().unwrap();
        let info = b"session";

        // Setup contexts
        let (enc, mut sender_ctx) = hpke.setup_base_sender(&pk_r, info).unwrap();
        let mut recipient_ctx = hpke.setup_base_recipient(&enc, &sk_r, info).unwrap();

        // Send multiple messages
        for i in 0..3 {
            let msg = format!("Message {}", i);
            let ct = sender_ctx.seal(&[], msg.as_bytes()).unwrap();
            let pt = recipient_ctx.open(&[], &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_hpke_export() {
        let suite = HpkeCipherSuite::ech_default_p256();
        let hpke = HpcryptHpke::new(suite).unwrap();

        let (sk_r, pk_r) = hpke.generate_keypair().unwrap();
        let info = b"session";

        let (enc, sender_ctx) = hpke.setup_base_sender(&pk_r, info).unwrap();
        let recipient_ctx = hpke.setup_base_recipient(&enc, &sk_r, info).unwrap();

        // Export secrets
        let context = b"key derivation";
        let sender_secret = sender_ctx.export(context, 32);
        let recipient_secret = recipient_ctx.export(context, 32);

        assert_eq!(sender_secret, recipient_secret);
        assert_eq!(sender_secret.len(), 32);
    }

    #[test]
    fn test_aes256_cipher_suite() {
        let suite = HpkeCipherSuite::new(
            HpkeKem::DhkemP256HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes256Gcm,
        );
        let hpke = HpcryptHpke::new(suite).unwrap();

        let (sk_r, pk_r) = hpke.generate_keypair().unwrap();
        let plaintext = b"test with AES-256-GCM";

        let enc_and_ct = hpke.seal_base(&pk_r, b"", b"", plaintext).unwrap();
        let decrypted = hpke.open_base(&enc_and_ct, &sk_r, b"", b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha_cipher_suite() {
        let suite = HpkeCipherSuite::new(
            HpkeKem::DhkemP256HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::ChaCha20Poly1305,
        );
        let hpke = HpcryptHpke::new(suite).unwrap();

        let (sk_r, pk_r) = hpke.generate_keypair().unwrap();
        let plaintext = b"test with ChaCha20-Poly1305";

        let enc_and_ct = hpke.seal_base(&pk_r, b"", b"", plaintext).unwrap();
        let decrypted = hpke.open_base(&enc_and_ct, &sk_r, b"", b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
