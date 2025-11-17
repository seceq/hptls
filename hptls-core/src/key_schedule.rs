//! TLS 1.3 Key Schedule (RFC 8446 Section 7.1).
//!
//! The TLS 1.3 key schedule uses HKDF to derive all cryptographic keys and IVs
//! from the shared secret established during the handshake.
//!
//! Key Schedule Overview:
//! ```text
//!              0
//!              |
//!              v
//!   PSK ->  HKDF-Extract = Early Secret
//!              |
//!              +-----> Derive-Secret(., "ext binder" | "res binder", "")
//!              |                     = binder_key
//!              |
//!              +-----> Derive-Secret(., "c e traffic", ClientHello)
//!              |                     = client_early_traffic_secret
//!              |
//!              +-----> Derive-Secret(., "e exp master", ClientHello)
//!              |                     = early_exporter_master_secret
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!   (EC)DHE -> HKDF-Extract = Handshake Secret
//!              |
//!              +-----> Derive-Secret(., "c hs traffic",
//!              |                     ClientHello...ServerHello)
//!              |                     = client_handshake_traffic_secret
//!              |
//!              +-----> Derive-Secret(., "s hs traffic",
//!              |                     ClientHello...ServerHello)
//!              |                     = server_handshake_traffic_secret
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!   0 -> HKDF-Extract = Master Secret
//!              |
//!              +-----> Derive-Secret(., "c ap traffic",
//!              |                     ClientHello...server Finished)
//!              |                     = client_application_traffic_secret_0
//!              |
//!              +-----> Derive-Secret(., "s ap traffic",
//!              |                     ClientHello...server Finished)
//!              |                     = server_application_traffic_secret_0
//!              |
//!              +-----> Derive-Secret(., "exp master",
//!              |                     ClientHello...server Finished)
//!              |                     = exporter_master_secret
//!              |
//!              +-----> Derive-Secret(., "res master",
//!                                    ClientHello...client Finished)
//!                                    = resumption_master_secret
//! ```

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};
use hptls_crypto::{CryptoProvider, HashAlgorithm, KdfAlgorithm};
use zeroize::Zeroizing;

/// TLS 1.3 Key Schedule.
///
/// Manages the derivation of all cryptographic secrets for a TLS 1.3 connection.
pub struct KeySchedule {
    /// Selected cipher suite
    cipher_suite: CipherSuite,

    /// Hash algorithm for this cipher suite
    hash_algorithm: HashAlgorithm,

    /// Hash length in bytes
    hash_len: usize,

    /// Early secret (derived from PSK or 0)
    early_secret: Option<Zeroizing<Vec<u8>>>,

    /// Client early traffic secret (for 0-RTT)
    client_early_traffic_secret: Option<Zeroizing<Vec<u8>>>,

    /// Handshake secret (derived from (EC)DHE)
    handshake_secret: Option<Zeroizing<Vec<u8>>>,

    /// Master secret (final secret)
    master_secret: Option<Zeroizing<Vec<u8>>>,

    /// Client handshake traffic secret
    client_handshake_traffic_secret: Option<Zeroizing<Vec<u8>>>,

    /// Server handshake traffic secret
    server_handshake_traffic_secret: Option<Zeroizing<Vec<u8>>>,

    /// Client application traffic secret
    client_application_traffic_secret: Option<Zeroizing<Vec<u8>>>,

    /// Server application traffic secret
    server_application_traffic_secret: Option<Zeroizing<Vec<u8>>>,

    /// Transcript hash at various points
    transcript_hash: Vec<u8>,
}

impl KeySchedule {
    /// Create a new key schedule for the given cipher suite.
    pub fn new(cipher_suite: CipherSuite) -> Self {
        let hash_algorithm = cipher_suite.hash_algorithm();
        let hash_len = match hash_algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        };

        Self {
            cipher_suite,
            hash_algorithm,
            hash_len,
            early_secret: None,
            client_early_traffic_secret: None,
            handshake_secret: None,
            master_secret: None,
            client_handshake_traffic_secret: None,
            server_handshake_traffic_secret: None,
            client_application_traffic_secret: None,
            server_application_traffic_secret: None,
            transcript_hash: Vec::new(),
        }
    }

    /// Initialize early secret from PSK.
    ///
    /// If no PSK, pass an empty slice to derive from 0.
    pub fn init_early_secret<P: CryptoProvider + ?Sized>(
        &mut self,
        provider: &P,
        psk: &[u8],
    ) -> Result<()> {
        let kdf = provider
            .kdf(KdfAlgorithm::HkdfSha256)
            .map_err(|e| Error::CryptoError(format!("KDF init failed: {:?}", e)))?;

        // If no PSK, use zero-filled array
        let psk_data = if psk.is_empty() {
            vec![0u8; self.hash_len]
        } else {
            psk.to_vec()
        };

        // Early Secret = HKDF-Extract(salt=0, IKM=PSK)
        let salt = vec![0u8; self.hash_len];
        let early_secret = kdf.extract(&salt, &psk_data);

        self.early_secret = Some(Zeroizing::new(early_secret));
        Ok(())
    }

    /// Derive PSK binder key for resumption
    ///
    /// The binder key is derived from the early secret and used to compute
    /// the PSK binder value in ClientHello.
    ///
    /// # RFC 8446 Section 4.2.11.2
    ///
    /// ```text
    /// binder_key = Derive-Secret(early_secret, "res binder" | "ext binder", "")
    /// finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
    /// ```
    ///
    /// Use "res binder" for resumption PSKs, "ext binder" for external PSKs.
    pub fn derive_binder_key<P: CryptoProvider + ?Sized>(
        &self,
        provider: &P,
        is_external: bool,
    ) -> Result<Vec<u8>> {
        if self.early_secret.is_none() {
            return Err(Error::InternalError("Early secret not initialized".into()));
        }

        let label = if is_external {
            "ext binder"
        } else {
            "res binder"
        };

        self.derive_secret(provider, self.early_secret.as_ref().unwrap(), label, &[])
    }

    /// Compute PSK binder value
    ///
    /// The binder is a MAC over the partial ClientHello (up to and including
    /// the PSK identities, but not the binders themselves).
    ///
    /// # Arguments
    ///
    /// * `provider` - Crypto provider
    /// * `binder_key` - The binder key derived from early secret
    /// * `transcript_hash` - Hash of partial ClientHello (up to binders)
    ///
    /// # Returns
    ///
    /// The PSK binder value
    pub fn compute_psk_binder(
        &self,
        provider: &dyn CryptoProvider,
        binder_key: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        // finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
        let finished_key = crate::transcript::hkdf_expand_label(
            provider,
            self.hash_algorithm,
            binder_key,
            b"finished",
            &[],
            self.hash_len,
        )?;

        // binder = HMAC(finished_key, transcript_hash)
        let mut hmac = provider.hmac(self.hash_algorithm, &finished_key)?;
        hmac.update(transcript_hash);
        let binder = hmac.finalize();

        Ok(binder)
    }

    /// Derive handshake secret from shared secret (ECDHE/DHE).
    pub fn derive_handshake_secret<P: CryptoProvider + ?Sized>(
        &mut self,
        provider: &P,
        shared_secret: &[u8],
    ) -> Result<()> {
        if self.early_secret.is_none() {
            return Err(Error::InternalError("Early secret not initialized".into()));
        }

        let kdf = provider
            .kdf(self.hash_algorithm.to_kdf_algorithm())
            .map_err(|e| Error::CryptoError(format!("KDF init failed: {:?}", e)))?;

        // Derive-Secret(early_secret, "derived", Hash(""))
        // The context for "derived" label is the hash of an empty string
        let empty_hash = {
            let hasher = provider.hash(self.hash_algorithm)?;
            hasher.finalize()
        };
        let derived = self.derive_secret(
            provider,
            self.early_secret.as_ref().unwrap(),
            "derived",
            &empty_hash,
        )?;

        // Handshake Secret = HKDF-Extract(salt=derived, IKM=shared_secret)
        let handshake_secret = kdf.extract(&derived, shared_secret);

        self.handshake_secret = Some(Zeroizing::new(handshake_secret));
        Ok(())
    }

    /// Derive master secret.
    pub fn derive_master_secret<P: CryptoProvider + ?Sized>(&mut self, provider: &P) -> Result<()> {
        if self.handshake_secret.is_none() {
            return Err(Error::InternalError(
                "Handshake secret not initialized".into(),
            ));
        }

        let kdf = provider
            .kdf(self.hash_algorithm.to_kdf_algorithm())
            .map_err(|e| Error::CryptoError(format!("KDF init failed: {:?}", e)))?;

        // Derive-Secret(handshake_secret, "derived", Hash(""))
        // The context for "derived" label is the hash of an empty string
        let empty_hash = {
            let hasher = provider.hash(self.hash_algorithm)?;
            hasher.finalize()
        };
        let derived = self.derive_secret(
            provider,
            self.handshake_secret.as_ref().unwrap(),
            "derived",
            &empty_hash,
        )?;

        // Master Secret = HKDF-Extract(salt=derived, IKM=0)
        let ikm = vec![0u8; self.hash_len];
        let master_secret = kdf.extract(&derived, &ikm);

        self.master_secret = Some(Zeroizing::new(master_secret));
        Ok(())
    }

    /// Derive a secret using Derive-Secret.
    ///
    /// Derive-Secret(Secret, Label, Messages) =
    ///     HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length)
    fn derive_secret<P: CryptoProvider + ?Sized>(
        &self,
        provider: &P,
        secret: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        let kdf = provider
            .kdf(self.hash_algorithm.to_kdf_algorithm())
            .map_err(|e| Error::CryptoError(format!("KDF init failed: {:?}", e)))?;

        // HkdfLabel structure:
        // struct {
        //     uint16 length = Hash.length;
        //     opaque label<7..255> = "tls13 " + Label;
        //     opaque context<0..255> = Hash(Messages);
        // } HkdfLabel;

        let full_label = format!("tls13 {}", label);
        let mut hkdf_label = Vec::new();

        // Length (2 bytes)
        hkdf_label.extend_from_slice(&(self.hash_len as u16).to_be_bytes());

        // Label length + label
        hkdf_label.push(full_label.len() as u8);
        hkdf_label.extend_from_slice(full_label.as_bytes());

        // Context length + context
        hkdf_label.push(transcript_hash.len() as u8);
        hkdf_label.extend_from_slice(transcript_hash);

        // HKDF-Expand(secret, info=HkdfLabel, length)
        kdf.expand(secret, &hkdf_label, self.hash_len)
            .map_err(|e| Error::CryptoError(format!("HKDF-Expand failed: {:?}", e)))
    }

    /// Derive client handshake traffic secret.
    pub fn derive_client_handshake_traffic_secret<P: CryptoProvider + ?Sized>(
        &mut self,
        provider: &P,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        if self.handshake_secret.is_none() {
            return Err(Error::InternalError(
                "Handshake secret not initialized".into(),
            ));
        }

        let secret = self.derive_secret(
            provider,
            self.handshake_secret.as_ref().unwrap(),
            "c hs traffic",
            transcript_hash,
        )?;

        self.client_handshake_traffic_secret = Some(Zeroizing::new(secret.clone()));
        Ok(secret)
    }

    /// Derive server handshake traffic secret.
    pub fn derive_server_handshake_traffic_secret<P: CryptoProvider + ?Sized>(
        &mut self,
        provider: &P,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        if self.handshake_secret.is_none() {
            return Err(Error::InternalError(
                "Handshake secret not initialized".into(),
            ));
        }

        let secret = self.derive_secret(
            provider,
            self.handshake_secret.as_ref().unwrap(),
            "s hs traffic",
            transcript_hash,
        )?;

        self.server_handshake_traffic_secret = Some(Zeroizing::new(secret.clone()));
        Ok(secret)
    }

    /// Derive client application traffic secret.
    pub fn derive_client_application_traffic_secret<P: CryptoProvider + ?Sized>(
        &mut self,
        provider: &P,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        if self.master_secret.is_none() {
            return Err(Error::InternalError("Master secret not initialized".into()));
        }

        let secret = self.derive_secret(
            provider,
            self.master_secret.as_ref().unwrap(),
            "c ap traffic",
            transcript_hash,
        )?;

        self.client_application_traffic_secret = Some(Zeroizing::new(secret.clone()));
        Ok(secret)
    }

    /// Derive server application traffic secret.
    pub fn derive_server_application_traffic_secret<P: CryptoProvider + ?Sized>(
        &mut self,
        provider: &P,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        if self.master_secret.is_none() {
            return Err(Error::InternalError("Master secret not initialized".into()));
        }

        let secret = self.derive_secret(
            provider,
            self.master_secret.as_ref().unwrap(),
            "s ap traffic",
            transcript_hash,
        )?;

        self.server_application_traffic_secret = Some(Zeroizing::new(secret.clone()));
        Ok(secret)
    }

    /// Derive client early traffic secret (for 0-RTT).
    ///
    /// This secret is derived from the early secret using the ClientHello
    /// transcript hash. It's used to encrypt early data (0-RTT).
    ///
    /// # RFC 8446 Key Schedule
    ///
    /// ```text
    /// client_early_traffic_secret =
    ///     Derive-Secret(early_secret, "c e traffic", ClientHello)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `provider` - Crypto provider
    /// * `transcript_hash` - Hash of ClientHello message
    ///
    /// # Returns
    ///
    /// Returns the client early traffic secret.
    pub fn derive_client_early_traffic_secret<P: CryptoProvider + ?Sized>(
        &mut self,
        provider: &P,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        if self.early_secret.is_none() {
            return Err(Error::InternalError("Early secret not initialized".into()));
        }

        let secret = self.derive_secret(
            provider,
            self.early_secret.as_ref().unwrap(),
            "c e traffic",
            transcript_hash,
        )?;

        self.client_early_traffic_secret = Some(Zeroizing::new(secret.clone()));
        Ok(secret)
    }

    /// Derive exporter master secret.
    pub fn derive_exporter_master_secret<P: CryptoProvider + ?Sized>(
        &self,
        provider: &P,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        if self.master_secret.is_none() {
            return Err(Error::InternalError("Master secret not initialized".into()));
        }

        self.derive_secret(
            provider,
            self.master_secret.as_ref().unwrap(),
            "exp master",
            transcript_hash,
        )
    }

    /// Derive resumption master secret.
    pub fn derive_resumption_master_secret<P: CryptoProvider + ?Sized>(
        &self,
        provider: &P,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        if self.master_secret.is_none() {
            return Err(Error::InternalError("Master secret not initialized".into()));
        }

        self.derive_secret(
            provider,
            self.master_secret.as_ref().unwrap(),
            "res master",
            transcript_hash,
        )
    }

    /// Derive traffic keys and IV from traffic secret.
    ///
    /// key = HKDF-Expand-Label(Secret, "key", "", key_length)
    /// iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
    pub fn derive_traffic_keys<P: CryptoProvider + ?Sized>(
        &self,
        provider: &P,
        traffic_secret: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let key_len = self.cipher_suite.key_length();
        let iv_len = self.cipher_suite.iv_length();

        let key = self.derive_secret(provider, traffic_secret, "key", &[])?;
        let iv = self.derive_secret(provider, traffic_secret, "iv", &[])?;

        Ok((key[..key_len].to_vec(), iv[..iv_len].to_vec()))
    }

    /// Get client early traffic secret (for 0-RTT).
    pub fn get_client_early_traffic_secret(&self) -> Option<&[u8]> {
        self.client_early_traffic_secret.as_ref().map(|s| s.as_slice())
    }

    /// Get client handshake traffic secret.
    pub fn get_client_handshake_traffic_secret(&self) -> Option<&[u8]> {
        self.client_handshake_traffic_secret.as_ref().map(|s| s.as_slice())
    }

    /// Get server handshake traffic secret.
    pub fn get_server_handshake_traffic_secret(&self) -> Option<&[u8]> {
        self.server_handshake_traffic_secret.as_ref().map(|s| s.as_slice())
    }

    /// Get client application traffic secret.
    pub fn get_client_application_traffic_secret(&self) -> Option<&[u8]> {
        self.client_application_traffic_secret.as_ref().map(|s| s.as_slice())
    }

    /// Get server application traffic secret.
    pub fn get_server_application_traffic_secret(&self) -> Option<&[u8]> {
        self.server_application_traffic_secret.as_ref().map(|s| s.as_slice())
    }

    /// Update client application traffic secret.
    ///
    /// Derives the next generation of client application traffic secret using:
    /// ```text
    /// application_traffic_secret_N+1 =
    ///     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
    /// ```
    ///
    /// This is used when processing a KeyUpdate message (RFC 8446 Section 4.6.3).
    pub fn update_client_application_traffic_secret(
        &mut self,
        provider: &dyn CryptoProvider,
    ) -> Result<()> {
        let current_secret = self.client_application_traffic_secret.as_ref().ok_or_else(|| {
            Error::InternalError("Client application traffic secret not derived".into())
        })?;

        // Derive next generation: HKDF-Expand-Label(current, "traffic upd", "", Hash.length)
        let next_secret = crate::transcript::hkdf_expand_label(
            provider,
            self.hash_algorithm,
            current_secret.as_slice(),
            b"traffic upd",
            &[],
            self.hash_len,
        )?;

        self.client_application_traffic_secret = Some(Zeroizing::new(next_secret));
        Ok(())
    }

    /// Update server application traffic secret.
    ///
    /// Derives the next generation of server application traffic secret using:
    /// ```text
    /// application_traffic_secret_N+1 =
    ///     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
    /// ```
    ///
    /// This is used when processing a KeyUpdate message (RFC 8446 Section 4.6.3).
    pub fn update_server_application_traffic_secret(
        &mut self,
        provider: &dyn CryptoProvider,
    ) -> Result<()> {
        let current_secret = self.server_application_traffic_secret.as_ref().ok_or_else(|| {
            Error::InternalError("Server application traffic secret not derived".into())
        })?;

        // Derive next generation: HKDF-Expand-Label(current, "traffic upd", "", Hash.length)
        let next_secret = crate::transcript::hkdf_expand_label(
            provider,
            self.hash_algorithm,
            current_secret.as_slice(),
            b"traffic upd",
            &[],
            self.hash_len,
        )?;

        self.server_application_traffic_secret = Some(Zeroizing::new(next_secret));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_schedule_creation() {
        let ks = KeySchedule::new(CipherSuite::Aes128GcmSha256);
        assert_eq!(ks.hash_len, 32);
        assert_eq!(ks.hash_algorithm, HashAlgorithm::Sha256);
    }

    // Full key schedule tests require a CryptoProvider implementation
    // These will be added when we have a concrete provider
}
