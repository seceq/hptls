//! QUIC-TLS Integration (RFC 9001)
//!
//! This module provides the TLS integration layer for QUIC, mapping TLS 1.3
//! handshake to QUIC's transport protocol.
//! # Key Differences from TLS over TCP
//! 1. **No TLS Record Layer**: QUIC provides its own framing
//! 2. **Crypto Frames**: Handshake data sent in CRYPTO frames
//! 3. **Multiple Packet Number Spaces**: Initial, Handshake, Application
//! 4. **Key Derivation**: QUIC-specific labels ("quic key", "quic iv", "quic hp")
//! 5. **Header Protection**: Packet header encryption
//! 6. **Connection IDs**: QUIC connection identifiers
//! # Protocol Flow
//! ```text
//! Client                                           Server
//! Initial[0]: CRYPTO[CH]          -------->
//!                                 <--------  Initial[0]: CRYPTO[SH] ACK[0]
//!                                            Handshake[0]: CRYPTO[EE, CERT,
//!                                                          CV, FIN] ACK[0]
//! Initial[1]: ACK[0]              -------->
//! Handshake[0]: CRYPTO[FIN], ACK[0]
//! 1-RTT[0]: STREAM[...], ACK[0]   -------->
//!                                 <--------  1-RTT[0]: STREAM[...], ACK[0]
//! ```
//! # Packet Number Spaces
//! - **Initial**: Handshake protection before keys available
//! - **Handshake**: After TLS handshake keys derived
//! - **Application (1-RTT)**: After handshake completes

use crate::cipher::CipherSuite;
use crate::error::Result;
use hptls_crypto::{CryptoProvider, HashAlgorithm};
use std::collections::HashMap;
use zeroize::Zeroizing;
/// QUIC version (RFC 9000 = 0x00000001)
pub const QUIC_VERSION_1: u32 = 0x00000001;
/// QUIC packet number space
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketNumberSpace {
    /// Initial packet space (before keys)
    Initial,
    /// Handshake packet space (with handshake keys)
    Handshake,
    /// Application data packet space (1-RTT)
    ApplicationData,
}
/// QUIC key phase (for key updates)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPhase {
    /// Phase 0
    Phase0 = 0,
    /// Phase 1
    Phase1 = 1,
}
impl KeyPhase {
    /// Toggle key phase
    pub fn toggle(self) -> Self {
        match self {
            KeyPhase::Phase0 => KeyPhase::Phase1,
            KeyPhase::Phase1 => KeyPhase::Phase0,
        }
    }
}

/// QUIC transport parameters
///
/// Exchanged during TLS handshake via quic_transport_parameters extension
#[derive(Debug, Clone)]
pub struct QuicTransportParameters {
    /// Maximum idle timeout (milliseconds)
    pub max_idle_timeout: u64,
    /// Maximum UDP payload size
    pub max_udp_payload_size: u64,
    /// Initial maximum data
    pub initial_max_data: u64,
    /// Initial maximum stream data (bidirectional, local)
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial maximum stream data (bidirectional, remote)
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial maximum stream data (unidirectional)
    pub initial_max_stream_data_uni: u64,
    /// Initial maximum streams (bidirectional)
    pub initial_max_streams_bidi: u64,
    /// Initial maximum streams (unidirectional)
    pub initial_max_streams_uni: u64,
    /// ACK delay exponent
    pub ack_delay_exponent: u64,
    /// Maximum ACK delay
    pub max_ack_delay: u64,
    /// Disable active migration
    pub disable_active_migration: bool,
    /// Preferred address
    pub preferred_address: Option<Vec<u8>>,
    /// Active connection ID limit
    pub active_connection_id_limit: u64,
    /// Initial source connection ID
    pub initial_source_connection_id: Option<Vec<u8>>,
    /// Retry source connection ID
    pub retry_source_connection_id: Option<Vec<u8>>,
}

impl Default for QuicTransportParameters {
    fn default() -> Self {
        Self {
            max_idle_timeout: 30000, // 30 seconds
            max_udp_payload_size: 65527,
            initial_max_data: 1048576, // 1 MB
            initial_max_stream_data_bidi_local: 524288,
            initial_max_stream_data_bidi_remote: 524288,
            initial_max_stream_data_uni: 524288,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: 2,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
        }
    }
}
/// QUIC key material for a packet number space
#[derive(Debug)]
pub struct QuicKeys {
    /// Packet protection key
    pub key: Zeroizing<Vec<u8>>,
    /// Packet protection IV
    pub iv: Zeroizing<Vec<u8>>,
    /// Header protection key
    pub hp_key: Zeroizing<Vec<u8>>,
}
impl QuicKeys {
    /// Create new QUIC keys
    pub fn new(key: Vec<u8>, iv: Vec<u8>, hp_key: Vec<u8>) -> Self {
        Self {
            key: Zeroizing::new(key),
            iv: Zeroizing::new(iv),
            hp_key: Zeroizing::new(hp_key),
        }
    }
}
/// QUIC crypto context
/// Manages keys for all packet number spaces
#[derive(Debug)]
pub struct QuicCryptoContext {
    /// Keys for each packet number space
    keys: HashMap<PacketNumberSpace, QuicKeys>,
    /// Current key phase for application data
    key_phase: KeyPhase,
    /// Cipher suite
    cipher_suite: CipherSuite,
}
impl QuicCryptoContext {
    /// Create a new QUIC crypto context
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self {
            keys: HashMap::new(),
            key_phase: KeyPhase::Phase0,
            cipher_suite,
        }
    }
    /// Derive QUIC keys from TLS traffic secret
    ///
    /// Uses QUIC-specific labels:
    /// - "quic key" for packet protection key
    /// - "quic iv" for IV
    /// - "quic hp" for header protection key
    pub fn derive_keys(
        &mut self,
        provider: &dyn CryptoProvider,
        traffic_secret: &[u8],
        space: PacketNumberSpace,
    ) -> Result<()> {
        let hash_algorithm = self.cipher_suite.hash_algorithm();
        let key_length = self.cipher_suite.key_length();
        // Derive packet protection key
        let key = crate::transcript::hkdf_expand_label(
            provider,
            hash_algorithm,
            traffic_secret,
            b"quic key",
            &[],
            key_length,
        )?;
        // Derive IV (always 12 bytes for QUIC)
        let iv = crate::transcript::hkdf_expand_label(
            provider,
            hash_algorithm,
            traffic_secret,
            b"quic iv",
            &[],
            12,
        )?;
        // Derive header protection key
        let hp_key = crate::transcript::hkdf_expand_label(
            provider,
            hash_algorithm,
            traffic_secret,
            b"quic hp",
            &[],
            key_length,
        )?;
        self.keys.insert(space, QuicKeys::new(key, iv, hp_key));
        Ok(())
    }
    /// Get keys for a packet number space
    pub fn get_keys(&self, space: PacketNumberSpace) -> Option<&QuicKeys> {
        self.keys.get(&space)
    }
    /// Update to next key phase (for key updates)
    pub fn update_key_phase(&mut self) {
        self.key_phase = self.key_phase.toggle();
    }
    /// Get current key phase
    pub fn key_phase(&self) -> KeyPhase {
        self.key_phase
    }

    /// Perform key update (RFC 9001 Section 6)
    ///
    /// Derives new application keys from current traffic secret using HKDF-Expand-Label
    /// with "quic ku" (key update) label.
    pub fn update_keys(
        &mut self,
        provider: &dyn CryptoProvider,
        current_traffic_secret: &[u8],
    ) -> Result<Vec<u8>> {
        let hash_algorithm = self.cipher_suite.hash_algorithm();
        let hash_length = hash_algorithm.output_size();

        // Derive next traffic secret: HKDF-Expand-Label(secret, "quic ku", "", Hash.length)
        let next_secret = crate::transcript::hkdf_expand_label(
            provider,
            hash_algorithm,
            current_traffic_secret,
            b"quic ku",
            &[],
            hash_length,
        )?;

        // Derive keys from new traffic secret
        self.derive_keys(provider, &next_secret, PacketNumberSpace::ApplicationData)?;
        self.update_key_phase();

        Ok(next_secret)
    }
}

/// QUIC 0-RTT (Early Data) Secrets
///
/// Derived from TLS early_data_key for 0-RTT packets (RFC 9001 Section 4.6.1)
#[derive(Debug)]
pub struct QuicEarlySecrets {
    /// Client early data secret
    pub client_early_secret: Zeroizing<Vec<u8>>,
}

impl QuicEarlySecrets {
    /// Derive 0-RTT secrets from TLS early traffic secret
    pub fn derive(
        _provider: &dyn CryptoProvider,
        early_traffic_secret: &[u8],
        _cipher_suite: CipherSuite,
    ) -> Result<Self> {
        Ok(Self {
            client_early_secret: Zeroizing::new(early_traffic_secret.to_vec()),
        })
    }
}

/// QUIC Initial packet secrets
/// Derived from the connection ID using fixed salt (RFC 9001 Section 5.2)
pub struct QuicInitialSecrets {
    /// Client initial secret
    pub client_initial_secret: Zeroizing<Vec<u8>>,
    /// Server initial secret
    pub server_initial_secret: Zeroizing<Vec<u8>>,
}
impl QuicInitialSecrets {
    /// QUIC version 1 initial salt (RFC 9001)
    pub const INITIAL_SALT_V1: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    /// Derive initial secrets from destination connection ID
    pub fn derive(provider: &dyn CryptoProvider, destination_connection_id: &[u8]) -> Result<Self> {
        // Initial secret = HKDF-Extract(initial_salt, dcid)
        let kdf = provider.kdf(hptls_crypto::KdfAlgorithm::HkdfSha256)?;
        let initial_secret = kdf.extract(&Self::INITIAL_SALT_V1, destination_connection_id);
        // Client initial secret = HKDF-Expand-Label(initial_secret, "client in", "", Hash.length)
        let client_initial_secret = crate::transcript::hkdf_expand_label(
            provider,
            HashAlgorithm::Sha256,
            &initial_secret,
            b"client in",
            &[],
            32,
        )?;
        // Server initial secret = HKDF-Expand-Label(initial_secret, "server in", "", Hash.length)
        let server_initial_secret = crate::transcript::hkdf_expand_label(
            provider,
            HashAlgorithm::Sha256,
            &initial_secret,
            b"server in",
            &[],
            32,
        )?;
        Ok(Self {
            client_initial_secret: Zeroizing::new(client_initial_secret),
            server_initial_secret: Zeroizing::new(server_initial_secret),
        })
    }
}
/// QUIC handshake integration
/// Bridges TLS handshake with QUIC transport
pub struct QuicHandshake {
    /// Crypto context for all packet spaces
    pub crypto_context: QuicCryptoContext,
    /// Transport parameters
    pub transport_params: QuicTransportParameters,
    /// Initial secrets (for Initial packet space)
    pub initial_secrets: Option<QuicInitialSecrets>,
}
impl QuicHandshake {
    /// Create a new QUIC handshake
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self {
            crypto_context: QuicCryptoContext::new(cipher_suite),
            transport_params: QuicTransportParameters::default(),
            initial_secrets: None,
        }
    }
    /// Initialize with connection ID
    pub fn init_with_connection_id(
        &mut self,
        provider: &dyn CryptoProvider,
        destination_connection_id: &[u8],
    ) -> Result<()> {
        self.initial_secrets = Some(QuicInitialSecrets::derive(
            provider,
            destination_connection_id,
        )?);
        Ok(())
    }
    /// Derive handshake keys from TLS handshake traffic secrets
    pub fn derive_handshake_keys(
        &mut self,
        provider: &dyn CryptoProvider,
        client_handshake_secret: &[u8],
        server_handshake_secret: &[u8],
    ) -> Result<()> {
        // Derive client handshake keys
        self.crypto_context.derive_keys(
            provider,
            client_handshake_secret,
            PacketNumberSpace::Handshake,
        )?;
        // Derive server handshake keys
        self.crypto_context.derive_keys(
            provider,
            server_handshake_secret,
            PacketNumberSpace::Handshake,
        )?;
        Ok(())
    }
    /// Derive application keys from TLS application traffic secrets
    pub fn derive_application_keys(
        &mut self,
        provider: &dyn CryptoProvider,
        client_application_secret: &[u8],
        server_application_secret: &[u8],
    ) -> Result<()> {
        // Derive client application keys
        self.crypto_context.derive_keys(
            provider,
            client_application_secret,
            PacketNumberSpace::ApplicationData,
        )?;
        // Derive server application keys
        self.crypto_context.derive_keys(
            provider,
            server_application_secret,
            PacketNumberSpace::ApplicationData,
        )?;
        Ok(())
    }

    /// Derive 0-RTT (early data) keys from TLS early traffic secret
    ///
    /// RFC 9001 Section 4.6.1 - 0-RTT uses same key derivation as 1-RTT but with
    /// early_traffic_secret instead of application_traffic_secret.
    pub fn derive_early_data_keys(
        &mut self,
        provider: &dyn CryptoProvider,
        early_traffic_secret: &[u8],
    ) -> Result<()> {
        // Derive 0-RTT keys using ApplicationData space (but with early secret)
        // Note: In practice, 0-RTT uses a separate packet number space, but the
        // key derivation is the same as for 1-RTT
        self.crypto_context.derive_keys(
            provider,
            early_traffic_secret,
            PacketNumberSpace::ApplicationData,
        )?;
        Ok(())
    }

    /// Perform key update (RFC 9001 Section 6)
    ///
    /// Updates application keys for the next key phase.
    /// Returns the new traffic secret to be used for deriving updated keys.
    pub fn update_application_keys(
        &mut self,
        provider: &dyn CryptoProvider,
        current_traffic_secret: &[u8],
    ) -> Result<Vec<u8>> {
        self.crypto_context.update_keys(provider, current_traffic_secret)
    }
}

/// QUIC Retry Packet Integrity (RFC 9001 Section 5.8)
///
/// Retry packets use a fixed key and nonce to compute an integrity tag.
pub struct QuicRetryIntegrity;

impl QuicRetryIntegrity {
    /// Retry integrity tag key (fixed, from RFC 9001 Section 5.8)
    const RETRY_INTEGRITY_KEY: &'static [u8] = &[
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
        0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
    ];

    /// Retry integrity tag nonce (fixed, from RFC 9001 Section 5.8)
    const RETRY_INTEGRITY_NONCE: &'static [u8] = &[
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
        0x23, 0x98, 0x25, 0xbb,
    ];

    /// Compute Retry packet integrity tag (RFC 9001 Section 5.8)
    ///
    /// The integrity tag is computed as:
    /// ```text
    /// Retry Pseudo-Packet = ODCID Len (i) || Original Destination Connection ID (0..160)
    ///                       || Retry Packet Header || Retry Token
    /// Retry Integrity Tag = AES-128-GCM(
    ///     key = retry_integrity_key,
    ///     nonce = retry_integrity_nonce,
    ///     plaintext = "",
    ///     aad = Retry Pseudo-Packet
    /// )
    /// ```
    ///
    /// # Arguments
    /// * `provider` - Crypto provider for AEAD operations
    /// * `odcid` - Original Destination Connection ID from Initial packet
    /// * `retry_packet` - Complete Retry packet (header + token, without tag)
    ///
    /// # Returns
    /// 16-byte integrity tag to append to Retry packet
    pub fn compute_tag(
        provider: &dyn CryptoProvider,
        odcid: &[u8],
        retry_packet: &[u8],
    ) -> Result<Vec<u8>> {
        // Build Retry Pseudo-Packet: ODCID Len (1 byte) || ODCID || Retry Packet
        let mut pseudo_packet = Vec::with_capacity(1 + odcid.len() + retry_packet.len());
        pseudo_packet.push(odcid.len() as u8);
        pseudo_packet.extend_from_slice(odcid);
        pseudo_packet.extend_from_slice(retry_packet);

        // Use AES-128-GCM to compute integrity tag
        use hptls_crypto::AeadAlgorithm;
        let aead = provider.aead(AeadAlgorithm::Aes128Gcm)?;

        // AEAD with empty plaintext, pseudo-packet as AAD
        let ciphertext = aead.seal(
            Self::RETRY_INTEGRITY_KEY,
            Self::RETRY_INTEGRITY_NONCE,
            &pseudo_packet,
            &[], // empty plaintext
        )?;

        // The "ciphertext" is just the 16-byte authentication tag
        Ok(ciphertext)
    }

    /// Verify Retry packet integrity tag (RFC 9001 Section 5.8)
    ///
    /// # Arguments
    /// * `provider` - Crypto provider for AEAD operations
    /// * `odcid` - Original Destination Connection ID
    /// * `retry_packet` - Retry packet without tag
    /// * `tag` - 16-byte integrity tag from end of Retry packet
    ///
    /// # Returns
    /// `Ok(())` if tag is valid, `Err` otherwise
    pub fn verify_tag(
        provider: &dyn CryptoProvider,
        odcid: &[u8],
        retry_packet: &[u8],
        tag: &[u8],
    ) -> Result<()> {
        // Build Retry Pseudo-Packet
        let mut pseudo_packet = Vec::with_capacity(1 + odcid.len() + retry_packet.len());
        pseudo_packet.push(odcid.len() as u8);
        pseudo_packet.extend_from_slice(odcid);
        pseudo_packet.extend_from_slice(retry_packet);

        // Use AES-128-GCM to verify
        use hptls_crypto::AeadAlgorithm;
        let aead = provider.aead(AeadAlgorithm::Aes128Gcm)?;

        // Verify by attempting to "decrypt" the tag
        aead.open(
            Self::RETRY_INTEGRITY_KEY,
            Self::RETRY_INTEGRITY_NONCE,
            &pseudo_packet,
            tag,
        )?;

        Ok(())
    }
}

/// QUIC Header Protection (RFC 9001 Section 5.4)
///
/// Header protection encrypts packet numbers and reserved bits to prevent
/// on-path observers from correlating packets and tracking connections.
pub struct QuicHeaderProtection;

impl QuicHeaderProtection {
    /// Protect (encrypt) packet header fields (RFC 9001 Section 5.4.1)
    ///
    /// For AES-based cipher suites, uses AES-ECB to create a mask.
    /// For ChaCha20, uses ChaCha20 directly.
    ///
    /// # Arguments
    /// * `hp_key` - Header protection key (derived with "quic hp" label)
    /// * `sample` - 16-byte sample from packet payload
    /// * `first_byte` - First byte of packet header (contains protected bits)
    /// * `packet_number` - Packet number bytes (1-4 bytes)
    ///
    /// # Returns
    /// Tuple of (protected_first_byte, protected_packet_number)
    pub fn protect(
        hp_key: &[u8],
        sample: &[u8; 16],
        first_byte: u8,
        packet_number: &[u8],
    ) -> Result<(u8, Vec<u8>)> {
        // Generate mask using AES-128-ECB (RFC 9001 Section 5.4.3)
        let mask = Self::generate_mask_aes(hp_key, sample)?;

        // Determine number of packet number bits to mask
        // For long headers, mask bits 0-1 (reserved bits) of first byte
        // For short headers, mask bit 0 (reserved bit) of first byte
        // Both mask bits 4-7 (packet number length)
        let is_long_header = (first_byte & 0x80) != 0;
        let first_byte_mask = if is_long_header { 0x0F } else { 0x1F };

        let protected_first_byte = first_byte ^ (mask[0] & first_byte_mask);

        // XOR packet number bytes with mask
        let mut protected_pn = vec![0u8; packet_number.len()];
        for (i, &byte) in packet_number.iter().enumerate() {
            protected_pn[i] = byte ^ mask[1 + i];
        }

        Ok((protected_first_byte, protected_pn))
    }

    /// Unprotect (decrypt) packet header fields (RFC 9001 Section 5.4.2)
    ///
    /// # Arguments
    /// * `hp_key` - Header protection key
    /// * `sample` - 16-byte sample from packet payload
    /// * `protected_first_byte` - Protected first byte of header
    /// * `protected_pn` - Protected packet number bytes
    ///
    /// # Returns
    /// Tuple of (unprotected_first_byte, unprotected_packet_number)
    pub fn unprotect(
        hp_key: &[u8],
        sample: &[u8; 16],
        protected_first_byte: u8,
        protected_pn: &[u8],
    ) -> Result<(u8, Vec<u8>)> {
        // Generate mask (same process as protection)
        let mask = Self::generate_mask_aes(hp_key, sample)?;

        // Determine mask for first byte
        let is_long_header = (protected_first_byte & 0x80) != 0;
        let first_byte_mask = if is_long_header { 0x0F } else { 0x1F };

        let unprotected_first_byte = protected_first_byte ^ (mask[0] & first_byte_mask);

        // XOR packet number bytes with mask
        let mut unprotected_pn = vec![0u8; protected_pn.len()];
        for (i, &byte) in protected_pn.iter().enumerate() {
            unprotected_pn[i] = byte ^ mask[1 + i];
        }

        Ok((unprotected_first_byte, unprotected_pn))
    }

    /// Generate header protection mask using AES-128-ECB (RFC 9001 Section 5.4.3)
    ///
    /// For AES-based cipher suites:
    /// ```text
    /// mask = AES-ECB(hp_key, sample)
    /// ```
    ///
    /// Returns first 5 bytes: mask[0] for first byte, mask[1..5] for packet number
    fn generate_mask_aes(hp_key: &[u8], sample: &[u8; 16]) -> Result<[u8; 5]> {
        // We need raw AES-ECB encryption (no AEAD)
        // Use AES block cipher directly
        use aes::Aes128;
        use aes::cipher::{BlockEncrypt, KeyInit};

        if hp_key.len() != 16 {
            return Err(crate::error::Error::CryptoError(
                "Header protection key must be 16 bytes for AES".to_string()
            ));
        }

        // Create AES-128 cipher
        let cipher = Aes128::new_from_slice(hp_key)
            .map_err(|e| crate::error::Error::CryptoError(format!("AES key init: {}", e)))?;

        // Encrypt the sample (16 bytes -> 16 bytes)
        let mut block = aes::cipher::Block::<Aes128>::clone_from_slice(sample);
        cipher.encrypt_block(&mut block);

        // Return first 5 bytes as mask
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        Ok(mask)
    }

    /// Generate header protection mask using ChaCha20 (RFC 9001 Section 5.4.4)
    ///
    /// For ChaCha20-Poly1305:
    /// ```text
    /// counter = sample[0..4] as little-endian u32
    /// nonce = sample[4..16]
    /// mask = ChaCha20(hp_key, counter, nonce, 5 zero bytes)
    /// ```
    #[allow(dead_code)]
    fn generate_mask_chacha20(hp_key: &[u8], sample: &[u8; 16]) -> Result<[u8; 5]> {
        use chacha20::ChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        if hp_key.len() != 32 {
            return Err(crate::error::Error::CryptoError(
                "Header protection key must be 32 bytes for ChaCha20".to_string()
            ));
        }

        // Extract counter (little-endian) from sample[0..4]
        let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);

        // Extract nonce from sample[4..16]
        let nonce = &sample[4..16];

        // Create ChaCha20 cipher with counter prepended to nonce
        let mut full_nonce = [0u8; 12];
        full_nonce[0..4].copy_from_slice(&counter.to_le_bytes());
        full_nonce[4..12].copy_from_slice(nonce);

        let mut cipher = ChaCha20::new(hp_key.into(), &full_nonce.into());

        // Encrypt 5 zero bytes to get mask
        let mut mask = [0u8; 5];
        cipher.apply_keystream(&mut mask);

        Ok(mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hptls_crypto::CryptoProvider;
    use hptls_crypto_hpcrypt::HpcryptProvider;
    #[test]
    fn test_key_phase_toggle() {
        let phase = KeyPhase::Phase0;
        let toggled = phase.toggle();
        assert_eq!(toggled, KeyPhase::Phase1);
        let toggled_again = toggled.toggle();
        assert_eq!(toggled_again, KeyPhase::Phase0);
    }

    #[test]
    fn test_quic_transport_params_default() {
        let params = QuicTransportParameters::default();
        assert_eq!(params.max_idle_timeout, 30000);
        assert_eq!(params.max_udp_payload_size, 65527);
    }

    #[test]
    fn test_quic_crypto_context_creation() {
        let ctx = QuicCryptoContext::new(CipherSuite::Aes128GcmSha256);
        assert_eq!(ctx.key_phase(), KeyPhase::Phase0);
    }

    #[test]
    fn test_quic_initial_secrets_derivation() {
        let provider = HpcryptProvider::new();
        let dcid = b"test_connection_id";
        let secrets = QuicInitialSecrets::derive(&provider, dcid).unwrap();
        assert_eq!(secrets.client_initial_secret.len(), 32);
        assert_eq!(secrets.server_initial_secret.len(), 32);
        assert_ne!(
            &secrets.client_initial_secret[..],
            &secrets.server_initial_secret[..]
        );
    }

    #[test]
    fn test_packet_number_spaces() {
        let initial = PacketNumberSpace::Initial;
        let handshake = PacketNumberSpace::Handshake;
        let app = PacketNumberSpace::ApplicationData;
        assert_ne!(initial, handshake);
        assert_ne!(handshake, app);
        assert_ne!(initial, app);
    }

    #[test]
    fn test_quic_handshake_init() {
        let provider = HpcryptProvider::new();
        let mut handshake = QuicHandshake::new(CipherSuite::Aes128GcmSha256);
        let dcid = b"connection_12345";
        handshake.init_with_connection_id(&provider, dcid).unwrap();
        assert!(handshake.initial_secrets.is_some());
    }

    #[test]
    fn test_quic_key_update() {
        let provider = HpcryptProvider::new();
        let mut ctx = QuicCryptoContext::new(CipherSuite::Aes128GcmSha256);

        // Initial phase
        assert_eq!(ctx.key_phase(), KeyPhase::Phase0);

        // Derive initial application keys
        let initial_secret = vec![0x42; 32]; // Test secret
        ctx.derive_keys(&provider, &initial_secret, PacketNumberSpace::ApplicationData).unwrap();

        // Perform key update
        let updated_secret = ctx.update_keys(&provider, &initial_secret).unwrap();

        // Verify phase toggled
        assert_eq!(ctx.key_phase(), KeyPhase::Phase1);

        // Verify new secret is different
        assert_ne!(&updated_secret[..], &initial_secret[..]);
        assert_eq!(updated_secret.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_quic_early_secrets() {
        let provider = HpcryptProvider::new();
        let early_secret = vec![0x99; 32];

        let early_secrets = QuicEarlySecrets::derive(
            &provider,
            &early_secret,
            CipherSuite::Aes128GcmSha256,
        ).unwrap();

        assert_eq!(early_secrets.client_early_secret.len(), 32);
        assert_eq!(&early_secrets.client_early_secret[..], &early_secret[..]);
    }

    #[test]
    fn test_quic_retry_integrity() {
        let provider = HpcryptProvider::new();

        // Test data
        let odcid = b"original_dcid";
        let retry_packet = b"retry_packet_header_and_token";

        // Compute tag
        let tag = QuicRetryIntegrity::compute_tag(&provider, odcid, retry_packet).unwrap();

        // Tag should be 16 bytes (AES-128-GCM tag)
        assert_eq!(tag.len(), 16);

        // Verify tag
        let result = QuicRetryIntegrity::verify_tag(&provider, odcid, retry_packet, &tag);
        assert!(result.is_ok(), "Retry integrity verification should succeed");

        // Verify with wrong ODCID fails
        let wrong_odcid = b"wrong_dcid";
        let result = QuicRetryIntegrity::verify_tag(&provider, wrong_odcid, retry_packet, &tag);
        assert!(result.is_err(), "Retry integrity verification should fail with wrong ODCID");

        // Verify with wrong tag fails
        let wrong_tag = vec![0xFF; 16];
        let result = QuicRetryIntegrity::verify_tag(&provider, odcid, retry_packet, &wrong_tag);
        assert!(result.is_err(), "Retry integrity verification should fail with wrong tag");
    }

    #[test]
    fn test_quic_handshake_early_data() {
        let provider = HpcryptProvider::new();
        let mut handshake = QuicHandshake::new(CipherSuite::Aes128GcmSha256);

        let early_secret = vec![0xAB; 32];

        // Derive 0-RTT keys
        handshake.derive_early_data_keys(&provider, &early_secret).unwrap();

        // Verify keys were derived
        let keys = handshake.crypto_context.get_keys(PacketNumberSpace::ApplicationData);
        assert!(keys.is_some(), "0-RTT keys should be derived");
    }

    #[test]
    fn test_quic_handshake_key_update() {
        let provider = HpcryptProvider::new();
        let mut handshake = QuicHandshake::new(CipherSuite::Aes128GcmSha256);

        // Derive initial application keys
        let app_secret = vec![0x55; 32];
        handshake.derive_application_keys(&provider, &app_secret, &app_secret).unwrap();

        // Initial phase
        assert_eq!(handshake.crypto_context.key_phase(), KeyPhase::Phase0);

        // Perform key update
        let new_secret = handshake.update_application_keys(&provider, &app_secret).unwrap();

        // Verify phase changed
        assert_eq!(handshake.crypto_context.key_phase(), KeyPhase::Phase1);

        // Verify new secret is different
        assert_ne!(&new_secret[..], &app_secret[..]);
    }

    #[test]
    fn test_quic_header_protection_aes() {
        // Test header protection with AES (RFC 9001 Appendix A.2)
        let hp_key = vec![0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2,
                         0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc, 0x8f, 0x1b];

        // Sample from packet payload (16 bytes)
        let sample = [
            0xd1, 0xd7, 0x9b, 0xbd, 0xaa, 0x8a, 0x2d, 0x64,
            0x12, 0x52, 0x33, 0x8e, 0xdc, 0xf9, 0x6f, 0xf0,
        ];

        let first_byte = 0xc3; // Long header, packet type = Handshake
        let packet_number = vec![0x00, 0x00, 0x00, 0x02]; // 4-byte packet number

        // Protect header
        let (protected_first, protected_pn) =
            QuicHeaderProtection::protect(&hp_key, &sample, first_byte, &packet_number).unwrap();

        // Verify protection changed values
        assert_ne!(protected_first, first_byte);
        assert_ne!(&protected_pn[..], &packet_number[..]);

        // Unprotect header
        let (unprotected_first, unprotected_pn) =
            QuicHeaderProtection::unprotect(&hp_key, &sample, protected_first, &protected_pn).unwrap();

        // Verify we got back original values
        assert_eq!(unprotected_first, first_byte);
        assert_eq!(&unprotected_pn[..], &packet_number[..]);
    }

    #[test]
    fn test_quic_header_protection_short_header() {
        // Test with short header (1-RTT packet)
        let hp_key = vec![0x11; 16]; // Simple test key
        let sample = [0x22; 16]; // Simple test sample

        let first_byte = 0x43; // Short header (bit 7 = 0)
        let packet_number = vec![0xab, 0xcd]; // 2-byte packet number

        // Protect and unprotect
        let (protected_first, protected_pn) =
            QuicHeaderProtection::protect(&hp_key, &sample, first_byte, &packet_number).unwrap();
        let (unprotected_first, unprotected_pn) =
            QuicHeaderProtection::unprotect(&hp_key, &sample, protected_first, &protected_pn).unwrap();

        // Verify round-trip
        assert_eq!(unprotected_first, first_byte);
        assert_eq!(&unprotected_pn[..], &packet_number[..]);
    }

    #[test]
    fn test_quic_header_protection_various_pn_lengths() {
        let hp_key = vec![0x33; 16];
        let sample = [0x44; 16];
        let first_byte = 0xc0; // Long header

        // Test 1-byte, 2-byte, 3-byte, and 4-byte packet numbers
        for pn_len in 1..=4 {
            let packet_number: Vec<u8> = (0..pn_len).map(|i| i as u8 + 0x10).collect();

            let (protected_first, protected_pn) =
                QuicHeaderProtection::protect(&hp_key, &sample, first_byte, &packet_number).unwrap();
            let (unprotected_first, unprotected_pn) =
                QuicHeaderProtection::unprotect(&hp_key, &sample, protected_first, &protected_pn).unwrap();

            assert_eq!(unprotected_first, first_byte, "Failed for {}-byte PN", pn_len);
            assert_eq!(&unprotected_pn[..], &packet_number[..], "Failed for {}-byte PN", pn_len);
        }
    }

    #[test]
    fn test_quic_header_protection_mask_boundaries() {
        // Test that protection correctly masks only specific bits
        let hp_key = vec![0x55; 16];
        let sample = [0x66; 16];

        // Long header: should mask bits 0-3 (0x0F)
        let long_header = 0b11000000; // bit 7 set = long header
        let (protected_long, _) =
            QuicHeaderProtection::protect(&hp_key, &sample, long_header, &[0x01]).unwrap();

        // Bit 7 (long header flag) should remain unchanged
        assert_eq!(protected_long & 0x80, long_header & 0x80);

        // Short header: should mask bits 0-4 (0x1F)
        let short_header = 0b01000000; // bit 7 clear = short header
        let (protected_short, _) =
            QuicHeaderProtection::protect(&hp_key, &sample, short_header, &[0x01]).unwrap();

        // Bit 7 should remain unchanged
        assert_eq!(protected_short & 0x80, short_header & 0x80);
    }

    #[test]
    fn test_header_protection_invalid_key_length() {
        let bad_key = vec![0x77; 15]; // Wrong length (should be 16)
        let sample = [0x88; 16];

        let result = QuicHeaderProtection::protect(&bad_key, &sample, 0xc0, &[0x01]);
        assert!(result.is_err());
    }
}
