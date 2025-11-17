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
}
