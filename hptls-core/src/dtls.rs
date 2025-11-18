//! DTLS 1.3 Support (RFC 9147)
//!
//! Datagram Transport Layer Security (DTLS) provides TLS security for
//! datagram protocols like UDP. DTLS 1.3 is based on TLS 1.3 with
//! modifications to handle:
//! - Packet loss and reordering
//! - Replay protection
//! - Record sequence numbers
//! - Fragmentation and reassembly
//! - Retransmission timers
//!
//! # Key Differences from TLS 1.3
//!
//! 1. **Explicit Sequence Numbers**: DTLS records include sequence numbers
//! 2. **Epoch Numbers**: Track key generation (for replay protection)
//! 3. **Retransmission**: Handshake messages are retransmitted on timeout
//! 4. **Record Replay Detection**: Sliding window for replay detection
//! 5. **PMTU Discovery**: Path MTU discovery for fragmentation
//! 6. **Connection IDs**: Optional connection identifiers for mobility
//!
//! # Protocol Flow
//!
//! ```text
//! Client                                Server
//!
//! ClientHello           -------->
//!                                  HelloRetryRequest
//!                       <--------  (+ cookie for DoS protection)
//! ClientHello           -------->
//! (+ cookie)
//!                       <--------  ServerHello
//!                                  EncryptedExtensions
//!                                  Certificate
//!                                  CertificateVerify
//!                       <--------  Finished
//! Certificate           -------->
//! CertificateVerify
//! Finished              -------->
//!                       <------->  Application Data
//! ```

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// DTLS 1.3 version number (0xFEFC)
pub const DTLS_13_VERSION: u16 = 0xFEFC;

/// Maximum epoch number before key rotation required
pub const MAX_EPOCH: u16 = 65535;

/// Default retransmission timeout (1 second)
pub const DEFAULT_RETRANSMIT_TIMEOUT_MS: u64 = 1000;

/// Maximum retransmission timeout (60 seconds)
pub const MAX_RETRANSMIT_TIMEOUT_MS: u64 = 60000;

/// Replay window size (64 packets)
pub const REPLAY_WINDOW_SIZE: u64 = 64;

/// Epoch number for key generation tracking
///
/// Each time keys are updated (handshake, key update), the epoch increments.
/// This is used for replay protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(pub u16);

impl Epoch {
    /// Initial epoch (unencrypted)
    pub const INITIAL: Epoch = Epoch(0);

    /// Handshake epoch (encrypted with handshake traffic keys)
    pub const HANDSHAKE: Epoch = Epoch(1);

    /// Application data epoch (encrypted with application traffic keys)
    pub const APPLICATION: Epoch = Epoch(2);

    /// Increment epoch
    pub fn next(self) -> Result<Epoch> {
        if self.0 == MAX_EPOCH {
            return Err(Error::InternalError("Epoch overflow".into()));
        }
        Ok(Epoch(self.0 + 1))
    }
}

/// DTLS record sequence number (48-bit)
///
/// Combined with epoch for unique record identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SequenceNumber(pub u64);

impl SequenceNumber {
    /// Maximum sequence number (2^48 - 1)
    pub const MAX: u64 = (1u64 << 48) - 1;

    /// Create from u64 (truncated to 48 bits)
    pub fn new(value: u64) -> Self {
        Self(value & Self::MAX)
    }

    /// Increment sequence number
    pub fn increment(&mut self) -> Result<()> {
        if self.0 >= Self::MAX {
            return Err(Error::InternalError("Sequence number overflow".into()));
        }
        self.0 += 1;
        Ok(())
    }

    /// Encode to 6 bytes (48-bit big-endian)
    pub fn to_bytes(&self) -> [u8; 6] {
        let bytes = self.0.to_be_bytes();
        [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
    }

    /// Decode from 6 bytes
    pub fn from_bytes(bytes: &[u8; 6]) -> Self {
        let value = u64::from_be_bytes([
            0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        ]);
        Self(value)
    }
}

/// DTLS record header
///
/// ```text
/// struct {
///     ContentType type;
///     ProtocolVersion legacy_record_version;
///     uint16 epoch;
///     uint48 sequence_number;
///     uint16 length;
/// } DTLSPlaintext;
/// ```
#[derive(Debug, Clone)]
pub struct DtlsRecordHeader {
    /// Content type
    pub content_type: crate::protocol::ContentType,

    /// Legacy version (always 0xFEFD for DTLS 1.2 compatibility)
    pub legacy_version: u16,

    /// Epoch number
    pub epoch: Epoch,

    /// Sequence number (48-bit)
    pub sequence_number: SequenceNumber,

    /// Fragment length
    pub length: u16,
}

impl DtlsRecordHeader {
    /// Header size (13 bytes)
    pub const SIZE: usize = 13;

    /// Encode to wire format
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.content_type.to_u8();
        buf[1..3].copy_from_slice(&self.legacy_version.to_be_bytes());
        buf[3..5].copy_from_slice(&self.epoch.0.to_be_bytes());
        buf[5..11].copy_from_slice(&self.sequence_number.to_bytes());
        buf[11..13].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    /// Decode from wire format
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::InvalidMessage("DTLS record header too short".into()));
        }

        let content_type = crate::protocol::ContentType::from_u8(data[0])
            .ok_or_else(|| Error::InvalidMessage("Invalid content type".into()))?;

        let legacy_version = u16::from_be_bytes([data[1], data[2]]);
        let epoch = Epoch(u16::from_be_bytes([data[3], data[4]]));

        let seq_bytes: [u8; 6] = [data[5], data[6], data[7], data[8], data[9], data[10]];
        let sequence_number = SequenceNumber::from_bytes(&seq_bytes);

        let length = u16::from_be_bytes([data[11], data[12]]);

        Ok(Self {
            content_type,
            legacy_version,
            epoch,
            sequence_number,
            length,
        })
    }
}

/// Anti-replay window for DTLS
///
/// Uses a sliding window to track received sequence numbers
/// and detect replayed packets.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Right edge of window (highest received sequence number)
    right_edge: u64,

    /// Bitmap of received packets (64-bit window)
    bitmap: u64,

    /// Window size
    window_size: u64,
}

impl ReplayWindow {
    /// Create a new replay window
    pub fn new() -> Self {
        Self {
            right_edge: 0,
            bitmap: 0,
            window_size: REPLAY_WINDOW_SIZE,
        }
    }

    /// Check if a sequence number should be accepted (anti-replay check)
    ///
    /// Implements RFC 9147 Section 4.5.1.1 anti-replay protection using
    /// a sliding window algorithm.
    ///
    /// Returns true if the packet is new (not a replay) and should be accepted.
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        // Special case: first packet (right_edge == 0 and bitmap == 0)
        if self.right_edge == 0 && self.bitmap == 0 {
            self.right_edge = seq;
            self.bitmap = 1;
            return true;
        }

        // Packet is to the right of window - accept and slide window
        if seq > self.right_edge {
            let diff = seq - self.right_edge;
            if diff < self.window_size {
                // Shift bitmap left by diff positions
                self.bitmap <<= diff;
                // Mark previous right_edge as received
                self.bitmap |= 1;
            } else {
                // Gap is larger than window - reset bitmap
                self.bitmap = 1;
            }
            self.right_edge = seq;
            return true;
        }

        // Exact duplicate of right edge
        if seq == self.right_edge {
            // Replay detected - right_edge is always marked as received
            return false;
        }

        // Packet is within window (to the left of right_edge)
        let diff = self.right_edge - seq;
        if diff < self.window_size {
            // Check if already received
            let mask = 1u64 << diff;
            if self.bitmap & mask != 0 {
                // Replay detected
                return false;
            }
            // Mark as received
            self.bitmap |= mask;
            return true;
        }

        // Packet is too old (left of window) - reject
        false
    }

    /// Reset the window
    pub fn reset(&mut self) {
        self.right_edge = 0;
        self.bitmap = 0;
    }

    /// Get the current right edge of the window
    pub fn right_edge(&self) -> u64 {
        self.right_edge
    }

    /// Get the number of packets currently marked as received in the window
    pub fn received_count(&self) -> u32 {
        self.bitmap.count_ones()
    }

    /// Check if a specific sequence number is marked as received (without updating)
    ///
    /// This is useful for diagnostics and testing.
    pub fn is_received(&self, seq: u64) -> bool {
        if seq == self.right_edge {
            return true;
        }
        if seq > self.right_edge {
            return false;
        }
        let diff = self.right_edge - seq;
        if diff >= self.window_size {
            return false;
        }
        let mask = 1u64 << diff;
        self.bitmap & mask != 0
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Retransmission timer for DTLS handshake messages
///
/// Implements exponential backoff for retransmissions
#[derive(Debug, Clone)]
pub struct RetransmitTimer {
    /// Initial timeout
    initial_timeout: Duration,

    /// Current timeout
    current_timeout: Duration,

    /// Maximum timeout
    max_timeout: Duration,

    /// Last transmission time
    last_transmit: Option<Instant>,

    /// Number of retransmissions
    retransmit_count: u32,

    /// Maximum retransmissions
    max_retransmits: u32,
}

impl RetransmitTimer {
    /// Create a new retransmit timer
    pub fn new() -> Self {
        Self {
            initial_timeout: Duration::from_millis(DEFAULT_RETRANSMIT_TIMEOUT_MS),
            current_timeout: Duration::from_millis(DEFAULT_RETRANSMIT_TIMEOUT_MS),
            max_timeout: Duration::from_millis(MAX_RETRANSMIT_TIMEOUT_MS),
            last_transmit: None,
            retransmit_count: 0,
            max_retransmits: 10,
        }
    }

    /// Record a transmission
    pub fn record_transmit(&mut self) {
        self.last_transmit = Some(Instant::now());
    }

    /// Check if retransmission is needed
    pub fn should_retransmit(&self) -> bool {
        if let Some(last) = self.last_transmit {
            last.elapsed() >= self.current_timeout
        } else {
            true // First transmission
        }
    }

    /// Perform a retransmission (doubles timeout with jitter)
    ///
    /// RFC 9147 Section 5.7 recommends using a timer based on RFC 6298
    /// with exponential backoff and jitter to prevent synchronized retransmissions.
    pub fn retransmit(&mut self) -> Result<()> {
        if self.retransmit_count >= self.max_retransmits {
            return Err(Error::HandshakeFailure(
                "Max retransmissions exceeded".into(),
            ));
        }

        self.retransmit_count += 1;
        self.last_transmit = Some(Instant::now());

        // Exponential backoff with jitter (RFC 6298-style)
        // Add ±25% jitter to prevent synchronized retransmissions
        let base_timeout = std::cmp::min(self.current_timeout * 2, self.max_timeout);

        // Simple jitter: vary by ±25%
        // In production, use a proper RNG. For now, use a deterministic pattern
        // based on retransmit count to provide some variation
        let jitter_percent = match self.retransmit_count % 4 {
            0 => 75,  // -25%
            1 => 90,  // -10%
            2 => 110, // +10%
            _ => 125, // +25%
        };

        self.current_timeout = Duration::from_millis(
            (base_timeout.as_millis() as u64 * jitter_percent) / 100
        );
        self.current_timeout = std::cmp::min(self.current_timeout, self.max_timeout);

        Ok(())
    }

    /// Reset timer (on successful handshake progression)
    pub fn reset(&mut self) {
        self.current_timeout = self.initial_timeout;
        self.retransmit_count = 0;
        self.last_transmit = None;
    }

    /// Get the current timeout value
    pub fn current_timeout(&self) -> Duration {
        self.current_timeout
    }

    /// Get the number of retransmissions
    pub fn retransmit_count(&self) -> u32 {
        self.retransmit_count
    }

    /// Get time since last transmission
    pub fn time_since_last_transmit(&self) -> Option<Duration> {
        self.last_transmit.map(|last| last.elapsed())
    }

    /// Get remaining time until next retransmission
    pub fn time_until_retransmit(&self) -> Option<Duration> {
        self.last_transmit.map(|last| {
            let elapsed = last.elapsed();
            if elapsed >= self.current_timeout {
                Duration::from_millis(0)
            } else {
                self.current_timeout - elapsed
            }
        })
    }

    /// Check if maximum retransmissions reached
    pub fn max_retransmits_reached(&self) -> bool {
        self.retransmit_count >= self.max_retransmits
    }

    /// Set custom maximum retransmissions (for testing or special cases)
    pub fn set_max_retransmits(&mut self, max: u32) {
        self.max_retransmits = max;
    }

    /// Set custom initial timeout (for testing or special cases)
    pub fn set_initial_timeout(&mut self, timeout: Duration) {
        self.initial_timeout = timeout;
        self.current_timeout = timeout;
    }
}

impl Default for RetransmitTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// DTLS connection state
#[derive(Debug)]
pub struct DtlsState {
    /// Current epoch
    pub epoch: Epoch,

    /// Current sequence number for sending
    pub send_sequence: SequenceNumber,

    /// Replay windows per epoch
    pub replay_windows: HashMap<Epoch, ReplayWindow>,

    /// Retransmission timer
    pub retransmit_timer: RetransmitTimer,

    /// Cipher suite
    pub cipher_suite: Option<CipherSuite>,
}

impl DtlsState {
    /// Create a new DTLS state
    pub fn new() -> Self {
        let mut replay_windows = HashMap::new();
        replay_windows.insert(Epoch::INITIAL, ReplayWindow::new());

        Self {
            epoch: Epoch::INITIAL,
            send_sequence: SequenceNumber::new(0),
            replay_windows,
            retransmit_timer: RetransmitTimer::new(),
            cipher_suite: None,
        }
    }

    /// Check if a record should be accepted (anti-replay)
    pub fn check_replay(&mut self, epoch: Epoch, seq: SequenceNumber) -> bool {
        self.replay_windows
            .entry(epoch)
            .or_insert_with(ReplayWindow::new)
            .check_and_update(seq.0)
    }

    /// Get next send sequence number
    pub fn next_send_sequence(&mut self) -> Result<SequenceNumber> {
        let seq = self.send_sequence;
        self.send_sequence.increment()?;
        Ok(seq)
    }

    /// Advance to next epoch (on key update)
    pub fn next_epoch(&mut self) -> Result<()> {
        self.epoch = self.epoch.next()?;
        self.send_sequence = SequenceNumber::new(0);
        self.replay_windows.insert(self.epoch, ReplayWindow::new());
        Ok(())
    }
}

impl Default for DtlsState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_increment() {
        let epoch = Epoch::INITIAL;
        let next = epoch.next().unwrap();
        assert_eq!(next.0, 1);
    }

    #[test]
    fn test_sequence_number_increment() {
        let mut seq = SequenceNumber::new(0);
        seq.increment().unwrap();
        assert_eq!(seq.0, 1);
    }

    #[test]
    fn test_sequence_number_encode_decode() {
        let seq = SequenceNumber::new(0x123456789ABC);
        let bytes = seq.to_bytes();
        let decoded = SequenceNumber::from_bytes(&bytes);
        assert_eq!(seq.0 & SequenceNumber::MAX, decoded.0);
    }

    #[test]
    fn test_dtls_record_header_encode_decode() {
        let header = DtlsRecordHeader {
            content_type: crate::protocol::ContentType::Handshake,
            legacy_version: 0xFEFD,
            epoch: Epoch(1),
            sequence_number: SequenceNumber::new(12345),
            length: 1024,
        };

        let encoded = header.encode();
        let decoded = DtlsRecordHeader::decode(&encoded).unwrap();

        assert_eq!(header.content_type, decoded.content_type);
        assert_eq!(header.epoch, decoded.epoch);
        assert_eq!(header.sequence_number, decoded.sequence_number);
        assert_eq!(header.length, decoded.length);
    }

    #[test]
    fn test_replay_window_basic() {
        let mut window = ReplayWindow::new();

        // First packet
        assert!(window.check_and_update(1));

        // Same packet - replay
        assert!(!window.check_and_update(1));

        // New packet
        assert!(window.check_and_update(2));
    }

    #[test]
    fn test_replay_window_sliding() {
        let mut window = ReplayWindow::new();

        // Receive packets in order (but skip 8)
        for i in 1..=10 {
            if i != 8 {
                assert!(window.check_and_update(i));
            }
        }

        // Replay older packet
        assert!(!window.check_and_update(5));

        // Out of order but in window (8 was skipped, so it's new)
        assert!(window.check_and_update(8));
    }

    #[test]
    fn test_replay_window_old_packet() {
        let mut window = ReplayWindow::new();

        // Receive packet far ahead
        assert!(window.check_and_update(100));

        // Very old packet (outside window) - rejected
        assert!(!window.check_and_update(1));
    }

    #[test]
    fn test_retransmit_timer() {
        let mut timer = RetransmitTimer::new();

        // Should transmit initially
        assert!(timer.should_retransmit());

        timer.record_transmit();

        // Shouldn't retransmit immediately
        assert!(!timer.should_retransmit());
    }

    #[test]
    fn test_dtls_state_sequence_increment() {
        let mut state = DtlsState::new();

        let seq1 = state.next_send_sequence().unwrap();
        let seq2 = state.next_send_sequence().unwrap();

        assert_eq!(seq1.0, 0);
        assert_eq!(seq2.0, 1);
    }

    #[test]
    fn test_dtls_state_epoch_advance() {
        let mut state = DtlsState::new();

        assert_eq!(state.epoch, Epoch::INITIAL);

        state.next_epoch().unwrap();

        assert_eq!(state.epoch, Epoch(1));
        assert_eq!(state.send_sequence.0, 0); // Reset on epoch change
    }
}
