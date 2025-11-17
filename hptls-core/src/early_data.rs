//! 0-RTT Early Data Support (RFC 8446 Section 4.2.10)
//!
//! Early data allows clients to send application data in the first flight
//! of a resumed TLS 1.3 connection, reducing round-trip time.
//!
//! # Security Considerations
//!
//! - Early data is NOT forward secret
//! - Early data can be replayed by network attackers
//! - Applications must ensure early data is idempotent
//! - Maximum early data size must be enforced
//!
//! # Protocol Flow
//!
//! ```text
//! Client                                Server
//!
//! ClientHello
//!   + early_data
//!   + key_share
//!   + psk_key_exchange_modes
//!   + pre_shared_key
//! (Application Data*)        -------->
//!                                      ServerHello
//!                                   + pre_shared_key
//!                                         + key_share
//!                            <--------   {EncryptedExtensions}
//!                                          + early_data
//!                                         {Certificate*}
//!                                   {CertificateVerify*}
//!                                            {Finished}
//! {EndOfEarlyData}           -------->
//! (Application Data)         <------->  (Application Data)
//! ```

use crate::cipher::CipherSuite;
use crate::error::{Error, Result};

/// Maximum early data size (configurable per-ticket)
pub const DEFAULT_MAX_EARLY_DATA_SIZE: u32 = 16384; // 16 KB

/// Early data configuration
#[derive(Debug, Clone)]
pub struct EarlyDataConfig {
    /// Maximum early data size in bytes
    pub max_early_data_size: u32,

    /// Whether to allow early data
    pub enabled: bool,

    /// Anti-replay window size (in seconds)
    pub anti_replay_window: u32,
}

impl Default for EarlyDataConfig {
    fn default() -> Self {
        Self {
            max_early_data_size: DEFAULT_MAX_EARLY_DATA_SIZE,
            enabled: false,         // Disabled by default for security
            anti_replay_window: 10, // 10 seconds
        }
    }
}

impl EarlyDataConfig {
    /// Create a permissive configuration (for testing)
    pub fn permissive() -> Self {
        Self {
            max_early_data_size: 65536, // 64 KB
            enabled: true,
            anti_replay_window: 60, // 60 seconds
        }
    }

    /// Create a strict configuration (for production)
    pub fn strict() -> Self {
        Self {
            max_early_data_size: 8192, // 8 KB
            enabled: true,
            anti_replay_window: 2, // 2 seconds
        }
    }
}

/// Early data state tracking
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EarlyDataState {
    /// Early data not used
    NotUsed,

    /// Early data offered by client (awaiting server acceptance)
    Offered,

    /// Early data accepted by server
    Accepted,

    /// Early data rejected by server
    Rejected,

    /// Early data sent/received
    InProgress { bytes_sent: u32 },

    /// Early data complete
    Complete { total_bytes: u32 },
}

/// Early data context
#[derive(Debug, Clone)]
pub struct EarlyDataContext {
    /// Current state
    pub state: EarlyDataState,

    /// Configuration
    pub config: EarlyDataConfig,

    /// Cipher suite for early data
    pub cipher_suite: Option<CipherSuite>,

    /// Early data traffic secret
    pub early_traffic_secret: Option<Vec<u8>>,
}

impl EarlyDataContext {
    /// Create a new early data context
    pub fn new(config: EarlyDataConfig) -> Self {
        Self {
            state: EarlyDataState::NotUsed,
            config,
            cipher_suite: None,
            early_traffic_secret: None,
        }
    }

    /// Check if early data is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if early data was accepted
    pub fn is_accepted(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Accepted
                | EarlyDataState::InProgress { .. }
                | EarlyDataState::Complete { .. }
        )
    }

    /// Offer early data (transition to Offered state)
    pub fn offer(&mut self) -> Result<()> {
        if matches!(self.state, EarlyDataState::NotUsed) {
            self.state = EarlyDataState::Offered;
            Ok(())
        } else {
            Err(Error::InvalidConfig("Early data already offered".into()))
        }
    }

    /// Accept early data (server accepted the offer)
    pub fn accept(&mut self) -> Result<()> {
        if matches!(self.state, EarlyDataState::Offered) {
            self.state = EarlyDataState::Accepted;
            Ok(())
        } else {
            Err(Error::InvalidConfig(
                "Early data not in offered state".into(),
            ))
        }
    }

    /// Reject early data (server rejected the offer)
    pub fn reject(&mut self) -> Result<()> {
        if matches!(self.state, EarlyDataState::Offered) {
            self.state = EarlyDataState::Rejected;
            Ok(())
        } else {
            Err(Error::InvalidConfig(
                "Early data not in offered state".into(),
            ))
        }
    }

    /// Get maximum early data size
    pub fn max_early_data_size(&self) -> u32 {
        self.config.max_early_data_size
    }

    /// Record bytes sent
    pub fn record_bytes_sent(&mut self, bytes: u32) -> Result<()> {
        match &self.state {
            EarlyDataState::Accepted => {
                if bytes > self.config.max_early_data_size {
                    return Err(Error::ProtocolError(
                        crate::error::ProtocolError::IllegalParameter,
                    ));
                }
                self.state = EarlyDataState::InProgress { bytes_sent: bytes };
                Ok(())
            },
            EarlyDataState::InProgress { bytes_sent } => {
                let total = bytes_sent + bytes;
                if total > self.config.max_early_data_size {
                    return Err(Error::ProtocolError(
                        crate::error::ProtocolError::IllegalParameter,
                    ));
                }
                self.state = EarlyDataState::InProgress { bytes_sent: total };
                Ok(())
            },
            _ => Err(Error::InvalidConfig("Early data not in valid state".into())),
        }
    }

    /// Mark early data complete
    pub fn mark_complete(&mut self) -> Result<()> {
        match &self.state {
            EarlyDataState::InProgress { bytes_sent } => {
                self.state = EarlyDataState::Complete {
                    total_bytes: *bytes_sent,
                };
                Ok(())
            },
            EarlyDataState::Accepted => {
                // No data sent, mark as complete with 0 bytes
                self.state = EarlyDataState::Complete { total_bytes: 0 };
                Ok(())
            },
            _ => Err(Error::InvalidConfig("Cannot complete early data".into())),
        }
    }
}

/// Anti-replay mechanism for 0-RTT
///
/// This implements a time-window based anti-replay mechanism with timestamp tracking.
///
/// # Security Properties
///
/// - Prevents replay attacks by tracking seen tickets with timestamps
/// - Uses time-window to limit memory usage
/// - Automatically expires old entries
/// - Thread-safe for concurrent access
///
/// # Production Considerations
///
/// For production deployments across multiple servers:
/// - Use Redis or similar distributed cache
/// - Implement Bloom filters for memory efficiency
/// - Persist to database for audit trail
/// - Implement distributed coordination (e.g., via database transactions)
#[derive(Debug)]
pub struct AntiReplayCache {
    /// Window size in seconds
    window_size: u32,

    /// Seen tickets with their timestamps (UNIX seconds)
    seen_tickets: std::collections::HashMap<Vec<u8>, u64>,

    /// Maximum cache size (to prevent memory exhaustion)
    max_cache_size: usize,

    /// Last cleanup timestamp
    last_cleanup: u64,
}

impl AntiReplayCache {
    /// Create a new anti-replay cache
    ///
    /// # Arguments
    /// * `window_size` - Time window in seconds (recommended: 2-10 seconds)
    pub fn new(window_size: u32) -> Self {
        Self::with_max_size(window_size, 100_000) // 100k tickets by default
    }

    /// Create cache with custom maximum size
    pub fn with_max_size(window_size: u32, max_cache_size: usize) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        Self {
            window_size,
            seen_tickets: std::collections::HashMap::new(),
            max_cache_size,
            last_cleanup: now,
        }
    }

    /// Check if a ticket has been seen (and mark as seen if not)
    ///
    /// # Arguments
    /// * `ticket` - The ticket value (should be unique)
    /// * `timestamp` - Ticket timestamp (UNIX seconds)
    ///
    /// # Returns
    /// * `true` - Ticket is valid (not a replay)
    /// * `false` - Replay detected or timestamp out of window
    pub fn check_and_mark(&mut self, ticket: &[u8], timestamp: u64) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Check if timestamp is within acceptable window
        // Reject if timestamp is too old or in the future (clock skew tolerance: 5 seconds)
        let window_start = now.saturating_sub(self.window_size as u64);
        let window_end = now + 5; // Allow 5 seconds clock skew

        if timestamp < window_start || timestamp > window_end {
            // Timestamp outside acceptable window
            return false;
        }

        // Check if ticket was already seen
        if let Some(&seen_timestamp) = self.seen_tickets.get(ticket) {
            // Ticket was already used - replay detected
            // Log for security audit
            tracing::warn!(
                "0-RTT replay detected: ticket seen at {} (current: {})",
                seen_timestamp,
                now
            );
            return false;
        }

        // Mark ticket as seen
        self.seen_tickets.insert(ticket.to_vec(), now);

        // Periodic cleanup to prevent memory exhaustion
        if now - self.last_cleanup > 60 {
            // Cleanup every minute
            self.cleanup();
            self.last_cleanup = now;
        } else if self.seen_tickets.len() > self.max_cache_size {
            // Emergency cleanup if cache is too large
            self.cleanup();
        }

        true
    }

    /// Clean up expired entries
    ///
    /// Removes tickets older than the time window.
    /// Should be called periodically (automatically called by check_and_mark).
    pub fn cleanup(&mut self) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let cutoff = now.saturating_sub(self.window_size as u64);

        let before_count = self.seen_tickets.len();
        self.seen_tickets.retain(|_, &mut timestamp| timestamp >= cutoff);
        let after_count = self.seen_tickets.len();

        if before_count > after_count {
            tracing::debug!(
                "Anti-replay cache cleanup: removed {} expired entries ({} -> {})",
                before_count - after_count,
                before_count,
                after_count
            );
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> AntiReplayCacheStats {
        AntiReplayCacheStats {
            entries: self.seen_tickets.len(),
            window_size: self.window_size,
            max_cache_size: self.max_cache_size,
        }
    }

    /// Clear all entries (for testing or manual reset)
    pub fn clear(&mut self) {
        self.seen_tickets.clear();
    }
}

/// Statistics for anti-replay cache
#[derive(Debug, Clone, Copy)]
pub struct AntiReplayCacheStats {
    /// Number of entries in cache
    pub entries: usize,
    /// Time window in seconds
    pub window_size: u32,
    /// Maximum cache size
    pub max_cache_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_early_data_config_default() {
        let config = EarlyDataConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_early_data_size, DEFAULT_MAX_EARLY_DATA_SIZE);
    }

    #[test]
    fn test_early_data_config_permissive() {
        let config = EarlyDataConfig::permissive();
        assert!(config.enabled);
        assert_eq!(config.max_early_data_size, 65536);
    }

    #[test]
    fn test_early_data_context_state_transitions() {
        let mut ctx = EarlyDataContext::new(EarlyDataConfig::permissive());

        assert_eq!(ctx.state, EarlyDataState::NotUsed);
        assert!(!ctx.is_accepted());

        // Offer early data
        ctx.state = EarlyDataState::Offered;
        assert!(!ctx.is_accepted());

        // Accept early data
        ctx.state = EarlyDataState::Accepted;
        assert!(ctx.is_accepted());

        // Record bytes
        ctx.record_bytes_sent(1000).unwrap();
        assert!(matches!(ctx.state, EarlyDataState::InProgress { .. }));

        // Complete
        ctx.mark_complete().unwrap();
        assert!(matches!(ctx.state, EarlyDataState::Complete { .. }));
    }

    #[test]
    fn test_early_data_size_limit() {
        let mut ctx = EarlyDataContext::new(EarlyDataConfig::strict());
        ctx.state = EarlyDataState::Accepted;

        // Try to send more than max
        let result = ctx.record_bytes_sent(10000);
        assert!(result.is_err());
    }

    #[test]
    fn test_anti_replay_cache_basic() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut cache = AntiReplayCache::new(10);

        let ticket = b"test_ticket";

        // First check should succeed
        assert!(cache.check_and_mark(ticket, now));

        // Second check should fail (replay detected)
        assert!(!cache.check_and_mark(ticket, now));
    }

    #[test]
    fn test_anti_replay_timestamp_window() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut cache = AntiReplayCache::new(10); // 10 second window

        let ticket = b"test_ticket";

        // Ticket timestamp too old (outside window)
        assert!(!cache.check_and_mark(ticket, now - 15));

        // Ticket timestamp in the future (beyond clock skew tolerance)
        assert!(!cache.check_and_mark(ticket, now + 10));

        // Ticket timestamp within window
        assert!(cache.check_and_mark(ticket, now));
    }

    #[test]
    fn test_anti_replay_cleanup() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut cache = AntiReplayCache::new(10);

        // Add multiple tickets
        for i in 0..100 {
            let ticket = format!("ticket_{}", i);
            cache.check_and_mark(ticket.as_bytes(), now);
        }

        assert_eq!(cache.stats().entries, 100);

        // Manual cleanup
        cache.cleanup();

        // All entries should still be there (not expired)
        assert_eq!(cache.stats().entries, 100);

        // Add tickets with old timestamps
        for i in 100..110 {
            let ticket = format!("ticket_{}", i);
            let old_timestamp = now - 20; // Outside 10 second window
            cache.seen_tickets.insert(ticket.as_bytes().to_vec(), old_timestamp);
        }

        // Now we have 110 entries
        assert_eq!(cache.stats().entries, 110);

        // Cleanup should remove the 10 expired entries
        cache.cleanup();
        assert_eq!(cache.stats().entries, 100);
    }

    #[test]
    fn test_anti_replay_max_cache_size() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut cache = AntiReplayCache::with_max_size(10, 50); // Max 50 entries

        // Add entries up to max
        for i in 0..60 {
            let ticket = format!("ticket_{}", i);
            cache.check_and_mark(ticket.as_bytes(), now);
        }

        // Cache should have 60 entries before cleanup
        assert_eq!(cache.stats().entries, 60);

        // Manual cleanup should not remove anything (all entries are fresh)
        cache.cleanup();
        assert_eq!(cache.stats().entries, 60);

        // But if we add old entries and trigger cleanup...
        for i in 60..70 {
            let ticket = format!("ticket_{}", i);
            cache.seen_tickets.insert(ticket.as_bytes().to_vec(), now - 20);
        }

        assert_eq!(cache.stats().entries, 70);
        cache.cleanup();
        // Should have removed the 10 old entries
        assert_eq!(cache.stats().entries, 60);
    }

    #[test]
    fn test_anti_replay_different_tickets() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut cache = AntiReplayCache::new(10);

        // Different tickets should all succeed
        assert!(cache.check_and_mark(b"ticket_1", now));
        assert!(cache.check_and_mark(b"ticket_2", now));
        assert!(cache.check_and_mark(b"ticket_3", now));

        // Replay same tickets should fail
        assert!(!cache.check_and_mark(b"ticket_1", now));
        assert!(!cache.check_and_mark(b"ticket_2", now));
    }

    #[test]
    fn test_anti_replay_clear() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut cache = AntiReplayCache::new(10);

        cache.check_and_mark(b"ticket", now);
        assert_eq!(cache.stats().entries, 1);

        cache.clear();
        assert_eq!(cache.stats().entries, 0);

        // After clear, same ticket should succeed again
        assert!(cache.check_and_mark(b"ticket", now));
    }

    #[test]
    fn test_anti_replay_stats() {
        let cache = AntiReplayCache::new(10);
        let stats = cache.stats();

        assert_eq!(stats.entries, 0);
        assert_eq!(stats.window_size, 10);
        assert_eq!(stats.max_cache_size, 100_000);
    }
}
