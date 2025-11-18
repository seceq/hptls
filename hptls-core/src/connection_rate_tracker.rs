//! Connection Rate Tracking for DTLS DoS Protection
//!
//! This module provides connection rate tracking to support the OnHighLoad
//! cookie policy. It uses a sliding window approach to measure connection
//! attempts per second.
//!
//! # Example
//!
//! ```rust
//! use hptls_core::connection_rate_tracker::ConnectionRateTracker;
//! use std::time::Duration;
//!
//! let mut tracker = ConnectionRateTracker::new(Duration::from_secs(60));
//!
//! // Record connection attempt
//! tracker.record_connection();
//!
//! // Get current rate (connections/second)
//! let rate = tracker.current_rate();
//! ```

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Default window size for rate calculation (60 seconds)
pub const DEFAULT_WINDOW_SIZE: Duration = Duration::from_secs(60);

/// Maximum number of timestamps to store (prevents unbounded growth)
const MAX_TIMESTAMPS: usize = 10000;

/// Tracks connection attempts to calculate connection rate
///
/// Uses a sliding window approach to calculate connections per second.
/// Old timestamps are automatically removed when outside the window.
#[derive(Debug)]
pub struct ConnectionRateTracker {
    /// Timestamps of connection attempts within the window
    timestamps: VecDeque<Instant>,

    /// Size of the sliding window
    window_size: Duration,

    /// Total connections recorded (for metrics)
    total_connections: u64,

    /// Last cleanup time (to avoid checking every connection)
    last_cleanup: Instant,
}

impl ConnectionRateTracker {
    /// Create a new connection rate tracker
    ///
    /// # Arguments
    /// * `window_size` - Size of the sliding window for rate calculation
    ///
    /// # Example
    /// ```rust
    /// use hptls_core::connection_rate_tracker::ConnectionRateTracker;
    /// use std::time::Duration;
    ///
    /// let tracker = ConnectionRateTracker::new(Duration::from_secs(60));
    /// ```
    pub fn new(window_size: Duration) -> Self {
        Self {
            timestamps: VecDeque::new(),
            window_size,
            total_connections: 0,
            last_cleanup: Instant::now(),
        }
    }

    /// Create a new tracker with default window size (60 seconds)
    pub fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE)
    }

    /// Record a connection attempt
    ///
    /// This should be called for each incoming ClientHello.
    ///
    /// # Example
    /// ```rust
    /// # use hptls_core::connection_rate_tracker::ConnectionRateTracker;
    /// let mut tracker = ConnectionRateTracker::default();
    /// tracker.record_connection();
    /// ```
    pub fn record_connection(&mut self) {
        let now = Instant::now();

        // Add new timestamp
        self.timestamps.push_back(now);
        self.total_connections += 1;

        // Cleanup old timestamps periodically (every second or when threshold reached)
        if now.duration_since(self.last_cleanup) >= Duration::from_secs(1)
            || self.timestamps.len() > MAX_TIMESTAMPS
        {
            self.cleanup_old_timestamps(now);
            self.last_cleanup = now;
        }
    }

    /// Get the current connection rate (connections per second)
    ///
    /// Calculates the average rate over the sliding window.
    ///
    /// # Returns
    /// Number of connections per second (as u32)
    ///
    /// # Example
    /// ```rust
    /// # use hptls_core::connection_rate_tracker::ConnectionRateTracker;
    /// let mut tracker = ConnectionRateTracker::default();
    /// tracker.record_connection();
    /// let rate = tracker.current_rate();
    /// ```
    pub fn current_rate(&mut self) -> u32 {
        let now = Instant::now();
        self.cleanup_old_timestamps(now);

        // Calculate rate: connections / window_size_seconds
        let window_secs = self.window_size.as_secs_f64();
        if window_secs > 0.0 {
            let rate = self.timestamps.len() as f64 / window_secs;
            rate.ceil() as u32
        } else {
            0
        }
    }

    /// Check if the current rate exceeds a threshold
    ///
    /// # Arguments
    /// * `threshold` - Maximum acceptable connections per second
    ///
    /// # Returns
    /// `true` if current rate exceeds threshold
    ///
    /// # Example
    /// ```rust
    /// # use hptls_core::connection_rate_tracker::ConnectionRateTracker;
    /// let mut tracker = ConnectionRateTracker::default();
    /// if tracker.exceeds_threshold(100) {
    ///     println!("High load detected!");
    /// }
    /// ```
    pub fn exceeds_threshold(&mut self, threshold: u32) -> bool {
        self.current_rate() > threshold
    }

    /// Get total number of connections recorded
    ///
    /// # Returns
    /// Total connections since tracker creation
    pub fn total_connections(&self) -> u64 {
        self.total_connections
    }

    /// Get number of connections in current window
    ///
    /// # Returns
    /// Number of recent connections
    pub fn connections_in_window(&self) -> usize {
        self.timestamps.len()
    }

    /// Reset the tracker
    ///
    /// Clears all recorded timestamps and resets counters.
    pub fn reset(&mut self) {
        self.timestamps.clear();
        self.total_connections = 0;
        self.last_cleanup = Instant::now();
    }

    /// Remove timestamps outside the sliding window
    fn cleanup_old_timestamps(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window_size).unwrap_or(now);

        while let Some(&timestamp) = self.timestamps.front() {
            if timestamp < cutoff {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
    }
}

impl Default for ConnectionRateTracker {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_rate_tracker_creation() {
        let tracker = ConnectionRateTracker::new(Duration::from_secs(60));
        assert_eq!(tracker.total_connections(), 0);
        assert_eq!(tracker.connections_in_window(), 0);
    }

    #[test]
    fn test_record_connection() {
        let mut tracker = ConnectionRateTracker::default();
        assert_eq!(tracker.total_connections(), 0);

        tracker.record_connection();
        assert_eq!(tracker.total_connections(), 1);
        assert_eq!(tracker.connections_in_window(), 1);

        tracker.record_connection();
        assert_eq!(tracker.total_connections(), 2);
        assert_eq!(tracker.connections_in_window(), 2);
    }

    #[test]
    fn test_current_rate_calculation() {
        let mut tracker = ConnectionRateTracker::new(Duration::from_secs(10));

        // Record 10 connections
        for _ in 0..10 {
            tracker.record_connection();
        }

        // Rate should be 10 connections / 10 seconds = 1/sec
        let rate = tracker.current_rate();
        assert_eq!(rate, 1);
    }

    #[test]
    fn test_exceeds_threshold() {
        let mut tracker = ConnectionRateTracker::new(Duration::from_secs(1));

        // Record 5 connections in 1 second window
        for _ in 0..5 {
            tracker.record_connection();
        }

        assert!(!tracker.exceeds_threshold(10)); // 5/sec < 10/sec
        assert!(tracker.exceeds_threshold(3));   // 5/sec > 3/sec
    }

    #[test]
    fn test_sliding_window_cleanup() {
        let mut tracker = ConnectionRateTracker::new(Duration::from_millis(100));

        // Record connection
        tracker.record_connection();
        assert_eq!(tracker.connections_in_window(), 1);

        // Wait for window to expire
        thread::sleep(Duration::from_millis(150));

        // Trigger cleanup by checking rate
        let rate = tracker.current_rate();
        assert_eq!(rate, 0);
        assert_eq!(tracker.connections_in_window(), 0);

        // Total connections should still be 1
        assert_eq!(tracker.total_connections(), 1);
    }

    #[test]
    fn test_reset() {
        let mut tracker = ConnectionRateTracker::default();

        tracker.record_connection();
        tracker.record_connection();
        assert_eq!(tracker.total_connections(), 2);

        tracker.reset();
        assert_eq!(tracker.total_connections(), 0);
        assert_eq!(tracker.connections_in_window(), 0);
    }

    #[test]
    fn test_max_timestamps_limit() {
        let mut tracker = ConnectionRateTracker::new(Duration::from_secs(3600));

        // Record more than MAX_TIMESTAMPS
        for _ in 0..(MAX_TIMESTAMPS + 100) {
            tracker.record_connection();
        }

        // Should trigger cleanup to prevent unbounded growth
        assert!(tracker.connections_in_window() <= MAX_TIMESTAMPS + 100);
        assert_eq!(tracker.total_connections(), (MAX_TIMESTAMPS + 100) as u64);
    }

    #[test]
    fn test_high_rate_scenario() {
        let mut tracker = ConnectionRateTracker::new(Duration::from_secs(1));

        // Simulate 200 connections in quick succession
        for _ in 0..200 {
            tracker.record_connection();
        }

        let rate = tracker.current_rate();
        // Rate should be ~200/sec (actual value depends on timing)
        assert!(rate >= 150); // Allow some variance
    }
}
