//! Cookie Secret Management for DTLS 1.3
//!
//! This module provides secure cookie secret management with automatic rotation
//! for DTLS 1.3 stateless DoS protection.
//!
//! # Overview
//!
//! The `CookieSecretManager` manages cookie secrets used in HMAC-based cookie
//! generation for DTLS 1.3 HelloRetryRequest flows. It provides:
//!
//! - **Automatic Rotation**: Secrets rotate periodically (default: 1 hour)
//! - **Grace Period**: Old secrets remain valid during transition
//! - **Secure Zeroization**: Old secrets are securely wiped from memory
//! - **Thread-Safe**: Can be shared across multiple threads
//!
//! # Example
//!
//! ```rust
//! use hptls_core::cookie_manager::CookieSecretManager;
//! use std::time::Duration;
//! use hptls_crypto_hpcrypt::HpcryptProvider;
//! use hptls_crypto::CryptoProvider;
//!
//! let provider = HpcryptProvider::new();
//! let manager = CookieSecretManager::new(
//!     &provider,
//!     Duration::from_secs(3600) // Rotate every hour
//! ).unwrap();
//!
//! // Generate cookie with current secret
//! let cookie = manager.generate_cookie(
//!     &provider,
//!     b"client_hello_data",
//!     b"client_addr"
//! ).unwrap();
//!
//! // Verify cookie (works with current or previous secret)
//! assert!(manager.verify_cookie(
//!     &provider,
//!     &cookie,
//!     b"client_hello_data",
//!     b"client_addr"
//! ).unwrap());
//! ```

use crate::error::{Error, Result};
use hptls_crypto::{CryptoProvider, HashAlgorithm, Random};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Cookie secret size (32 bytes for HMAC-SHA256)
pub const COOKIE_SECRET_SIZE: usize = 32;

/// Cookie secret with metadata
#[derive(Clone)]
struct CookieSecret {
    /// Secret key (32 bytes for HMAC-SHA256)
    secret: Zeroizing<Vec<u8>>,
    /// When this secret was created
    created_at: Instant,
}

impl CookieSecret {
    /// Create a new cookie secret
    fn new(secret: Vec<u8>, created_at: Instant) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            created_at,
        }
    }

    /// Get age of this secret
    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Inner state for `CookieSecretManager` (protected by Mutex)
struct CookieSecretManagerInner {
    /// Current active secret
    current: CookieSecret,
    /// Previous secret (valid during grace period)
    previous: Option<CookieSecret>,
    /// Rotation interval
    rotation_interval: Duration,
    /// Grace period for old secrets
    grace_period: Duration,
    /// Total number of rotations performed
    rotation_count: u64,
}

impl CookieSecretManagerInner {
    /// Check if rotation is needed
    fn needs_rotation(&self) -> bool {
        self.current.age() >= self.rotation_interval
    }

    /// Check if previous secret has expired
    fn previous_expired(&self) -> bool {
        if let Some(ref prev) = self.previous {
            prev.age() > self.rotation_interval + self.grace_period
        } else {
            false
        }
    }
}

/// Cookie secret manager with automatic rotation
///
/// Manages cookie secrets for DTLS 1.3 stateless DoS protection. Provides:
/// - Automatic rotation after a configured interval
/// - Grace period for old secrets during transition
/// - Secure zeroization of expired secrets
/// - Thread-safe operation
#[derive(Clone)]
pub struct CookieSecretManager {
    /// Inner state (protected by Mutex for thread-safety)
    inner: Arc<Mutex<CookieSecretManagerInner>>,
}

impl CookieSecretManager {
    /// Create a new cookie secret manager
    ///
    /// # Arguments
    ///
    /// * `provider` - Crypto provider for random number generation
    /// * `rotation_interval` - How often to rotate secrets
    ///
    /// # Returns
    ///
    /// A new `CookieSecretManager` with a freshly generated secret
    ///
    /// # Example
    ///
    /// ```rust
    /// use hptls_core::cookie_manager::CookieSecretManager;
    /// use std::time::Duration;
    /// use hptls_crypto_hpcrypt::HpcryptProvider;
    /// use hptls_crypto::CryptoProvider;
    ///
    /// let provider = HpcryptProvider::new();
    /// let manager = CookieSecretManager::new(
    ///     &provider,
    ///     Duration::from_secs(3600) // 1 hour
    /// ).unwrap();
    /// ```
    pub fn new(provider: &dyn CryptoProvider, rotation_interval: Duration) -> Result<Self> {
        // Generate initial secret
        let mut secret = vec![0u8; COOKIE_SECRET_SIZE];
        let rng = provider.random();
        rng.fill(&mut secret)?;

        let current = CookieSecret::new(secret, Instant::now());

        // Grace period is 10% of rotation interval (minimum 60 seconds)
        let grace_period = rotation_interval
            .div_f32(10.0)
            .max(Duration::from_secs(60));

        let inner = CookieSecretManagerInner {
            current,
            previous: None,
            rotation_interval,
            grace_period,
            rotation_count: 0,
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Create a manager with custom grace period
    ///
    /// # Arguments
    ///
    /// * `provider` - Crypto provider
    /// * `rotation_interval` - How often to rotate
    /// * `grace_period` - How long old secrets remain valid
    pub fn with_grace_period(
        provider: &dyn CryptoProvider,
        rotation_interval: Duration,
        grace_period: Duration,
    ) -> Result<Self> {
        let mut manager = Self::new(provider, rotation_interval)?;

        // Update grace period
        let mut inner = manager.inner.lock().unwrap();
        inner.grace_period = grace_period;
        drop(inner);

        Ok(manager)
    }

    /// Rotate the cookie secret
    ///
    /// Moves current secret to previous, generates new current secret.
    /// Old previous secret (if any) is dropped and zeroized.
    ///
    /// # Arguments
    ///
    /// * `provider` - Crypto provider for random number generation
    ///
    /// # Example
    ///
    /// ```rust
    /// # use hptls_core::cookie_manager::CookieSecretManager;
    /// # use std::time::Duration;
    /// # use hptls_crypto_hpcrypt::HpcryptProvider;
    /// # use hptls_crypto::CryptoProvider;
    /// # let provider = HpcryptProvider::new();
    /// # let manager = CookieSecretManager::new(&provider, Duration::from_secs(3600)).unwrap();
    /// // Manually trigger rotation
    /// manager.rotate(&provider).unwrap();
    /// ```
    pub fn rotate(&self, provider: &dyn CryptoProvider) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();

        // Generate new secret
        let mut new_secret = vec![0u8; COOKIE_SECRET_SIZE];
        let rng = provider.random();
        rng.fill(&mut new_secret)?;

        // Move current to previous (old previous is dropped and zeroized)
        let old_current = inner.current.clone();
        inner.previous = Some(old_current);

        // Set new current
        inner.current = CookieSecret::new(new_secret, Instant::now());
        inner.rotation_count += 1;

        Ok(())
    }

    /// Check if rotation is needed and rotate if so
    ///
    /// # Arguments
    ///
    /// * `provider` - Crypto provider
    ///
    /// # Returns
    ///
    /// `true` if rotation was performed
    pub fn rotate_if_needed(&self, provider: &dyn CryptoProvider) -> Result<bool> {
        let needs_rotation = {
            let inner = self.inner.lock().unwrap();
            inner.needs_rotation()
        };

        if needs_rotation {
            self.rotate(provider)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Clean up expired previous secrets
    ///
    /// Removes previous secret if it has exceeded rotation_interval + grace_period
    pub fn cleanup_expired(&self) {
        let mut inner = self.inner.lock().unwrap();

        if inner.previous_expired() {
            // Drop previous secret (will be zeroized)
            inner.previous = None;
        }
    }

    /// Generate a cookie using HMAC-SHA256
    ///
    /// # Arguments
    ///
    /// * `provider` - Crypto provider
    /// * `client_hello` - ClientHello message bytes
    /// * `client_addr` - Client address bytes
    ///
    /// # Returns
    ///
    /// 32-byte HMAC-SHA256 cookie
    pub fn generate_cookie(
        &self,
        provider: &dyn CryptoProvider,
        client_hello: &[u8],
        client_addr: &[u8],
    ) -> Result<Vec<u8>> {
        let inner = self.inner.lock().unwrap();
        let secret = &inner.current.secret;

        // Compute HMAC-SHA256(secret, client_addr || client_hello)
        let mut hmac = provider.hmac(HashAlgorithm::Sha256, secret)?;
        hmac.update(client_addr);
        hmac.update(client_hello);
        Ok(hmac.finalize())
    }

    /// Verify a cookie (checks both current and previous secrets)
    ///
    /// # Arguments
    ///
    /// * `provider` - Crypto provider
    /// * `cookie` - Cookie to verify (32 bytes)
    /// * `client_hello` - ClientHello message bytes
    /// * `client_addr` - Client address bytes
    ///
    /// # Returns
    ///
    /// `true` if cookie is valid (matches current or previous secret)
    pub fn verify_cookie(
        &self,
        provider: &dyn CryptoProvider,
        cookie: &[u8],
        client_hello: &[u8],
        client_addr: &[u8],
    ) -> Result<bool> {
        let inner = self.inner.lock().unwrap();

        // Try current secret first
        let mut hmac_current = provider.hmac(HashAlgorithm::Sha256, &inner.current.secret)?;
        hmac_current.update(client_addr);
        hmac_current.update(client_hello);

        if hmac_current.verify(cookie) {
            return Ok(true);
        }

        // Try previous secret if it exists and hasn't expired
        if let Some(ref prev) = inner.previous {
            if !inner.previous_expired() {
                let mut hmac_prev = provider.hmac(HashAlgorithm::Sha256, &prev.secret)?;
                hmac_prev.update(client_addr);
                hmac_prev.update(client_hello);

                if hmac_prev.verify(cookie) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get current secret age
    pub fn current_secret_age(&self) -> Duration {
        let inner = self.inner.lock().unwrap();
        inner.current.age()
    }

    /// Get previous secret age (if exists)
    pub fn previous_secret_age(&self) -> Option<Duration> {
        let inner = self.inner.lock().unwrap();
        inner.previous.as_ref().map(|p| p.age())
    }

    /// Get total number of rotations performed
    pub fn rotation_count(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.rotation_count
    }

    /// Get rotation interval
    pub fn rotation_interval(&self) -> Duration {
        let inner = self.inner.lock().unwrap();
        inner.rotation_interval
    }

    /// Get grace period
    pub fn grace_period(&self) -> Duration {
        let inner = self.inner.lock().unwrap();
        inner.grace_period
    }

    /// Check if rotation is needed
    pub fn needs_rotation(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.needs_rotation()
    }

    /// Check if there is a previous secret
    pub fn has_previous_secret(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.previous.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hptls_crypto_hpcrypt::HpcryptProvider;
    use std::thread;

    #[test]
    fn test_cookie_manager_creation() {
        let provider = HpcryptProvider::new();
        let manager = CookieSecretManager::new(&provider, Duration::from_secs(3600)).unwrap();

        assert_eq!(manager.rotation_count(), 0);
        assert!(!manager.has_previous_secret());
        assert!(manager.current_secret_age() < Duration::from_millis(100));
    }

    #[test]
    fn test_cookie_generation_and_verification() {
        let provider = HpcryptProvider::new();
        let manager = CookieSecretManager::new(&provider, Duration::from_secs(3600)).unwrap();

        let client_hello = b"test_client_hello_data";
        let client_addr = b"192.168.1.1:12345";

        // Generate cookie
        let cookie = manager
            .generate_cookie(&provider, client_hello, client_addr)
            .unwrap();

        assert_eq!(cookie.len(), 32); // HMAC-SHA256 output size

        // Verify cookie
        assert!(manager
            .verify_cookie(&provider, &cookie, client_hello, client_addr)
            .unwrap());

        // Wrong cookie should fail
        let wrong_cookie = vec![0u8; 32];
        assert!(!manager
            .verify_cookie(&provider, &wrong_cookie, client_hello, client_addr)
            .unwrap());

        // Wrong client_hello should fail
        assert!(!manager
            .verify_cookie(&provider, &cookie, b"different_hello", client_addr)
            .unwrap());

        // Wrong client_addr should fail
        assert!(!manager
            .verify_cookie(&provider, &cookie, client_hello, b"different_addr")
            .unwrap());
    }

    #[test]
    fn test_secret_rotation() {
        let provider = HpcryptProvider::new();
        let manager = CookieSecretManager::new(&provider, Duration::from_secs(1)).unwrap();

        let client_hello = b"test_data";
        let client_addr = b"127.0.0.1:4433";

        // Generate cookie with first secret
        let cookie1 = manager
            .generate_cookie(&provider, client_hello, client_addr)
            .unwrap();

        assert_eq!(manager.rotation_count(), 0);
        assert!(!manager.has_previous_secret());

        // Rotate secret
        manager.rotate(&provider).unwrap();

        assert_eq!(manager.rotation_count(), 1);
        assert!(manager.has_previous_secret());

        // Generate cookie with new secret
        let cookie2 = manager
            .generate_cookie(&provider, client_hello, client_addr)
            .unwrap();

        // Cookies should be different
        assert_ne!(cookie1, cookie2);

        // Both cookies should still verify (grace period)
        assert!(manager
            .verify_cookie(&provider, &cookie1, client_hello, client_addr)
            .unwrap());
        assert!(manager
            .verify_cookie(&provider, &cookie2, client_hello, client_addr)
            .unwrap());
    }

    #[test]
    fn test_automatic_rotation() {
        let provider = HpcryptProvider::new();
        let manager =
            CookieSecretManager::new(&provider, Duration::from_millis(100)).unwrap();

        assert!(!manager.needs_rotation());
        assert_eq!(manager.rotation_count(), 0);

        // Wait for rotation interval
        thread::sleep(Duration::from_millis(150));

        assert!(manager.needs_rotation());

        // Trigger automatic rotation
        assert!(manager.rotate_if_needed(&provider).unwrap());
        assert_eq!(manager.rotation_count(), 1);

        // Should not rotate again immediately
        assert!(!manager.needs_rotation());
        assert!(!manager.rotate_if_needed(&provider).unwrap());
    }

    #[test]
    fn test_grace_period() {
        let provider = HpcryptProvider::new();
        let manager = CookieSecretManager::with_grace_period(
            &provider,
            Duration::from_millis(100),
            Duration::from_millis(50),
        )
        .unwrap();

        let client_hello = b"test";
        let client_addr = b"addr";

        // Generate cookie with first secret
        let cookie1 = manager
            .generate_cookie(&provider, client_hello, client_addr)
            .unwrap();

        // Rotate
        manager.rotate(&provider).unwrap();

        // Cookie should still be valid (within grace period)
        assert!(manager
            .verify_cookie(&provider, &cookie1, client_hello, client_addr)
            .unwrap());

        // Wait for grace period to expire
        thread::sleep(Duration::from_millis(160)); // rotation_interval + grace_period

        // Clean up expired secrets
        manager.cleanup_expired();

        // Old cookie should no longer be valid
        assert!(!manager
            .verify_cookie(&provider, &cookie1, client_hello, client_addr)
            .unwrap());
    }

    #[test]
    fn test_multiple_rotations() {
        let provider = HpcryptProvider::new();
        let manager =
            CookieSecretManager::new(&provider, Duration::from_millis(50)).unwrap();

        for i in 1..=5 {
            thread::sleep(Duration::from_millis(60));
            manager.rotate_if_needed(&provider).unwrap();
            assert_eq!(manager.rotation_count(), i);
        }
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;

        let provider = Arc::new(HpcryptProvider::new());
        let manager = Arc::new(
            CookieSecretManager::new(&*provider, Duration::from_secs(10)).unwrap(),
        );

        let mut handles = vec![];

        // Spawn multiple threads that generate and verify cookies
        for i in 0..10 {
            let manager_clone = Arc::clone(&manager);
            let provider_clone = Arc::clone(&provider);

            let handle = thread::spawn(move || {
                let data = format!("thread_{}", i);
                let cookie = manager_clone
                    .generate_cookie(&*provider_clone, data.as_bytes(), b"addr")
                    .unwrap();

                assert!(manager_clone
                    .verify_cookie(&*provider_clone, &cookie, data.as_bytes(), b"addr")
                    .unwrap());
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
