//! Linux-specific bindings (kTLS, io_uring).

use crate::{Error, Result};

/// kTLS (Kernel TLS) support for Linux.
///
/// Linux kernel >= 4.13 supports TLS offload to the kernel.
/// This provides hardware-accelerated encryption/decryption.
#[cfg(feature = "kTLS")]
pub mod ktls {
    use super::*;

    // TLS socket options (from linux/tls.h)
    const SOL_TLS: i32 = 282;
    const TLS_TX: i32 = 1;
    const TLS_RX: i32 = 2;

    /// TLS version for kTLS
    #[repr(u16)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TlsVersion {
        /// TLS 1.2
        Tls12 = 0x0303,
        /// TLS 1.3
        Tls13 = 0x0304,
    }

    /// TLS cipher type for kTLS
    #[repr(u16)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CipherType {
        /// AES-128-GCM
        Aes128Gcm = 51,
        /// AES-256-GCM
        Aes256Gcm = 52,
        /// ChaCha20-Poly1305
        ChaCha20Poly1305 = 54,
    }

    /// Check if kTLS is available on this system.
    pub fn is_available() -> bool {
        // TODO: Check if kernel supports kTLS
        // This would involve checking /proc/sys/net/tls/tx and rx
        false
    }

    /// Enable kTLS transmit (TX) on a socket.
    ///
    /// # Safety
    ///
    /// The socket must be a valid TCP socket file descriptor.
    pub unsafe fn enable_tx(
        _socket_fd: i32,
        _version: TlsVersion,
        _cipher: CipherType,
        _key: &[u8],
        _iv: &[u8],
        _seq: u64,
    ) -> Result<()> {
        // TODO: Implement using setsockopt(SOL_TLS, TLS_TX, ...)
        Err(Error::FeatureNotAvailable(
            "kTLS not yet implemented".into(),
        ))
    }

    /// Enable kTLS receive (RX) on a socket.
    ///
    /// # Safety
    ///
    /// The socket must be a valid TCP socket file descriptor.
    pub unsafe fn enable_rx(
        _socket_fd: i32,
        _version: TlsVersion,
        _cipher: CipherType,
        _key: &[u8],
        _iv: &[u8],
        _seq: u64,
    ) -> Result<()> {
        // TODO: Implement using setsockopt(SOL_TLS, TLS_RX, ...)
        Err(Error::FeatureNotAvailable(
            "kTLS not yet implemented".into(),
        ))
    }
}

/// io_uring support for Linux.
///
/// Provides modern async I/O using io_uring (kernel >= 5.1).
#[cfg(feature = "io-uring")]
pub mod io_uring {
    use super::*;

    /// Check if io_uring is available on this system.
    pub fn is_available() -> bool {
        // TODO: Check kernel version and io_uring support
        false
    }

    /// io_uring instance (placeholder).
    pub struct IoUring {
        _private: (),
    }

    impl IoUring {
        /// Create a new io_uring instance.
        pub fn new(_entries: u32) -> Result<Self> {
            // TODO: Implement using io_uring_setup syscall
            Err(Error::FeatureNotAvailable(
                "io_uring not yet implemented".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[cfg(feature = "kTLS")]
    fn test_ktls_availability() {
        // Just check it doesn't panic
        let _ = ktls::is_available();
    }

    #[test]
    #[cfg(feature = "io-uring")]
    fn test_io_uring_availability() {
        // Just check it doesn't panic
        let _ = io_uring::is_available();
    }
}
