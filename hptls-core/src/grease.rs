//! GREASE (Generate Random Extensions And Sustain Extensibility) - RFC 8701
//!
//! GREASE prevents protocol ossification by injecting random values into
//! protocol extensions, cipher suites, versions, and other fields. This ensures
//! that implementations properly ignore unknown values instead of failing.
//!
//! # Purpose
//!
//! Over time, protocols can become "ossified" when implementations start to
//! assume only a fixed set of values are valid. GREASE prevents this by:
//!
//! - Randomly inserting reserved values that MUST be ignored
//! - Testing that peers handle unknown values gracefully
//! - Ensuring future protocol extensions won't break existing implementations
//!
//! # GREASE Values
//!
//! RFC 8701 defines specific reserved values with a pattern:
//! - 0x0A0A (2570)
//! - 0x1A1A (6682)
//! - 0x2A2A (10794)
//! - 0x3A3A (14906)
//! - 0x4A4A (19018)
//! - 0x5A5A (23130)
//! - 0x6A6A (27242)
//! - 0x7A7A (31354)
//! - 0x8A8A (35466)
//! - 0x9A9A (39578)
//! - 0xAAAA (43690)
//! - 0xBABA (47802)
//! - 0xCACA (51914)
//! - 0xDADA (56026)
//! - 0xEAEA (60138)
//! - 0xFAFA (64250)
//!
//! # Usage
//!
//! ```rust
//! use hptls_core::grease::GreaseGenerator;
//!
//! let mut grease = GreaseGenerator::new();
//!
//! // Get random GREASE values for different fields
//! let grease_cipher = grease.cipher_suite();
//! let grease_group = grease.named_group();
//! let grease_extension = grease.extension_type();
//! ```

use rand::Rng;

/// GREASE values as defined in RFC 8701
///
/// These are reserved values with the pattern 0x?A?A where ? is any hex digit.
const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// GREASE generator for TLS protocol
///
/// Generates random GREASE values to prevent protocol ossification.
/// Each instance should be used for one handshake to ensure consistency.
#[derive(Debug, Clone)]
pub struct GreaseGenerator {
    /// Selected GREASE values for this handshake (for consistency)
    cipher_suite_grease: u16,
    group_grease: u16,
    extension_grease: u16,
    version_grease: u16,
    psk_mode_grease: u8,
    signature_algorithm_grease: u16,
}

impl GreaseGenerator {
    /// Create a new GREASE generator with random values
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();

        // Select different GREASE values for different fields
        // to maximize compatibility testing
        let indices: Vec<usize> = (0..GREASE_VALUES.len()).collect();
        let mut selected_indices = indices.clone();

        // Shuffle to get random selection
        use rand::seq::SliceRandom;
        selected_indices.shuffle(&mut rng);

        Self {
            cipher_suite_grease: GREASE_VALUES[selected_indices[0]],
            group_grease: GREASE_VALUES[selected_indices[1]],
            extension_grease: GREASE_VALUES[selected_indices[2]],
            version_grease: GREASE_VALUES[selected_indices[3]],
            psk_mode_grease: (GREASE_VALUES[selected_indices[4]] & 0xFF) as u8,
            signature_algorithm_grease: GREASE_VALUES[selected_indices[5]],
        }
    }

    /// Create a deterministic GREASE generator (for testing)
    #[cfg(test)]
    pub fn deterministic() -> Self {
        Self {
            cipher_suite_grease: GREASE_VALUES[0],
            group_grease: GREASE_VALUES[1],
            extension_grease: GREASE_VALUES[2],
            version_grease: GREASE_VALUES[3],
            psk_mode_grease: 0x0A,
            signature_algorithm_grease: GREASE_VALUES[4],
        }
    }

    /// Get GREASE cipher suite value
    ///
    /// Should be inserted at a random position in the cipher suite list.
    pub fn cipher_suite(&self) -> u16 {
        self.cipher_suite_grease
    }

    /// Get GREASE named group value
    ///
    /// Should be inserted at a random position in the supported groups list.
    pub fn named_group(&self) -> u16 {
        self.group_grease
    }

    /// Get GREASE extension type
    ///
    /// Should be inserted with empty data as an extension.
    pub fn extension_type(&self) -> u16 {
        self.extension_grease
    }

    /// Get GREASE protocol version
    ///
    /// Can be used in supported_versions extension.
    pub fn protocol_version(&self) -> u16 {
        self.version_grease
    }

    /// Get GREASE PSK key exchange mode
    ///
    /// Should be inserted in psk_key_exchange_modes extension.
    pub fn psk_key_exchange_mode(&self) -> u8 {
        self.psk_mode_grease
    }

    /// Get GREASE signature algorithm
    ///
    /// Should be inserted in signature_algorithms extension.
    pub fn signature_algorithm(&self) -> u16 {
        self.signature_algorithm_grease
    }

    /// Check if a value is a GREASE value
    ///
    /// This is useful for implementations to ignore GREASE values from peers.
    pub fn is_grease_value(value: u16) -> bool {
        GREASE_VALUES.contains(&value)
    }

    /// Check if a byte is a GREASE value (for single-byte fields)
    pub fn is_grease_byte(value: u8) -> bool {
        (value & 0x0F) == 0x0A
    }

    /// Get a random GREASE value
    pub fn random_grease() -> u16 {
        let mut rng = rand::thread_rng();
        GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())]
    }
}

impl Default for GreaseGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for GREASE insertion
#[derive(Debug, Clone, Copy)]
pub struct GreaseConfig {
    /// Enable GREASE for cipher suites
    pub cipher_suites: bool,

    /// Enable GREASE for named groups
    pub named_groups: bool,

    /// Enable GREASE for extensions
    pub extensions: bool,

    /// Enable GREASE for protocol versions
    pub versions: bool,

    /// Enable GREASE for PSK key exchange modes
    pub psk_modes: bool,

    /// Enable GREASE for signature algorithms
    pub signature_algorithms: bool,
}

impl GreaseConfig {
    /// Enable all GREASE features (recommended for clients)
    pub fn all() -> Self {
        Self {
            cipher_suites: true,
            named_groups: true,
            extensions: true,
            versions: true,
            psk_modes: true,
            signature_algorithms: true,
        }
    }

    /// Disable all GREASE features
    pub fn none() -> Self {
        Self {
            cipher_suites: false,
            named_groups: false,
            extensions: false,
            versions: false,
            psk_modes: false,
            signature_algorithms: false,
        }
    }

    /// Conservative GREASE (only widely supported fields)
    pub fn conservative() -> Self {
        Self {
            cipher_suites: true,
            named_groups: true,
            extensions: true,
            versions: false,
            psk_modes: false,
            signature_algorithms: true,
        }
    }
}

impl Default for GreaseConfig {
    fn default() -> Self {
        Self::all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_values_pattern() {
        // All GREASE values should match the pattern 0x?A?A
        for value in GREASE_VALUES.iter() {
            assert_eq!(
                value & 0x0F0F,
                0x0A0A,
                "GREASE value {:04X} doesn't match pattern",
                value
            );
        }
    }

    #[test]
    fn test_grease_generator_deterministic() {
        let grease = GreaseGenerator::deterministic();

        assert_eq!(grease.cipher_suite(), 0x0A0A);
        assert_eq!(grease.named_group(), 0x1A1A);
        assert_eq!(grease.extension_type(), 0x2A2A);
        assert_eq!(grease.protocol_version(), 0x3A3A);
        assert_eq!(grease.psk_key_exchange_mode(), 0x0A);
        assert_eq!(grease.signature_algorithm(), 0x4A4A);
    }

    #[test]
    fn test_grease_generator_random() {
        let grease1 = GreaseGenerator::new();
        let grease2 = GreaseGenerator::new();

        // All values should be valid GREASE values
        assert!(GreaseGenerator::is_grease_value(grease1.cipher_suite()));
        assert!(GreaseGenerator::is_grease_value(grease1.named_group()));
        assert!(GreaseGenerator::is_grease_value(grease1.extension_type()));
        assert!(GreaseGenerator::is_grease_value(grease1.protocol_version()));
        assert!(GreaseGenerator::is_grease_value(
            grease1.signature_algorithm()
        ));

        // Two different generators might have different values (not guaranteed but likely)
        // Just verify they're all valid GREASE values
        assert!(GreaseGenerator::is_grease_value(grease2.cipher_suite()));
        assert!(GreaseGenerator::is_grease_value(grease2.named_group()));
    }

    #[test]
    fn test_is_grease_value() {
        // Valid GREASE values
        assert!(GreaseGenerator::is_grease_value(0x0A0A));
        assert!(GreaseGenerator::is_grease_value(0x1A1A));
        assert!(GreaseGenerator::is_grease_value(0xFAFA));

        // Invalid GREASE values
        assert!(!GreaseGenerator::is_grease_value(0x0000));
        assert!(!GreaseGenerator::is_grease_value(0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(!GreaseGenerator::is_grease_value(0x0A0B)); // Close but wrong pattern
    }

    #[test]
    fn test_is_grease_byte() {
        // Valid GREASE bytes
        assert!(GreaseGenerator::is_grease_byte(0x0A));
        assert!(GreaseGenerator::is_grease_byte(0x1A));
        assert!(GreaseGenerator::is_grease_byte(0xFA));

        // Invalid GREASE bytes
        assert!(!GreaseGenerator::is_grease_byte(0x00));
        assert!(!GreaseGenerator::is_grease_byte(0x01));
        assert!(!GreaseGenerator::is_grease_byte(0x0B));
    }

    #[test]
    fn test_random_grease() {
        for _ in 0..100 {
            let value = GreaseGenerator::random_grease();
            assert!(GreaseGenerator::is_grease_value(value));
        }
    }

    #[test]
    fn test_grease_config() {
        let all = GreaseConfig::all();
        assert!(all.cipher_suites);
        assert!(all.named_groups);
        assert!(all.extensions);
        assert!(all.versions);
        assert!(all.psk_modes);
        assert!(all.signature_algorithms);

        let none = GreaseConfig::none();
        assert!(!none.cipher_suites);
        assert!(!none.named_groups);
        assert!(!none.extensions);

        let conservative = GreaseConfig::conservative();
        assert!(conservative.cipher_suites);
        assert!(conservative.named_groups);
        assert!(!conservative.versions);
    }

    #[test]
    fn test_grease_values_are_unique() {
        use std::collections::HashSet;
        let unique: HashSet<u16> = GREASE_VALUES.iter().copied().collect();
        assert_eq!(
            unique.len(),
            GREASE_VALUES.len(),
            "GREASE values should be unique"
        );
    }

    #[test]
    fn test_grease_values_count() {
        assert_eq!(
            GREASE_VALUES.len(),
            16,
            "Should have exactly 16 GREASE values"
        );
    }
}
