//! EndOfEarlyData message (RFC 8446 Section 4.5)
//!
//! The EndOfEarlyData message indicates the end of 0-RTT early data
//! from the client. After receiving this message (and verifying the
//! Finished message), the server can start sending encrypted handshake
//! messages and application data.
//!
//! # Protocol Flow
//!
//! ```text
//! Client                                               Server
//!
//! ClientHello
//!   + early_data
//!   + key_share
//!   + psk_key_exchange_modes
//!   + pre_shared_key
//! (Application Data*)        -------->
//!                                             ServerHello
//!                                          + pre_shared_key
//!                                                + key_share
//!                                   {EncryptedExtensions}
//!                                             + early_data
//!                                            {Certificate*}
//!                                      {CertificateVerify*}
//!                                               {Finished}
//!                            <--------
//! {EndOfEarlyData}           -------->   // THIS MESSAGE
//! [Application Data]         <------->   [Application Data]
//! ```
//!
//! # Message Structure
//!
//! The EndOfEarlyData message has no content (empty body).
//! Its presence alone signals the end of early data.

use crate::error::{Error, Result};

/// EndOfEarlyData message.
///
/// This message is sent by the client to indicate that all 0-RTT
/// early data has been sent. After this message, the connection
/// transitions to using handshake traffic keys.
///
/// # RFC 8446 Section 4.5
///
/// ```text
/// struct {} EndOfEarlyData;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndOfEarlyData;

impl EndOfEarlyData {
    /// Create a new EndOfEarlyData message.
    pub fn new() -> Self {
        Self
    }

    /// Encode to bytes.
    ///
    /// Since EndOfEarlyData has no content, this returns an empty vector.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    /// Decode from bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Should be empty for a valid EndOfEarlyData message
    ///
    /// # Returns
    ///
    /// Returns `Ok(EndOfEarlyData)` if data is empty, error otherwise.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if !data.is_empty() {
            return Err(Error::InvalidMessage(
                "EndOfEarlyData must have empty body".into(),
            ));
        }
        Ok(Self)
    }
}

impl Default for EndOfEarlyData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_of_early_data_new() {
        let eoed = EndOfEarlyData::new();
        assert_eq!(eoed, EndOfEarlyData);
    }

    #[test]
    fn test_end_of_early_data_encode() {
        let eoed = EndOfEarlyData::new();
        let encoded = eoed.encode().unwrap();
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_end_of_early_data_decode_empty() {
        let data = vec![];
        let eoed = EndOfEarlyData::decode(&data).unwrap();
        assert_eq!(eoed, EndOfEarlyData);
    }

    #[test]
    fn test_end_of_early_data_decode_non_empty() {
        let data = vec![0x01, 0x02];
        let result = EndOfEarlyData::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_end_of_early_data_encode_decode_roundtrip() {
        let eoed = EndOfEarlyData::new();
        let encoded = eoed.encode().unwrap();
        let decoded = EndOfEarlyData::decode(&encoded).unwrap();
        assert_eq!(eoed, decoded);
    }

    #[test]
    fn test_end_of_early_data_default() {
        let eoed = EndOfEarlyData::default();
        assert_eq!(eoed, EndOfEarlyData::new());
    }
}
