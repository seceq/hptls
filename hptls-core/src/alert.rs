//! TLS alert protocol.

use crate::error::{AlertDescription, Error, Result};

/// Alert level (RFC 8446 Section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AlertLevel {
    /// Warning (1) - Not used in TLS 1.3 except for close_notify
    Warning = 1,

    /// Fatal (2) - All alerts except close_notify and user_canceled
    Fatal = 2,
}

impl AlertLevel {
    /// Create from wire format (u8).
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(AlertLevel::Warning),
            2 => Some(AlertLevel::Fatal),
            _ => None,
        }
    }

    /// Convert to wire format (u8).
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// TLS alert message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    /// Alert level
    pub level: AlertLevel,

    /// Alert description
    pub description: AlertDescription,
}

impl Alert {
    /// Create a new alert.
    pub fn new(level: AlertLevel, description: AlertDescription) -> Self {
        Self { level, description }
    }

    /// Create a fatal alert.
    pub fn fatal(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }

    /// Create a close_notify alert.
    pub fn close_notify() -> Self {
        Self {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        }
    }

    /// Encode the alert to bytes.
    pub fn encode(&self) -> [u8; 2] {
        [self.level.to_u8(), self.description.to_u8()]
    }

    /// Decode an alert from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::InvalidMessage("Alert too short".into()));
        }

        let level = AlertLevel::from_u8(data[0])
            .ok_or_else(|| Error::InvalidMessage("Invalid alert level".into()))?;

        let description = AlertDescription::from_u8(data[1])
            .ok_or_else(|| Error::InvalidMessage("Invalid alert description".into()))?;

        Ok(Self { level, description })
    }

    /// Check if this alert is fatal.
    pub fn is_fatal(&self) -> bool {
        self.level == AlertLevel::Fatal || self.description.is_fatal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_encode_decode() {
        let alert = Alert::fatal(AlertDescription::HandshakeFailure);
        let encoded = alert.encode();

        let decoded = Alert::decode(&encoded).unwrap();
        assert_eq!(decoded.level, AlertLevel::Fatal);
        assert_eq!(decoded.description, AlertDescription::HandshakeFailure);
        assert!(decoded.is_fatal());
    }

    #[test]
    fn test_close_notify() {
        let alert = Alert::close_notify();
        assert_eq!(alert.level, AlertLevel::Warning);
        assert_eq!(alert.description, AlertDescription::CloseNotify);
        assert!(!alert.is_fatal());
    }

    #[test]
    fn test_invalid_alert() {
        let result = Alert::decode(&[255, 0]);
        assert!(result.is_err());
    }
}
