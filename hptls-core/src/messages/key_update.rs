//! KeyUpdate message (RFC 8446 Section 4.6.3).

use crate::error::{Error, Result};

/// KeyUpdate request type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyUpdateRequest {
    UpdateNotRequested = 0,
    UpdateRequested = 1,
}

/// KeyUpdate message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUpdate {
    pub request_update: KeyUpdateRequest,
}

impl KeyUpdate {
    pub fn new(request_update: KeyUpdateRequest) -> Self {
        Self { request_update }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(vec![self.request_update as u8])
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidMessage("KeyUpdate too short".into()));
        }
        let request_update = match data[0] {
            0 => KeyUpdateRequest::UpdateNotRequested,
            1 => KeyUpdateRequest::UpdateRequested,
            _ => return Err(Error::InvalidMessage("Invalid KeyUpdateRequest".into())),
        };
        Ok(Self { request_update })
    }
}
