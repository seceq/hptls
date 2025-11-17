//! NewSessionTicket message (RFC 8446 Section 4.6.1).

use crate::error::{Error, Result};
use crate::extensions::Extensions;
use bytes::{Buf, BufMut, BytesMut};

/// NewSessionTicket message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSessionTicket {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub extensions: Extensions,
}

impl NewSessionTicket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        buf.put_u32(self.ticket_lifetime);
        buf.put_u32(self.ticket_age_add);
        if self.ticket_nonce.len() > 255 {
            return Err(Error::InvalidMessage("Nonce too long".into()));
        }
        buf.put_u8(self.ticket_nonce.len() as u8);
        buf.put_slice(&self.ticket_nonce);
        if self.ticket.len() > 65535 {
            return Err(Error::InvalidMessage("Ticket too large".into()));
        }
        buf.put_u16(self.ticket.len() as u16);
        buf.put_slice(&self.ticket);
        buf.put_slice(&self.extensions.encode());
        Ok(buf.to_vec())
    }

    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.len() < 13 {
            return Err(Error::InvalidMessage("NewSessionTicket too short".into()));
        }
        let ticket_lifetime = data.get_u32();
        let ticket_age_add = data.get_u32();
        let nonce_len = data.get_u8() as usize;
        if data.len() < nonce_len {
            return Err(Error::InvalidMessage("Incomplete nonce".into()));
        }
        let ticket_nonce = data[..nonce_len].to_vec();
        data.advance(nonce_len);
        let ticket_len = data.get_u16() as usize;
        if data.len() < ticket_len {
            return Err(Error::InvalidMessage("Incomplete ticket".into()));
        }
        let ticket = data[..ticket_len].to_vec();
        data.advance(ticket_len);
        let extensions = Extensions::decode(data)?;
        Ok(Self {
            ticket_lifetime,
            ticket_age_add,
            ticket_nonce,
            ticket,
            extensions,
        })
    }
}
