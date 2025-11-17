//! TLS connection state management.

use crate::cipher::CipherSuite;
use crate::handshake::{ClientState, ServerState};
use crate::protocol::ProtocolVersion;

/// Connection role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client
    Client,

    /// Server
    Server,
}

/// Connection state.
#[derive(Debug)]
pub struct ConnectionState {
    /// Connection role (client or server)
    pub role: Role,

    /// Negotiated protocol version
    pub version: Option<ProtocolVersion>,

    /// Negotiated cipher suite
    pub cipher_suite: Option<CipherSuite>,

    /// Client state (if client role)
    pub client_state: Option<ClientState>,

    /// Server state (if server role)
    pub server_state: Option<ServerState>,

    /// Session ID
    pub session_id: Vec<u8>,

    /// Early data allowed
    pub early_data_allowed: bool,
}

impl ConnectionState {
    /// Create a new client connection state.
    pub fn new_client() -> Self {
        Self {
            role: Role::Client,
            version: None,
            cipher_suite: None,
            client_state: Some(ClientState::Start),
            server_state: None,
            session_id: Vec::new(),
            early_data_allowed: false,
        }
    }

    /// Create a new server connection state.
    pub fn new_server() -> Self {
        Self {
            role: Role::Server,
            version: None,
            cipher_suite: None,
            client_state: None,
            server_state: Some(ServerState::Start),
            session_id: Vec::new(),
            early_data_allowed: false,
        }
    }

    /// Check if the connection is established.
    pub fn is_connected(&self) -> bool {
        match self.role {
            Role::Client => self.client_state == Some(ClientState::Connected),
            Role::Server => self.server_state == Some(ServerState::Connected),
        }
    }

    /// Check if the connection is in error state.
    pub fn is_error(&self) -> bool {
        match self.role {
            Role::Client => self.client_state == Some(ClientState::Failed),
            Role::Server => self.server_state == Some(ServerState::Failed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_state() {
        let state = ConnectionState::new_client();
        assert_eq!(state.role, Role::Client);
        assert_eq!(state.client_state, Some(ClientState::Start));
        assert!(!state.is_connected());
        assert!(!state.is_error());
    }

    #[test]
    fn test_server_state() {
        let state = ConnectionState::new_server();
        assert_eq!(state.role, Role::Server);
        assert_eq!(state.server_state, Some(ServerState::Start));
        assert!(!state.is_connected());
        assert!(!state.is_error());
    }
}
