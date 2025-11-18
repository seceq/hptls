//! Alert Handling Tests
//!
//! Tests for TLS alert protocol, including:
//! - Sending close_notify alerts
//! - Processing close_notify alerts
//! - Handling fatal alerts
//! - Connection termination

use hptls_core::alert::{Alert, AlertLevel};
use hptls_core::error::AlertDescription;
use hptls_core::handshake::{ClientHandshake, ServerHandshake};

/// Test client sending close_notify alert.
#[test]
fn test_client_send_close_notify() {
    let mut client = ClientHandshake::new();

    let alert = client.send_close_notify();

    assert_eq!(alert.level, AlertLevel::Warning);
    assert_eq!(alert.description, AlertDescription::CloseNotify);
    assert!(!alert.is_fatal());
}

/// Test server sending close_notify alert.
#[test]
fn test_server_send_close_notify() {
    let mut server = ServerHandshake::new(vec![]);

    let alert = server.send_close_notify();

    assert_eq!(alert.level, AlertLevel::Warning);
    assert_eq!(alert.description, AlertDescription::CloseNotify);
    assert!(!alert.is_fatal());
}

/// Test client processing close_notify alert.
#[test]
fn test_client_process_close_notify() {
    let mut client = ClientHandshake::new();
    // Set state to Connected to test state transition
    // (in practice, client would be in Connected state after handshake)

    let alert = Alert::close_notify();
    let result = client.process_close_notify(&alert);

    assert!(result.is_ok());
}

/// Test server processing close_notify alert.
#[test]
fn test_server_process_close_notify() {
    let mut server = ServerHandshake::new(vec![]);

    let alert = Alert::close_notify();
    let result = server.process_close_notify(&alert);

    assert!(result.is_ok());
}

/// Test client rejecting non-close_notify alert in process_close_notify().
#[test]
fn test_client_reject_non_close_notify() {
    let mut client = ClientHandshake::new();

    let alert = Alert::fatal(AlertDescription::HandshakeFailure);
    let result = client.process_close_notify(&alert);

    assert!(result.is_err());
}

/// Test server rejecting non-close_notify alert in process_close_notify().
#[test]
fn test_server_reject_non_close_notify() {
    let mut server = ServerHandshake::new(vec![]);

    let alert = Alert::fatal(AlertDescription::HandshakeFailure);
    let result = server.process_close_notify(&alert);

    assert!(result.is_err());
}

/// Test client processing close_notify in process_alert().
#[test]
fn test_client_process_alert_close_notify() {
    let client = ClientHandshake::new();

    let alert = Alert::close_notify();
    let result = client.process_alert(&alert);

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true); // Should close connection
}

/// Test server processing close_notify in process_alert().
#[test]
fn test_server_process_alert_close_notify() {
    let server = ServerHandshake::new(vec![]);

    let alert = Alert::close_notify();
    let result = server.process_alert(&alert);

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true); // Should close connection
}

/// Test client processing fatal alert.
#[test]
fn test_client_process_fatal_alert() {
    let client = ClientHandshake::new();

    let alert = Alert::fatal(AlertDescription::HandshakeFailure);
    let result = client.process_alert(&alert);

    assert!(result.is_err());
}

/// Test server processing fatal alert.
#[test]
fn test_server_process_fatal_alert() {
    let server = ServerHandshake::new(vec![]);

    let alert = Alert::fatal(AlertDescription::HandshakeFailure);
    let result = server.process_alert(&alert);

    assert!(result.is_err());
}

/// Test all fatal alert types are handled correctly by client.
#[test]
fn test_client_all_fatal_alerts() {
    let client = ClientHandshake::new();

    let fatal_alerts = vec![
        AlertDescription::HandshakeFailure,
        AlertDescription::BadCertificate,
        AlertDescription::CertificateExpired,
        AlertDescription::DecryptError,
        AlertDescription::ProtocolVersion,
        AlertDescription::InternalError,
    ];

    for desc in fatal_alerts {
        let alert = Alert::fatal(desc);
        let result = client.process_alert(&alert);
        assert!(result.is_err(), "Fatal alert {:?} should fail", desc);
    }
}

/// Test all fatal alert types are handled correctly by server.
#[test]
fn test_server_all_fatal_alerts() {
    let server = ServerHandshake::new(vec![]);

    let fatal_alerts = vec![
        AlertDescription::HandshakeFailure,
        AlertDescription::BadCertificate,
        AlertDescription::CertificateExpired,
        AlertDescription::DecryptError,
        AlertDescription::ProtocolVersion,
        AlertDescription::InternalError,
    ];

    for desc in fatal_alerts {
        let alert = Alert::fatal(desc);
        let result = server.process_alert(&alert);
        assert!(result.is_err(), "Fatal alert {:?} should fail", desc);
    }
}

/// Test alert encoding and decoding round-trip.
#[test]
fn test_alert_encode_decode_round_trip() {
    let original = Alert::close_notify();
    let encoded = original.encode();
    let decoded = Alert::decode(&encoded).unwrap();

    assert_eq!(decoded.level, original.level);
    assert_eq!(decoded.description, original.description);
}

/// Test fatal alert encoding.
#[test]
fn test_fatal_alert_encoding() {
    let alert = Alert::fatal(AlertDescription::HandshakeFailure);
    let encoded = alert.encode();

    assert_eq!(encoded[0], AlertLevel::Fatal as u8);
    assert_eq!(encoded[1], AlertDescription::HandshakeFailure as u8);
}

/// Test close_notify is not fatal.
#[test]
fn test_close_notify_not_fatal() {
    let alert = Alert::close_notify();
    assert!(!alert.is_fatal());
}

/// Test fatal alerts are identified correctly.
#[test]
fn test_fatal_alerts_identification() {
    let fatal = Alert::fatal(AlertDescription::HandshakeFailure);
    assert!(fatal.is_fatal());

    let bad_cert = Alert::fatal(AlertDescription::BadCertificate);
    assert!(bad_cert.is_fatal());
}

/// Test client connection state management during close.
#[test]
fn test_client_connection_state_transitions() {
    use hptls_core::handshake::ClientState;

    let mut client = ClientHandshake::new();

    // Initially not closing or closed
    assert!(!client.is_closing());
    assert!(!client.is_closed());

    // Send close_notify → Closing state
    let _alert = client.send_close_notify();
    assert!(client.is_closing());
    assert!(!client.is_closed());
    assert_eq!(client.state(), ClientState::Closing);

    // Complete close → Closed state
    client.complete_close();
    assert!(!client.is_closing()); // No longer "closing", now "closed"
    assert!(client.is_closed());
    assert_eq!(client.state(), ClientState::Closed);
}

/// Test server connection state management during close.
#[test]
fn test_server_connection_state_transitions() {
    use hptls_core::handshake::ServerState;

    let mut server = ServerHandshake::new(vec![]);

    // Initially not closing or closed
    assert!(!server.is_closing());
    assert!(!server.is_closed());

    // Send close_notify → Closing state
    let _alert = server.send_close_notify();
    assert!(server.is_closing());
    assert!(!server.is_closed());
    assert_eq!(server.state(), ServerState::Closing);

    // Complete close → Closed state
    server.complete_close();
    assert!(!server.is_closing()); // No longer "closing", now "closed"
    assert!(server.is_closed());
    assert_eq!(server.state(), ServerState::Closed);
}
