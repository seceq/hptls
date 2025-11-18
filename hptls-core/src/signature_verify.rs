//! TLS 1.3 Signature Verification
//!
//! This module implements signature verification for CertificateVerify messages
//! as specified in RFC 8446 Section 4.4.3.
//!
//! # Digital Signatures
//!
//! TLS 1.3 uses digital signatures to prove possession of the private key
//! corresponding to the certificate's public key. The signature is computed
//! over a specially formatted message that includes the handshake transcript.
//!
//! # Signature Format (RFC 8446 Section 4.4.3)
//!
//! ```text
//! struct {
//!     opaque signature<0..2^16-1>;
//! } CertificateVerify;
//! ```
//!
//! The signature is computed over the following structure:
//!
//! ```text
//! "                                " (64 spaces)
//! "TLS 1.3, server CertificateVerify" (or "TLS 1.3, client CertificateVerify")
//! 0x00
//! transcript_hash (Hash of all handshake messages up to this point)
//! ```

use crate::error::{Error, Result};
use hptls_crypto::{CryptoProvider, SignatureAlgorithm};

/// Context string for server CertificateVerify signatures.
const SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// Context string for client CertificateVerify signatures.
const CLIENT_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";

/// Padding for signature messages (64 spaces).
const SIGNATURE_PADDING: [u8; 64] = [0x20; 64];

/// Build the signature message for CertificateVerify.
///
/// # Arguments
///
/// * `transcript_hash` - Hash of all handshake messages up to CertificateVerify
/// * `is_server` - true for server signatures, false for client signatures
///
/// # Returns
///
/// Returns the formatted message to be signed/verified.
///
/// # Format (RFC 8446 Section 4.4.3)
///
/// ```text
/// message = padding || context || 0x00 || transcript_hash
/// where:
///   padding = 64 spaces (0x20)
///   context = "TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify"
/// ```
pub fn build_signature_message(transcript_hash: &[u8], is_server: bool) -> Vec<u8> {
    let context = if is_server {
        SERVER_CONTEXT
    } else {
        CLIENT_CONTEXT
    };

    let mut message = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
    message.extend_from_slice(&SIGNATURE_PADDING);
    message.extend_from_slice(context);
    message.push(0x00);
    message.extend_from_slice(transcript_hash);

    message
}

/// Verify a CertificateVerify signature.
///
/// # Arguments
///
/// * `provider` - Crypto provider for signature verification
/// * `algorithm` - Signature algorithm used
/// * `public_key` - Public key to verify against (DER-encoded)
/// * `signature` - Signature to verify
/// * `transcript_hash` - Hash of handshake transcript
/// * `is_server` - true if verifying server signature, false for client
///
/// # Returns
///
/// Returns `Ok(())` if signature is valid, error otherwise.
pub fn verify_certificate_verify_signature(
    provider: &dyn CryptoProvider,
    algorithm: SignatureAlgorithm,
    public_key: &[u8],
    signature: &[u8],
    transcript_hash: &[u8],
    is_server: bool,
) -> Result<()> {
    // Build the message that was signed
    let message = build_signature_message(transcript_hash, is_server);

    // Debug logging
    eprintln!("[DEBUG SIG] Signature algorithm: {:?}", algorithm);
    eprintln!("[DEBUG SIG] Public key len: {}", public_key.len());
    eprintln!(
        "[DEBUG SIG] Public key (first 64 bytes): {:02x?}",
        &public_key[..public_key.len().min(64)]
    );
    eprintln!("[DEBUG SIG] Signature len: {}", signature.len());
    eprintln!("[DEBUG SIG] Signature: {:02x?}", signature);
    eprintln!("[DEBUG SIG] Message len: {}", message.len());
    eprintln!(
        "[DEBUG SIG] Message (first 100 bytes): {:02x?}",
        &message[..100.min(message.len())]
    );
    eprintln!("[DEBUG SIG] Transcript hash len: {}", transcript_hash.len());
    eprintln!("[DEBUG SIG] Transcript hash: {:02x?}", transcript_hash);
    eprintln!("[DEBUG SIG] Is server: {}", is_server);

    // Get signature instance from crypto provider
    let sig = provider
        .signature(algorithm)
        .map_err(|e| Error::CryptoError(format!("Failed to get signature handler: {}", e)))?;

    // Verify the signature
    sig.verify(public_key, &message, signature).map_err(|e| {
        eprintln!("[DEBUG SIG] Verification FAILED: {}", e);
        Error::CertificateVerificationFailed(format!("Signature verification failed: {}", e))
    })?;

    eprintln!("[DEBUG SIG] Verification SUCCEEDED!");
    Ok(())
}

/// Create a CertificateVerify signature (for server/client authentication).
///
/// # Arguments
///
/// * `provider` - Crypto provider for signature generation
/// * `algorithm` - Signature algorithm to use
/// * `private_key` - Private key for signing (DER-encoded)
/// * `transcript_hash` - Hash of handshake transcript
/// * `is_server` - true if creating server signature, false for client
///
/// # Returns
///
/// Returns the signature bytes.
pub fn create_certificate_verify_signature(
    provider: &dyn CryptoProvider,
    algorithm: SignatureAlgorithm,
    private_key: &[u8],
    transcript_hash: &[u8],
    is_server: bool,
) -> Result<Vec<u8>> {
    // Build the message to sign
    let message = build_signature_message(transcript_hash, is_server);

    // Get signature instance from crypto provider
    let sig = provider
        .signature(algorithm)
        .map_err(|e| Error::CryptoError(format!("Failed to get signature handler: {}", e)))?;

    // Create the signature
    let signature = sig
        .sign(private_key, &message)
        .map_err(|e| Error::CryptoError(format!("Signature creation failed: {}", e)))?;

    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_server_signature_message() {
        let transcript_hash = vec![0x01, 0x02, 0x03, 0x04];
        let message = build_signature_message(&transcript_hash, true);

        // Check structure
        assert_eq!(message.len(), 64 + SERVER_CONTEXT.len() + 1 + 4);

        // Check padding (first 64 bytes should be spaces)
        assert_eq!(&message[0..64], &SIGNATURE_PADDING);

        // Check context
        assert_eq!(&message[64..64 + SERVER_CONTEXT.len()], SERVER_CONTEXT);

        // Check separator
        assert_eq!(message[64 + SERVER_CONTEXT.len()], 0x00);

        // Check transcript hash
        assert_eq!(&message[64 + SERVER_CONTEXT.len() + 1..], &transcript_hash);
    }

    #[test]
    fn test_build_client_signature_message() {
        let transcript_hash = vec![0xAA, 0xBB, 0xCC];
        let message = build_signature_message(&transcript_hash, false);

        // Check context is client context
        assert_eq!(&message[64..64 + CLIENT_CONTEXT.len()], CLIENT_CONTEXT);

        // Check transcript hash
        assert_eq!(&message[64 + CLIENT_CONTEXT.len() + 1..], &transcript_hash);
    }

    #[test]
    fn test_server_client_messages_differ() {
        let transcript_hash = vec![0x01, 0x02, 0x03];
        let server_message = build_signature_message(&transcript_hash, true);
        let client_message = build_signature_message(&transcript_hash, false);

        // Messages should be different due to different context strings
        assert_ne!(server_message, client_message);

        // But should have same length of padding and transcript
        assert_eq!(server_message[0..64], client_message[0..64]); // Same padding
        assert_eq!(
            &server_message[server_message.len() - 3..],
            &client_message[client_message.len() - 3..]
        ); // Same transcript
    }

    #[test]
    fn test_signature_message_rfc_format() {
        // Verify the exact format from RFC 8446 Section 4.4.3
        let transcript_hash = vec![0xFF; 32]; // 32-byte hash
        let message = build_signature_message(&transcript_hash, true);

        // Total length: 64 (padding) + 33 (context) + 1 (separator) + 32 (hash) = 130
        assert_eq!(message.len(), 130);

        // Verify padding is exactly 64 spaces
        assert!(message[0..64].iter().all(|&b| b == 0x20));

        // Verify context string
        let context_str = std::str::from_utf8(&message[64..97]).unwrap();
        assert_eq!(context_str, "TLS 1.3, server CertificateVerify");

        // Verify separator
        assert_eq!(message[97], 0x00);

        // Verify hash
        assert_eq!(&message[98..130], &vec![0xFF; 32][..]);
    }
}
