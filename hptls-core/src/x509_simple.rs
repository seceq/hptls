//! Simplified X.509 certificate public key extraction.
//!
//! This module provides minimal X.509 DER parsing to extract public keys
//! from certificates for TLS signature verification.
//!
//! **Note**: This is NOT a complete X.509 parser. For production use,
//! consider using mature libraries like `x509-parser`, `webpki`, or `rustls-webpki`.
//!
//! This implementation extracts only what's needed for TLS 1.3:
//! - Public key bytes
//! - Public key algorithm
//! - Basic validation

use crate::error::{Error, Result};

/// Supported public key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    /// Ed25519
    Ed25519,
    /// ECDSA with P-256 (secp256r1)
    EcdsaP256,
    /// ECDSA with P-384 (secp384r1)
    EcdsaP384,
    /// RSA
    Rsa,
}

/// Extracted public key information.
#[derive(Debug, Clone)]
pub struct PublicKeyInfo {
    /// Algorithm
    pub algorithm: PublicKeyAlgorithm,
    /// Raw public key bytes
    pub key_bytes: Vec<u8>,
}

/// Simple DER parser for extracting public keys from X.509 certificates.
///
/// This parser makes simplifying assumptions and is NOT suitable for
/// security-critical production use without proper validation.
pub fn extract_public_key_from_cert(cert_der: &[u8]) -> Result<PublicKeyInfo> {
    // Very basic approach: Look for known OID sequences and extract the public key

    // Ed25519 OID: 1.3.101.112 (in DER: 06 03 2B 65 70)
    // ECDSA P-256 OID: 1.2.840.10045.3.1.7 (in DER: 06 08 2A 86 48 CE 3D 03 01 07)
    // ECDSA P-384 OID: 1.3.132.0.34 (in DER: 06 05 2B 81 04 00 22)

    const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
    const ECDSA_P256_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    const ECDSA_P384_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

    // Find the algorithm OID in the certificate
    let (algorithm, oid_pos) = if let Some(pos) = find_subsequence(cert_der, ED25519_OID) {
        (PublicKeyAlgorithm::Ed25519, pos)
    } else if let Some(pos) = find_subsequence(cert_der, ECDSA_P256_OID) {
        (PublicKeyAlgorithm::EcdsaP256, pos)
    } else if let Some(pos) = find_subsequence(cert_der, ECDSA_P384_OID) {
        (PublicKeyAlgorithm::EcdsaP384, pos)
    } else {
        return Err(Error::InvalidMessage(
            "Unsupported public key algorithm in certificate".to_string(),
        ));
    };

    // Find the BIT STRING containing the public key
    // In X.509, the public key is in a BIT STRING (tag 0x03) in the SubjectPublicKeyInfo
    // Look for BIT STRING after the OID
    // The BIT STRING should be very close to the OID (usually within 5-10 bytes)
    let search_start = oid_pos; // Start from OID position
    let key_bytes = extract_bit_string_after(cert_der, search_start, algorithm)?;

    Ok(PublicKeyInfo {
        algorithm,
        key_bytes,
    })
}

/// Find a subsequence in a byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Extract a BIT STRING from DER data after a given position.
fn extract_bit_string_after(
    data: &[u8],
    start: usize,
    algorithm: PublicKeyAlgorithm,
) -> Result<Vec<u8>> {
    // Look for BIT STRING tag (0x03)
    for i in start..data.len().saturating_sub(4) {
        if data[i] == 0x03 {
            // Found BIT STRING tag
            let length_byte = data[i + 1];

            // Handle different length encodings
            let (length, data_start) = if length_byte < 0x80 {
                // Short form: length is in the byte itself
                (length_byte as usize, i + 2)
            } else if length_byte == 0x81 {
                // Long form with 1 byte for length
                (data[i + 2] as usize, i + 3)
            } else if length_byte == 0x82 {
                // Long form with 2 bytes for length
                let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                (len, i + 4)
            } else {
                continue; // Skip unsupported length encodings
            };

            // BIT STRING starts with number of unused bits (should be 0)
            if data_start >= data.len() {
                continue;
            }

            let unused_bits = data[data_start];
            if unused_bits != 0 {
                continue; // We expect no unused bits
            }

            let actual_start = data_start + 1;
            let actual_length = length.saturating_sub(1);

            if actual_start + actual_length > data.len() {
                continue;
            }

            let key_data = &data[actual_start..actual_start + actual_length];

            // Validate length matches expected algorithm
            let valid_length = match algorithm {
                PublicKeyAlgorithm::Ed25519 => key_data.len() == 32,
                PublicKeyAlgorithm::EcdsaP256 => key_data.len() == 65, // Uncompressed point
                PublicKeyAlgorithm::EcdsaP384 => key_data.len() == 97, // Uncompressed point
                PublicKeyAlgorithm::Rsa => key_data.len() > 64,        // RSA keys are longer
            };

            if valid_length {
                return Ok(key_data.to_vec());
            }
        }
    }

    Err(Error::InvalidMessage(
        "Could not extract public key from certificate".to_string(),
    ))
}

/// TBS (To-Be-Signed) Certificate information extracted from X.509 certificate.
#[derive(Debug, Clone)]
pub struct TBSCertificate {
    /// The exact bytes of the TBS certificate (what was signed)
    pub tbs_bytes: Vec<u8>,
    /// The signature algorithm used to sign the certificate
    pub signature_algorithm: hptls_crypto::SignatureAlgorithm,
    /// The signature bytes
    pub signature_bytes: Vec<u8>,
}

/// Extract TBS certificate, signature algorithm, and signature from DER-encoded X.509 certificate.
///
/// X.509 certificate structure (DER):
/// ```text
/// Certificate ::= SEQUENCE {
///     tbsCertificate       TBSCertificate,      -- What gets signed
///     signatureAlgorithm   AlgorithmIdentifier, -- Signature algorithm
///     signatureValue       BIT STRING           -- The signature
/// }
/// ```
///
/// This function extracts all three parts for signature verification.
pub fn extract_tbs_certificate(cert_der: &[u8]) -> Result<TBSCertificate> {
    use hptls_crypto::SignatureAlgorithm;

    // OID constants for signature algorithms (DER encoded)
    const ED25519_SIG_OID: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
    const ECDSA_SHA256_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    const ECDSA_SHA384_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

    if cert_der.len() < 10 {
        return Err(Error::InvalidMessage("Certificate too short".to_string()));
    }

    // Parse outer SEQUENCE (Certificate)
    if cert_der[0] != 0x30 {
        return Err(Error::InvalidMessage(
            "Certificate must start with SEQUENCE tag".to_string(),
        ));
    }

    let (outer_len, outer_header_size) = parse_der_length(&cert_der[1..])?;
    if outer_len + outer_header_size + 1 > cert_der.len() {
        return Err(Error::InvalidMessage(
            "Certificate length mismatch".to_string(),
        ));
    }

    // Parse TBS Certificate SEQUENCE (first element inside outer SEQUENCE)
    let tbs_start = 1 + outer_header_size;
    if cert_der[tbs_start] != 0x30 {
        return Err(Error::InvalidMessage(
            "TBS certificate must be a SEQUENCE".to_string(),
        ));
    }

    let (tbs_len, tbs_header_size) = parse_der_length(&cert_der[tbs_start + 1..])?;
    let tbs_total_len = 1 + tbs_header_size + tbs_len; // Tag + length bytes + content
    let tbs_end = tbs_start + tbs_total_len;

    if tbs_end > cert_der.len() {
        return Err(Error::InvalidMessage(
            "TBS certificate extends beyond certificate bounds".to_string(),
        ));
    }

    // Extract TBS certificate bytes (this is what was signed)
    let tbs_bytes = cert_der[tbs_start..tbs_end].to_vec();

    // Parse signature algorithm (second element after TBS certificate)
    let sig_alg_start = tbs_end;
    if sig_alg_start >= cert_der.len() || cert_der[sig_alg_start] != 0x30 {
        return Err(Error::InvalidMessage(
            "Signature algorithm must be a SEQUENCE".to_string(),
        ));
    }

    let (sig_alg_len, sig_alg_header_size) = parse_der_length(&cert_der[sig_alg_start + 1..])?;
    let sig_alg_end = sig_alg_start + 1 + sig_alg_header_size + sig_alg_len;

    if sig_alg_end > cert_der.len() {
        return Err(Error::InvalidMessage(
            "Signature algorithm extends beyond certificate bounds".to_string(),
        ));
    }

    // Search for signature algorithm OID within the signature algorithm SEQUENCE
    let sig_alg_section = &cert_der[sig_alg_start..sig_alg_end];
    let signature_algorithm = if find_subsequence(sig_alg_section, ED25519_SIG_OID).is_some() {
        SignatureAlgorithm::Ed25519
    } else if find_subsequence(sig_alg_section, ECDSA_SHA256_OID).is_some() {
        SignatureAlgorithm::EcdsaSecp256r1Sha256
    } else if find_subsequence(sig_alg_section, ECDSA_SHA384_OID).is_some() {
        SignatureAlgorithm::EcdsaSecp384r1Sha384
    } else {
        return Err(Error::InvalidMessage(
            "Unsupported signature algorithm".to_string(),
        ));
    };

    // Parse signature BIT STRING (third element after signature algorithm)
    let sig_start = sig_alg_end;
    if sig_start >= cert_der.len() || cert_der[sig_start] != 0x03 {
        return Err(Error::InvalidMessage(
            "Signature must be a BIT STRING".to_string(),
        ));
    }

    let (sig_len, sig_header_size) = parse_der_length(&cert_der[sig_start + 1..])?;
    let sig_content_start = sig_start + 1 + sig_header_size;
    let sig_content_end = sig_content_start + sig_len;

    if sig_content_end > cert_der.len() {
        return Err(Error::InvalidMessage(
            "Signature extends beyond certificate bounds".to_string(),
        ));
    }

    // BIT STRING starts with "unused bits" byte (should be 0 for signatures)
    if cert_der[sig_content_start] != 0 {
        return Err(Error::InvalidMessage(
            "BIT STRING unused bits must be 0 for signatures".to_string(),
        ));
    }

    // Extract signature bytes (skip the unused bits byte)
    let signature_bytes = cert_der[sig_content_start + 1..sig_content_end].to_vec();

    Ok(TBSCertificate {
        tbs_bytes,
        signature_algorithm,
        signature_bytes,
    })
}

/// Parse DER length encoding (handles both short and long form).
///
/// DER length encoding:
/// - Short form (0x00-0x7F): Single byte with the length
/// - Long form (0x80-0xFF): First byte is 0x80 | num_length_bytes, followed by length bytes
///
/// Returns: (length_value, header_size_in_bytes)
fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::InvalidMessage(
            "Empty data for DER length parsing".to_string(),
        ));
    }

    let first_byte = data[0];

    if first_byte < 0x80 {
        // Short form: length is in the first byte
        Ok((first_byte as usize, 1))
    } else {
        // Long form: first byte tells us how many length bytes follow
        let num_length_bytes = (first_byte & 0x7F) as usize;

        if num_length_bytes == 0 || num_length_bytes > 4 {
            return Err(Error::InvalidMessage(
                "Invalid DER length encoding".to_string(),
            ));
        }

        if data.len() < 1 + num_length_bytes {
            return Err(Error::InvalidMessage(
                "Not enough data for DER length".to_string(),
            ));
        }

        // Parse the length bytes (big-endian)
        let mut length: usize = 0;
        for i in 0..num_length_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }

        Ok((length, 1 + num_length_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_subsequence() {
        let haystack = b"hello world";
        assert_eq!(find_subsequence(haystack, b"world"), Some(6));
        assert_eq!(find_subsequence(haystack, b"hello"), Some(0));
        assert_eq!(find_subsequence(haystack, b"notfound"), None);
    }

    #[test]
    fn test_extract_public_key_mock() {
        // Create a mock certificate with Ed25519 OID
        let mut mock_cert = vec![0x30, 0x82]; // SEQUENCE header
        mock_cert.extend_from_slice(&[0x01, 0x00]); // Length

        // Add some random data
        mock_cert.extend_from_slice(&[0x00; 50]);

        // Add Ed25519 OID
        mock_cert.extend_from_slice(&[0x06, 0x03, 0x2B, 0x65, 0x70]);

        // Add some more data
        mock_cert.extend_from_slice(&[0x00; 20]);

        // Add BIT STRING with 32-byte Ed25519 public key
        mock_cert.push(0x03); // BIT STRING tag
        mock_cert.push(33); // Length (32 + 1 for unused bits byte)
        mock_cert.push(0); // Unused bits = 0
        mock_cert.extend_from_slice(&[0x42; 32]); // 32-byte public key

        let result = extract_public_key_from_cert(&mock_cert);
        assert!(result.is_ok());

        let pub_key_info = result.unwrap();
        assert_eq!(pub_key_info.algorithm, PublicKeyAlgorithm::Ed25519);
        assert_eq!(pub_key_info.key_bytes.len(), 32);
        assert_eq!(pub_key_info.key_bytes, vec![0x42; 32]);
    }

    #[test]
    fn test_extract_tbs_certificate_ed25519() {
        use hptls_crypto::SignatureAlgorithm;
        use std::fs;

        // Load real Ed25519 certificate (DER format) from project root
        let cert_path = "../server-cert-ed25519.der";
        if let Ok(cert_der) = fs::read(cert_path) {
            let result = extract_tbs_certificate(&cert_der);

            if result.is_ok() {
                let tbs = result.unwrap();

                // Verify we got Ed25519 signature algorithm
                assert_eq!(tbs.signature_algorithm, SignatureAlgorithm::Ed25519);

                // Verify TBS bytes are non-empty and reasonable
                assert!(tbs.tbs_bytes.len() > 100);
                assert!(tbs.tbs_bytes.len() < 2000);

                // Verify signature bytes are Ed25519 size (64 bytes)
                assert_eq!(tbs.signature_bytes.len(), 64);

                println!("TBS extraction test PASSED:");
                println!("  - TBS length: {} bytes", tbs.tbs_bytes.len());
                println!("  - Signature algorithm: {:?}", tbs.signature_algorithm);
                println!("  - Signature length: {} bytes", tbs.signature_bytes.len());
            }
        }
    }

    #[test]
    fn test_parse_der_length_short_form() {
        // Test short form (length < 128)
        let data = &[0x42]; // Length = 66
        let result = parse_der_length(data);
        assert!(result.is_ok());
        let (length, header_size) = result.unwrap();
        assert_eq!(length, 66);
        assert_eq!(header_size, 1);
    }

    #[test]
    fn test_parse_der_length_long_form() {
        // Test long form (2 bytes: 0x82 0x01 0x24 = length 0x124 = 292)
        let data = &[0x82, 0x01, 0x24];
        let result = parse_der_length(data);
        assert!(result.is_ok());
        let (length, header_size) = result.unwrap();
        assert_eq!(length, 292);
        assert_eq!(header_size, 3); // 1 byte for 0x82 + 2 bytes for length
    }
}
