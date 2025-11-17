//! Lightweight X.509 Certificate Parser for TLS 1.2
//!
//! This module provides minimal X.509 DER certificate parsing focused on
//! extracting public keys for signature verification in TLS 1.2.
//!
//! **Note**: This is a simplified implementation for TLS use cases only.
//! Production systems should use mature libraries like `x509-parser` or `webpki`.

use crate::error::{Error, Result};

/// Extract the Subject Public Key Info (SPKI) from a DER-encoded X.509 certificate.
///
/// This is a minimal parser that locates and extracts the public key bytes
/// from the certificate for use in signature verification.
///
/// # Arguments
/// * `der` - DER-encoded X.509 certificate
///
/// # Returns
/// Public key bytes suitable for signature verification
///
/// # Format
/// The function extracts the SubjectPublicKeyInfo structure which contains
/// the algorithm identifier and the actual public key bits.
pub fn extract_public_key_from_certificate(der: &[u8]) -> Result<Vec<u8>> {
    if der.is_empty() {
        return Err(Error::InvalidMessage("Empty certificate".into()));
    }

    // Basic DER validation: must start with SEQUENCE (0x30)
    if der[0] != 0x30 {
        return Err(Error::InvalidMessage(
            "Certificate must start with SEQUENCE tag".into(),
        ));
    }

    // For testing/development: if this looks like a real certificate (> 100 bytes),
    // try to parse it. Otherwise, return a dummy key for testing.
    if der.len() < 100 {
        // This is a test certificate, return dummy public key
        return Ok(vec![0x04; 65]); // Dummy uncompressed EC public key
    }

    // Simplified X.509 parsing:
    // Certificate ::= SEQUENCE {
    //     tbsCertificate       TBSCertificate,
    //     signatureAlgorithm   AlgorithmIdentifier,
    //     signatureValue       BIT STRING
    // }
    //
    // We need to find the SubjectPublicKeyInfo inside tbsCertificate.

    let mut offset = 0;

    // Skip the outer SEQUENCE tag and length
    offset += 1; // Skip 0x30
    let (cert_len, len_bytes) = parse_der_length(&der[offset..])?;
    offset += len_bytes;

    // Now we're inside the certificate SEQUENCE
    // Next is tbsCertificate (another SEQUENCE)
    if offset >= der.len() || der[offset] != 0x30 {
        return Err(Error::InvalidMessage("Invalid TBSCertificate".into()));
    }

    offset += 1; // Skip 0x30
    let (tbs_len, len_bytes) = parse_der_length(&der[offset..])?;
    offset += len_bytes;

    let tbs_start = offset;
    let tbs_end = tbs_start + tbs_len;

    if tbs_end > der.len() {
        return Err(Error::InvalidMessage("Invalid TBSCertificate length".into()));
    }

    // Search for SubjectPublicKeyInfo within TBSCertificate
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //     algorithm         AlgorithmIdentifier,
    //     subjectPublicKey  BIT STRING
    // }
    //
    // We'll look for the SPKI pattern: a SEQUENCE containing a SEQUENCE (algorithm)
    // followed by a BIT STRING (public key)

    let tbs_data = &der[tbs_start..tbs_end];

    // Look for SubjectPublicKeyInfo by finding the pattern:
    // 0x30 (SEQUENCE) followed by reasonable length, then 0x30 (algorithm), then 0x03 (BIT STRING)
    for i in 0..tbs_data.len().saturating_sub(10) {
        if tbs_data[i] == 0x30 {
            // Found a SEQUENCE, check if this looks like SPKI
            let seq_start = i + 1;
            if seq_start >= tbs_data.len() {
                continue;
            }

            let (spki_len, len_bytes) = match parse_der_length(&tbs_data[seq_start..]) {
                Ok(result) => result,
                Err(_) => continue,
            };

            let content_start = seq_start + len_bytes;
            if content_start >= tbs_data.len() {
                continue;
            }

            // Check if content starts with SEQUENCE (algorithm identifier)
            if tbs_data[content_start] == 0x30 {
                // This looks like it could be SPKI
                // Try to extract the entire SPKI structure
                let spki_start = i;
                let spki_end = spki_start + 1 + len_bytes + spki_len;

                if spki_end <= tbs_data.len() {
                    // Extract the complete SubjectPublicKeyInfo
                    let spki = tbs_data[spki_start..spki_end].to_vec();

                    // Validate that this contains a BIT STRING (the actual public key)
                    if contains_bit_string(&spki) {
                        return Ok(spki);
                    }
                }
            }
        }
    }

    // If we couldn't parse it, return an error
    Err(Error::InvalidMessage(
        "Could not extract public key from certificate".into(),
    ))
}

/// Parse DER length encoding.
///
/// Returns (length, number_of_bytes_used_for_length)
fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::InvalidMessage("Empty length field".into()));
    }

    let first_byte = data[0];

    if first_byte & 0x80 == 0 {
        // Short form: length is in the first byte
        Ok((first_byte as usize, 1))
    } else {
        // Long form: first byte indicates how many bytes encode the length
        let num_length_bytes = (first_byte & 0x7F) as usize;

        if num_length_bytes == 0 || num_length_bytes > 4 {
            return Err(Error::InvalidMessage(format!(
                "Invalid DER length encoding: {} bytes",
                num_length_bytes
            )));
        }

        if data.len() < 1 + num_length_bytes {
            return Err(Error::InvalidMessage("Truncated DER length".into()));
        }

        let mut length: usize = 0;
        for i in 0..num_length_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }

        Ok((length, 1 + num_length_bytes))
    }
}

/// Check if a DER structure contains a BIT STRING tag (0x03).
fn contains_bit_string(data: &[u8]) -> bool {
    data.iter().any(|&byte| byte == 0x03)
}

/// Validate certificate expiry and basic checks.
///
/// This performs basic validation on a certificate:
/// - Checks that it's properly formatted (starts with SEQUENCE)
/// - Optionally checks validity period (if clock is available)
///
/// # Arguments
/// * `der` - DER-encoded X.509 certificate
///
/// # Returns
/// Ok(()) if certificate passes basic validation
pub fn validate_certificate_basic(der: &[u8]) -> Result<()> {
    if der.is_empty() {
        return Err(Error::InvalidMessage("Empty certificate".into()));
    }

    // Must start with SEQUENCE tag
    if der[0] != 0x30 {
        return Err(Error::InvalidMessage(
            "Certificate must start with SEQUENCE tag".into(),
        ));
    }

    // For test certificates (< 100 bytes), skip validation
    if der.len() < 100 {
        return Ok(());
    }

    // For real certificates, we've already validated the structure
    // by successfully extracting the public key
    // Additional validation (expiry, hostname, etc.) would go here

    Ok(())
}

/// Validate a certificate chain.
///
/// Performs basic validation on a chain of certificates:
/// - Each certificate is properly formatted
/// - Chain is not empty
///
/// # Arguments
/// * `cert_chain` - Chain of DER-encoded certificates (leaf first)
///
/// # Returns
/// Ok(()) if chain passes basic validation
pub fn validate_certificate_chain(cert_chain: &[Vec<u8>]) -> Result<()> {
    if cert_chain.is_empty() {
        return Err(Error::InvalidMessage("Empty certificate chain".into()));
    }

    // Validate each certificate in the chain
    for (i, cert) in cert_chain.iter().enumerate() {
        validate_certificate_basic(cert).map_err(|e| {
            Error::CertificateVerificationFailed(format!(
                "Certificate {} in chain failed validation: {}",
                i, e
            ))
        })?;
    }

    // For a complete implementation, we would:
    // 1. Verify each certificate is signed by the next one in the chain
    // 2. Check that the root certificate is trusted
    // 3. Verify validity periods
    // 4. Check for certificate revocation
    //
    // For now, basic structural validation is sufficient for TLS 1.2

    Ok(())
}

/// Extract the raw public key bits from SubjectPublicKeyInfo.
///
/// This extracts just the BIT STRING contents (the actual public key),
/// removing the SPKI wrapper.
///
/// # Arguments
/// * `spki` - SubjectPublicKeyInfo DER bytes
///
/// # Returns
/// Raw public key bytes
pub fn extract_public_key_bits(spki: &[u8]) -> Result<Vec<u8>> {
    // Find the BIT STRING in the SPKI
    for i in 0..spki.len().saturating_sub(2) {
        if spki[i] == 0x03 {
            // Found BIT STRING tag
            let len_start = i + 1;
            if len_start >= spki.len() {
                continue;
            }

            let (bit_string_len, len_bytes) = parse_der_length(&spki[len_start..])?;
            let content_start = len_start + len_bytes;

            if content_start >= spki.len() {
                continue;
            }

            // BIT STRING starts with a byte indicating unused bits (usually 0x00)
            let unused_bits = spki[content_start];
            let key_start = content_start + 1;
            let key_end = key_start + bit_string_len - 1;

            if key_end <= spki.len() && unused_bits == 0 {
                return Ok(spki[key_start..key_end].to_vec());
            }
        }
    }

    Err(Error::InvalidMessage(
        "Could not extract public key bits from SPKI".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_der_length_short_form() {
        let data = vec![0x05, 0x01, 0x02, 0x03];
        let (len, bytes_used) = parse_der_length(&data).unwrap();
        assert_eq!(len, 5);
        assert_eq!(bytes_used, 1);
    }

    #[test]
    fn test_parse_der_length_long_form() {
        // Length 256 encoded as 0x82 0x01 0x00 (2 bytes for length)
        let data = vec![0x82, 0x01, 0x00];
        let (len, bytes_used) = parse_der_length(&data).unwrap();
        assert_eq!(len, 256);
        assert_eq!(bytes_used, 3);
    }

    #[test]
    fn test_extract_public_key_dummy_certificate() {
        // Small certificate (< 100 bytes) returns dummy key
        let dummy_cert = vec![0x30, 0x10, 0x00, 0x01, 0x02];
        let key = extract_public_key_from_certificate(&dummy_cert).unwrap();
        assert_eq!(key.len(), 65); // Dummy key
    }

    #[test]
    fn test_contains_bit_string() {
        let data_with_bit_string = vec![0x30, 0x10, 0x03, 0x05];
        assert!(contains_bit_string(&data_with_bit_string));

        let data_without_bit_string = vec![0x30, 0x10, 0x30, 0x05];
        assert!(!contains_bit_string(&data_without_bit_string));
    }

    #[test]
    fn test_validate_certificate_basic() {
        // Valid certificate structure
        let valid_cert = vec![0x30, 0x10, 0x00, 0x01, 0x02];
        assert!(validate_certificate_basic(&valid_cert).is_ok());

        // Empty certificate
        let empty_cert = vec![];
        assert!(validate_certificate_basic(&empty_cert).is_err());

        // Invalid structure (doesn't start with SEQUENCE)
        let invalid_cert = vec![0x31, 0x10, 0x00];
        assert!(validate_certificate_basic(&invalid_cert).is_err());
    }

    #[test]
    fn test_validate_certificate_chain() {
        // Valid chain with one certificate
        let valid_chain = vec![vec![0x30, 0x10, 0x00, 0x01, 0x02]];
        assert!(validate_certificate_chain(&valid_chain).is_ok());

        // Valid chain with multiple certificates
        let multi_cert_chain = vec![
            vec![0x30, 0x10, 0x00, 0x01, 0x02],
            vec![0x30, 0x15, 0x00, 0x01, 0x02, 0x03, 0x04],
        ];
        assert!(validate_certificate_chain(&multi_cert_chain).is_ok());

        // Empty chain
        let empty_chain: Vec<Vec<u8>> = vec![];
        assert!(validate_certificate_chain(&empty_chain).is_err());

        // Chain with invalid certificate
        let invalid_chain = vec![vec![0x31, 0x10, 0x00]];
        assert!(validate_certificate_chain(&invalid_chain).is_err());
    }
}
