//! Minimal DER (Distinguished Encoding Rules) parser for RSA keys.
//!
//! This module provides just enough ASN.1 DER parsing to handle:
//! - PKCS#8 PrivateKeyInfo (RFC 5208, RFC 5958)
//! - X.509 SubjectPublicKeyInfo (RFC 5280)
//! - RSA key components
//!
//! This is intentionally minimal and focused only on what's needed for TLS.

use num_bigint::BigUint;

/// DER parsing errors
#[derive(Debug)]
pub enum DerError {
    /// Unexpected end of input
    UnexpectedEof,
    /// Invalid tag encountered
    InvalidTag {
        /// Expected tag value
        expected: u8,
        /// Actual tag value found
        got: u8,
    },
    /// Invalid length encoding
    InvalidLength,
    /// Unsupported or invalid data
    InvalidData(String),
}

impl std::fmt::Display for DerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DerError::UnexpectedEof => write!(f, "Unexpected end of DER data"),
            DerError::InvalidTag { expected, got } => {
                write!(f, "Invalid DER tag: expected 0x{:02x}, got 0x{:02x}", expected, got)
            }
            DerError::InvalidLength => write!(f, "Invalid DER length encoding"),
            DerError::InvalidData(msg) => write!(f, "Invalid DER data: {}", msg),
        }
    }
}

impl std::error::Error for DerError {}

/// Result type for DER parsing operations
pub type Result<T> = std::result::Result<T, DerError>;

/// ASN.1 tag values
#[allow(dead_code)]
mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;
}

/// DER decoder with position tracking
#[derive(Debug)]
pub struct DerDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerDecoder<'a> {
    /// Create a new DER decoder
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Get current position
    #[allow(dead_code)]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Check if we've consumed all data
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Peek at the next byte without consuming it
    fn peek_byte(&self) -> Result<u8> {
        self.data.get(self.pos).copied().ok_or(DerError::UnexpectedEof)
    }

    /// Read a single byte
    fn read_byte(&mut self) -> Result<u8> {
        let byte = self.peek_byte()?;
        self.pos += 1;
        Ok(byte)
    }

    /// Read exactly N bytes
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(DerError::UnexpectedEof);
        }
        let bytes = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(bytes)
    }

    /// Read a DER length field
    fn read_length(&mut self) -> Result<usize> {
        let first_byte = self.read_byte()?;

        if first_byte < 0x80 {
            // Short form: length is in the first byte
            Ok(first_byte as usize)
        } else if first_byte == 0x80 {
            // Indefinite form: not allowed in DER
            Err(DerError::InvalidLength)
        } else {
            // Long form: first byte tells us how many length bytes follow
            let num_length_bytes = (first_byte & 0x7f) as usize;
            if num_length_bytes == 0 || num_length_bytes > 4 {
                return Err(DerError::InvalidLength);
            }

            let length_bytes = self.read_bytes(num_length_bytes)?;
            let mut length = 0usize;
            for &byte in length_bytes {
                length = length
                    .checked_shl(8)
                    .and_then(|l| l.checked_add(byte as usize))
                    .ok_or(DerError::InvalidLength)?;
            }

            // DER requires shortest form encoding
            if length < 0x80 {
                return Err(DerError::InvalidLength);
            }

            Ok(length)
        }
    }

    /// Read and verify a tag, then return the contents
    pub fn read_tagged(&mut self, expected_tag: u8) -> Result<&'a [u8]> {
        let tag = self.read_byte()?;
        if tag != expected_tag {
            return Err(DerError::InvalidTag {
                expected: expected_tag,
                got: tag,
            });
        }

        let length = self.read_length()?;
        self.read_bytes(length)
    }

    /// Read a SEQUENCE and return a decoder for its contents
    pub fn read_sequence(&mut self) -> Result<DerDecoder<'a>> {
        let contents = self.read_tagged(tag::SEQUENCE)?;
        Ok(DerDecoder::new(contents))
    }

    /// Read an INTEGER as a BigUint
    pub fn read_integer(&mut self) -> Result<BigUint> {
        let bytes = self.read_tagged(tag::INTEGER)?;

        if bytes.is_empty() {
            return Err(DerError::InvalidData("Empty INTEGER".to_string()));
        }

        // Skip leading zeros (except if the number is just 0)
        let start = if bytes.len() > 1 && bytes[0] == 0 && bytes[1] < 0x80 {
            1
        } else {
            0
        };

        Ok(BigUint::from_bytes_be(&bytes[start..]))
    }

    /// Read an INTEGER and expect it to be a small unsigned value
    pub fn read_integer_u32(&mut self) -> Result<u32> {
        let bigint = self.read_integer()?;
        let bytes = bigint.to_bytes_be();

        if bytes.len() > 4 {
            return Err(DerError::InvalidData("INTEGER too large for u32".to_string()));
        }

        let mut result = 0u32;
        for &byte in &bytes {
            result = (result << 8) | (byte as u32);
        }
        Ok(result)
    }

    /// Read an OCTET STRING
    pub fn read_octet_string(&mut self) -> Result<&'a [u8]> {
        self.read_tagged(tag::OCTET_STRING)
    }

    /// Read a BIT STRING (ignoring the unused bits field for now)
    pub fn read_bit_string(&mut self) -> Result<&'a [u8]> {
        let contents = self.read_tagged(tag::BIT_STRING)?;

        if contents.is_empty() {
            return Err(DerError::InvalidData("Empty BIT STRING".to_string()));
        }

        // First byte is the number of unused bits in the last byte
        let unused_bits = contents[0];
        if unused_bits > 7 {
            return Err(DerError::InvalidData(format!(
                "Invalid unused bits in BIT STRING: {}",
                unused_bits
            )));
        }

        // For our purposes (RSA keys), we expect 0 unused bits
        if unused_bits != 0 {
            return Err(DerError::InvalidData(
                "BIT STRING with unused bits not supported".to_string(),
            ));
        }

        Ok(&contents[1..])
    }

    /// Read and verify an OID (Object Identifier)
    pub fn read_oid(&mut self) -> Result<Vec<u32>> {
        let bytes = self.read_tagged(tag::OID)?;

        if bytes.is_empty() {
            return Err(DerError::InvalidData("Empty OID".to_string()));
        }

        let mut components = Vec::new();

        // First byte encodes the first two components
        let first = bytes[0];
        components.push((first / 40) as u32);
        components.push((first % 40) as u32);

        // Remaining bytes encode subsequent components
        let mut i = 1;
        while i < bytes.len() {
            let mut value = 0u32;
            loop {
                if i >= bytes.len() {
                    return Err(DerError::InvalidData("Incomplete OID component".to_string()));
                }

                let byte = bytes[i];
                i += 1;

                value = value
                    .checked_shl(7)
                    .and_then(|v| v.checked_add((byte & 0x7f) as u32))
                    .ok_or_else(|| DerError::InvalidData("OID component overflow".to_string()))?;

                if byte & 0x80 == 0 {
                    break;
                }
            }
            components.push(value);
        }

        Ok(components)
    }

    /// Read and expect a NULL
    pub fn read_null(&mut self) -> Result<()> {
        let contents = self.read_tagged(tag::NULL)?;
        if !contents.is_empty() {
            return Err(DerError::InvalidData("NULL must be empty".to_string()));
        }
        Ok(())
    }
}

/// RSA public key components
#[derive(Debug, Clone)]
pub struct RsaPublicKeyComponents {
    /// Modulus n
    pub n: BigUint,
    /// Public exponent e
    pub e: BigUint,
}

/// RSA private key components (PKCS#1 format)
#[derive(Debug, Clone)]
pub struct RsaPrivateKeyComponents {
    /// Modulus n
    pub n: BigUint,
    /// Public exponent e
    pub e: BigUint,
    /// Private exponent d
    pub d: BigUint,
    /// First prime p
    pub p: BigUint,
    /// Second prime q
    pub q: BigUint,
    /// d mod (p-1)
    pub dp: BigUint,
    /// d mod (q-1)
    pub dq: BigUint,
    /// q^(-1) mod p
    pub qinv: BigUint,
}

// RSA OID: 1.2.840.113549.1.1.1
const RSA_OID: &[u32] = &[1, 2, 840, 113549, 1, 1, 1];

/// Parse an RSA public key from PKCS#1 DER format
pub fn parse_rsa_public_key_pkcs1(der: &[u8]) -> Result<RsaPublicKeyComponents> {
    let mut decoder = DerDecoder::new(der);
    let mut seq = decoder.read_sequence()?;

    let n = seq.read_integer()?;
    let e = seq.read_integer()?;

    if !seq.is_empty() {
        return Err(DerError::InvalidData(
            "Extra data in RSA public key".to_string(),
        ));
    }

    Ok(RsaPublicKeyComponents { n, e })
}

/// Parse an RSA private key from PKCS#1 DER format
pub fn parse_rsa_private_key_pkcs1(der: &[u8]) -> Result<RsaPrivateKeyComponents> {
    let mut decoder = DerDecoder::new(der);
    let mut seq = decoder.read_sequence()?;

    // Version (should be 0 for two-prime RSA)
    let version = seq.read_integer_u32()?;
    if version != 0 {
        return Err(DerError::InvalidData(format!(
            "Unsupported RSA key version: {}",
            version
        )));
    }

    let n = seq.read_integer()?;
    let e = seq.read_integer()?;
    let d = seq.read_integer()?;
    let p = seq.read_integer()?;
    let q = seq.read_integer()?;
    let dp = seq.read_integer()?;
    let dq = seq.read_integer()?;
    let qinv = seq.read_integer()?;

    Ok(RsaPrivateKeyComponents {
        n,
        e,
        d,
        p,
        q,
        dp,
        dq,
        qinv,
    })
}

/// Parse an RSA public key from X.509 SubjectPublicKeyInfo DER format
pub fn parse_rsa_public_key_spki(der: &[u8]) -> Result<RsaPublicKeyComponents> {
    let mut decoder = DerDecoder::new(der);
    let mut seq = decoder.read_sequence()?;

    // AlgorithmIdentifier
    let mut alg_seq = seq.read_sequence()?;
    let oid = alg_seq.read_oid()?;

    if oid.as_slice() != RSA_OID {
        return Err(DerError::InvalidData(format!(
            "Not an RSA public key (OID: {:?})",
            oid
        )));
    }

    // Parameters (NULL for RSA)
    alg_seq.read_null()?;

    // subjectPublicKey (BIT STRING containing PKCS#1 public key)
    let public_key_bits = seq.read_bit_string()?;

    // Parse the PKCS#1 public key from the BIT STRING contents
    parse_rsa_public_key_pkcs1(public_key_bits)
}

/// Parse an RSA private key from PKCS#8 DER format
pub fn parse_rsa_private_key_pkcs8(der: &[u8]) -> Result<RsaPrivateKeyComponents> {
    let mut decoder = DerDecoder::new(der);
    let mut seq = decoder.read_sequence()?;

    // Version (should be 0)
    let version = seq.read_integer_u32()?;
    if version != 0 {
        return Err(DerError::InvalidData(format!(
            "Unsupported PKCS#8 version: {}",
            version
        )));
    }

    // AlgorithmIdentifier
    let mut alg_seq = seq.read_sequence()?;
    let oid = alg_seq.read_oid()?;

    if oid.as_slice() != RSA_OID {
        return Err(DerError::InvalidData(format!(
            "Not an RSA private key (OID: {:?})",
            oid
        )));
    }

    // Parameters (NULL for RSA)
    alg_seq.read_null()?;

    // PrivateKey (OCTET STRING containing PKCS#1 private key)
    let private_key_bytes = seq.read_octet_string()?;

    // Parse the PKCS#1 private key from the OCTET STRING contents
    parse_rsa_private_key_pkcs1(private_key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_length_short() {
        let data = [0x05]; // Length 5
        let mut decoder = DerDecoder::new(&data);
        assert_eq!(decoder.read_length().unwrap(), 5);
    }

    #[test]
    fn test_der_length_long() {
        let data = [0x82, 0x01, 0x00]; // Length 256
        let mut decoder = DerDecoder::new(&data);
        assert_eq!(decoder.read_length().unwrap(), 256);
    }

    #[test]
    fn test_read_integer() {
        // INTEGER 42
        let data = [0x02, 0x01, 0x2a];
        let mut decoder = DerDecoder::new(&data);
        let int = decoder.read_integer().unwrap();
        assert_eq!(int, BigUint::from(42u32));
    }

    #[test]
    fn test_read_sequence() {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        let data = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let mut decoder = DerDecoder::new(&data);
        let mut seq = decoder.read_sequence().unwrap();

        let a = seq.read_integer().unwrap();
        let b = seq.read_integer().unwrap();

        assert_eq!(a, BigUint::from(1u32));
        assert_eq!(b, BigUint::from(2u32));
        assert!(seq.is_empty());
    }

    #[test]
    fn test_read_oid_rsa() {
        // OID 1.2.840.113549.1.1.1 (RSA encryption)
        let data = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        let mut decoder = DerDecoder::new(&data);
        let oid = decoder.read_oid().unwrap();
        assert_eq!(oid.as_slice(), RSA_OID);
    }
}
