//! TLS extensions implementation.

use crate::error::{Error, Result};
use crate::protocol::ExtensionType;
use crate::psk::{
    PreSharedKeyExtension, PreSharedKeyServerExtension, PskKeyExchangeModesExtension,
};

/// TLS extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Extension type
    pub extension_type: ExtensionType,

    /// Extension data
    pub data: Vec<u8>,
}

impl Extension {
    /// Create a new extension.
    pub fn new(extension_type: ExtensionType, data: Vec<u8>) -> Self {
        Self {
            extension_type,
            data,
        }
    }

    /// Encode the extension to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.data.len());

        // Type (2 bytes)
        buf.extend_from_slice(&self.extension_type.to_u16().to_be_bytes());

        // Length (2 bytes)
        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());

        // Data
        buf.extend_from_slice(&self.data);

        buf
    }

    /// Decode an extension from bytes.
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(Error::InvalidMessage("Extension too short".into()));
        }

        let ext_type_raw = u16::from_be_bytes([data[0], data[1]]);
        let extension_type = ExtensionType::from_u16(ext_type_raw).ok_or_else(|| {
            Error::InvalidMessage(format!("Unknown extension type: {}", ext_type_raw))
        })?;

        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + length {
            return Err(Error::InvalidMessage("Incomplete extension data".into()));
        }

        let ext_data = data[4..4 + length].to_vec();

        Ok((
            Self {
                extension_type,
                data: ext_data,
            },
            4 + length,
        ))
    }
}

/// Extension list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extensions {
    extensions: Vec<Extension>,
}

impl Extensions {
    /// Create a new empty extension list.
    pub fn new() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }

    /// Add an extension.
    pub fn add(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }

    /// Get an extension by type.
    pub fn get(&self, ext_type: ExtensionType) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.extension_type == ext_type)
    }

    /// Check if an extension is present.
    pub fn has(&self, ext_type: ExtensionType) -> bool {
        self.get(ext_type).is_some()
    }

    /// Encode all extensions.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        for ext in &self.extensions {
            buf.extend_from_slice(&ext.encode());
        }

        // Prepend total length (2 bytes)
        let mut result = Vec::with_capacity(2 + buf.len());
        result.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        result.extend_from_slice(&buf);

        result
    }

    /// Decode extensions from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::InvalidMessage("Extensions too short".into()));
        }

        let total_length = u16::from_be_bytes([data[0], data[1]]) as usize;

        if data.len() < 2 + total_length {
            return Err(Error::InvalidMessage("Incomplete extensions".into()));
        }

        let mut extensions = Vec::new();
        let mut offset = 2;

        while offset < 2 + total_length {
            let (ext, consumed) = Extension::decode(&data[offset..])?;
            extensions.push(ext);
            offset += consumed;
        }

        Ok(Self { extensions })
    }

    /// Get the number of extensions.
    pub fn len(&self) -> usize {
        self.extensions.len()
    }

    /// Check if the extension list is empty.
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    /// Add a Pre-Shared Key extension (client-side).
    ///
    /// IMPORTANT: This extension MUST be the last extension in ClientHello per RFC 8446.
    pub fn add_pre_shared_key(&mut self, psk_ext: PreSharedKeyExtension) {
        let data = psk_ext.encode();
        self.add(Extension::new(ExtensionType::PreSharedKey, data));
    }

    /// Get the Pre-Shared Key extension (client-side).
    pub fn get_pre_shared_key(&self) -> Result<Option<PreSharedKeyExtension>> {
        if let Some(ext) = self.get(ExtensionType::PreSharedKey) {
            let psk_ext = PreSharedKeyExtension::decode(&ext.data)?;
            Ok(Some(psk_ext))
        } else {
            Ok(None)
        }
    }

    /// Remove the Pre-Shared Key extension if present.
    pub fn remove_pre_shared_key(&mut self) {
        self.extensions.retain(|e| e.extension_type != ExtensionType::PreSharedKey);
    }

    /// Add a Pre-Shared Key extension (server-side).
    pub fn add_pre_shared_key_server(&mut self, psk_ext: PreSharedKeyServerExtension) {
        let data = psk_ext.encode();
        self.add(Extension::new(ExtensionType::PreSharedKey, data));
    }

    /// Get the Pre-Shared Key extension (server-side).
    pub fn get_pre_shared_key_server(&self) -> Result<Option<PreSharedKeyServerExtension>> {
        if let Some(ext) = self.get(ExtensionType::PreSharedKey) {
            let psk_ext = PreSharedKeyServerExtension::decode(&ext.data)?;
            Ok(Some(psk_ext))
        } else {
            Ok(None)
        }
    }

    /// Add PSK Key Exchange Modes extension.
    pub fn add_psk_key_exchange_modes(&mut self, modes_ext: PskKeyExchangeModesExtension) {
        let data = modes_ext.encode();
        self.add(Extension::new(ExtensionType::PskKeyExchangeModes, data));
    }

    /// Get PSK Key Exchange Modes extension.
    pub fn get_psk_key_exchange_modes(&self) -> Result<Option<PskKeyExchangeModesExtension>> {
        if let Some(ext) = self.get(ExtensionType::PskKeyExchangeModes) {
            let modes_ext = PskKeyExchangeModesExtension::decode(&ext.data)?;
            Ok(Some(modes_ext))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_encode_decode() {
        let ext = Extension::new(ExtensionType::ServerName, vec![1, 2, 3]);
        let encoded = ext.encode();

        let (decoded, consumed) = Extension::decode(&encoded).unwrap();
        assert_eq!(decoded.extension_type, ExtensionType::ServerName);
        assert_eq!(decoded.data, vec![1, 2, 3]);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_extensions_encode_decode() {
        let mut exts = Extensions::new();
        exts.add(Extension::new(ExtensionType::ServerName, vec![1, 2, 3]));
        exts.add(Extension::new(
            ExtensionType::SupportedVersions,
            vec![4, 5, 6],
        ));

        let encoded = exts.encode();
        let decoded = Extensions::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert!(decoded.has(ExtensionType::ServerName));
        assert!(decoded.has(ExtensionType::SupportedVersions));
    }
}
