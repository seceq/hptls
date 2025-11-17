//! RSA key bridge
//!
//! This module provides a bridge to construct hpcrypt-rsa keys from DER-parsed components.

use crate::der::{RsaPrivateKeyComponents, RsaPublicKeyComponents};
use hptls_crypto::{Error, Result};

/// Create an RsaPrivateKey from DER-parsed components
///
/// This function validates the components and constructs an RsaPrivateKey using
/// the public `from_components` API provided by hpcrypt-rsa.
pub fn private_key_from_components(
    components: RsaPrivateKeyComponents,
) -> Result<hpcrypt_rsa::RsaPrivateKey> {
    hpcrypt_rsa::RsaPrivateKey::from_components(
        components.n,
        components.e,
        components.d,
        components.p,
        components.q,
        components.dp,
        components.dq,
        components.qinv,
    )
    .map_err(|e| Error::CryptoError(format!("Failed to create RSA private key: {:?}", e)))
}

/// Create an RsaPublicKey from DER-parsed components
pub fn public_key_from_components(
    components: RsaPublicKeyComponents,
) -> Result<hpcrypt_rsa::RsaPublicKey> {
    hpcrypt_rsa::RsaPublicKey::new(components.n, components.e)
        .map_err(|e| Error::CryptoError(format!("Invalid RSA public key: {:?}", e)))
}
