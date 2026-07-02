//! Client configuration.

use std::{fs, path::Path};

use serde::Deserialize;

/// Client TOML configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// UK server socket address.
    pub server_addr: String,
    /// TLS server name.
    pub server_name: String,
    /// CA certificate PEM path.
    pub ca_cert_path: String,
    /// Opaque key id.
    pub key_id: String,
    /// Shared secret. v0.1 treats this as UTF-8 bytes.
    pub secret: String,
}

impl ClientConfig {
    /// Loads a client config from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let text = fs::read_to_string(path)?;
        let config = toml::from_str(&text)?;
        Ok(config)
    }
}
