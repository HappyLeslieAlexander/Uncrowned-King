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
    /// Optional server connection and authentication timeout in seconds.
    pub handshake_timeout_seconds: Option<u64>,
    /// Optional SOCKS5 greeting/request timeout in seconds.
    pub socks_handshake_timeout_seconds: Option<u64>,
}

impl ClientConfig {
    /// Loads a client config from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let text = fs::read_to_string(path)?;
        let config = toml::from_str(&text)?;
        Ok(config)
    }

    /// Server connection and authentication timeout in seconds. Zero disables it.
    pub fn handshake_timeout_seconds(&self) -> u64 {
        self.handshake_timeout_seconds.unwrap_or(10)
    }

    /// SOCKS5 greeting/request timeout in seconds. Zero disables it.
    pub fn socks_handshake_timeout_seconds(&self) -> u64 {
        self.socks_handshake_timeout_seconds.unwrap_or(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> ClientConfig {
        ClientConfig {
            server_addr: "127.0.0.1:443".to_owned(),
            server_name: "localhost".to_owned(),
            ca_cert_path: "ca.pem".to_owned(),
            key_id: "client".to_owned(),
            secret: "secret".to_owned(),
            handshake_timeout_seconds: None,
            socks_handshake_timeout_seconds: None,
        }
    }

    #[test]
    fn defaults_handshake_timeout() {
        assert_eq!(minimal_config().handshake_timeout_seconds(), 10);
    }

    #[test]
    fn parses_handshake_timeout() {
        let config: ClientConfig = toml::from_str(
            r#"
server_addr = "127.0.0.1:443"
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
handshake_timeout_seconds = 4
"#,
        )
        .unwrap();

        assert_eq!(config.handshake_timeout_seconds(), 4);
    }

    #[test]
    fn defaults_socks_handshake_timeout() {
        assert_eq!(minimal_config().socks_handshake_timeout_seconds(), 10);
    }

    #[test]
    fn parses_socks_handshake_timeout() {
        let config: ClientConfig = toml::from_str(
            r#"
server_addr = "127.0.0.1:443"
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
socks_handshake_timeout_seconds = 5
"#,
        )
        .unwrap();

        assert_eq!(config.socks_handshake_timeout_seconds(), 5);
    }
}
