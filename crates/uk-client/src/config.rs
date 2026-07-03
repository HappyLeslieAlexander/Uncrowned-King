//! Client configuration.

use std::{error::Error, fs, net::SocketAddr, path::Path};

use serde::Deserialize;
use uk_auth::{AuthError, validate_key_id, validate_shared_secret};

/// Client TOML configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Optional timeout for waiting on TCP open acknowledgement in seconds.
    pub tcp_open_timeout_seconds: Option<u64>,
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

    /// TCP open acknowledgement timeout in seconds. Zero disables it.
    pub fn tcp_open_timeout_seconds(&self) -> u64 {
        self.tcp_open_timeout_seconds.unwrap_or(10)
    }

    /// Validates local authentication material before opening a network session.
    pub fn validate_auth_material(&self) -> Result<(), AuthError> {
        validate_key_id(self.key_id.as_bytes())?;
        validate_shared_secret(self.secret.as_bytes())
    }

    /// Validates configured network endpoints without resolving DNS.
    pub fn validate_network_endpoints(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        validate_endpoint("server_addr", &self.server_addr)
    }
}

/// Validates one `host:port` endpoint without resolving DNS.
pub fn validate_endpoint(
    name: &'static str,
    value: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return validate_port(name, addr.port());
    }

    let (host, port) = split_host_port(value).ok_or_else(|| {
        format!("{name} must be a host:port endpoint; bracket IPv6 literals like [::1]:443")
    })?;
    if host.is_empty() || host.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(format!("{name} has an invalid host").into());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("{name} has an invalid port"))?;
    validate_port(name, port)
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?;
        Some((host, port))
    } else {
        let (host, port) = value.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        Some((host, port))
    }
}

fn validate_port(name: &'static str, port: u16) -> Result<(), Box<dyn Error + Send + Sync>> {
    if port == 0 {
        Err(format!("{name} port must be 1..=65535").into())
    } else {
        Ok(())
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
            secret: "0123456789abcdef0123456789abcdef".to_owned(),
            handshake_timeout_seconds: None,
            socks_handshake_timeout_seconds: None,
            tcp_open_timeout_seconds: None,
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

    #[test]
    fn defaults_tcp_open_timeout() {
        assert_eq!(minimal_config().tcp_open_timeout_seconds(), 10);
    }

    #[test]
    fn parses_tcp_open_timeout() {
        let config: ClientConfig = toml::from_str(
            r#"
server_addr = "127.0.0.1:443"
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
tcp_open_timeout_seconds = 6
"#,
        )
        .unwrap();

        assert_eq!(config.tcp_open_timeout_seconds(), 6);
    }

    #[test]
    fn parses_zero_timeout_values() {
        let config: ClientConfig = toml::from_str(
            r#"
server_addr = "127.0.0.1:443"
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
handshake_timeout_seconds = 0
socks_handshake_timeout_seconds = 0
tcp_open_timeout_seconds = 0
"#,
        )
        .unwrap();

        assert_eq!(config.handshake_timeout_seconds(), 0);
        assert_eq!(config.socks_handshake_timeout_seconds(), 0);
        assert_eq!(config.tcp_open_timeout_seconds(), 0);
    }

    #[test]
    fn rejects_unknown_client_config_fields() {
        let result = toml::from_str::<ClientConfig>(
            r#"
server_addr = "127.0.0.1:443"
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
handshake_timeout_secondz = 4
"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn accepts_valid_auth_material() {
        assert!(minimal_config().validate_auth_material().is_ok());
    }

    #[test]
    fn accepts_domain_server_addr() {
        let mut config = minimal_config();
        config.server_addr = "uk.example.com:443".to_owned();

        assert!(config.validate_network_endpoints().is_ok());
    }

    #[test]
    fn accepts_bracketed_ipv6_server_addr() {
        let mut config = minimal_config();
        config.server_addr = "[::1]:9443".to_owned();

        assert!(config.validate_network_endpoints().is_ok());
    }

    #[test]
    fn rejects_server_addr_without_port() {
        let mut config = minimal_config();
        config.server_addr = "uk.example.com".to_owned();

        assert!(config.validate_network_endpoints().is_err());
    }

    #[test]
    fn rejects_zero_server_addr_port() {
        let mut config = minimal_config();
        config.server_addr = "uk.example.com:0".to_owned();

        assert!(config.validate_network_endpoints().is_err());
    }

    #[test]
    fn rejects_unbracketed_ipv6_server_addr() {
        let mut config = minimal_config();
        config.server_addr = "::1:9443".to_owned();

        assert!(config.validate_network_endpoints().is_err());
    }

    #[test]
    fn rejects_empty_key_id_auth_material() {
        let mut config = minimal_config();
        config.key_id.clear();

        assert_eq!(
            config.validate_auth_material(),
            Err(AuthError::InvalidKeyIdLength)
        );
    }

    #[test]
    fn rejects_long_key_id_auth_material() {
        let mut config = minimal_config();
        config.key_id = "k".repeat(65);

        assert_eq!(
            config.validate_auth_material(),
            Err(AuthError::InvalidKeyIdLength)
        );
    }

    #[test]
    fn rejects_short_secret_auth_material() {
        let mut config = minimal_config();
        config.secret = "too-short".to_owned();

        assert_eq!(
            config.validate_auth_material(),
            Err(AuthError::SecretTooShort)
        );
    }
}
