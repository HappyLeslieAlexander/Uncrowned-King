//! Client configuration.

use std::{error::Error, fs, path::Path};

use serde::Deserialize;
use uk_auth::{AuthError, validate_key_id, validate_shared_secret};
use uk_proto::{MAX_FRAME_PAYLOAD_SIZE, validate_host_port_endpoint};

/// Client TOML configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// UK server socket address.
    pub server_addr: String,
    /// Optional fallback UK server socket addresses.
    pub server_addrs: Option<Vec<String>>,
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
    /// Optional maximum local bytes buffered while waiting for TCP open ack.
    pub max_pending_open_bytes: Option<u64>,
    /// Optional maximum concurrent local SOCKS5 connections.
    pub max_socks_connections: Option<u64>,
    /// Optional maximum queued server-to-local bytes across one UK session.
    pub max_buffered_bytes_per_session: Option<u64>,
    /// Optional maximum queued server-to-local bytes per TCP flow.
    pub max_buffered_bytes_per_flow: Option<u64>,
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

    /// Maximum local bytes buffered while waiting for TCP open ack.
    pub fn max_pending_open_bytes(&self) -> u64 {
        self.max_pending_open_bytes.unwrap_or(65_536)
    }

    /// Maximum concurrent local SOCKS5 connections.
    pub fn max_socks_connections(&self) -> u64 {
        self.max_socks_connections.unwrap_or(1024)
    }

    /// Maximum queued server-to-local bytes across one UK session.
    pub fn max_buffered_bytes_per_session(&self) -> u64 {
        self.max_buffered_bytes_per_session
            .unwrap_or(MAX_FRAME_PAYLOAD_SIZE)
    }

    /// Maximum queued server-to-local bytes per TCP flow.
    pub fn max_buffered_bytes_per_flow(&self) -> u64 {
        self.max_buffered_bytes_per_flow.unwrap_or(2_097_152)
    }

    /// Validates local authentication material before opening a network session.
    pub fn validate_auth_material(&self) -> Result<(), AuthError> {
        validate_key_id(self.key_id.as_bytes())?;
        validate_shared_secret(self.secret.as_bytes())
    }

    /// Validates configured network endpoints without resolving DNS.
    pub fn validate_network_endpoints(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        validate_endpoint("server_addr", &self.server_addr)
            .map_err(|err| format!("server_addr: {err}"))?;
        for (index, endpoint) in self.server_addrs().iter().enumerate() {
            validate_endpoint("server_addrs", endpoint)
                .map_err(|err| format!("server_addrs[{index}]: {err}"))?;
        }
        Ok(())
    }

    /// Additional fallback UK server endpoints.
    pub fn server_addrs(&self) -> &[String] {
        self.server_addrs.as_deref().unwrap_or(&[])
    }

    /// Returns primary then fallback UK server endpoints in dial order.
    pub fn server_endpoints(&self) -> Vec<&str> {
        std::iter::once(self.server_addr.as_str())
            .chain(self.server_addrs().iter().map(String::as_str))
            .collect()
    }

    /// Validates local client resource limits.
    pub fn validate_resource_limits(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let max_socks_connections = self.max_socks_connections();
        if max_socks_connections == 0 {
            return Err("max_socks_connections must be greater than zero".into());
        }
        usize::try_from(max_socks_connections)
            .map_err(|_| "max_socks_connections is too large for this platform")?;
        let max_pending_open_bytes = self.max_pending_open_bytes();
        if max_pending_open_bytes == 0 {
            return Err("max_pending_open_bytes must be greater than zero".into());
        }
        if max_pending_open_bytes > MAX_FRAME_PAYLOAD_SIZE {
            return Err(
                format!("max_pending_open_bytes must be at most {MAX_FRAME_PAYLOAD_SIZE}").into(),
            );
        }
        let max_buffered_bytes_per_session = self.max_buffered_bytes_per_session();
        if max_buffered_bytes_per_session == 0 {
            return Err("max_buffered_bytes_per_session must be greater than zero".into());
        }
        if max_buffered_bytes_per_session > MAX_FRAME_PAYLOAD_SIZE {
            return Err(format!(
                "max_buffered_bytes_per_session must be at most {MAX_FRAME_PAYLOAD_SIZE}"
            )
            .into());
        }
        let max_buffered_bytes_per_flow = self.max_buffered_bytes_per_flow();
        if max_buffered_bytes_per_flow == 0 {
            return Err("max_buffered_bytes_per_flow must be greater than zero".into());
        }
        if max_buffered_bytes_per_flow > MAX_FRAME_PAYLOAD_SIZE {
            return Err(format!(
                "max_buffered_bytes_per_flow must be at most {MAX_FRAME_PAYLOAD_SIZE}"
            )
            .into());
        }
        Ok(())
    }
}

/// Validates one `host:port` endpoint without resolving DNS.
pub fn validate_endpoint(
    name: &'static str,
    value: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_host_port_endpoint(name, value)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> ClientConfig {
        ClientConfig {
            server_addr: "127.0.0.1:443".to_owned(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            ca_cert_path: "ca.pem".to_owned(),
            key_id: "client".to_owned(),
            secret: "0123456789abcdef0123456789abcdef".to_owned(),
            handshake_timeout_seconds: None,
            socks_handshake_timeout_seconds: None,
            tcp_open_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
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
    fn defaults_max_socks_connections() {
        assert_eq!(minimal_config().max_socks_connections(), 1024);
    }

    #[test]
    fn defaults_pending_open_buffer_limit() {
        assert_eq!(minimal_config().max_pending_open_bytes(), 65_536);
    }

    #[test]
    fn parses_pending_open_buffer_limit() {
        let config: ClientConfig = toml::from_str(
            r#"
server_addr = "127.0.0.1:443"
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
max_pending_open_bytes = 2048
"#,
        )
        .unwrap();

        assert_eq!(config.max_pending_open_bytes(), 2048);
    }

    #[test]
    fn rejects_zero_pending_open_buffer_limit() {
        let mut config = minimal_config();
        config.max_pending_open_bytes = Some(0);

        assert!(config.validate_resource_limits().is_err());
    }

    #[test]
    fn rejects_too_large_pending_open_buffer_limit() {
        let mut config = minimal_config();
        config.max_pending_open_bytes = Some(MAX_FRAME_PAYLOAD_SIZE + 1);

        assert!(config.validate_resource_limits().is_err());
    }

    #[test]
    fn parses_max_socks_connections() {
        let config: ClientConfig = toml::from_str(
            r#"
server_addr = "127.0.0.1:443"
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
max_socks_connections = 7
"#,
        )
        .unwrap();

        assert_eq!(config.max_socks_connections(), 7);
    }

    #[test]
    fn rejects_zero_max_socks_connections() {
        let mut config = minimal_config();
        config.max_socks_connections = Some(0);

        assert!(config.validate_resource_limits().is_err());
    }

    #[test]
    fn defaults_buffered_bytes_per_session_limit() {
        assert_eq!(
            minimal_config().max_buffered_bytes_per_session(),
            MAX_FRAME_PAYLOAD_SIZE
        );
    }

    #[test]
    fn defaults_buffered_bytes_per_flow_limit() {
        assert_eq!(minimal_config().max_buffered_bytes_per_flow(), 2_097_152);
    }

    #[test]
    fn parses_buffered_bytes_per_session_limit() {
        let config: ClientConfig = toml::from_str(
            r#"
server_addr = "127.0.0.1:443"
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
max_buffered_bytes_per_session = 8192
"#,
        )
        .unwrap();

        assert_eq!(config.max_buffered_bytes_per_session(), 8192);
    }

    #[test]
    fn rejects_zero_buffered_bytes_per_session_limit() {
        let mut config = minimal_config();
        config.max_buffered_bytes_per_session = Some(0);

        assert!(config.validate_resource_limits().is_err());
    }

    #[test]
    fn rejects_too_large_buffered_bytes_per_session_limit() {
        let mut config = minimal_config();
        config.max_buffered_bytes_per_session = Some(MAX_FRAME_PAYLOAD_SIZE + 1);

        assert!(config.validate_resource_limits().is_err());
    }

    #[test]
    fn parses_buffered_bytes_per_flow_limit() {
        let config: ClientConfig = toml::from_str(
            r#"
server_addr = "127.0.0.1:443"
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
max_buffered_bytes_per_flow = 4096
"#,
        )
        .unwrap();

        assert_eq!(config.max_buffered_bytes_per_flow(), 4096);
    }

    #[test]
    fn rejects_zero_buffered_bytes_per_flow_limit() {
        let mut config = minimal_config();
        config.max_buffered_bytes_per_flow = Some(0);

        assert!(config.validate_resource_limits().is_err());
    }

    #[test]
    fn rejects_too_large_buffered_bytes_per_flow_limit() {
        let mut config = minimal_config();
        config.max_buffered_bytes_per_flow = Some(MAX_FRAME_PAYLOAD_SIZE + 1);

        assert!(config.validate_resource_limits().is_err());
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
max_pending_open_bytes = 1024
max_socks_connections = 1
max_buffered_bytes_per_session = 1024
max_buffered_bytes_per_flow = 1024
"#,
        )
        .unwrap();

        assert_eq!(config.handshake_timeout_seconds(), 0);
        assert_eq!(config.socks_handshake_timeout_seconds(), 0);
        assert_eq!(config.tcp_open_timeout_seconds(), 0);
        assert_eq!(config.max_pending_open_bytes(), 1024);
        assert_eq!(config.max_socks_connections(), 1);
        assert_eq!(config.max_buffered_bytes_per_session(), 1024);
        assert_eq!(config.max_buffered_bytes_per_flow(), 1024);
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
    fn parses_fallback_server_addrs() {
        let config: ClientConfig = toml::from_str(
            r#"
server_addr = "127.0.0.1:443"
server_addrs = ["uk-a.example.com:443", "[::1]:9443"]
server_name = "localhost"
ca_cert_path = "ca.pem"
key_id = "client"
secret = "secret"
"#,
        )
        .unwrap();

        assert_eq!(
            config.server_endpoints(),
            vec!["127.0.0.1:443", "uk-a.example.com:443", "[::1]:9443"]
        );
        assert!(config.validate_network_endpoints().is_ok());
    }

    #[test]
    fn rejects_server_addr_without_port() {
        let mut config = minimal_config();
        config.server_addr = "uk.example.com".to_owned();

        assert!(config.validate_network_endpoints().is_err());
    }

    #[test]
    fn rejects_invalid_fallback_server_addr() {
        let mut config = minimal_config();
        config.server_addrs = Some(vec!["uk.example.com".to_owned()]);

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
