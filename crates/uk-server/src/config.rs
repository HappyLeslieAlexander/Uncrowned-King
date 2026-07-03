//! Server configuration.

use std::{error::Error, fs, path::Path};

use serde::Deserialize;
use uk_auth::{AuthError, Credential, CredentialStatus, DEFAULT_REPLAY_CACHE_MAX_ENTRIES};
use uk_policy::PolicySet;

const DEFAULT_REPLAY_CACHE_WINDOW_SECONDS: u64 = 300;

/// Server TOML configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// TCP listen address.
    pub listen: String,
    /// Certificate chain PEM path.
    pub cert_path: String,
    /// Private key PEM path.
    pub key_path: String,
    /// Allowed timestamp skew in seconds.
    pub auth_skew_seconds: Option<u64>,
    /// Optional limits.
    pub limits: Option<LimitConfig>,
    /// Optional TOML policy file. If omitted, the server denies all targets.
    pub policy_path: Option<String>,
    /// Static credential list.
    pub credentials: Vec<CredentialConfig>,
}

impl ServerConfig {
    /// Loads a server config from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let text = fs::read_to_string(path)?;
        let config = toml::from_str(&text)?;
        Ok(config)
    }

    /// Converts static credential config into auth records.
    pub fn credentials(&self) -> Result<Vec<Credential>, AuthError> {
        self.credentials
            .iter()
            .map(CredentialConfig::to_credential)
            .collect()
    }

    /// Loads the configured policy set. Missing policy config means deny-all.
    pub fn policy_set(&self) -> Result<PolicySet, Box<dyn Error + Send + Sync>> {
        let Some(path) = &self.policy_path else {
            return Ok(PolicySet::default());
        };
        let text = fs::read_to_string(path)?;
        Ok(PolicySet::from_toml(&text)?)
    }

    /// Validates configured resource limits.
    pub fn validate_limits(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        reject_zero_limit("max_pre_auth_bytes", self.max_pre_auth_bytes())?;
        reject_zero_limit("max_frame_size", self.max_frame_size())?;
        reject_zero_limit("max_streams", self.max_streams())?;
        reject_zero_limit(
            "max_buffered_bytes_per_flow",
            self.max_buffered_bytes_per_flow(),
        )?;
        reject_zero_limit(
            "replay_cache_window_seconds",
            self.replay_cache_window_seconds(),
        )?;
        reject_zero_limit("replay_cache_max_entries", self.replay_cache_max_entries())?;
        Ok(())
    }

    /// Configured pre-auth frame limit.
    pub fn max_pre_auth_bytes(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_pre_auth_bytes)
            .unwrap_or(4096)
    }

    /// Configured post-auth frame limit.
    pub fn max_frame_size(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_frame_size)
            .unwrap_or(65_536)
    }

    /// Configured maximum concurrent TCP streams per authenticated session.
    pub fn max_streams(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_streams)
            .unwrap_or(64)
    }

    /// Configured idle timeout in seconds. Zero disables idle timeout.
    pub fn idle_timeout_seconds(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.idle_timeout_seconds)
            .unwrap_or(300)
    }

    /// Maximum queued client-to-target bytes per TCP flow.
    pub fn max_buffered_bytes_per_flow(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_buffered_bytes_per_flow)
            .unwrap_or(2_097_152)
    }

    /// TLS and authentication handshake timeout in seconds. Zero disables it.
    pub fn handshake_timeout_seconds(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.handshake_timeout_seconds)
            .unwrap_or(10)
    }

    /// DNS resolution and TCP dial timeout for target opens. Zero disables it.
    pub fn target_connect_timeout_seconds(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.target_connect_timeout_seconds)
            .unwrap_or(10)
    }

    /// TCP half-close drain timeout in seconds. Zero disables it.
    pub fn tcp_half_close_timeout_seconds(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.tcp_half_close_timeout_seconds)
            .unwrap_or(30)
    }

    /// Replay cache retention window in seconds.
    pub fn replay_cache_window_seconds(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.replay_cache_window_seconds)
            .unwrap_or(DEFAULT_REPLAY_CACHE_WINDOW_SECONDS)
    }

    /// Maximum accepted nonce pairs retained by the replay cache.
    pub fn replay_cache_max_entries(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.replay_cache_max_entries)
            .unwrap_or(DEFAULT_REPLAY_CACHE_MAX_ENTRIES as u64)
    }
}

fn reject_zero_limit(name: &str, value: u64) -> Result<(), Box<dyn Error + Send + Sync>> {
    if value == 0 {
        Err(format!("{name} must be greater than zero").into())
    } else {
        Ok(())
    }
}

/// Server resource limits.
#[derive(Debug, Clone, Deserialize)]
#[allow(clippy::struct_field_names)]
#[serde(deny_unknown_fields)]
pub struct LimitConfig {
    /// Maximum pre-authentication frame payload.
    pub max_pre_auth_bytes: Option<u64>,
    /// Maximum post-authentication frame payload.
    pub max_frame_size: Option<u64>,
    /// Maximum concurrent TCP streams per authenticated session.
    pub max_streams: Option<u64>,
    /// Idle timeout for authenticated relay sessions in seconds.
    pub idle_timeout_seconds: Option<u64>,
    /// Maximum queued client-to-target bytes per TCP flow.
    pub max_buffered_bytes_per_flow: Option<u64>,
    /// TLS and authentication handshake timeout in seconds.
    pub handshake_timeout_seconds: Option<u64>,
    /// DNS resolution and TCP dial timeout for target opens.
    pub target_connect_timeout_seconds: Option<u64>,
    /// TCP half-close drain timeout in seconds.
    pub tcp_half_close_timeout_seconds: Option<u64>,
    /// Replay cache retention window in seconds.
    pub replay_cache_window_seconds: Option<u64>,
    /// Maximum accepted nonce pairs retained by the replay cache.
    pub replay_cache_max_entries: Option<u64>,
}

/// One configured credential.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    /// Opaque key id.
    pub key_id: String,
    /// Shared secret. v0.1 treats this as UTF-8 bytes.
    pub secret: String,
    /// Credential status.
    pub status: Option<String>,
    /// Optional not-before unix time.
    pub not_before: Option<u64>,
    /// Optional not-after unix time.
    pub not_after: Option<u64>,
    /// Optional policy group.
    pub policy_group: Option<String>,
}

impl CredentialConfig {
    fn to_credential(&self) -> Result<Credential, AuthError> {
        let status_text = self.status.as_deref().unwrap_or("active");
        let status = match status_text {
            "active" => CredentialStatus::Active,
            "disabled" => CredentialStatus::Disabled,
            "retired" => CredentialStatus::Retired,
            _ => return Err(AuthError::InvalidCredentialStatus),
        };
        let mut credential = Credential::active(self.key_id.as_bytes(), self.secret.as_bytes())?;
        credential.status = status;
        credential.not_before = self.not_before;
        credential.not_after = self.not_after;
        credential.policy_group.clone_from(&self.policy_group);
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".to_owned(),
            cert_path: "cert.pem".to_owned(),
            key_path: "key.pem".to_owned(),
            auth_skew_seconds: None,
            limits: None,
            policy_path: None,
            credentials: Vec::new(),
        }
    }

    #[test]
    fn defaults_idle_timeout() {
        assert_eq!(minimal_config().idle_timeout_seconds(), 300);
    }

    #[test]
    fn parses_idle_timeout_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
idle_timeout_seconds = 42
"#,
        )
        .unwrap();

        assert_eq!(config.idle_timeout_seconds(), 42);
    }

    #[test]
    fn defaults_buffered_bytes_per_flow_limit() {
        assert_eq!(minimal_config().max_buffered_bytes_per_flow(), 2_097_152);
    }

    #[test]
    fn accepts_default_limits() {
        assert!(minimal_config().validate_limits().is_ok());
    }

    #[test]
    fn parses_buffered_bytes_per_flow_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_buffered_bytes_per_flow = 4096
"#,
        )
        .unwrap();

        assert_eq!(config.max_buffered_bytes_per_flow(), 4096);
    }

    #[test]
    fn defaults_handshake_timeout() {
        assert_eq!(minimal_config().handshake_timeout_seconds(), 10);
    }

    #[test]
    fn parses_handshake_timeout() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
handshake_timeout_seconds = 3
"#,
        )
        .unwrap();

        assert_eq!(config.handshake_timeout_seconds(), 3);
    }

    #[test]
    fn defaults_target_connect_timeout() {
        assert_eq!(minimal_config().target_connect_timeout_seconds(), 10);
    }

    #[test]
    fn parses_target_connect_timeout() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
target_connect_timeout_seconds = 7
"#,
        )
        .unwrap();

        assert_eq!(config.target_connect_timeout_seconds(), 7);
    }

    #[test]
    fn defaults_tcp_half_close_timeout() {
        assert_eq!(minimal_config().tcp_half_close_timeout_seconds(), 30);
    }

    #[test]
    fn parses_tcp_half_close_timeout() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
tcp_half_close_timeout_seconds = 11
"#,
        )
        .unwrap();

        assert_eq!(config.tcp_half_close_timeout_seconds(), 11);
    }

    #[test]
    fn defaults_replay_cache_limits() {
        assert_eq!(minimal_config().replay_cache_window_seconds(), 300);
        assert_eq!(
            minimal_config().replay_cache_max_entries(),
            DEFAULT_REPLAY_CACHE_MAX_ENTRIES as u64
        );
    }

    #[test]
    fn parses_replay_cache_limits() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
replay_cache_window_seconds = 120
replay_cache_max_entries = 8192
"#,
        )
        .unwrap();

        assert_eq!(config.replay_cache_window_seconds(), 120);
        assert_eq!(config.replay_cache_max_entries(), 8192);
    }

    #[test]
    fn rejects_unknown_server_config_fields() {
        let result = toml::from_str::<ServerConfig>(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
unknown = true
credentials = []
"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_unknown_limit_fields() {
        let result = toml::from_str::<ServerConfig>(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_streamz = 64
"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_zero_pre_auth_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_pre_auth_bytes = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_zero_frame_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_frame_size = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_zero_stream_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_streams = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_zero_buffered_bytes_per_flow_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_buffered_bytes_per_flow = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_zero_replay_cache_window() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
replay_cache_window_seconds = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_zero_replay_cache_entries() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
replay_cache_max_entries = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_unknown_credential_fields() {
        let result = toml::from_str::<ServerConfig>(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "secret"
policy_grop = "default"
"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_credential_key_id() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = ""
secret = "0123456789abcdef0123456789abcdef"
"#,
        )
        .unwrap();

        assert_eq!(config.credentials(), Err(AuthError::InvalidKeyIdLength));
    }

    #[test]
    fn rejects_long_credential_key_id() {
        let mut config = minimal_config();
        config.credentials.push(CredentialConfig {
            key_id: "k".repeat(65),
            secret: "0123456789abcdef0123456789abcdef".to_owned(),
            status: None,
            not_before: None,
            not_after: None,
            policy_group: None,
        });

        assert_eq!(config.credentials(), Err(AuthError::InvalidKeyIdLength));
    }

    #[test]
    fn rejects_short_credential_secret() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "too-short"
"#,
        )
        .unwrap();

        assert_eq!(config.credentials(), Err(AuthError::SecretTooShort));
    }

    #[test]
    fn accepts_disabled_credential_status() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "0123456789abcdef0123456789abcdef"
status = "disabled"
"#,
        )
        .unwrap();

        let credentials = config.credentials().unwrap();
        assert_eq!(credentials[0].status, CredentialStatus::Disabled);
    }

    #[test]
    fn rejects_unknown_credential_status() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "0123456789abcdef0123456789abcdef"
status = "disabledd"
"#,
        )
        .unwrap();

        assert_eq!(
            config.credentials(),
            Err(AuthError::InvalidCredentialStatus)
        );
    }
}
