//! Server configuration.

use std::{collections::HashSet, error::Error, fmt, fs, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde::Deserialize;
use tokio::sync::Semaphore;
use uk_auth::{
    AuthError, Credential, CredentialStatus, DEFAULT_REPLAY_CACHE_MAX_ENTRIES,
    DEFAULT_REPLAY_CACHE_WINDOW_SECONDS, MIN_AUTH_RESPONSE_PAYLOAD_SIZE,
};
use uk_policy::PolicySet;
use uk_proto::{MAX_FRAME_PAYLOAD_SIZE, MIN_TCP_RELAY_FRAME_SIZE, validate_host_port_endpoint};

/// Default accepted authentication timestamp skew in seconds.
pub const DEFAULT_AUTH_SKEW_SECONDS: u64 = 30;

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
        let path = path.as_ref();
        validate_sensitive_file_permissions(path, "server config")?;
        let text = fs::read_to_string(path)
            .map_err(|err| format!("failed to read server config {}: {err}", path.display()))?;
        let mut config: Self = toml::from_str(&text)
            .map_err(|err| format!("invalid server config {}: {err}", path.display()))?;
        config.resolve_paths(config_base_dir(path));
        Ok(config)
    }

    /// Converts static credential config into auth records.
    pub fn credentials(&self) -> Result<Vec<Credential>, AuthError> {
        if self.credentials.is_empty() {
            return Err(AuthError::NoCredentials);
        }
        let mut seen_key_ids = HashSet::new();
        let mut credentials = Vec::with_capacity(self.credentials.len());
        for credential_config in &self.credentials {
            let credential = credential_config.to_credential()?;
            if !seen_key_ids.insert(credential.key_id.clone()) {
                return Err(AuthError::DuplicateCredentialKeyId);
            }
            credentials.push(credential);
        }
        Ok(credentials)
    }

    /// Loads the configured policy set. Missing policy config means deny-all.
    pub fn policy_set(&self) -> Result<PolicySet, Box<dyn Error + Send + Sync>> {
        let Some(path) = &self.policy_path else {
            return Ok(PolicySet::default());
        };
        let text = fs::read_to_string(path)
            .map_err(|err| format!("failed to read policy file {path}: {err}"))?;
        PolicySet::from_toml(&text)
            .map_err(|err| format!("invalid policy file {path}: {err}").into())
    }

    /// Validates configured resource limits.
    pub fn validate_limits(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        reject_zero_limit("max_pre_auth_bytes", self.max_pre_auth_bytes())?;
        reject_small_limit(
            "max_pre_auth_bytes",
            self.max_pre_auth_bytes(),
            MIN_AUTH_RESPONSE_PAYLOAD_SIZE,
        )?;
        reject_large_limit(
            "max_pre_auth_bytes",
            self.max_pre_auth_bytes(),
            MAX_FRAME_PAYLOAD_SIZE,
        )?;
        reject_zero_limit("max_frame_size", self.max_frame_size())?;
        reject_small_limit(
            "max_frame_size",
            self.max_frame_size(),
            MIN_TCP_RELAY_FRAME_SIZE,
        )?;
        reject_large_limit(
            "max_frame_size",
            self.max_frame_size(),
            MAX_FRAME_PAYLOAD_SIZE,
        )?;
        reject_zero_limit("max_sessions", self.max_sessions())?;
        reject_semaphore_permit_limit("max_sessions", self.max_sessions())?;
        reject_zero_limit("max_streams", self.max_streams())?;
        reject_large_limit("max_udp_flows", self.max_udp_flows(), self.max_streams())?;
        reject_zero_limit(
            "max_outbound_dials_per_session",
            self.max_outbound_dials_per_session(),
        )?;
        reject_semaphore_permit_limit(
            "max_outbound_dials_per_session",
            self.max_outbound_dials_per_session(),
        )?;
        reject_zero_limit(
            "max_buffered_bytes_per_session",
            self.max_buffered_bytes_per_session(),
        )?;
        reject_large_limit(
            "max_buffered_bytes_per_session",
            self.max_buffered_bytes_per_session(),
            MAX_FRAME_PAYLOAD_SIZE,
        )?;
        reject_zero_limit(
            "max_buffered_bytes_per_flow",
            self.max_buffered_bytes_per_flow(),
        )?;
        reject_large_limit(
            "max_buffered_bytes_per_flow",
            self.max_buffered_bytes_per_flow(),
            MAX_FRAME_PAYLOAD_SIZE,
        )?;
        reject_zero_limit(
            "replay_cache_window_seconds",
            self.replay_cache_window_seconds(),
        )?;
        reject_zero_limit("replay_cache_max_entries", self.replay_cache_max_entries())?;
        reject_usize_limit("replay_cache_max_entries", self.replay_cache_max_entries())?;
        Ok(())
    }

    /// Validates configured network endpoints without resolving DNS.
    pub fn validate_network_endpoints(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        validate_host_port_endpoint("listen", &self.listen)?;
        Ok(())
    }

    /// Validates local files that contain private material.
    pub fn validate_sensitive_paths(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        validate_sensitive_file_permissions(Path::new(&self.key_path), "private key")?;
        Ok(())
    }

    /// Allowed authentication timestamp skew in seconds.
    pub fn auth_skew_seconds(&self) -> u64 {
        self.auth_skew_seconds.unwrap_or(DEFAULT_AUTH_SKEW_SECONDS)
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

    /// Configured maximum concurrent carrier sessions accepted by the server.
    pub fn max_sessions(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_sessions)
            .unwrap_or(1024)
    }

    /// Configured maximum concurrent TCP streams per authenticated session.
    pub fn max_streams(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_streams)
            .unwrap_or(64)
    }

    /// Configured maximum concurrent UDP flows per authenticated session.
    /// Zero disables UDP relay.
    pub fn max_udp_flows(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_udp_flows)
            .unwrap_or_else(|| self.max_streams())
    }

    /// Configured maximum in-flight target socket dials per authenticated session.
    pub fn max_outbound_dials_per_session(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_outbound_dials_per_session)
            .unwrap_or(16)
    }

    /// Maximum queued client-to-target bytes across one authenticated session.
    pub fn max_buffered_bytes_per_session(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_buffered_bytes_per_session)
            .unwrap_or(MAX_FRAME_PAYLOAD_SIZE)
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

    /// UDP flow idle timeout in seconds. Zero disables it.
    pub fn udp_flow_idle_timeout_seconds(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.udp_flow_idle_timeout_seconds)
            .unwrap_or(120)
    }

    /// Graceful listener shutdown timeout in seconds. Zero disables it.
    pub fn shutdown_timeout_seconds(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.shutdown_timeout_seconds)
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

    fn resolve_paths(&mut self, base_dir: &Path) {
        self.cert_path = resolve_config_relative_path(base_dir, &self.cert_path);
        self.key_path = resolve_config_relative_path(base_dir, &self.key_path);
        self.policy_path = self
            .policy_path
            .as_deref()
            .map(|path| resolve_config_relative_path(base_dir, path));
    }
}

fn reject_zero_limit(name: &str, value: u64) -> Result<(), Box<dyn Error + Send + Sync>> {
    if value == 0 {
        Err(format!("{name} must be greater than zero").into())
    } else {
        Ok(())
    }
}

fn reject_small_limit(
    name: &str,
    value: u64,
    minimum: u64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if value < minimum {
        Err(format!("{name} must be at least {minimum}").into())
    } else {
        Ok(())
    }
}

fn reject_large_limit(
    name: &str,
    value: u64,
    maximum: u64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if value > maximum {
        Err(format!("{name} must be at most {maximum}").into())
    } else {
        Ok(())
    }
}

fn reject_semaphore_permit_limit(
    name: &str,
    value: u64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    reject_large_limit(name, value, Semaphore::MAX_PERMITS as u64)
}

fn reject_usize_limit(name: &str, value: u64) -> Result<(), Box<dyn Error + Send + Sync>> {
    usize::try_from(value)
        .map(|_| ())
        .map_err(|_| format!("{name} is too large for this platform").into())
}

/// Server resource limits.
#[derive(Debug, Clone, Default, Deserialize)]
#[allow(clippy::struct_field_names)]
#[serde(deny_unknown_fields)]
pub struct LimitConfig {
    /// Maximum pre-authentication frame payload.
    pub max_pre_auth_bytes: Option<u64>,
    /// Maximum post-authentication frame payload.
    pub max_frame_size: Option<u64>,
    /// Maximum concurrent carrier sessions accepted by the server.
    pub max_sessions: Option<u64>,
    /// Maximum concurrent TCP streams per authenticated session.
    pub max_streams: Option<u64>,
    /// Maximum concurrent UDP flows per authenticated session. Zero disables UDP relay.
    pub max_udp_flows: Option<u64>,
    /// Maximum in-flight target socket dials per authenticated session.
    pub max_outbound_dials_per_session: Option<u64>,
    /// Maximum queued client-to-target bytes across one authenticated session.
    pub max_buffered_bytes_per_session: Option<u64>,
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
    /// UDP flow idle timeout in seconds.
    pub udp_flow_idle_timeout_seconds: Option<u64>,
    /// Graceful listener shutdown timeout in seconds.
    pub shutdown_timeout_seconds: Option<u64>,
    /// Replay cache retention window in seconds.
    pub replay_cache_window_seconds: Option<u64>,
    /// Maximum accepted nonce pairs retained by the replay cache.
    pub replay_cache_max_entries: Option<u64>,
}

/// One configured credential.
#[derive(Clone, Deserialize)]
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

impl fmt::Debug for CredentialConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialConfig")
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .field("status", &self.status)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("policy_group", &self.policy_group)
            .finish()
    }
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
        if self
            .policy_group
            .as_deref()
            .is_some_and(invalid_policy_group)
        {
            return Err(AuthError::InvalidCredentialPolicyGroup);
        }
        if self
            .not_before
            .zip(self.not_after)
            .is_some_and(|(not_before, not_after)| not_before > not_after)
        {
            return Err(AuthError::InvalidCredentialValidityWindow);
        }
        let mut credential = Credential::active(self.key_id.as_bytes(), self.secret.as_bytes())?;
        credential.status = status;
        credential.not_before = self.not_before;
        credential.not_after = self.not_after;
        credential.policy_group.clone_from(&self.policy_group);
        Ok(credential)
    }
}

fn invalid_policy_group(group: &str) -> bool {
    group.is_empty() || group.bytes().any(|byte| byte.is_ascii_control())
}

#[cfg(unix)]
fn validate_sensitive_file_permissions(
    path: &Path,
    label: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let metadata = fs::metadata(path)
        .map_err(|err| format!("failed to read {label} metadata {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{label} {} must be a regular file", path.display()).into());
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "{label} {} must not be accessible by group or other users",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_sensitive_file_permissions(
    _path: &Path,
    _label: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Ok(())
}

fn config_base_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn resolve_config_relative_path(base_dir: &Path, value: &str) -> String {
    let path = Path::new(value);
    if path.is_absolute() {
        value.to_owned()
    } else {
        base_dir.join(path).to_string_lossy().into_owned()
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

    #[cfg(unix)]
    fn temp_path(label: &str, extension: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "uk-server-{label}-test-{}-{now}.{extension}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn write_temp_file(
        label: &str,
        extension: &str,
        contents: &str,
        mode: u32,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path(label, extension);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[cfg(unix)]
    fn write_temp_server_config(mode: u32) -> std::path::PathBuf {
        write_temp_file(
            "config",
            "toml",
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "0123456789abcdef0123456789abcdef"
"#,
            mode,
        )
    }

    #[cfg(unix)]
    #[test]
    fn load_accepts_owner_only_config_file() {
        let path = write_temp_server_config(0o600);

        let result = ServerConfig::load(&path);
        let _ = fs::remove_file(&path);

        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn load_resolves_file_paths_relative_to_config_file() {
        let path = write_temp_file(
            "config-with-policy",
            "toml",
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
policy_path = "policy.toml"

[[credentials]]
key_id = "client"
secret = "0123456789abcdef0123456789abcdef"
"#,
            0o600,
        );
        let base_dir = path.parent().unwrap();
        let expected_cert_path = base_dir.join("cert.pem").to_string_lossy().into_owned();
        let expected_key_path = base_dir.join("key.pem").to_string_lossy().into_owned();
        let expected_policy_path = base_dir.join("policy.toml").to_string_lossy().into_owned();

        let config = ServerConfig::load(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(config.cert_path, expected_cert_path);
        assert_eq!(config.key_path, expected_key_path);
        assert_eq!(
            config.policy_path.as_deref(),
            Some(expected_policy_path.as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_config_file_error_includes_path() {
        let path = temp_path("missing-config", "toml");
        let path_text = path.to_string_lossy().into_owned();

        let error = ServerConfig::load(&path).unwrap_err().to_string();

        assert!(error.contains(&path_text));
    }

    #[cfg(unix)]
    #[test]
    fn invalid_config_toml_error_includes_path() {
        let path = write_temp_file("invalid-config", "toml", "not = [valid", 0o600);
        let path_text = path.to_string_lossy().into_owned();

        let error = ServerConfig::load(&path).unwrap_err().to_string();
        let _ = fs::remove_file(&path);

        assert!(error.contains(&path_text));
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_group_readable_config_file() {
        let path = write_temp_server_config(0o644);
        let path_text = path.to_string_lossy().into_owned();

        let error = ServerConfig::load(&path).unwrap_err().to_string();
        let _ = fs::remove_file(&path);

        assert!(error.contains("server config"));
        assert!(error.contains(&path_text));
        assert!(error.contains("group or other"));
    }

    #[cfg(unix)]
    #[test]
    fn validates_owner_only_private_key_file() {
        let path = write_temp_file("key", "pem", "private key", 0o600);
        let mut config = minimal_config();
        config.key_path = path.to_string_lossy().into_owned();

        let result = config.validate_sensitive_paths();
        let _ = fs::remove_file(&path);

        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_private_key_file() {
        let path = write_temp_file("key", "pem", "private key", 0o644);
        let path_text = path.to_string_lossy().into_owned();
        let mut config = minimal_config();
        config.key_path = path.to_string_lossy().into_owned();

        let error = config.validate_sensitive_paths().unwrap_err().to_string();
        let _ = fs::remove_file(&path);

        assert!(error.contains("private key"));
        assert!(error.contains(&path_text));
        assert!(error.contains("group or other"));
    }

    #[test]
    fn defaults_auth_skew() {
        assert_eq!(
            minimal_config().auth_skew_seconds(),
            DEFAULT_AUTH_SKEW_SECONDS
        );
    }

    #[test]
    fn parses_auth_skew() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
auth_skew_seconds = 45
credentials = []
"#,
        )
        .unwrap();

        assert_eq!(config.auth_skew_seconds(), 45);
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
    fn defaults_udp_flow_limit_to_stream_limit() {
        assert_eq!(
            minimal_config().max_udp_flows(),
            minimal_config().max_streams()
        );
    }

    #[test]
    fn parses_udp_flow_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_streams = 8
max_udp_flows = 3
"#,
        )
        .unwrap();

        assert_eq!(config.max_udp_flows(), 3);
    }

    #[test]
    fn accepts_zero_udp_flow_limit_to_disable_udp() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_udp_flows = 0
"#,
        )
        .unwrap();

        assert_eq!(config.max_udp_flows(), 0);
        assert!(config.validate_limits().is_ok());
    }

    #[test]
    fn rejects_udp_flow_limit_above_stream_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_streams = 2
max_udp_flows = 3
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn defaults_buffered_bytes_per_session_limit() {
        assert_eq!(
            minimal_config().max_buffered_bytes_per_session(),
            MAX_FRAME_PAYLOAD_SIZE
        );
    }

    #[test]
    fn accepts_default_limits() {
        assert!(minimal_config().validate_limits().is_ok());
    }

    #[test]
    fn parses_example_server_config() {
        let config: ServerConfig = toml::from_str(include_str!("../../../examples/server.toml"))
            .expect("example server config should parse");

        assert_eq!(config.listen, "127.0.0.1:9443");
        assert_eq!(config.policy_path.as_deref(), Some("policy.toml"));
        assert!(config.validate_network_endpoints().is_ok());
        assert!(config.validate_limits().is_ok());
        assert_eq!(config.credentials().unwrap().len(), 1);
    }

    #[test]
    fn missing_policy_file_error_includes_path() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "uk-server-missing-policy-test-{}-{now}.toml",
            std::process::id()
        ));
        let path = path.to_string_lossy().into_owned();
        let mut config = minimal_config();
        config.policy_path = Some(path.clone());

        let error = config.policy_set().unwrap_err().to_string();

        assert!(error.contains(&path));
    }

    #[test]
    fn invalid_policy_file_error_includes_path() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "uk-server-invalid-policy-test-{}-{now}.toml",
            std::process::id()
        ));
        fs::write(&path, "not = [valid").unwrap();
        let path = path.to_string_lossy().into_owned();
        let mut config = minimal_config();
        config.policy_path = Some(path.clone());

        let error = config.policy_set().unwrap_err().to_string();
        let _ = fs::remove_file(&path);

        assert!(error.contains(&path));
    }

    #[test]
    fn accepts_domain_listen_addr() {
        let mut config = minimal_config();
        config.listen = "localhost:9443".to_owned();

        assert!(config.validate_network_endpoints().is_ok());
    }

    #[test]
    fn accepts_bracketed_ipv6_listen_addr() {
        let mut config = minimal_config();
        config.listen = "[::1]:9443".to_owned();

        assert!(config.validate_network_endpoints().is_ok());
    }

    #[test]
    fn rejects_listen_addr_without_port() {
        let mut config = minimal_config();
        config.listen = "localhost".to_owned();

        assert!(config.validate_network_endpoints().is_err());
    }

    #[test]
    fn rejects_zero_listen_addr_port() {
        let mut config = minimal_config();
        config.listen = "127.0.0.1:0".to_owned();

        assert!(config.validate_network_endpoints().is_err());
    }

    #[test]
    fn rejects_unbracketed_ipv6_listen_addr() {
        let mut config = minimal_config();
        config.listen = "::1:9443".to_owned();

        assert!(config.validate_network_endpoints().is_err());
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
    fn parses_buffered_bytes_per_session_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_buffered_bytes_per_session = 8192
"#,
        )
        .unwrap();

        assert_eq!(config.max_buffered_bytes_per_session(), 8192);
    }

    #[test]
    fn defaults_max_sessions_limit() {
        assert_eq!(minimal_config().max_sessions(), 1024);
    }

    #[test]
    fn parses_max_sessions_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_sessions = 128
"#,
        )
        .unwrap();

        assert_eq!(config.max_sessions(), 128);
    }

    #[test]
    fn defaults_outbound_dials_limit() {
        assert_eq!(minimal_config().max_outbound_dials_per_session(), 16);
    }

    #[test]
    fn parses_outbound_dials_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_outbound_dials_per_session = 4
"#,
        )
        .unwrap();

        assert_eq!(config.max_outbound_dials_per_session(), 4);
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
    fn defaults_udp_flow_idle_timeout() {
        assert_eq!(minimal_config().udp_flow_idle_timeout_seconds(), 120);
    }

    #[test]
    fn defaults_shutdown_timeout() {
        assert_eq!(minimal_config().shutdown_timeout_seconds(), 30);
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
    fn parses_udp_flow_idle_timeout() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
udp_flow_idle_timeout_seconds = 17
"#,
        )
        .unwrap();

        assert_eq!(config.udp_flow_idle_timeout_seconds(), 17);
    }

    #[test]
    fn parses_shutdown_timeout() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
shutdown_timeout_seconds = 9
"#,
        )
        .unwrap();

        assert_eq!(config.shutdown_timeout_seconds(), 9);
    }

    #[test]
    fn accepts_zero_timeout_limits() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
idle_timeout_seconds = 0
handshake_timeout_seconds = 0
target_connect_timeout_seconds = 0
tcp_half_close_timeout_seconds = 0
udp_flow_idle_timeout_seconds = 0
shutdown_timeout_seconds = 0
"#,
        )
        .unwrap();

        assert_eq!(config.idle_timeout_seconds(), 0);
        assert_eq!(config.handshake_timeout_seconds(), 0);
        assert_eq!(config.target_connect_timeout_seconds(), 0);
        assert_eq!(config.tcp_half_close_timeout_seconds(), 0);
        assert_eq!(config.udp_flow_idle_timeout_seconds(), 0);
        assert_eq!(config.shutdown_timeout_seconds(), 0);
        assert!(config.validate_limits().is_ok());
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
    fn rejects_too_small_pre_auth_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_pre_auth_bytes = 74
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_too_large_pre_auth_limit() {
        let config: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_pre_auth_bytes = {}
"#,
            MAX_FRAME_PAYLOAD_SIZE + 1
        ))
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
    fn rejects_too_small_frame_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_frame_size = 261
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_too_large_frame_limit() {
        let config: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_frame_size = {}
"#,
            MAX_FRAME_PAYLOAD_SIZE + 1
        ))
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
    fn rejects_zero_session_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_sessions = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_session_limit_above_semaphore_capacity() {
        let config: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_sessions = {}
"#,
            Semaphore::MAX_PERMITS as u64 + 1
        ))
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_zero_outbound_dials_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_outbound_dials_per_session = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_outbound_dials_limit_above_semaphore_capacity() {
        let config: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_outbound_dials_per_session = {}
"#,
            Semaphore::MAX_PERMITS as u64 + 1
        ))
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
    fn rejects_zero_buffered_bytes_per_session_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_buffered_bytes_per_session = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_too_large_buffered_bytes_per_flow_limit() {
        let config: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_buffered_bytes_per_flow = {}
"#,
            MAX_FRAME_PAYLOAD_SIZE + 1
        ))
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_too_large_buffered_bytes_per_session_limit() {
        let config: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_buffered_bytes_per_session = {}
"#,
            MAX_FRAME_PAYLOAD_SIZE + 1
        ))
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
    fn rejects_empty_credential_list() {
        let config = minimal_config();

        assert_eq!(config.credentials(), Err(AuthError::NoCredentials));
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
    fn credential_config_debug_redacts_secret() {
        let credential = CredentialConfig {
            key_id: "client".to_owned(),
            secret: "0123456789abcdef0123456789abcdef".to_owned(),
            status: Some("active".to_owned()),
            not_before: None,
            not_after: None,
            policy_group: Some("default".to_owned()),
        };

        let debug = format!("{credential:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("0123456789abcdef"));
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
    fn rejects_reversed_credential_validity_window() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "0123456789abcdef0123456789abcdef"
not_before = 20
not_after = 10
"#,
        )
        .unwrap();

        assert_eq!(
            config.credentials(),
            Err(AuthError::InvalidCredentialValidityWindow)
        );
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

    #[test]
    fn rejects_duplicate_credential_key_id() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client-a"
secret = "0123456789abcdef0123456789abcdef"

[[credentials]]
key_id = "client-a"
secret = "abcdef0123456789abcdef0123456789"
"#,
        )
        .unwrap();

        assert_eq!(
            config.credentials(),
            Err(AuthError::DuplicateCredentialKeyId)
        );
    }

    #[test]
    fn rejects_empty_credential_policy_group() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "0123456789abcdef0123456789abcdef"
policy_group = ""
"#,
        )
        .unwrap();

        assert_eq!(
            config.credentials(),
            Err(AuthError::InvalidCredentialPolicyGroup)
        );
    }

    #[test]
    fn rejects_control_character_credential_policy_group() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "0123456789abcdef0123456789abcdef"
policy_group = "bad\ngroup"
"#,
        )
        .unwrap();

        assert_eq!(
            config.credentials(),
            Err(AuthError::InvalidCredentialPolicyGroup)
        );
    }
}
