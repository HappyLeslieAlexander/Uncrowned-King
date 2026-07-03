//! Server configuration.

use std::{error::Error, fs, path::Path};

use serde::Deserialize;
use uk_auth::{AuthError, Credential, CredentialStatus};
use uk_policy::PolicySet;

/// Server TOML configuration.
#[derive(Debug, Clone, Deserialize)]
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
}

/// Server resource limits.
#[derive(Debug, Clone, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct LimitConfig {
    /// Maximum pre-authentication frame payload.
    pub max_pre_auth_bytes: Option<u64>,
    /// Maximum post-authentication frame payload.
    pub max_frame_size: Option<u64>,
    /// Maximum concurrent TCP streams per authenticated session.
    pub max_streams: Option<u64>,
    /// Idle timeout for authenticated relay sessions in seconds.
    pub idle_timeout_seconds: Option<u64>,
}

/// One configured credential.
#[derive(Debug, Clone, Deserialize)]
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
        let status = if status_text == "active" {
            CredentialStatus::Active
        } else if status_text == "retired" {
            CredentialStatus::Retired
        } else {
            CredentialStatus::Disabled
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
}
