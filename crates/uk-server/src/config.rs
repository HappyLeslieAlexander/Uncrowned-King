//! Server configuration.

use std::{collections::HashSet, error::Error, fmt, fs, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::rate_limit::AuthRateLimitConfig;
use serde::Deserialize;
use tokio::sync::Semaphore;
use tracing::warn;
use uk_auth::{
    AuthError, Credential, CredentialStatus, DEFAULT_REPLAY_CACHE_MAX_ENTRIES,
    DEFAULT_REPLAY_CACHE_WINDOW_SECONDS, MIN_AUTH_RESPONSE_PAYLOAD_SIZE,
    warn_on_low_secret_diversity,
};
use uk_policy::PolicySet;
use uk_proto::{
    BindExposure, MAX_FRAME_PAYLOAD_SIZE, MAX_NEGOTIATED_FLOWS,
    MAX_NEGOTIATED_IDLE_TIMEOUT_SECONDS, MIN_TCP_RELAY_FRAME_SIZE, validate_host_port_endpoint,
    validate_observability_bind,
};
use zeroize::{Zeroize, Zeroizing};

/// Default accepted authentication timestamp skew in seconds.
pub const DEFAULT_AUTH_SKEW_SECONDS: u64 = 30;

/// Default global concurrent stream budget across all authenticated sessions.
pub const DEFAULT_MAX_TOTAL_STREAMS: u64 = 65_536;

/// Default global client-to-target buffered-byte budget across all sessions.
pub const DEFAULT_MAX_TOTAL_BUFFERED_BYTES: u64 = 512 * 1024 * 1024;

/// Largest accepted global limit. One TiB is far above any realistic host and
/// only prevents absurd values from overflowing platform conversions.
const MAX_TOTAL_LIMIT: u64 = 1024 * 1024 * 1024 * 1024;

/// Largest accepted authentication timestamp skew in seconds.
///
/// The skew is the freshness guarantee for challenges and responses, so a large
/// value effectively disables timestamp checking. Five minutes is generous for
/// NTP-synchronised hosts while keeping the replay window small.
pub const MAX_AUTH_SKEW_SECONDS: u64 = 300;

/// Server TOML configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// TCP listen address for the TLS/TCP carrier.
    pub listen: String,
    /// Optional UDP listen address for the QUIC carrier. When set, the server
    /// accepts QUIC connections here in addition to the TLS/TCP listener.
    pub quic_listen: Option<String>,
    /// Optional unauthenticated HTTP health and metrics listen address.
    pub observability_listen: Option<String>,
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
    /// Optional transport masking. Disabled by default.
    pub masking: Option<MaskingConfig>,
}

impl ServerConfig {
    /// Loads a server config from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path = path.as_ref();
        validate_sensitive_file_permissions(path, "server config")?;
        // The file holds every credential secret in cleartext, so the buffer is
        // scrubbed when it drops rather than being left in freed heap. Only this
        // buffer is reachable: serde's own intermediate allocations are not.
        let text =
            Zeroizing::new(fs::read_to_string(path).map_err(|err| {
                format!("failed to read server config {}: {err}", path.display())
            })?);
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
        validate_owner_only_writable_file(Path::new(path), "policy file")?;
        let text = fs::read_to_string(path)
            .map_err(|err| format!("failed to read policy file {path}: {err}"))?;
        let policy_set = PolicySet::from_toml(&text)
            .map_err(|err| format!("invalid policy file {path}: {err}"))?;
        if policy_set.has_unrestricted_private_allow() {
            warn!(
                event = "policy.unrestricted_private",
                path = %path,
                "policy file contains allow rules with explicit 'private = true' \
                 that are not preceded by a blanket 'deny private = true' rule; \
                 these rules permit private/loopback targets (SSRF surface), \
                 ensure this is intended"
            );
        }
        Ok(policy_set)
    }

    /// Validates configured resource limits.
    pub fn validate_limits(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.validate_masking()?;
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
        reject_zero_limit("max_handshakes", self.max_handshakes())?;
        reject_semaphore_permit_limit("max_handshakes", self.max_handshakes())?;
        reject_zero_limit("max_streams", self.max_streams())?;
        reject_large_limit("max_streams", self.max_streams(), MAX_NEGOTIATED_FLOWS)?;
        reject_large_limit("max_udp_flows", self.max_udp_flows(), self.max_streams())?;
        reject_large_limit("max_udp_flows", self.max_udp_flows(), MAX_NEGOTIATED_FLOWS)?;
        reject_zero_limit("max_total_streams", self.max_total_streams())?;
        reject_large_limit(
            "max_total_streams",
            self.max_total_streams(),
            MAX_TOTAL_LIMIT,
        )?;
        reject_usize_limit("max_total_streams", self.max_total_streams())?;
        reject_zero_limit("max_total_buffered_bytes", self.max_total_buffered_bytes())?;
        reject_large_limit(
            "max_total_buffered_bytes",
            self.max_total_buffered_bytes(),
            MAX_TOTAL_LIMIT,
        )?;
        reject_usize_limit("max_total_buffered_bytes", self.max_total_buffered_bytes())?;
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
        reject_zero_limit("auth_skew_seconds", self.auth_skew_seconds())?;
        reject_large_limit(
            "auth_skew_seconds",
            self.auth_skew_seconds(),
            MAX_AUTH_SKEW_SECONDS,
        )?;
        reject_large_limit(
            "idle_timeout_seconds",
            self.idle_timeout_seconds(),
            MAX_NEGOTIATED_IDLE_TIMEOUT_SECONDS,
        )?;
        self.validate_replay_cache_covers_auth_skew()?;
        if let Some(buf_size) = self.limits.as_ref().and_then(|l| l.relay_buffer_size) {
            reject_small_limit("relay_buffer_size", buf_size as u64, 1024)?;
            reject_large_limit("relay_buffer_size", buf_size as u64, 1024 * 1024)?;
        }
        self.validate_quic_window_limits()?;
        self.validate_auth_rate_limits()?;
        Ok(())
    }

    fn validate_quic_window_limits(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(stream_window) = self
            .limits
            .as_ref()
            .and_then(|l| l.quic_stream_receive_window)
        {
            reject_small_limit(
                "quic_stream_receive_window",
                stream_window,
                u64::from(crate::quic::MIN_QUIC_RECEIVE_WINDOW),
            )?;
            reject_large_limit(
                "quic_stream_receive_window",
                stream_window,
                u64::from(crate::quic::MAX_QUIC_RECEIVE_WINDOW),
            )?;
        }
        if let Some(conn_window) = self
            .limits
            .as_ref()
            .and_then(|l| l.quic_connection_receive_window)
        {
            reject_small_limit(
                "quic_connection_receive_window",
                conn_window,
                u64::from(crate::quic::MIN_QUIC_RECEIVE_WINDOW),
            )?;
            reject_large_limit(
                "quic_connection_receive_window",
                conn_window,
                u64::from(crate::quic::MAX_QUIC_RECEIVE_WINDOW),
            )?;
        }
        if self.quic_connection_receive_window() < self.quic_stream_receive_window() {
            return Err(
                "quic_connection_receive_window must be greater than or equal to quic_stream_receive_window"
                    .into(),
            );
        }
        Ok(())
    }

    fn validate_auth_rate_limits(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let rate_limit = self.auth_rate_limit_config();
        reject_large_limit(
            "auth_rate_limit_failures",
            u64::from(rate_limit.max_failures),
            100_000,
        )?;
        if rate_limit.max_failures > 0 {
            reject_zero_limit("auth_rate_limit_window_seconds", rate_limit.window_secs)?;
            reject_zero_limit("auth_rate_limit_ban_seconds", rate_limit.ban_secs)?;
        }
        reject_large_limit(
            "auth_rate_limit_window_seconds",
            rate_limit.window_secs,
            2_592_000,
        )?;
        reject_large_limit(
            "auth_rate_limit_ban_seconds",
            rate_limit.ban_secs,
            2_592_000,
        )?;
        // Each allowlist entry must parse as a CIDR (or bare IP) now, so a
        // typo cannot silently limit nothing.
        for entry in self.auth_rate_limit_allowlist() {
            if parse_allowlist_entry(&entry).is_none() {
                return Err(format!(
                    "auth_rate_limit_allowlist entry {entry:?} is not a valid CIDR or IP"
                )
                .into());
            }
        }
        Ok(())
    }

    /// Networks exempt from authentication failure rate limiting.
    ///
    /// Failures from these peers (a shared NAT egress, a monitoring prober)
    /// are neither counted nor banned; every other source keeps the default
    /// `5 failures / 60s -> 300s ban` protection. Changing the list requires
    /// a restart (it is part of the static admission path).
    /// Validates the `[masking]` section.
    fn validate_masking(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(masking) = &self.masking {
            if let Some(replay_identities) = masking.replay_identities {
                reject_small_limit("masking.replay_identities", replay_identities as u64, 1024)?;
                reject_large_limit(
                    "masking.replay_identities",
                    replay_identities as u64,
                    uk_mask::MAX_REPLAY_IDENTITIES as u64,
                )?;
            }
            if masking.enabled.unwrap_or(false) && self.credentials.is_empty() {
                return Err("masking.enabled requires at least one credential".into());
            }
            if masking.quic.unwrap_or(false) {
                let Some(key_id) = &masking.quic_key_id else {
                    return Err(
                        "masking.quic_key_id is required when masking.quic is enabled".into(),
                    );
                };
                let matches = self
                    .credentials
                    .iter()
                    .any(|credential| &credential.key_id == key_id);
                if !matches {
                    return Err(format!(
                        "masking.quic_key_id {key_id:?} does not match any configured credential"
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    /// Configured authentication-failure rate-limit allowlist entries.
    pub fn auth_rate_limit_allowlist(&self) -> Vec<String> {
        self.limits
            .as_ref()
            .and_then(|limits| limits.auth_rate_limit_allowlist.clone())
            .unwrap_or_default()
    }

    /// The allowlist parsed into CIDRs; only valid after `validate_limits`.
    pub fn auth_rate_limit_allowlist_cidrs(&self) -> Vec<uk_policy::Cidr> {
        self.auth_rate_limit_allowlist()
            .iter()
            .filter_map(|entry| parse_allowlist_entry(entry))
            .collect()
    }

    /// Ensures the replay cache outlives the whole accepted timestamp window.
    ///
    /// A response is accepted anywhere in `now ± auth_skew_seconds`, so a cache
    /// that forgets a nonce pair sooner than `2 * auth_skew_seconds` would let
    /// that pair be replayed while it is still considered fresh.
    fn validate_replay_cache_covers_auth_skew(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let skew = self.auth_skew_seconds();
        let required_window = skew.saturating_mul(2);
        if self.replay_cache_window_seconds() < required_window {
            return Err(format!(
                "replay_cache_window_seconds ({}) must be at least twice auth_skew_seconds ({skew}), that is {required_window}",
                self.replay_cache_window_seconds()
            )
            .into());
        }
        Ok(())
    }

    /// Validates configured network endpoints without resolving DNS.
    pub fn validate_network_endpoints(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        validate_host_port_endpoint("listen", &self.listen)?;
        if let Some(listen) = &self.quic_listen {
            validate_host_port_endpoint("quic_listen", listen)?;
            listen
                .parse::<std::net::SocketAddr>()
                .map_err(|err| format!("invalid quic_listen address {listen}: {err}"))?;
        }
        if let Some(listen) = &self.observability_listen {
            // The probe endpoint is unauthenticated: wildcard binds are
            // rejected outright, and any other non-loopback bind gets a
            // loud warning so the operator consciously keeps it internal.
            match validate_observability_bind("observability_listen", listen)? {
                BindExposure::Loopback => {}
                BindExposure::NonLoopback => warn!(
                    event = "server.config.observability_non_loopback",
                    listen = listen.as_str(),
                    "observability_listen is bound to a non-loopback address; \
                     the /metrics and probe endpoints are unauthenticated, \
                     keep this listener on an internal network"
                ),
            }
        }
        Ok(())
    }

    /// Validates local files that contain private material.
    pub fn validate_sensitive_paths(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Only the private key is checked: the certificate is public material
        // by design (it is presented to every connecting peer during the
        // handshake), so demanding 0600 on it would provide no
        // confidentiality benefit while breaking standard deployments
        // (Kubernetes Secret mounts default to 0444/0644, system trust
        // stores are world-readable). See the PR discussion on AGENTS.md's
        // certificate-permission line.
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

    /// Configured maximum concurrent unauthenticated TLS/auth handshakes.
    pub fn max_handshakes(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_handshakes)
            .unwrap_or_else(|| self.max_sessions())
    }

    /// Configured maximum concurrent TCP streams per authenticated session.
    pub fn max_streams(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_streams)
            .unwrap_or(64)
    }

    /// Maximum concurrent streams across all authenticated sessions.
    pub fn max_total_streams(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_total_streams)
            .unwrap_or(DEFAULT_MAX_TOTAL_STREAMS)
    }

    /// Maximum client-to-target bytes buffered across all authenticated sessions.
    pub fn max_total_buffered_bytes(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.max_total_buffered_bytes)
            .unwrap_or(DEFAULT_MAX_TOTAL_BUFFERED_BYTES)
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

    /// Deadline for a single frame write to the client carrier. Zero disables it.
    ///
    /// Carrier writes are serialised behind one lock, so a client that stops
    /// reading would otherwise park the writer — and everything queued behind
    /// it — for the lifetime of the process, pinning the session slot.
    pub fn carrier_write_timeout_seconds(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.carrier_write_timeout_seconds)
            .unwrap_or(30)
    }

    /// TCP keepalive idle time in seconds for accepted carriers. Zero disables it.
    ///
    /// Detects a peer that disappeared without closing (power loss, a NAT that
    /// dropped the mapping). Such a session is otherwise only reclaimed at
    /// `idle_timeout_seconds`, which is far longer. QUIC carriers do not need
    /// this: quinn enforces its own transport idle timeout.
    pub fn tcp_keepalive_seconds(&self) -> u64 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.tcp_keepalive_seconds)
            .unwrap_or(60)
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

    /// Relay chunk buffer size in bytes. Default: 16 KiB (16384).
    pub fn relay_buffer_size(&self) -> usize {
        self.limits
            .as_ref()
            .and_then(|limits| limits.relay_buffer_size)
            .unwrap_or(16 * 1024)
    }

    /// Rate limiting configuration for failed authentication attempts.
    pub fn auth_rate_limit_config(&self) -> AuthRateLimitConfig {
        let limits = self.limits.as_ref();
        AuthRateLimitConfig {
            max_failures: limits.and_then(|l| l.auth_rate_limit_failures).unwrap_or(5),
            window_secs: limits
                .and_then(|l| l.auth_rate_limit_window_seconds)
                .unwrap_or(60),
            ban_secs: limits
                .and_then(|l| l.auth_rate_limit_ban_seconds)
                .unwrap_or(300),
        }
    }

    /// Whether transport masking is enabled for the TLS/TCP carrier.
    pub fn masking_enabled(&self) -> bool {
        self.masking
            .as_ref()
            .and_then(|masking| masking.enabled)
            .unwrap_or(false)
    }

    /// Whether transport masking is enabled for the QUIC carrier.
    pub fn masking_quic_enabled(&self) -> bool {
        self.masking
            .as_ref()
            .is_some_and(|masking| masking.quic.unwrap_or(false))
    }

    /// The credential whose keys mask the QUIC endpoint (validated at config
    /// load when `masking.quic` is on).
    pub fn masking_quic_key_id(&self) -> Option<&str> {
        self.masking
            .as_ref()
            .and_then(|masking| masking.quic_key_id.as_deref())
    }

    /// Replay registry capacity in tracked client identities.
    pub fn masking_replay_identities(&self) -> usize {
        self.masking
            .as_ref()
            .and_then(|masking| masking.replay_identities)
            .unwrap_or(uk_mask::DEFAULT_REPLAY_IDENTITIES)
    }

    /// QUIC stream receive window in bytes.
    pub fn quic_stream_receive_window(&self) -> u32 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.quic_stream_receive_window)
            .map_or(crate::quic::DEFAULT_QUIC_STREAM_RECEIVE_WINDOW, |w| {
                w as u32
            })
    }

    /// QUIC connection receive window in bytes.
    pub fn quic_connection_receive_window(&self) -> u32 {
        self.limits
            .as_ref()
            .and_then(|limits| limits.quic_connection_receive_window)
            .map_or(crate::quic::DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW, |w| {
                w as u32
            })
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

fn parse_allowlist_entry(entry: &str) -> Option<uk_policy::Cidr> {
    if let Ok(cidr) = entry.parse::<uk_policy::Cidr>() {
        return Some(cidr);
    }
    match entry.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => uk_policy::Cidr::new_v4(ip, 32).ok(),
        Ok(std::net::IpAddr::V6(ip)) => uk_policy::Cidr::new_v6(ip, 128).ok(),
        Err(_) => None,
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

/// Server transport masking configuration. Changing any field requires a
/// restart; mask keys are derived per credential, so credential reloads
/// rotate masking authority for new connections without touching this section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaskingConfig {
    /// Enable masking on the TLS/TCP carrier listener.
    pub enabled: Option<bool>,
    /// Replay registry capacity in tracked client identities. Default 16384.
    pub replay_identities: Option<usize>,
    /// Enable masking on the QUIC carrier listener. UDP datagrams carry no
    /// per-packet authentication, so the endpoint is masked under exactly one
    /// designated credential's keys.
    pub quic: Option<bool>,
    /// The `key_id` whose keys mask the QUIC endpoint. Required when
    /// `quic = true`; clients must use the same credential.
    pub quic_key_id: Option<String>,
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
    /// Maximum concurrent unauthenticated TLS/auth handshakes.
    pub max_handshakes: Option<u64>,
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
    /// Maximum concurrent streams across all authenticated sessions.
    pub max_total_streams: Option<u64>,
    /// Maximum queued client-to-target bytes across all authenticated sessions.
    pub max_total_buffered_bytes: Option<u64>,
    /// TLS and authentication handshake timeout in seconds.
    pub handshake_timeout_seconds: Option<u64>,
    /// DNS resolution and TCP dial timeout for target opens.
    pub target_connect_timeout_seconds: Option<u64>,
    /// TCP half-close drain timeout in seconds.
    pub tcp_half_close_timeout_seconds: Option<u64>,
    /// Deadline for a single frame write to the client carrier.
    pub carrier_write_timeout_seconds: Option<u64>,
    /// TCP keepalive idle time in seconds for accepted carriers.
    pub tcp_keepalive_seconds: Option<u64>,
    /// UDP flow idle timeout in seconds.
    pub udp_flow_idle_timeout_seconds: Option<u64>,
    /// Graceful listener shutdown timeout in seconds.
    pub shutdown_timeout_seconds: Option<u64>,
    /// Replay cache retention window in seconds.
    pub replay_cache_window_seconds: Option<u64>,
    /// Maximum accepted nonce pairs retained by the replay cache.
    pub replay_cache_max_entries: Option<u64>,
    /// Relay chunk buffer size in bytes. Default: 16 KiB (16384).
    pub relay_buffer_size: Option<usize>,
    /// Maximum authentication failures from an IP within the window before temporary ban.
    pub auth_rate_limit_failures: Option<u32>,
    /// Time window for accumulating authentication failures in seconds.
    pub auth_rate_limit_window_seconds: Option<u64>,
    /// Ban duration in seconds when auth_rate_limit_failures is exceeded.
    pub auth_rate_limit_ban_seconds: Option<u64>,
    /// Networks (CIDR or bare IP strings) exempt from authentication failure
    /// rate limiting, e.g. a shared NAT egress. Empty by default; changing it
    /// requires a restart.
    pub auth_rate_limit_allowlist: Option<Vec<String>>,
    /// QUIC stream receive window in bytes. Default: 1 MiB (1048576). Range: 64 KiB .. 16 MiB.
    pub quic_stream_receive_window: Option<u64>,
    /// QUIC connection receive window in bytes. Default: 1 MiB (1048576). Range: 64 KiB .. 16 MiB.
    pub quic_connection_receive_window: Option<u64>,
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
    pub(crate) fn zeroize_secret(&mut self) {
        self.secret.zeroize();
    }

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
        warn_on_low_secret_diversity(self.secret.as_bytes());
        let mut credential = Credential::active(self.key_id.as_bytes(), self.secret.as_bytes())?;
        credential.status = status;
        credential.not_before = self.not_before;
        credential.not_after = self.not_after;
        credential.policy_group.clone_from(&self.policy_group);
        Ok(credential)
    }
}

impl Drop for CredentialConfig {
    fn drop(&mut self) {
        self.zeroize_secret();
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
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to read {label} metadata {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{label} {} must be a regular file, not a symlink or directory",
            path.display()
        )
        .into());
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

/// Rejects a file that another local user could rewrite.
///
/// Unlike [`validate_sensitive_file_permissions`] this does not require the file
/// to be secret; a policy file holds no key material and is commonly world
/// readable but root owned. What matters is integrity, so only group and other
/// *write* bits are refused. The path itself must be a regular file, which also
/// rejects a symlink planted where the policy file is expected.
#[cfg(unix)]
fn validate_owner_only_writable_file(
    path: &Path,
    label: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to read {label} metadata {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{label} {} must be a regular file, not a symlink or directory",
            path.display()
        )
        .into());
    }
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(format!(
            "{label} {} must not be writable by group or other users",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only_writable_file(
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
            quic_listen: None,
            observability_listen: None,
            cert_path: "cert.pem".to_owned(),
            key_path: "key.pem".to_owned(),
            auth_skew_seconds: None,
            limits: None,
            policy_path: None,
            credentials: Vec::new(),
            masking: None,
        }
    }

    #[cfg(unix)]
    const VALID_POLICY_TOML: &str = r#"
[[rules]]
action = "allow"
domain = "example.com"
port_start = 443
port_end = 443
"#;

    #[cfg(unix)]
    static NEXT_TEMP_PATH_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[cfg(unix)]
    fn temp_path(label: &str, extension: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path_id = NEXT_TEMP_PATH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "uk-server-{label}-test-{}-{now}-{path_id}.{extension}",
            std::process::id(),
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

    #[test]
    fn config_file_buffer_is_scrubbed_after_parsing() {
        // `load` reads the file into this wrapper: the parse borrows it and the
        // wrapper scrubs the cleartext on drop. Freed heap cannot be inspected
        // from safe Rust, so this pins the mechanism rather than the aftermath.
        let mut text = Zeroizing::new(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "0123456789abcdef0123456789abcdef"
"#
            .to_owned(),
        );

        let config: ServerConfig = toml::from_str(&text).unwrap();
        assert_eq!(config.credentials().unwrap().len(), 1);

        text.zeroize();

        assert!(text.is_empty());
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
    fn parses_observability_listener() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:9443"
observability_listen = "127.0.0.1:9090"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []
"#,
        )
        .unwrap();

        assert_eq!(
            config.observability_listen.as_deref(),
            Some("127.0.0.1:9090")
        );
        assert!(config.validate_network_endpoints().is_ok());
    }

    #[test]
    fn rejects_invalid_observability_listener() {
        let mut config = minimal_config();
        config.listen = "127.0.0.1:9443".to_owned();
        config.observability_listen = Some("127.0.0.1".to_owned());

        let error = config.validate_network_endpoints().unwrap_err().to_string();

        assert!(error.contains("observability_listen"));
    }

    #[test]
    fn rejects_wildcard_observability_listener() {
        for wildcard in ["0.0.0.0:9090", "[::]:9090"] {
            let mut config = minimal_config();
            config.listen = "127.0.0.1:9443".to_owned();
            config.observability_listen = Some(wildcard.to_owned());

            let error = config.validate_network_endpoints().unwrap_err().to_string();

            assert!(
                error.contains("observability_listen") && error.contains("wildcard"),
                "unexpected error for {wildcard}: {error}"
            );
        }
    }

    #[test]
    fn warns_but_accepts_non_loopback_observability_listener() {
        let mut config = minimal_config();
        config.listen = "127.0.0.1:9443".to_owned();
        config.observability_listen = Some("10.0.0.5:9090".to_owned());

        // Accepted (internal cluster networks are legitimate), but the
        // operator gets a warning via tracing.
        assert!(config.validate_network_endpoints().is_ok());
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
    fn rejects_invalid_auth_rate_limit_allowlist_entries() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            auth_rate_limit_allowlist: Some(vec![
                "198.51.100.0/24".to_owned(),
                "not-a-cidr".to_owned(),
            ]),
            ..LimitConfig::default()
        });
        let err = config.validate_limits().unwrap_err();
        assert!(err.to_string().contains("not-a-cidr"), "got: {err}");
    }

    #[test]
    fn accepts_valid_auth_rate_limit_allowlist() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            auth_rate_limit_allowlist: Some(vec![
                "198.51.100.0/24".to_owned(),
                "2001:db8::/32".to_owned(),
                "203.0.113.7".to_owned(),
            ]),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_ok());
        assert_eq!(config.auth_rate_limit_allowlist_cidrs().len(), 3);
    }

    #[test]
    fn rejects_protocol_limit_above_wire_cap() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_streams: Some(MAX_NEGOTIATED_FLOWS + 1),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_streams: Some(MAX_NEGOTIATED_FLOWS),
            max_udp_flows: Some(MAX_NEGOTIATED_FLOWS + 1),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_idle_timeout_above_wire_cap() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            idle_timeout_seconds: Some(MAX_NEGOTIATED_IDLE_TIMEOUT_SECONDS + 1),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_zero_global_limits() {
        for limits in [
            LimitConfig {
                max_total_streams: Some(0),
                ..LimitConfig::default()
            },
            LimitConfig {
                max_total_buffered_bytes: Some(0),
                ..LimitConfig::default()
            },
        ] {
            let mut config = minimal_config();
            config.limits = Some(limits);
            assert!(config.validate_limits().is_err());
        }
    }

    #[test]
    fn defaults_global_limits() {
        let config = minimal_config();
        assert_eq!(config.max_total_streams(), DEFAULT_MAX_TOTAL_STREAMS);
        assert_eq!(
            config.max_total_buffered_bytes(),
            DEFAULT_MAX_TOTAL_BUFFERED_BYTES
        );
        assert!(config.validate_limits().is_ok());
    }

    #[test]
    fn accepts_protocol_limits_at_wire_cap() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_streams: Some(MAX_NEGOTIATED_FLOWS),
            max_udp_flows: Some(MAX_NEGOTIATED_FLOWS),
            idle_timeout_seconds: Some(MAX_NEGOTIATED_IDLE_TIMEOUT_SECONDS),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_ok());
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
    fn accepts_socket_addr_quic_listen() {
        let mut config = minimal_config();
        config.listen = "127.0.0.1:9443".to_owned();
        config.quic_listen = Some("127.0.0.1:9443".to_owned());

        assert!(config.validate_network_endpoints().is_ok());
    }

    #[test]
    fn rejects_domain_quic_listen() {
        let mut config = minimal_config();
        config.listen = "127.0.0.1:9443".to_owned();
        config.quic_listen = Some("localhost:9443".to_owned());

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
    fn defaults_max_handshakes_limit_to_session_limit() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_sessions: Some(17),
            ..LimitConfig::default()
        });

        assert_eq!(config.max_handshakes(), 17);
    }

    #[test]
    fn parses_max_handshakes_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_sessions = 128
max_handshakes = 12
"#,
        )
        .unwrap();

        assert_eq!(config.max_handshakes(), 12);
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
    fn defaults_carrier_write_timeout() {
        assert_eq!(minimal_config().carrier_write_timeout_seconds(), 30);
    }

    #[test]
    fn parses_carrier_write_timeout() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
carrier_write_timeout_seconds = 9
"#,
        )
        .unwrap();

        assert_eq!(config.carrier_write_timeout_seconds(), 9);
        config.validate_limits().unwrap();
    }

    #[test]
    fn accepts_disabled_carrier_write_timeout() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
carrier_write_timeout_seconds = 0
"#,
        )
        .unwrap();

        assert_eq!(config.carrier_write_timeout_seconds(), 0);
        config.validate_limits().unwrap();
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
    fn rejects_invalid_auth_rate_limit_config() {
        let base = minimal_config();

        // Zero max_failures disables rate limiting and is valid.
        let mut config = base.clone();
        config.limits = Some(LimitConfig {
            auth_rate_limit_failures: Some(0),
            auth_rate_limit_window_seconds: Some(0),
            auth_rate_limit_ban_seconds: Some(0),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_ok());

        let mut config = base.clone();
        config.limits = Some(LimitConfig {
            auth_rate_limit_failures: Some(1_000_000),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = base.clone();
        config.limits = Some(LimitConfig {
            auth_rate_limit_window_seconds: Some(0),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = base.clone();
        config.limits = Some(LimitConfig {
            auth_rate_limit_ban_seconds: Some(0),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = base.clone();
        config.limits = Some(LimitConfig {
            auth_rate_limit_window_seconds: Some(2_592_001),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = base.clone();
        config.limits = Some(LimitConfig {
            auth_rate_limit_ban_seconds: Some(2_592_001),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = base;
        config.limits = Some(LimitConfig {
            auth_rate_limit_failures: Some(10),
            auth_rate_limit_window_seconds: Some(60),
            auth_rate_limit_ban_seconds: Some(300),
            ..LimitConfig::default()
        });
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
    fn rejects_zero_handshake_limit() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_handshakes = 0
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn rejects_handshake_limit_above_semaphore_capacity() {
        let config: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
credentials = []

[limits]
max_handshakes = {}
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
    fn rejects_zero_auth_skew() {
        let mut config = minimal_config();
        config.auth_skew_seconds = Some(0);

        let error = config.validate_limits().unwrap_err().to_string();

        assert!(error.contains("auth_skew_seconds"));
        assert!(error.contains("greater than zero"));
    }

    #[test]
    fn rejects_too_large_auth_skew() {
        let mut config = minimal_config();
        config.auth_skew_seconds = Some(MAX_AUTH_SKEW_SECONDS + 1);
        config.limits = Some(LimitConfig {
            replay_cache_window_seconds: Some(u64::MAX),
            ..LimitConfig::default()
        });

        let error = config.validate_limits().unwrap_err().to_string();

        assert!(error.contains("auth_skew_seconds"));
        assert!(error.contains(&MAX_AUTH_SKEW_SECONDS.to_string()));
    }

    #[test]
    fn rejects_unbounded_auth_skew() {
        let mut config = minimal_config();
        config.auth_skew_seconds = Some(u64::MAX);

        assert!(config.validate_limits().is_err());
    }

    #[test]
    fn accepts_auth_skew_at_the_documented_ceiling() {
        let mut config = minimal_config();
        config.auth_skew_seconds = Some(MAX_AUTH_SKEW_SECONDS);
        config.limits = Some(LimitConfig {
            replay_cache_window_seconds: Some(MAX_AUTH_SKEW_SECONDS * 2),
            ..LimitConfig::default()
        });

        assert!(config.validate_limits().is_ok());
    }

    #[test]
    fn rejects_replay_cache_window_shorter_than_twice_auth_skew() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
auth_skew_seconds = 60
credentials = []

[limits]
replay_cache_window_seconds = 119
"#,
        )
        .unwrap();

        let error = config.validate_limits().unwrap_err().to_string();

        assert!(error.contains("replay_cache_window_seconds"));
        assert!(error.contains("auth_skew_seconds"));
    }

    #[test]
    fn accepts_replay_cache_window_of_exactly_twice_auth_skew() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"
auth_skew_seconds = 60
credentials = []

[limits]
replay_cache_window_seconds = 120
"#,
        )
        .unwrap();

        assert!(config.validate_limits().is_ok());
    }

    #[test]
    fn validates_quic_receive_windows() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            quic_stream_receive_window: Some(u64::from(crate::quic::MIN_QUIC_RECEIVE_WINDOW) - 1),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            quic_stream_receive_window: Some(u64::from(crate::quic::MAX_QUIC_RECEIVE_WINDOW) + 1),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            quic_connection_receive_window: Some(
                u64::from(crate::quic::MIN_QUIC_RECEIVE_WINDOW) - 1,
            ),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            quic_connection_receive_window: Some(
                u64::from(crate::quic::MAX_QUIC_RECEIVE_WINDOW) + 1,
            ),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_err());

        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            quic_stream_receive_window: Some(2 * 1024 * 1024),
            quic_connection_receive_window: Some(1024 * 1024),
            ..LimitConfig::default()
        });
        let err = config.validate_limits().unwrap_err().to_string();
        assert!(err.contains("quic_connection_receive_window must be greater than or equal to quic_stream_receive_window"));

        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            quic_stream_receive_window: Some(2 * 1024 * 1024),
            quic_connection_receive_window: Some(4 * 1024 * 1024),
            ..LimitConfig::default()
        });
        assert!(config.validate_limits().is_ok());
        assert_eq!(config.quic_stream_receive_window(), 2 * 1024 * 1024);
        assert_eq!(config.quic_connection_receive_window(), 4 * 1024 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn policy_set_accepts_world_readable_owner_only_writable_policy_file() {
        let path = write_temp_file("policy", "toml", VALID_POLICY_TOML, 0o644);
        let mut config = minimal_config();
        config.policy_path = Some(path.to_string_lossy().into_owned());

        let result = config.policy_set();
        let _ = fs::remove_file(&path);

        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn policy_set_rejects_group_writable_policy_file() {
        let path = write_temp_file("policy", "toml", VALID_POLICY_TOML, 0o664);
        let path_text = path.to_string_lossy().into_owned();
        let mut config = minimal_config();
        config.policy_path = Some(path_text.clone());

        let error = config.policy_set().unwrap_err().to_string();
        let _ = fs::remove_file(&path);

        assert!(error.contains("policy file"));
        assert!(error.contains(&path_text));
        assert!(error.contains("writable by group or other"));
    }

    #[cfg(unix)]
    #[test]
    fn policy_set_rejects_world_writable_policy_file() {
        let path = write_temp_file("policy", "toml", VALID_POLICY_TOML, 0o646);
        let mut config = minimal_config();
        config.policy_path = Some(path.to_string_lossy().into_owned());

        let error = config.policy_set().unwrap_err().to_string();
        let _ = fs::remove_file(&path);

        assert!(error.contains("writable by group or other"));
    }

    #[cfg(unix)]
    #[test]
    fn policy_set_rejects_symlinked_policy_path() {
        let target = write_temp_file("policy-target", "toml", VALID_POLICY_TOML, 0o644);
        let link = temp_path("policy-link", "toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_text = link.to_string_lossy().into_owned();
        let mut config = minimal_config();
        config.policy_path = Some(link_text.clone());

        let error = config.policy_set().unwrap_err().to_string();
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);

        assert!(error.contains("policy file"));
        assert!(error.contains(&link_text));
        assert!(error.contains("regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_sensitive_paths_rejects_symlinked_key_path() {
        let target = write_temp_file("key-target", "pem", "private-key-content", 0o600);
        let link = temp_path("key-link", "pem");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_text = link.to_string_lossy().into_owned();
        let mut config = minimal_config();
        config.key_path = link_text.clone();

        let error = config.validate_sensitive_paths().unwrap_err().to_string();
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);

        assert!(error.contains("private key"));
        assert!(error.contains(&link_text));
        assert!(error.contains("regular file, not a symlink"));
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
    fn credential_config_supports_explicit_secret_zeroization() {
        let mut credential = CredentialConfig {
            key_id: "client".to_owned(),
            secret: "0123456789abcdef0123456789abcdef".to_owned(),
            status: Some("active".to_owned()),
            not_before: None,
            not_after: None,
            policy_group: Some("default".to_owned()),
        };

        credential.zeroize_secret();

        assert!(
            credential.secret.is_empty(),
            "zeroize must clear the secret"
        );
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
    fn rejects_credential_secret_of_one_repeated_byte() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
        )
        .unwrap();

        assert_eq!(config.credentials(), Err(AuthError::SecretNotRandom));
    }

    #[test]
    fn accepts_but_warns_about_a_low_diversity_credential_secret() {
        let config: ServerConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
cert_path = "cert.pem"
key_path = "key.pem"

[[credentials]]
key_id = "client"
secret = "abababababababababababababababab"
"#,
        )
        .unwrap();

        // Low diversity is a warning, never an error: rejecting it would be a
        // breaking config change.
        assert_eq!(config.credentials().unwrap().len(), 1);
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
