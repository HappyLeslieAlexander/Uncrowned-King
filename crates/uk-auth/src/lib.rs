//! Challenge-response authentication for Uncrowned King.

use std::{
    collections::HashMap,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use uk_proto::{ProtocolError, varint};

type HmacSha256 = Hmac<Sha256>;

const AUTH_LABEL: &[u8] = b"UK-AUTH-v1";
/// TLS/QUIC exporter label used by UK authentication.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-UK-v1";
/// Maximum accepted key id length.
pub const MAX_KEY_ID_LEN: usize = 64;
/// Minimum accepted shared secret length in bytes.
pub const MIN_SECRET_LEN: usize = 32;
const MIN_RESPONSE_TAIL_LEN: usize = 73;
/// Minimum AUTH_RESPONSE payload size accepted by the v0.1 wire format.
pub const MIN_AUTH_RESPONSE_PAYLOAD_SIZE: u64 = 75;
/// Default replay cache retention window in seconds.
pub const DEFAULT_REPLAY_CACHE_WINDOW_SECONDS: u64 = 300;
/// Default maximum accepted nonce pairs retained by the replay cache.
pub const DEFAULT_REPLAY_CACHE_MAX_ENTRIES: usize = 65_536;

/// Authentication result alias.
pub type AuthResult<T> = Result<T, AuthError>;

/// Authentication failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The supplied key id does not exist.
    #[error("unknown key")]
    UnknownKey,
    /// The credential is not active for the current time.
    #[error("credential is not active")]
    CredentialNotActive,
    /// The supplied tag does not match.
    #[error("invalid hmac tag")]
    InvalidTag,
    /// An authentication timestamp is outside the allowed skew.
    #[error("authentication timestamp outside allowed skew")]
    ClockSkew,
    /// The nonce pair has already been accepted.
    #[error("replayed nonce")]
    Replay,
    /// Secret material is too short.
    #[error("secret must be at least 32 bytes")]
    SecretTooShort,
    /// Key id length is outside the protocol bounds.
    #[error("key id length must be 1..=64 bytes")]
    InvalidKeyIdLength,
    /// Credential status text is not recognized.
    #[error("credential status must be active, disabled, or retired")]
    InvalidCredentialStatus,
    /// Two configured credentials use the same key id.
    #[error("duplicate credential key id")]
    DuplicateCredentialKeyId,
    /// No credentials were configured.
    #[error("at least one credential is required")]
    NoCredentials,
    /// A configured credential has an invalid policy group.
    #[error("credential policy group must be non-empty and printable")]
    InvalidCredentialPolicyGroup,
    /// A configured credential validity window is impossible.
    #[error("credential not_before must be less than or equal to not_after")]
    InvalidCredentialValidityWindow,
    /// Authentication payload is malformed.
    #[error("invalid auth payload: {0}")]
    InvalidPayload(&'static str),
    /// Protocol codec failure inside an auth payload.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Credential lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    /// May authenticate.
    Active,
    /// Temporarily disabled.
    Disabled,
    /// Permanently retired.
    Retired,
}

/// Server-side credential record.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    /// Opaque key id sent by the client.
    pub key_id: Vec<u8>,
    /// Shared secret, at least 32 bytes.
    pub secret: Vec<u8>,
    /// Lifecycle status.
    pub status: CredentialStatus,
    /// Optional unix timestamp when the key becomes valid.
    pub not_before: Option<u64>,
    /// Optional unix timestamp when the key stops being valid.
    pub not_after: Option<u64>,
    /// Optional policy group name.
    pub policy_group: Option<String>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credential")
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .field("status", &self.status)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("policy_group", &self.policy_group)
            .finish()
    }
}

impl Credential {
    /// Creates an active credential with no validity window.
    pub fn active(key_id: impl Into<Vec<u8>>, secret: impl Into<Vec<u8>>) -> AuthResult<Self> {
        let credential = Self {
            key_id: key_id.into(),
            secret: secret.into(),
            status: CredentialStatus::Active,
            not_before: None,
            not_after: None,
            policy_group: None,
        };
        credential.validate_auth_material()?;
        Ok(credential)
    }

    fn validate_auth_material(&self) -> AuthResult<()> {
        validate_key_id(&self.key_id)?;
        validate_shared_secret(&self.secret)
    }

    fn is_active_at(&self, now: u64) -> bool {
        if self.status != CredentialStatus::Active {
            return false;
        }
        if self.not_before.is_some_and(|not_before| now < not_before) {
            return false;
        }
        if self.not_after.is_some_and(|not_after| now > not_after) {
            return false;
        }
        true
    }
}

/// Server challenge payload data.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    /// 32 bytes generated by the server.
    pub server_nonce: [u8; 32],
    /// Server unix time in seconds.
    pub server_time: u64,
    /// Opaque 16-byte session id.
    pub session_id: [u8; 16],
    /// Server capability bytes.
    pub server_capabilities: Vec<u8>,
    /// Server limit bytes.
    pub limits: Vec<u8>,
}

impl fmt::Debug for AuthChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthChallenge")
            .field("server_nonce", &"<redacted>")
            .field("server_time", &self.server_time)
            .field("session_id", &"<redacted>")
            .field("server_capabilities", &self.server_capabilities)
            .field("limits", &self.limits)
            .finish()
    }
}

impl AuthChallenge {
    /// Generates a fresh challenge for `now`.
    pub fn generate(now: u64) -> Self {
        let mut server_nonce = [0_u8; 32];
        let mut session_id = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut server_nonce);
        rand::thread_rng().fill_bytes(&mut session_id);
        Self {
            server_nonce,
            server_time: now,
            session_id,
            server_capabilities: Vec::new(),
            limits: Vec::new(),
        }
    }

    /// Encodes this challenge as an `AUTH_CHALLENGE` payload.
    pub fn encode(&self, dst: &mut impl BufMut) -> AuthResult<()> {
        dst.put_slice(&self.server_nonce);
        dst.put_u64(self.server_time);
        dst.put_slice(&self.session_id);
        varint::encode(self.server_capabilities.len() as u64, dst)?;
        dst.put_slice(&self.server_capabilities);
        varint::encode(self.limits.len() as u64, dst)?;
        dst.put_slice(&self.limits);
        Ok(())
    }

    /// Decodes an `AUTH_CHALLENGE` payload.
    pub fn decode(src: &mut impl Buf) -> AuthResult<Self> {
        if src.remaining() < 56 {
            return Err(AuthError::InvalidPayload("challenge is truncated"));
        }
        let mut server_nonce = [0_u8; 32];
        src.copy_to_slice(&mut server_nonce);
        let server_time = src.get_u64();
        let mut session_id = [0_u8; 16];
        src.copy_to_slice(&mut session_id);
        let server_capabilities = read_varbytes(src, "server capabilities")?;
        let limits = read_varbytes(src, "limits")?;
        if src.has_remaining() {
            return Err(AuthError::InvalidPayload("trailing challenge bytes"));
        }
        Ok(Self {
            server_nonce,
            server_time,
            session_id,
            server_capabilities,
            limits,
        })
    }
}

/// Client authentication response data.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthResponse {
    /// Opaque key id.
    pub key_id: Vec<u8>,
    /// 32 bytes generated by the client.
    pub client_nonce: [u8; 32],
    /// Client unix time in seconds.
    pub client_time: u64,
    /// Client capability bytes.
    pub client_capabilities: Vec<u8>,
    /// 32-byte HMAC tag.
    pub tag: [u8; 32],
}

impl fmt::Debug for AuthResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthResponse")
            .field("key_id", &self.key_id)
            .field("client_nonce", &"<redacted>")
            .field("client_time", &self.client_time)
            .field("client_capabilities", &self.client_capabilities)
            .field("tag", &"<redacted>")
            .finish()
    }
}

impl AuthResponse {
    /// Creates and signs a fresh response for `challenge`.
    pub fn for_challenge(
        key_id: impl Into<Vec<u8>>,
        secret: &[u8],
        exporter_32: &[u8; 32],
        challenge: &AuthChallenge,
        client_time: u64,
        client_capabilities: Vec<u8>,
    ) -> AuthResult<Self> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        validate_shared_secret(secret)?;
        let mut client_nonce = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut client_nonce);
        let tag = compute_auth_tag(
            secret,
            exporter_32,
            challenge,
            &key_id,
            &client_nonce,
            client_time,
            &client_capabilities,
        )?;
        Ok(Self {
            key_id,
            client_nonce,
            client_time,
            client_capabilities,
            tag,
        })
    }

    /// Encodes this response as an `AUTH_RESPONSE` payload.
    pub fn encode(&self, dst: &mut impl BufMut) -> AuthResult<()> {
        validate_key_id(&self.key_id)?;
        varint::encode(self.key_id.len() as u64, dst)?;
        dst.put_slice(&self.key_id);
        dst.put_slice(&self.client_nonce);
        dst.put_u64(self.client_time);
        varint::encode(self.client_capabilities.len() as u64, dst)?;
        dst.put_slice(&self.client_capabilities);
        dst.put_slice(&self.tag);
        Ok(())
    }

    /// Decodes an `AUTH_RESPONSE` payload.
    pub fn decode(src: &mut impl Buf) -> AuthResult<Self> {
        let key_id = read_varbytes(src, "key id")?;
        validate_key_id(&key_id)?;
        if src.remaining() < MIN_RESPONSE_TAIL_LEN {
            return Err(AuthError::InvalidPayload("response is truncated"));
        }
        let mut client_nonce = [0_u8; 32];
        src.copy_to_slice(&mut client_nonce);
        let client_time = src.get_u64();
        let client_capabilities = read_varbytes(src, "client capabilities")?;
        if src.remaining() < 32 {
            return Err(AuthError::InvalidPayload("response tag is truncated"));
        }
        if src.remaining() > 32 {
            return Err(AuthError::InvalidPayload("trailing response bytes"));
        }
        let mut tag = [0_u8; 32];
        src.copy_to_slice(&mut tag);
        Ok(Self {
            key_id,
            client_nonce,
            client_time,
            client_capabilities,
            tag,
        })
    }
}

/// In-memory replay cache for accepted nonce pairs.
#[derive(Clone)]
pub struct ReplayCache {
    window: Duration,
    max_entries: usize,
    entries: HashMap<ReplayKey, u64>,
}

impl ReplayCache {
    /// Creates a cache retaining accepted nonces for `window`.
    pub fn new(window: Duration) -> Self {
        Self::with_max_entries(window, DEFAULT_REPLAY_CACHE_MAX_ENTRIES)
    }

    /// Creates a cache retaining at most `max_entries` accepted nonces for `window`.
    ///
    /// A zero entry limit is treated as one so the cache still rejects immediate replays.
    pub fn with_max_entries(window: Duration, max_entries: usize) -> Self {
        Self {
            window,
            max_entries: max_entries.max(1),
            entries: HashMap::new(),
        }
    }

    /// Records a nonce pair or rejects it if it was already seen.
    pub fn check_and_insert(
        &mut self,
        now: u64,
        server_nonce: [u8; 32],
        client_nonce: [u8; 32],
    ) -> AuthResult<()> {
        self.prune(now);
        let key = ReplayKey {
            server_nonce,
            client_nonce,
        };
        if self.entries.contains_key(&key) {
            return Err(AuthError::Replay);
        }
        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }
        self.entries.insert(key, now);
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        let window = self.window.as_secs();
        self.entries
            .retain(|_, inserted_at| now.saturating_sub(*inserted_at) <= window);
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, inserted_at)| **inserted_at)
            .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest_key);
        }
    }
}

impl fmt::Debug for ReplayCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayCache")
            .field("window", &self.window)
            .field("max_entries", &self.max_entries)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(DEFAULT_REPLAY_CACHE_WINDOW_SECONDS))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReplayKey {
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
}

/// Computes the v0.1 authentication HMAC tag.
pub fn compute_auth_tag(
    secret: &[u8],
    exporter_32: &[u8; 32],
    challenge: &AuthChallenge,
    key_id: &[u8],
    client_nonce: &[u8; 32],
    client_time: u64,
    client_capabilities: &[u8],
) -> AuthResult<[u8; 32]> {
    let mac = auth_mac(
        secret,
        exporter_32,
        challenge,
        key_id,
        client_nonce,
        client_time,
        client_capabilities,
    )?;
    let bytes = mac.finalize().into_bytes();
    Ok(bytes.into())
}

/// Verifies an authentication response and records the nonce pair in the replay cache.
pub fn verify_auth_response(
    credentials: &[Credential],
    exporter_32: &[u8; 32],
    challenge: &AuthChallenge,
    response: &AuthResponse,
    now: u64,
    allowed_skew: Duration,
    replay_cache: &mut ReplayCache,
) -> AuthResult<Credential> {
    let credential = credentials
        .iter()
        .find(|credential| credential.key_id == response.key_id)
        .ok_or(AuthError::UnknownKey)?;
    credential.validate_auth_material()?;

    if !credential.is_active_at(now) {
        return Err(AuthError::CredentialNotActive);
    }

    if !timestamp_within_skew(challenge.server_time, now, allowed_skew)
        || !timestamp_within_skew(response.client_time, now, allowed_skew)
    {
        return Err(AuthError::ClockSkew);
    }

    auth_mac(
        &credential.secret,
        exporter_32,
        challenge,
        &response.key_id,
        &response.client_nonce,
        response.client_time,
        &response.client_capabilities,
    )?
    .verify_slice(&response.tag)
    .map_err(|_| AuthError::InvalidTag)?;

    replay_cache.check_and_insert(now, challenge.server_nonce, response.client_nonce)?;
    Ok(credential.clone())
}

fn auth_mac(
    secret: &[u8],
    exporter_32: &[u8; 32],
    challenge: &AuthChallenge,
    key_id: &[u8],
    client_nonce: &[u8; 32],
    client_time: u64,
    client_capabilities: &[u8],
) -> AuthResult<HmacSha256> {
    validate_shared_secret(secret)?;
    validate_key_id(key_id)?;
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AuthError::SecretTooShort)?;
    mac.update(AUTH_LABEL);
    mac.update(exporter_32);
    mac.update(&encoded_challenge_payload(challenge)?);
    mac.update(&encoded_response_prefix(
        key_id,
        client_nonce,
        client_time,
        client_capabilities,
    )?);
    Ok(mac)
}

fn timestamp_within_skew(timestamp: u64, now: u64, allowed_skew: Duration) -> bool {
    now.abs_diff(timestamp) <= allowed_skew.as_secs()
}

fn encoded_challenge_payload(challenge: &AuthChallenge) -> AuthResult<BytesMut> {
    let mut payload = BytesMut::new();
    challenge.encode(&mut payload)?;
    Ok(payload)
}

fn encoded_response_prefix(
    key_id: &[u8],
    client_nonce: &[u8; 32],
    client_time: u64,
    client_capabilities: &[u8],
) -> AuthResult<BytesMut> {
    let mut payload = BytesMut::new();
    varint::encode(key_id.len() as u64, &mut payload)?;
    payload.put_slice(key_id);
    payload.put_slice(client_nonce);
    payload.put_u64(client_time);
    varint::encode(client_capabilities.len() as u64, &mut payload)?;
    payload.put_slice(client_capabilities);
    Ok(payload)
}

/// Validates that a key id can be represented on the wire.
pub fn validate_key_id(key_id: &[u8]) -> AuthResult<()> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
        Err(AuthError::InvalidKeyIdLength)
    } else {
        Ok(())
    }
}

/// Validates shared secret material before using it for HMAC authentication.
pub fn validate_shared_secret(secret: &[u8]) -> AuthResult<()> {
    if secret.len() < MIN_SECRET_LEN {
        Err(AuthError::SecretTooShort)
    } else {
        Ok(())
    }
}

fn read_varbytes(src: &mut impl Buf, name: &'static str) -> AuthResult<Vec<u8>> {
    let len = usize::try_from(varint::decode(src)?).map_err(|_| ProtocolError::InvalidVarint)?;
    if src.remaining() < len {
        return Err(AuthError::InvalidPayload(name));
    }
    Ok(src.copy_to_bytes(len).to_vec())
}

/// Returns the current unix time in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Credential, [u8; 32], AuthChallenge, AuthResponse) {
        let credential = Credential::active(
            b"client-a".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let exporter = [0x11; 32];
        let challenge = AuthChallenge {
            server_nonce: [0x22; 32],
            server_time: 1_700_000_000,
            session_id: [0x33; 16],
            server_capabilities: vec![1, 2, 3],
            limits: vec![4, 5, 6],
        };
        let client_nonce = [0x44; 32];
        let client_time = 1_700_000_001;
        let tag = compute_auth_tag(
            &credential.secret,
            &exporter,
            &challenge,
            &credential.key_id,
            &client_nonce,
            client_time,
            b"cap",
        )
        .unwrap();
        let response = AuthResponse {
            key_id: credential.key_id.clone(),
            client_nonce,
            client_time,
            client_capabilities: b"cap".to_vec(),
            tag,
        };
        (credential, exporter, challenge, response)
    }

    #[test]
    fn rejects_empty_credential_key_id() {
        assert_eq!(
            Credential::active(Vec::new(), vec![0; MIN_SECRET_LEN]),
            Err(AuthError::InvalidKeyIdLength)
        );
    }

    #[test]
    fn rejects_long_credential_key_id() {
        assert_eq!(
            Credential::active(vec![0; MAX_KEY_ID_LEN + 1], vec![0; MIN_SECRET_LEN]),
            Err(AuthError::InvalidKeyIdLength)
        );
    }

    #[test]
    fn rejects_short_credential_secret() {
        assert_eq!(
            Credential::active(b"client-a".to_vec(), b"too-short".to_vec()),
            Err(AuthError::SecretTooShort)
        );
    }

    #[test]
    fn credential_debug_redacts_secret() {
        let credential = Credential::active(
            b"client-a".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();

        let debug = format!("{credential:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("0123456789abcdef"));
    }

    #[test]
    fn auth_challenge_debug_redacts_nonce_and_session_id() {
        let (_, _, challenge, _) = fixture();

        let debug = format!("{challenge:?}");

        assert!(debug.contains("<redacted>"));
        let server_nonce = challenge.server_nonce;
        let session_id = challenge.session_id;
        assert!(!debug.contains(&format!("{server_nonce:?}")));
        assert!(!debug.contains(&format!("{session_id:?}")));
    }

    #[test]
    fn auth_response_debug_redacts_tag() {
        let (_, _, _, response) = fixture();

        let debug = format!("{response:?}");

        assert!(debug.contains("<redacted>"));
        let client_nonce = response.client_nonce;
        let tag = response.tag;
        assert!(!debug.contains(&format!("{client_nonce:?}")));
        assert!(!debug.contains(&format!("{tag:?}")));
    }

    #[test]
    fn replay_cache_debug_redacts_nonce_pairs() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(300), 4);
        let server_nonce = [0x55; 32];
        let client_nonce = [0x66; 32];
        replay_cache
            .check_and_insert(100, server_nonce, client_nonce)
            .unwrap();

        let debug = format!("{replay_cache:?}");

        assert!(debug.contains("entry_count"));
        assert!(!debug.contains(&format!("{server_nonce:?}")));
        assert!(!debug.contains(&format!("{client_nonce:?}")));
    }

    #[test]
    fn rejects_short_response_secret() {
        let (_, exporter, challenge, _) = fixture();

        assert_eq!(
            AuthResponse::for_challenge(
                b"client-a".to_vec(),
                b"too-short",
                &exporter,
                &challenge,
                1_700_000_001,
                Vec::new()
            ),
            Err(AuthError::SecretTooShort)
        );
    }

    #[test]
    fn computes_known_auth_tag_vector() {
        let (_, _, _, response) = fixture();

        assert_eq!(
            response.tag,
            [
                0x52, 0x9e, 0xd7, 0x26, 0xb1, 0xaf, 0xea, 0x54, 0xcf, 0xca, 0xac, 0x09, 0x2b, 0x73,
                0xe3, 0x17, 0x1f, 0xeb, 0xb7, 0xe0, 0x06, 0x59, 0xc1, 0x0b, 0xb8, 0x9c, 0xf6, 0x86,
                0xe7, 0xd5, 0x3c, 0x71,
            ]
        );
    }

    #[test]
    fn auth_tag_covers_challenge_metadata() {
        let (credential, exporter, challenge, response) = fixture();
        let mut changed_time = challenge.clone();
        changed_time.server_time += 1;
        let mut changed_capabilities = challenge.clone();
        changed_capabilities.server_capabilities.push(0xff);
        let mut changed_limits = challenge.clone();
        changed_limits.limits.push(0xee);

        for changed_challenge in [changed_time, changed_capabilities, changed_limits] {
            assert_ne!(
                compute_auth_tag(
                    &credential.secret,
                    &exporter,
                    &changed_challenge,
                    &response.key_id,
                    &response.client_nonce,
                    response.client_time,
                    &response.client_capabilities,
                )
                .unwrap(),
                response.tag
            );
        }
    }

    #[test]
    fn roundtrips_challenge_payload() {
        let (_, _, challenge, _) = fixture();
        let mut out = Vec::new();
        challenge.encode(&mut out).unwrap();
        let mut bytes = bytes::Bytes::from(out);
        assert_eq!(AuthChallenge::decode(&mut bytes).unwrap(), challenge);
    }

    #[test]
    fn roundtrips_response_payload() {
        let (_, _, _, response) = fixture();
        let mut out = Vec::new();
        response.encode(&mut out).unwrap();
        let mut bytes = bytes::Bytes::from(out);
        assert_eq!(AuthResponse::decode(&mut bytes).unwrap(), response);
    }

    #[test]
    fn rejects_truncated_empty_capability_response() {
        let (credential, _, _, response) = fixture();
        let response = AuthResponse {
            key_id: credential.key_id,
            client_nonce: response.client_nonce,
            client_time: response.client_time,
            client_capabilities: Vec::new(),
            tag: response.tag,
        };
        let mut out = Vec::new();
        response.encode(&mut out).unwrap();
        out.pop();
        let mut bytes = bytes::Bytes::from(out);

        assert_eq!(
            AuthResponse::decode(&mut bytes),
            Err(AuthError::InvalidPayload("response is truncated"))
        );
    }

    #[test]
    fn rejects_trailing_response_bytes() {
        let (credential, _, _, response) = fixture();
        let response = AuthResponse {
            key_id: credential.key_id,
            client_nonce: response.client_nonce,
            client_time: response.client_time,
            client_capabilities: Vec::new(),
            tag: response.tag,
        };
        let mut out = Vec::new();
        response.encode(&mut out).unwrap();
        out.push(0);
        let mut bytes = bytes::Bytes::from(out);

        assert_eq!(
            AuthResponse::decode(&mut bytes),
            Err(AuthError::InvalidPayload("trailing response bytes"))
        );
    }

    #[test]
    fn rejects_truncated_response_tag_after_capabilities() {
        let (_, _, _, response) = fixture();
        let mut out = Vec::new();
        response.encode(&mut out).unwrap();
        out.pop();
        let mut bytes = bytes::Bytes::from(out);

        assert_eq!(
            AuthResponse::decode(&mut bytes),
            Err(AuthError::InvalidPayload("response tag is truncated"))
        );
    }

    #[test]
    fn rejects_encoding_empty_response_key_id() {
        let (_, _, _, mut response) = fixture();
        response.key_id.clear();
        let mut out = Vec::new();

        assert_eq!(
            response.encode(&mut out),
            Err(AuthError::InvalidKeyIdLength)
        );
    }

    #[test]
    fn accepts_valid_auth() {
        let (credential, exporter, challenge, response) = fixture();
        let mut replay_cache = ReplayCache::default();
        let verified = verify_auth_response(
            &[credential],
            &exporter,
            &challenge,
            &response,
            1_700_000_001,
            Duration::from_secs(30),
            &mut replay_cache,
        )
        .unwrap();
        assert_eq!(verified.key_id, b"client-a");
    }

    #[test]
    fn rejects_unknown_key() {
        let (credential, exporter, challenge, mut response) = fixture();
        response.key_id = b"missing".to_vec();
        let mut replay_cache = ReplayCache::default();
        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                1_700_000_001,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::UnknownKey)
        );
    }

    #[test]
    fn rejects_invalid_hmac() {
        let (credential, exporter, challenge, mut response) = fixture();
        response.tag[0] ^= 0xff;
        let mut replay_cache = ReplayCache::default();
        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                1_700_000_001,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::InvalidTag)
        );
    }

    #[test]
    fn rejects_expired_timestamp() {
        let (credential, exporter, challenge, mut response) = fixture();
        response.client_time = 1_600_000_000;
        response.tag = compute_auth_tag(
            &credential.secret,
            &exporter,
            &challenge,
            &response.key_id,
            &response.client_nonce,
            response.client_time,
            &response.client_capabilities,
        )
        .unwrap();
        let mut replay_cache = ReplayCache::default();
        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                1_700_000_001,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::ClockSkew)
        );
    }

    #[test]
    fn rejects_expired_challenge_timestamp() {
        let (credential, exporter, mut challenge, mut response) = fixture();
        challenge.server_time = 1_600_000_000;
        response.tag = compute_auth_tag(
            &credential.secret,
            &exporter,
            &challenge,
            &response.key_id,
            &response.client_nonce,
            response.client_time,
            &response.client_capabilities,
        )
        .unwrap();
        let mut replay_cache = ReplayCache::default();

        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                1_700_000_001,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::ClockSkew)
        );
    }

    #[test]
    fn rejects_disabled_credential() {
        let (mut credential, exporter, challenge, response) = fixture();
        credential.status = CredentialStatus::Disabled;
        let mut replay_cache = ReplayCache::default();

        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                1_700_000_001,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::CredentialNotActive)
        );
    }

    #[test]
    fn rejects_retired_credential() {
        let (mut credential, exporter, challenge, response) = fixture();
        credential.status = CredentialStatus::Retired;
        let mut replay_cache = ReplayCache::default();

        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                1_700_000_001,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::CredentialNotActive)
        );
    }

    #[test]
    fn rejects_credential_before_not_before() {
        let (mut credential, exporter, challenge, response) = fixture();
        credential.not_before = Some(1_700_000_010);
        let mut replay_cache = ReplayCache::default();

        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                1_700_000_001,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::CredentialNotActive)
        );
    }

    #[test]
    fn rejects_credential_after_not_after() {
        let (mut credential, exporter, challenge, response) = fixture();
        credential.not_after = Some(1_700_000_000);
        let mut replay_cache = ReplayCache::default();

        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                1_700_000_001,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::CredentialNotActive)
        );
    }

    #[test]
    fn rejects_replayed_nonce() {
        let (credential, exporter, challenge, response) = fixture();
        let mut replay_cache = ReplayCache::default();
        verify_auth_response(
            std::slice::from_ref(&credential),
            &exporter,
            &challenge,
            &response,
            1_700_000_001,
            Duration::from_secs(30),
            &mut replay_cache,
        )
        .unwrap();
        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                1_700_000_002,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::Replay)
        );
    }

    #[test]
    fn replay_cache_prunes_expired_entries() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(10), 4);
        let first = ReplayKey {
            server_nonce: [0x10; 32],
            client_nonce: [0x20; 32],
        };
        let second = ReplayKey {
            server_nonce: [0x11; 32],
            client_nonce: [0x21; 32],
        };

        replay_cache
            .check_and_insert(100, first.server_nonce, first.client_nonce)
            .unwrap();
        replay_cache
            .check_and_insert(111, second.server_nonce, second.client_nonce)
            .unwrap();

        assert!(!replay_cache.entries.contains_key(&first));
        assert!(replay_cache.entries.contains_key(&second));
        assert_eq!(replay_cache.entries.len(), 1);
    }

    #[test]
    fn replay_cache_evicts_oldest_entry_when_full() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(300), 2);
        let oldest = ReplayKey {
            server_nonce: [0x30; 32],
            client_nonce: [0x40; 32],
        };
        let middle = ReplayKey {
            server_nonce: [0x31; 32],
            client_nonce: [0x41; 32],
        };
        let newest = ReplayKey {
            server_nonce: [0x32; 32],
            client_nonce: [0x42; 32],
        };

        replay_cache
            .check_and_insert(100, oldest.server_nonce, oldest.client_nonce)
            .unwrap();
        replay_cache
            .check_and_insert(101, middle.server_nonce, middle.client_nonce)
            .unwrap();
        replay_cache
            .check_and_insert(102, newest.server_nonce, newest.client_nonce)
            .unwrap();

        assert!(!replay_cache.entries.contains_key(&oldest));
        assert!(replay_cache.entries.contains_key(&middle));
        assert!(replay_cache.entries.contains_key(&newest));
        assert_eq!(replay_cache.entries.len(), 2);
    }

    #[test]
    fn replay_cache_rejects_replay_before_capacity_eviction() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(300), 1);
        let key = ReplayKey {
            server_nonce: [0x50; 32],
            client_nonce: [0x60; 32],
        };

        replay_cache
            .check_and_insert(100, key.server_nonce, key.client_nonce)
            .unwrap();

        assert_eq!(
            replay_cache.check_and_insert(101, key.server_nonce, key.client_nonce),
            Err(AuthError::Replay)
        );
        assert_eq!(replay_cache.entries.len(), 1);
    }

    #[test]
    fn replay_cache_treats_zero_capacity_as_one_entry() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(300), 0);
        let first = ReplayKey {
            server_nonce: [0x70; 32],
            client_nonce: [0x80; 32],
        };
        let second = ReplayKey {
            server_nonce: [0x71; 32],
            client_nonce: [0x81; 32],
        };

        replay_cache
            .check_and_insert(100, first.server_nonce, first.client_nonce)
            .unwrap();
        replay_cache
            .check_and_insert(101, second.server_nonce, second.client_nonce)
            .unwrap();

        assert!(!replay_cache.entries.contains_key(&first));
        assert!(replay_cache.entries.contains_key(&second));
        assert_eq!(replay_cache.entries.len(), 1);
    }
}
