//! Challenge-response authentication for Uncrowned King.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::OnceLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use uk_proto::{ProtocolError, varint};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const AUTH_LABEL: &[u8] = b"UK-AUTH-v1";
/// TLS/QUIC exporter label used by UK authentication.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-UK-v1";
/// Maximum accepted key id length.
pub const MAX_KEY_ID_LEN: usize = 64;
/// Minimum accepted shared secret length in bytes.
pub const MIN_SECRET_LEN: usize = 32;
/// Distinct byte values below which a shared secret is implausibly uniform.
///
/// A secret is the raw UTF-8 of a config string, so its length is only a proxy
/// for its entropy. This bound is the weakest statement that still cannot fire
/// on properly generated material: 32 uniform random bytes hold about 30
/// distinct values, and the narrowest encoding this project documents — 32 hex
/// characters over a 16-symbol alphabet — holds about 14. Landing below eight
/// distinct values has probability under 2^-120 for raw random bytes and under
/// 2^-24 for random hex, so only hand-typed or padded secrets reach it.
pub const MIN_PLAUSIBLE_DISTINCT_SECRET_BYTES: usize = 8;
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
    /// Secret material carries no entropy at all.
    #[error("secret must not be a single repeated byte")]
    SecretNotRandom,
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
#[derive(Clone)]
pub struct Credential {
    /// Opaque key id sent by the client.
    pub key_id: Vec<u8>,
    /// Shared secret, at least 32 bytes.
    pub secret: Zeroizing<Vec<u8>>,
    /// Lifecycle status.
    pub status: CredentialStatus,
    /// Optional unix timestamp when the key becomes valid.
    pub not_before: Option<u64>,
    /// Optional unix timestamp when the key stops being valid.
    pub not_after: Option<u64>,
    /// Optional policy group name.
    pub policy_group: Option<String>,
}

/// Authenticated identity safe to retain after secret verification completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedIdentity {
    /// Opaque authenticated key id.
    pub key_id: Vec<u8>,
    /// Optional policy group associated with the credential.
    pub policy_group: Option<String>,
}

impl From<&Credential> for AuthenticatedIdentity {
    fn from(credential: &Credential) -> Self {
        Self {
            key_id: credential.key_id.clone(),
            policy_group: credential.policy_group.clone(),
        }
    }
}

/// Compares two credentials without a byte-wise compare of secret material.
///
/// This is hand written rather than derived so that no call site can turn `==`
/// into a short-circuiting oracle on `secret`. Key id and secret are compared in
/// constant time and their results combined before any branch; the remaining
/// fields hold no secrets.
impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        let material_matches = self.key_id.ct_eq(&other.key_id)
            & self.secret.as_slice().ct_eq(other.secret.as_slice());
        bool::from(material_matches)
            && self.status == other.status
            && self.not_before == other.not_before
            && self.not_after == other.not_after
            && self.policy_group == other.policy_group
    }
}

impl Eq for Credential {}

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
            secret: Zeroizing::new(secret.into()),
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

    /// Returns whether the credential may authenticate at the supplied Unix time.
    pub fn is_active_at(&self, now: u64) -> bool {
        if now == UNREADABLE_CLOCK {
            return false;
        }
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
#[derive(Clone)]
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
#[derive(Clone)]
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

/// Compares two responses without a byte-wise compare of the authentication tag.
///
/// The tag is secret-equivalent — a byte-wise compare against a known-good tag
/// is a forgery oracle — so it is compared in constant time. The remaining
/// fields travel in the clear on the wire.
/// Compares the freshness-critical fields in constant time.
///
/// `server_nonce` and `session_id` are unpredictable values the peer must not
/// be able to learn by probing; comparing them with a short-circuiting `==`
/// would leak a prefix to any future call site, the same trap the derived
/// `PartialEq` left on [`Credential`] and [`AuthResponse`].
impl PartialEq for AuthChallenge {
    fn eq(&self, other: &Self) -> bool {
        let secrets =
            self.server_nonce.ct_eq(&other.server_nonce) & self.session_id.ct_eq(&other.session_id);
        bool::from(secrets)
            && self.server_time == other.server_time
            && self.server_capabilities == other.server_capabilities
            && self.limits == other.limits
    }
}

impl Eq for AuthChallenge {}

impl PartialEq for AuthResponse {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.tag.as_slice().ct_eq(other.tag.as_slice()))
            && self.key_id == other.key_id
            && self.client_nonce == other.client_nonce
            && self.client_time == other.client_time
            && self.client_capabilities == other.client_capabilities
    }
}

impl Eq for AuthResponse {}

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
///
/// Insertion order is tracked next to the lookup map so that expiry and
/// capacity eviction never scan the whole cache: one insert costs O(1) plus the
/// number of entries it actually removes.
///
/// Retention is measured against [`Instant`], not the wall clock, so an NTP
/// step or a virtual machine resume can neither flush the cache in one pass nor
/// over-retain: the monotonic clock only ever moves forward at roughly real
/// speed. Wall-clock time is still what decides whether a *response* is fresh,
/// but that check lives in [`verify_auth_response`].
#[derive(Clone)]
pub struct ReplayCache {
    window: Duration,
    max_entries: usize,
    entries: HashMap<ReplayKey, Instant>,
    order: VecDeque<(Instant, ReplayKey)>,
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
            order: VecDeque::new(),
        }
    }

    /// Records a nonce pair or rejects it if it was already seen.
    ///
    /// `now` is the caller's wall-clock reading. It is accepted for symmetry
    /// with the freshness checks that share it but takes no part in retention,
    /// which is measured monotonically; a wall clock that jumps therefore
    /// cannot expire or resurrect an entry.
    pub fn check_and_insert(
        &mut self,
        now: u64,
        server_nonce: [u8; 32],
        client_nonce: [u8; 32],
    ) -> AuthResult<()> {
        let _ = now;
        self.check_and_insert_at(Instant::now(), server_nonce, client_nonce)
    }

    /// Records a nonce pair as if it had been observed at `inserted_at`.
    fn check_and_insert_at(
        &mut self,
        inserted_at: Instant,
        server_nonce: [u8; 32],
        client_nonce: [u8; 32],
    ) -> AuthResult<()> {
        self.prune(inserted_at);
        let key = ReplayKey {
            server_nonce,
            client_nonce,
        };
        if self.entries.contains_key(&key) {
            return Err(AuthError::Replay);
        }
        while self.entries.len() >= self.max_entries {
            if !self.evict_oldest() {
                break;
            }
        }
        self.entries.insert(key, inserted_at);
        self.order.push_back((inserted_at, key));
        Ok(())
    }

    /// Drops entries whose retention window has elapsed.
    ///
    /// Entries leave in insertion order, so this stops at the first live entry
    /// instead of walking the map. `now` comes from the monotonic clock, so the
    /// queue is always ordered and an entry is dropped only once it has really
    /// aged out.
    fn prune(&mut self, now: Instant) {
        while let Some(&(inserted_at, key)) = self.order.front() {
            if now.saturating_duration_since(inserted_at) <= self.window {
                break;
            }
            self.order.pop_front();
            self.entries.remove(&key);
        }
    }

    /// Removes the least recently inserted entry, returning whether one went.
    fn evict_oldest(&mut self) -> bool {
        match self.order.pop_front() {
            Some((_, key)) => {
                self.entries.remove(&key);
                true
            }
            None => false,
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
            .finish_non_exhaustive()
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
    verify_auth_response_credential(
        credentials,
        exporter_32,
        challenge,
        response,
        now,
        allowed_skew,
        replay_cache,
    )
    .cloned()
}

/// Verifies an authentication response and returns identity data without secret material.
pub fn verify_auth_response_identity(
    credentials: &[Credential],
    exporter_32: &[u8; 32],
    challenge: &AuthChallenge,
    response: &AuthResponse,
    now: u64,
    allowed_skew: Duration,
    replay_cache: &mut ReplayCache,
) -> AuthResult<AuthenticatedIdentity> {
    verify_auth_response_credential(
        credentials,
        exporter_32,
        challenge,
        response,
        now,
        allowed_skew,
        replay_cache,
    )
    .map(AuthenticatedIdentity::from)
}

/// Verifies an authentication response statelessly without modifying the replay cache.
///
/// Performs constant-time credential lookup, computes HMAC-SHA256, verifies tag and timestamps.
/// The caller records nonces into the replay cache separately if successful.
pub fn verify_auth_response_stateless<'a>(
    credentials: &'a [Credential],
    exporter_32: &[u8; 32],
    challenge: &AuthChallenge,
    response: &AuthResponse,
    now: u64,
    allowed_skew: Duration,
) -> AuthResult<&'a Credential> {
    let matched = find_credential(credentials, &response.key_id);

    // Every rejection path below costs one HMAC. An unknown key id — and a
    // configured credential whose own material is unusable, which can never
    // authenticate anyway — falls back to a per-process dummy secret so that the
    // expensive work happens before any cheap check can return. The cheap checks
    // (validity window, clock skew) therefore no longer answer faster than the
    // tag check, which is what let an unauthenticated prober binary-search the
    // server clock.
    let secret = matched
        .filter(|credential| credential.validate_auth_material().is_ok())
        .map_or_else(
            || dummy_secret().as_slice(),
            |credential| credential.secret.as_slice(),
        );
    let tag_matches = auth_mac(
        secret,
        exporter_32,
        challenge,
        &response.key_id,
        &response.client_nonce,
        response.client_time,
        &response.client_capabilities,
    )?
    .verify_slice(&response.tag)
    .map_err(|_| AuthError::InvalidTag);

    let credential = matched.ok_or(AuthError::UnknownKey)?;
    credential.validate_auth_material()?;
    tag_matches?;

    if !credential.is_active_at(now) {
        return Err(AuthError::CredentialNotActive);
    }

    if !timestamp_within_skew(challenge.server_time, now, allowed_skew)
        || !timestamp_within_skew(response.client_time, now, allowed_skew)
    {
        return Err(AuthError::ClockSkew);
    }

    Ok(credential)
}

/// Verifies an authentication response statelessly and returns identity data.
pub fn verify_auth_response_identity_stateless(
    credentials: &[Credential],
    exporter_32: &[u8; 32],
    challenge: &AuthChallenge,
    response: &AuthResponse,
    now: u64,
    allowed_skew: Duration,
) -> AuthResult<AuthenticatedIdentity> {
    verify_auth_response_stateless(
        credentials,
        exporter_32,
        challenge,
        response,
        now,
        allowed_skew,
    )
    .map(AuthenticatedIdentity::from)
}

fn verify_auth_response_credential<'a>(
    credentials: &'a [Credential],
    exporter_32: &[u8; 32],
    challenge: &AuthChallenge,
    response: &AuthResponse,
    now: u64,
    allowed_skew: Duration,
    replay_cache: &mut ReplayCache,
) -> AuthResult<&'a Credential> {
    let credential = verify_auth_response_stateless(
        credentials,
        exporter_32,
        challenge,
        response,
        now,
        allowed_skew,
    )?;
    replay_cache.check_and_insert(now, challenge.server_nonce, response.client_nonce)?;
    Ok(credential)
}

/// Finds the credential for `key_id` without leaking its bytes through timing.
///
/// Every configured credential is inspected and every key id is compared in
/// constant time, so neither a shared key id prefix nor the position of the
/// match changes how long the lookup takes.
///
/// Both key ids are padded to a fixed-length buffer before comparison so that
/// `ct_eq` always operates on equal-length inputs and never short-circuits on
/// a length mismatch.
fn find_credential<'a>(credentials: &'a [Credential], key_id: &[u8]) -> Option<&'a Credential> {
    let mut matched = None;
    let input_padded = pad_key_id_for_ct(key_id);
    for credential in credentials {
        let cred_padded = pad_key_id_for_ct(&credential.key_id);
        let input_ref: &[u8] = &input_padded;
        let cred_ref: &[u8] = &cred_padded;
        let is_match = bool::from(input_ref.ct_eq(cred_ref));
        if is_match && matched.is_none() {
            matched = Some(credential);
        }
    }
    matched
}

/// Pads a key id to a fixed-length buffer for constant-time comparison.
///
/// The buffer stores the key bytes in the first [`MAX_KEY_ID_LEN`] positions
/// and the original length as a little-endian u64 in the last eight bytes.
/// This ensures that (a) two key ids of different lengths never collide and
/// (b) `ct_eq` always runs over equal-length buffers, preventing the
/// length-dependent early return in `subtle::ConstantTimeEq` for slices.
fn pad_key_id_for_ct(key_id: &[u8]) -> [u8; MAX_KEY_ID_LEN + 8] {
    let mut buf = [0u8; MAX_KEY_ID_LEN + 8];
    let len = key_id.len().min(MAX_KEY_ID_LEN);
    buf[..len].copy_from_slice(&key_id[..len]);
    buf[MAX_KEY_ID_LEN..].copy_from_slice(&(key_id.len() as u64).to_le_bytes());
    buf
}

/// Returns the process-local secret used to keep unknown key ids expensive.
///
/// It is random per process, so a client can neither predict nor collide with
/// the tag it produces; the result of that MAC is only ever discarded.
fn dummy_secret() -> &'static Zeroizing<Vec<u8>> {
    static DUMMY_SECRET: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();
    DUMMY_SECRET.get_or_init(|| {
        let mut secret = vec![0_u8; MIN_SECRET_LEN];
        rand::thread_rng().fill_bytes(&mut secret);
        Zeroizing::new(secret)
    })
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
    if timestamp == UNREADABLE_CLOCK || now == UNREADABLE_CLOCK {
        return false;
    }
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
///
/// A v0.1 secret is the raw UTF-8 of a config string, so length is the only
/// hard entropy proxy available — plus one degenerate case worth refusing
/// outright: a secret made of a single repeated byte carries no entropy at all,
/// whatever its length. Randomly generated material of `n` bytes hits that case
/// with probability `256^(1-n)`, below 2^-248 at the minimum accepted length,
/// so this can never reject a properly generated secret.
///
/// Anything weaker than that is reported by [`warn_on_low_secret_diversity`]
/// instead, because rejecting it would break existing configurations.
pub fn validate_shared_secret(secret: &[u8]) -> AuthResult<()> {
    if secret.len() < MIN_SECRET_LEN {
        return Err(AuthError::SecretTooShort);
    }
    if is_single_repeated_byte(secret) {
        return Err(AuthError::SecretNotRandom);
    }
    Ok(())
}

/// Warns when configured secret material has implausibly low byte diversity.
///
/// This is advisory only: the threshold is
/// [`MIN_PLAUSIBLE_DISTINCT_SECRET_BYTES`], chosen so that it cannot fire on
/// randomly generated material in any encoding this project documents. Call it
/// where configuration is loaded rather than on the verification path, so a
/// weak secret costs one log line per load and not one per handshake.
pub fn warn_on_low_secret_diversity(secret: &[u8]) {
    let distinct_bytes = distinct_byte_count(secret);
    if distinct_bytes < MIN_PLAUSIBLE_DISTINCT_SECRET_BYTES {
        tracing::warn!(
            distinct_bytes,
            secret_len = secret.len(),
            "shared secret uses implausibly few distinct byte values; generate it \
             with a CSPRNG as described in docs/key-management.md"
        );
    }
}

/// Returns whether every byte of `secret` is the same. Empty input is not.
///
/// Written branch-free so that the comparison against the server's own secret
/// does not stop at its first distinct byte.
fn is_single_repeated_byte(secret: &[u8]) -> bool {
    let Some(&first) = secret.first() else {
        return false;
    };
    secret
        .iter()
        .fold(0_u8, |differences, &byte| differences | (byte ^ first))
        == 0
}

/// Counts how many distinct byte values appear in `secret`.
fn distinct_byte_count(secret: &[u8]) -> usize {
    let mut seen = [false; 256];
    for &byte in secret {
        seen[usize::from(byte)] = true;
    }
    seen.into_iter().filter(|&was_seen| was_seen).count()
}

fn read_varbytes(src: &mut impl Buf, name: &'static str) -> AuthResult<Vec<u8>> {
    let len = usize::try_from(varint::decode(src)?).map_err(|_| ProtocolError::InvalidVarint)?;
    if src.remaining() < len {
        return Err(AuthError::InvalidPayload(name));
    }
    Ok(src.copy_to_bytes(len).to_vec())
}

/// Timestamp substituted by [`unix_now`] when the host clock is unreadable.
///
/// Every timestamp comparison in this crate fails closed for this value: it is
/// outside any credential validity window and outside any accepted clock skew,
/// so authentication is refused before the replay cache is ever consulted. The
/// cache itself ignores wall-clock time, so this value neither expires nor
/// preserves its entries.
pub const UNREADABLE_CLOCK: u64 = u64::MAX;

/// Returns the current unix time in seconds, or `None` when the host clock
/// predates the Unix epoch.
///
/// Callers must treat `None` as a hard failure: refuse to issue a challenge and
/// fail the handshake instead of substituting a placeholder timestamp.
pub fn try_unix_now() -> Option<u64> {
    unix_seconds_since_epoch(SystemTime::now())
}

/// Returns the current unix time in seconds.
///
/// Prefer [`try_unix_now`], which reports an unreadable clock explicitly. When
/// the host clock predates the Unix epoch this returns [`UNREADABLE_CLOCK`],
/// which fails every freshness, validity window, and replay window check,
/// rather than the plausible-looking `0` of a real epoch timestamp.
pub fn unix_now() -> u64 {
    try_unix_now().unwrap_or(UNREADABLE_CLOCK)
}

fn unix_seconds_since_epoch(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

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
    fn credential_secret_supports_explicit_zeroization() {
        let mut credential = Credential::active(
            b"client-a".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();

        credential.secret.zeroize();

        assert!(credential.secret.is_empty());
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
    fn returns_authenticated_identity_without_cloning_secret() {
        let (mut credential, exporter, challenge, response) = fixture();
        credential.policy_group = Some("production".to_owned());
        let mut replay_cache = ReplayCache::default();

        let identity = verify_auth_response_identity(
            &[credential],
            &exporter,
            &challenge,
            &response,
            1_700_000_001,
            Duration::from_secs(30),
            &mut replay_cache,
        )
        .unwrap();

        assert_eq!(
            identity,
            AuthenticatedIdentity {
                key_id: b"client-a".to_vec(),
                policy_group: Some("production".to_owned()),
            }
        );
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
        let start = Instant::now();
        let first = ReplayKey {
            server_nonce: [0x10; 32],
            client_nonce: [0x20; 32],
        };
        let second = ReplayKey {
            server_nonce: [0x11; 32],
            client_nonce: [0x21; 32],
        };

        replay_cache
            .check_and_insert_at(start, first.server_nonce, first.client_nonce)
            .unwrap();
        replay_cache
            .check_and_insert_at(
                start + Duration::from_secs(11),
                second.server_nonce,
                second.client_nonce,
            )
            .unwrap();

        assert!(!replay_cache.entries.contains_key(&first));
        assert!(replay_cache.entries.contains_key(&second));
        assert_eq!(replay_cache.entries.len(), 1);
    }

    #[test]
    fn replay_cache_retention_ignores_a_wall_clock_jump_forward() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(10), 8);
        let key = ReplayKey {
            server_nonce: [0x12; 32],
            client_nonce: [0x22; 32],
        };
        replay_cache
            .check_and_insert(100, key.server_nonce, key.client_nonce)
            .unwrap();

        // A wall clock that steps far past the retention window must not flush
        // the cache, and the pair it already holds must still be a replay.
        replay_cache
            .check_and_insert(u64::MAX, [0x13; 32], [0x23; 32])
            .unwrap();

        assert!(replay_cache.entries.contains_key(&key));
        assert_eq!(replay_cache.entries.len(), 2);
        assert_eq!(replay_cache.order.len(), 2);
        assert_eq!(
            replay_cache.check_and_insert(u64::MAX, key.server_nonce, key.client_nonce),
            Err(AuthError::Replay)
        );
    }

    #[test]
    fn replay_cache_retention_ignores_a_wall_clock_jump_backwards() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(10), 8);
        let key = ReplayKey {
            server_nonce: [0x14; 32],
            client_nonce: [0x24; 32],
        };
        replay_cache
            .check_and_insert(1_700_000_000, key.server_nonce, key.client_nonce)
            .unwrap();

        assert_eq!(
            replay_cache.check_and_insert(1, key.server_nonce, key.client_nonce),
            Err(AuthError::Replay)
        );
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
    fn replay_cache_keeps_order_queue_aligned_with_entries() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(10), 3);

        for index in 0..64_u8 {
            replay_cache
                .check_and_insert(u64::from(index), [index; 32], [index; 32])
                .unwrap();
            assert_eq!(replay_cache.order.len(), replay_cache.entries.len());
            assert!(replay_cache.entries.len() <= 3);
        }
    }

    #[test]
    fn replay_cache_rejects_duplicate_after_many_inserts() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(300), 1024);
        let server_nonce = [0x90; 32];
        let client_nonce = [0x91; 32];
        replay_cache
            .check_and_insert(100, server_nonce, client_nonce)
            .unwrap();

        for index in 0..512_u16 {
            let filler = [u8::try_from(index % 251).unwrap(); 32];
            let mut other = [0_u8; 32];
            other[0..2].copy_from_slice(&index.to_be_bytes());
            replay_cache.check_and_insert(100, filler, other).unwrap();
        }

        assert_eq!(
            replay_cache.check_and_insert(100, server_nonce, client_nonce),
            Err(AuthError::Replay)
        );
    }

    #[test]
    fn replay_cache_prunes_only_expired_front_entries() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(10), 8);
        let start = Instant::now();
        let expired = ReplayKey {
            server_nonce: [0xa0; 32],
            client_nonce: [0xb0; 32],
        };
        let live = ReplayKey {
            server_nonce: [0xa1; 32],
            client_nonce: [0xb1; 32],
        };

        replay_cache
            .check_and_insert_at(start, expired.server_nonce, expired.client_nonce)
            .unwrap();
        replay_cache
            .check_and_insert_at(
                start + Duration::from_secs(5),
                live.server_nonce,
                live.client_nonce,
            )
            .unwrap();
        replay_cache
            .check_and_insert_at(start + Duration::from_secs(12), [0xa2; 32], [0xb2; 32])
            .unwrap();

        assert!(!replay_cache.entries.contains_key(&expired));
        assert!(replay_cache.entries.contains_key(&live));
        assert_eq!(replay_cache.entries.len(), 2);
        assert_eq!(replay_cache.order.len(), 2);
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

    #[test]
    fn reports_unreadable_clock_before_the_unix_epoch() {
        let before_epoch = UNIX_EPOCH - Duration::from_secs(1);

        assert_eq!(unix_seconds_since_epoch(before_epoch), None);
    }

    #[test]
    fn reads_clock_at_and_after_the_unix_epoch() {
        assert_eq!(unix_seconds_since_epoch(UNIX_EPOCH), Some(0));
        assert_eq!(
            unix_seconds_since_epoch(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            Some(1_700_000_000)
        );
        assert!(try_unix_now().is_some());
    }

    #[test]
    fn unreadable_clock_sentinel_fails_every_timestamp_check() {
        let (mut credential, exporter, challenge, response) = fixture();
        let (unexpired_cred, _, _, _) = fixture();
        assert!(!unexpired_cred.is_active_at(UNREADABLE_CLOCK));
        assert!(!timestamp_within_skew(
            UNREADABLE_CLOCK,
            UNREADABLE_CLOCK,
            Duration::from_secs(30)
        ));

        credential.not_after = Some(1_700_000_100);
        let mut replay_cache = ReplayCache::default();

        assert!(!credential.is_active_at(UNREADABLE_CLOCK));
        assert!(!timestamp_within_skew(
            challenge.server_time,
            UNREADABLE_CLOCK,
            Duration::from_secs(30)
        ));
        assert_eq!(
            verify_auth_response(
                &[credential],
                &exporter,
                &challenge,
                &response,
                UNREADABLE_CLOCK,
                Duration::from_secs(30),
                &mut replay_cache
            ),
            Err(AuthError::CredentialNotActive)
        );
    }

    #[test]
    fn unreadable_clock_sentinel_leaves_the_replay_cache_intact() {
        let mut replay_cache = ReplayCache::with_max_entries(Duration::from_secs(300), 8);
        replay_cache
            .check_and_insert(1_700_000_000, [0xc0; 32], [0xd0; 32])
            .unwrap();

        replay_cache
            .check_and_insert(UNREADABLE_CLOCK, [0xc1; 32], [0xd1; 32])
            .unwrap();

        // The sentinel fails every freshness check before the cache is reached,
        // so retention deliberately does not react to it.
        assert_eq!(replay_cache.entries.len(), 2);
        assert_eq!(replay_cache.order.len(), 2);
    }

    #[test]
    fn verifies_the_tag_before_reporting_clock_skew() {
        let (credential, exporter, challenge, mut response) = fixture();
        response.client_time = 1_600_000_000;
        response.tag[0] ^= 0xff;
        let mut replay_cache = ReplayCache::default();

        // The skew check used to answer first and far faster than the tag check,
        // which let an unauthenticated prober bisect the server clock.
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
    fn verifies_the_tag_before_reporting_an_inactive_credential() {
        let (mut credential, exporter, challenge, mut response) = fixture();
        credential.status = CredentialStatus::Disabled;
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
    fn unknown_key_is_rejected_after_a_full_mac_over_a_dummy_secret() {
        let (credential, exporter, challenge, mut response) = fixture();
        response.key_id = b"client-b".to_vec();
        let mut replay_cache = ReplayCache::default();

        // Same length and same first seven bytes as the configured key id: the
        // lookup must neither short-circuit on the shared prefix nor skip the MAC.
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
        assert!(validate_shared_secret(dummy_secret()).is_ok());
        assert_eq!(dummy_secret().len(), MIN_SECRET_LEN);
    }

    #[test]
    fn finds_credentials_by_exact_key_id_only() {
        let secret = b"0123456789abcdef0123456789abcdef".to_vec();
        let credentials = [
            Credential::active(b"client-a".to_vec(), secret.clone()).unwrap(),
            Credential::active(b"client-b".to_vec(), secret.clone()).unwrap(),
        ];

        assert_eq!(
            find_credential(&credentials, b"client-b").map(|found| found.key_id.clone()),
            Some(b"client-b".to_vec())
        );
        assert!(find_credential(&credentials, b"client-").is_none());
        assert!(find_credential(&credentials, b"client-a-longer").is_none());
        assert!(find_credential(&credentials, b"").is_none());
        assert!(find_credential(&[], b"client-a").is_none());
    }

    #[test]
    fn credential_equality_covers_every_field() {
        let credential = Credential::active(
            b"client-a".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();

        assert_eq!(credential, credential.clone());

        let mut other_secret = credential.clone();
        other_secret.secret = Zeroizing::new(b"0123456789abcdef0123456789abcdeF".to_vec());
        assert_ne!(credential, other_secret);

        let mut other_key_id = credential.clone();
        other_key_id.key_id = b"client-b".to_vec();
        assert_ne!(credential, other_key_id);

        let mut other_status = credential.clone();
        other_status.status = CredentialStatus::Retired;
        assert_ne!(credential, other_status);

        let mut other_window = credential.clone();
        other_window.not_before = Some(1);
        assert_ne!(credential, other_window);
        other_window = credential.clone();
        other_window.not_after = Some(1);
        assert_ne!(credential, other_window);

        let mut other_group = credential.clone();
        other_group.policy_group = Some("production".to_owned());
        assert_ne!(credential, other_group);
    }

    #[test]
    fn auth_response_equality_covers_every_field() {
        let (_, _, _, response) = fixture();

        assert_eq!(response, response.clone());

        let mut other_tag = response.clone();
        other_tag.tag[31] ^= 0x01;
        assert_ne!(response, other_tag);

        let mut other_key_id = response.clone();
        other_key_id.key_id = b"client-b".to_vec();
        assert_ne!(response, other_key_id);

        let mut other_nonce = response.clone();
        other_nonce.client_nonce[0] ^= 0x01;
        assert_ne!(response, other_nonce);

        let mut other_time = response.clone();
        other_time.client_time += 1;
        assert_ne!(response, other_time);

        let mut other_capabilities = response.clone();
        other_capabilities.client_capabilities.push(0xff);
        assert_ne!(response, other_capabilities);
    }

    #[test]
    fn rejects_a_secret_of_one_repeated_byte() {
        assert_eq!(
            validate_shared_secret(&[b'a'; MIN_SECRET_LEN]),
            Err(AuthError::SecretNotRandom)
        );
        assert_eq!(
            validate_shared_secret(&[0_u8; 4096]),
            Err(AuthError::SecretNotRandom)
        );
        assert_eq!(
            Credential::active(b"client-a".to_vec(), vec![b'a'; MIN_SECRET_LEN]),
            Err(AuthError::SecretNotRandom)
        );
    }

    #[test]
    fn accepts_a_low_diversity_secret_that_is_not_a_single_byte() {
        // Weak, but rejecting it would be a breaking config change, so it is
        // only ever warned about.
        let secret = b"abababababababababababababababab";

        assert_eq!(validate_shared_secret(secret), Ok(()));
        assert!(distinct_byte_count(secret) < MIN_PLAUSIBLE_DISTINCT_SECRET_BYTES);
        warn_on_low_secret_diversity(secret);
    }

    #[test]
    fn counts_distinct_secret_bytes() {
        assert_eq!(distinct_byte_count(b""), 0);
        assert_eq!(distinct_byte_count(b"aaaa"), 1);
        assert_eq!(distinct_byte_count(b"abcabc"), 3);
        assert_eq!(distinct_byte_count(b"0123456789abcdef0123456789abcdef"), 16);
        assert!(!is_single_repeated_byte(b""));
        assert!(is_single_repeated_byte(b"a"));
        assert!(is_single_repeated_byte(b"aaaa"));
        assert!(!is_single_repeated_byte(b"aaab"));
        assert!(!is_single_repeated_byte(b"baaa"));
    }

    #[test]
    fn diversity_threshold_never_rejects_randomly_generated_secrets() {
        const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut raw = [0_u8; MIN_SECRET_LEN];
        let mut hex = [0_u8; MIN_SECRET_LEN];

        for _ in 0..1_000 {
            rand::thread_rng().fill_bytes(&mut raw);
            for byte in &mut hex {
                let mut index = [0_u8; 1];
                rand::thread_rng().fill_bytes(&mut index);
                *byte = HEX_DIGITS[usize::from(index[0]) % HEX_DIGITS.len()];
            }

            assert_eq!(validate_shared_secret(&raw), Ok(()));
            assert_eq!(validate_shared_secret(&hex), Ok(()));
            assert!(distinct_byte_count(&raw) >= MIN_PLAUSIBLE_DISTINCT_SECRET_BYTES);
            assert!(distinct_byte_count(&hex) >= MIN_PLAUSIBLE_DISTINCT_SECRET_BYTES);
        }
    }
}
