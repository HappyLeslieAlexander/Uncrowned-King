//! Opt-in transport masking for Uncrowned King carriers.
//!
//! Masking hides the carrier's wire image from observers without a valid
//! credential. It wraps the *transport* (TLS over TCP today; QUIC later) in a
//! symmetric keystream so ClientHello, SNI, ALPN, certificates, and record
//! boundaries all become indistinguishable from random bytes. It is masking,
//! not cryptography of record: TLS/QUIC remain the sole provider of
//! authenticated encryption, integrity, and channel binding — the exporter
//! binding and ALPN verification inside the session are blind to this layer.
//!
//! # TCP prelude
//!
//! A masked TCP connection opens with a fixed 64-byte prelude followed by a
//! 12-byte random nonce. The first 32 prelude bytes (`P`) are policy-shaped
//! random filler. The last 32 bytes (the tail) keep their highest bit from the
//! generated prelude while the low 7 bits of each byte carry, MSB-first, a
//! 28-byte payload: `identity (8) ‖ counter (6) ‖ tag (14)`, XOR-masked with
//! `HMAC(mask_key, N ‖ P ‖ H)` where `H` is the 32 preserved high bits packed
//! MSB-first. The tag is `HMAC(auth_key, N ‖ P ‖ H ‖ identity ‖ counter)`
//! truncated to 14 bytes and compared in constant time. After the nonce, both
//! directions of the stream are ChaCha20 keystreams under per-direction keys
//! derived from the same credential.
//!
//! All prelude verification failures are reported as one indistinguishable
//! [`MaskError::PreludeRejected`]: a prober must not learn *which* check
//! failed.
//!
//! # Key schedule
//!
//! Every key is derived per credential, so masking authority inherits the
//! multi-credential model (rotating a credential rotates its mask keys):
//!
//! ```text
//! root            = HMAC-SHA256(secret, "uk/1/mask/root\x01" || key_id)
//! tcp_auth_key    = HMAC-SHA256(root,   "uk/1/mask/tcp-auth\x01")
//! prelude_mask_key= HMAC-SHA256(root,   "uk/1/mask/tcp-prelude-mask\x01")
//! tcp_c2s_key     = HMAC-SHA256(root,   "uk/1/mask/tcp-c2s\x01")
//! tcp_s2c_key     = HMAC-SHA256(root,   "uk/1/mask/tcp-s2c\x01")
//! udp_c2s_key     = HMAC-SHA256(root,   "uk/1/mask/udp-c2s\x01")
//! udp_s2c_key     = HMAC-SHA256(root,   "uk/1/mask/udp-s2c\x01")
//! ```
//!
//! # Known limits (documented, inherited from the construction)
//!
//! The prelude tag authenticates bootstrap metadata only; it does not bind the
//! ClientHello. Prelude metadata has no forward secrecy: disclosure of the
//! secret lets an attacker decode captured identity/counter pairs and verify
//! guesses against a captured tag offline. Replay history is in-memory: a
//! restart or registry eviction resets it, and a *valid* credential holder can
//! still churn windows. None of these weaken TLS itself.

pub mod replay;
pub mod stream;
pub mod udp;

use std::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, Mac};
use rand::{CryptoRng, Rng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use replay::{ReplayDecision, ReplayRegistry, Replayed};
pub use stream::MaskedStream;

/// Prelude length in bytes, sent before the nonce.
pub const PRELUDE_LEN: usize = 64;
/// Random nonce length in bytes, sent once after the prelude.
pub const NONCE_LEN: usize = 12;
/// Prelude prefix (`P`) length in bytes.
pub const PREFIX_LEN: usize = 32;
/// Prelude tail length in bytes; each byte carries 7 payload bits.
pub const TAIL_LEN: usize = 32;
/// Identity length in bytes inside the tail payload.
pub const IDENTITY_LEN: usize = 8;
/// Counter length in bytes inside the tail payload (48-bit counter).
pub const COUNTER_LEN: usize = 6;
/// Authentication tag length in bytes inside the tail payload.
pub const TAG_LEN: usize = 14;
/// Tail payload length: `identity ‖ counter ‖ tag` = 224 bits = 32 × 7 bits.
pub const TAIL_PAYLOAD_LEN: usize = IDENTITY_LEN + COUNTER_LEN + TAG_LEN;
/// Highest legal counter value (`2^48 − 1`); counters never wrap.
pub const MAX_COUNTER: u64 = (1_u64 << 48) - 1;
/// Per-direction keystream byte cap: ChaCha20's 32-bit block counter bounds a
/// stream to `2^38` bytes; stop one block short so partial-chunk math stays
/// inside the limit.
pub const STREAM_LIMIT: u64 = (1_u64 << 38) - 64;
/// Replay window width in counters per identity.
pub const REPLAY_WINDOW: u64 = 1024;
/// Default replay registry capacity in tracked identities.
pub const DEFAULT_REPLAY_IDENTITIES: usize = 16_384;
/// Largest configured replay registry capacity. The registry is fully
/// preallocated, so this bounds server memory (~150 bytes per identity).
pub const MAX_REPLAY_IDENTITIES: usize = 1_048_576;

/// Errors produced by masking. Verification failures collapse into a single
/// variant so observers cannot distinguish which check failed.
#[derive(Debug, thiserror::Error)]
pub enum MaskError {
    /// The prelude failed authentication or was malformed.
    #[error("masking prelude rejected")]
    PreludeRejected,
    /// A counter outside `1 ..= MAX_COUNTER` was supplied for encoding.
    #[error("masking counter out of range")]
    InvalidCounter,
    /// The process-local counter space is exhausted; restart the client.
    #[error("masking counter exhausted")]
    CounterExhausted,
    /// The per-direction keystream byte limit was exceeded.
    #[error("masking stream byte limit exceeded")]
    StreamLimitExceeded,
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    for part in parts {
        mac.update(part);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// Per-credential masking keys. Derived once and reused; zeroized on drop.
#[derive(Clone)]
pub struct MaskKeys {
    auth_key: Zeroizing<[u8; 32]>,
    prelude_mask_key: Zeroizing<[u8; 32]>,
    tcp_c2s: Zeroizing<[u8; 32]>,
    tcp_s2c: Zeroizing<[u8; 32]>,
    udp_c2s: Zeroizing<[u8; 32]>,
    udp_s2c: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for MaskKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MaskKeys { ... }")
    }
}

impl MaskKeys {
    /// Derives the masking keys from a credential's `key_id` and secret.
    pub fn derive(key_id: &[u8], secret: &[u8]) -> Self {
        let root_label: &[u8] = b"uk/1/mask/root\x01";
        let root = hmac(secret, &[root_label, key_id]);
        let auth_key = hmac(&root[..], &[b"uk/1/mask/tcp-auth\x01"]);
        let prelude_mask_key = hmac(&root[..], &[b"uk/1/mask/tcp-prelude-mask\x01"]);
        let tcp_c2s = hmac(&root[..], &[b"uk/1/mask/tcp-c2s\x01"]);
        let tcp_s2c = hmac(&root[..], &[b"uk/1/mask/tcp-s2c\x01"]);
        let udp_c2s = hmac(&root[..], &[b"uk/1/mask/udp-c2s\x01"]);
        let udp_s2c = hmac(&root[..], &[b"uk/1/mask/udp-s2c\x01"]);
        Self {
            auth_key,
            prelude_mask_key,
            tcp_c2s,
            tcp_s2c,
            udp_c2s,
            udp_s2c,
        }
    }

    /// Encodes a prelude for the given identity and counter.
    ///
    /// `counter` must be a fresh value from [`ClientSequence::allocate`];
    /// failed or abandoned connection attempts still consume values by design.
    pub fn encode_prelude<R: RngCore + CryptoRng>(
        &self,
        policy: PreludePolicy,
        rng: &mut R,
        identity: u64,
        counter: u64,
    ) -> Result<ClientPrelude, MaskError> {
        if counter == 0 || counter > MAX_COUNTER {
            return Err(MaskError::InvalidCounter);
        }
        let mut bytes = generate_prelude(policy, rng);
        let mut nonce = [0_u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let prefix = &bytes[..PREFIX_LEN];
        let high_bits = pack_high_bits(&bytes[PREFIX_LEN..]);
        let identity_bytes = identity.to_be_bytes();
        let counter_bytes = counter_to_be_bytes(counter);
        let tag = self.authentication_tag(&nonce, prefix, high_bits, identity_bytes, counter_bytes);
        let mut payload = [0_u8; TAIL_PAYLOAD_LEN];
        payload[..IDENTITY_LEN].copy_from_slice(&identity_bytes);
        payload[IDENTITY_LEN..IDENTITY_LEN + COUNTER_LEN].copy_from_slice(&counter_bytes);
        payload[IDENTITY_LEN + COUNTER_LEN..].copy_from_slice(&tag[..TAG_LEN]);
        let mask = self.prelude_mask(&nonce, prefix, high_bits);
        for (byte, mask_byte) in payload.iter_mut().zip(mask.iter()) {
            *byte ^= mask_byte;
        }
        write_tail_payload(&mut bytes[PREFIX_LEN..], &payload);
        Ok(ClientPrelude { bytes, nonce })
    }

    /// Decodes and verifies a prelude. Constant-time tag comparison; every
    /// failure is [`MaskError::PreludeRejected`].
    ///
    /// # Panics
    /// Never in practice: the internal tag extraction is statically sized to
    /// the fixed tail payload layout, so its defensive `expect` cannot fire.
    pub fn decode_prelude(
        &self,
        prelude: &[u8; PRELUDE_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<AuthenticatedPrelude, MaskError> {
        let prefix = &prelude[..PREFIX_LEN];
        let high_bits = pack_high_bits(&prelude[PREFIX_LEN..]);
        let masked_payload = read_tail_payload(&prelude[PREFIX_LEN..]);
        let mask = self.prelude_mask(nonce, prefix, high_bits);
        let mut payload = [0_u8; TAIL_PAYLOAD_LEN];
        for index in 0..TAIL_PAYLOAD_LEN {
            payload[index] = masked_payload[index] ^ mask[index];
        }
        let mut identity_bytes = [0_u8; IDENTITY_LEN];
        identity_bytes.copy_from_slice(&payload[..IDENTITY_LEN]);
        let mut counter_bytes = [0_u8; COUNTER_LEN];
        counter_bytes.copy_from_slice(&payload[IDENTITY_LEN..IDENTITY_LEN + COUNTER_LEN]);
        let counter = counter_from_be_bytes(counter_bytes);
        if counter == 0 {
            return Err(MaskError::PreludeRejected);
        }
        let expected =
            self.authentication_tag(nonce, prefix, high_bits, identity_bytes, counter_bytes);
        let given: [u8; TAG_LEN] = payload[IDENTITY_LEN + COUNTER_LEN..]
            .try_into()
            .expect("tail payload layout guarantees 14 tag bytes");
        if bool::from(given.ct_eq(&expected[..TAG_LEN])) {
            Ok(AuthenticatedPrelude {
                identity: u64::from_be_bytes(identity_bytes),
                counter,
            })
        } else {
            Err(MaskError::PreludeRejected)
        }
    }

    fn authentication_tag(
        &self,
        nonce: &[u8; NONCE_LEN],
        prefix: &[u8],
        high_bits: [u8; 4],
        identity: [u8; IDENTITY_LEN],
        counter: [u8; COUNTER_LEN],
    ) -> Zeroizing<[u8; 32]> {
        hmac(
            &self.auth_key[..],
            &[nonce, prefix, &high_bits, &identity, &counter],
        )
    }

    fn prelude_mask(
        &self,
        nonce: &[u8; NONCE_LEN],
        prefix: &[u8],
        high_bits: [u8; 4],
    ) -> Zeroizing<[u8; 32]> {
        hmac(&self.prelude_mask_key[..], &[nonce, prefix, &high_bits])
    }

    pub(crate) fn c2s(&self) -> [u8; 32] {
        *self.tcp_c2s
    }

    pub(crate) fn s2c(&self) -> [u8; 32] {
        *self.tcp_s2c
    }

    /// Client-to-server UDP (QUIC) masking key.
    pub fn udp_c2s(&self) -> [u8; 32] {
        *self.udp_c2s
    }

    /// Server-to-client UDP (QUIC) masking key.
    pub fn udp_s2c(&self) -> [u8; 32] {
        *self.udp_s2c
    }
}

/// Verifies a prelude against every credential's keys.
///
/// Every key performs the full verification — there is no early exit — so the
/// total work is independent of which credential (if any) matched. Returns the
/// matching keys (for stream setup) plus the authenticated prelude.
pub fn verify_prelude<'keys>(
    keys: &'keys [MaskKeys],
    prelude: &[u8; PRELUDE_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Option<(&'keys MaskKeys, AuthenticatedPrelude)> {
    let mut found = None;
    for key in keys {
        if let Ok(authenticated) = key.decode_prelude(prelude, nonce) {
            found = Some((key, authenticated));
        }
    }
    found
}

/// A client-generated prelude plus its cleartext nonce.
pub struct ClientPrelude {
    /// The 64 prelude bytes to write before the nonce.
    pub bytes: [u8; PRELUDE_LEN],
    /// The 12 random nonce bytes to write after the prelude.
    pub nonce: [u8; NONCE_LEN],
}

/// Identity and counter recovered from a verified prelude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPrelude {
    /// Caller-process identity from the prelude.
    pub identity: u64,
    /// Fresh counter from the prelude.
    pub counter: u64,
}

/// Shaping policy for the generated prelude's first bytes. The decoder is
/// policy-agnostic: a receiver accepts any policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreludePolicy {
    /// Printable-ASCII prefix fading to 7-bit then fully random (default).
    #[default]
    Fade,
    /// Fully random 8-bit prelude.
    Full8,
    /// Every byte masked to 7 bits for high-bit-hostile middleboxes.
    Low7,
}

impl PreludePolicy {
    /// Parses a configuration string (`fade`, `full8`, `low7`).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "fade" => Some(Self::Fade),
            "full8" => Some(Self::Full8),
            "low7" => Some(Self::Low7),
            _ => None,
        }
    }

    /// Configuration string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fade => "fade",
            Self::Full8 => "full8",
            Self::Low7 => "low7",
        }
    }
}

/// Process-local identity and counter allocator shared by all masked
/// connection attempts. Counters are allocated immediately before encoding;
/// failed or cancelled attempts still consume values so allocations stay
/// unique under concurrency.
pub struct ClientSequence {
    identity: u64,
    next: AtomicU64,
}

impl ClientSequence {
    /// Creates a sequence with a random 64-bit identity.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            identity: rng.next_u64(),
            next: AtomicU64::new(1),
        }
    }

    /// The random per-process identity embedded in every prelude.
    pub const fn identity(&self) -> u64 {
        self.identity
    }

    /// Allocates the next counter. Monotonic, never reused, never wraps.
    pub fn allocate(&self) -> Result<u64, MaskError> {
        let counter = self.next.fetch_add(1, Ordering::Relaxed);
        if counter == 0 || counter > MAX_COUNTER {
            Err(MaskError::CounterExhausted)
        } else {
            Ok(counter)
        }
    }
}

fn counter_to_be_bytes(counter: u64) -> [u8; COUNTER_LEN] {
    counter.to_be_bytes()[2..]
        .try_into()
        .expect("48-bit counter takes the low 6 bytes of a u64")
}

fn counter_from_be_bytes(bytes: [u8; COUNTER_LEN]) -> u64 {
    let mut wide = [0_u8; 8];
    wide[2..].copy_from_slice(&bytes);
    u64::from_be_bytes(wide)
}

/// Packs the high bit of each tail byte, MSB-first, into 4 bytes.
fn pack_high_bits(tail: &[u8]) -> [u8; 4] {
    let mut packed = [0_u8; 4];
    for (index, byte) in tail.iter().take(TAIL_LEN).enumerate() {
        packed[index / 8] |= (byte & 0x80) >> (7 - (index % 8));
    }
    packed
}

/// Writes the 224 payload bits into the low 7 bits of the 32 tail bytes,
/// MSB-first, preserving each byte's high bit.
fn write_tail_payload(tail: &mut [u8], payload: &[u8; TAIL_PAYLOAD_LEN]) {
    for bit_index in 0..TAIL_PAYLOAD_LEN * 8 {
        let bit = (payload[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
        let group = bit_index / 7;
        let position = bit_index % 7;
        let bit_mask = 1_u8 << (6 - position);
        tail[group] = (tail[group] & !bit_mask) | (bit << (6 - position));
    }
}

/// Reads the 224 payload bits back out of the tail's low 7 bits.
fn read_tail_payload(tail: &[u8]) -> [u8; TAIL_PAYLOAD_LEN] {
    let mut payload = [0_u8; TAIL_PAYLOAD_LEN];
    for bit_index in 0..TAIL_PAYLOAD_LEN * 8 {
        let group = bit_index / 7;
        let position = bit_index % 7;
        let bit = (tail[group] >> (6 - position)) & 1;
        payload[bit_index / 8] |= bit << (7 - (bit_index % 8));
    }
    payload
}

fn generate_prelude<R: RngCore + CryptoRng>(
    policy: PreludePolicy,
    rng: &mut R,
) -> [u8; PRELUDE_LEN] {
    let mut bytes = [0_u8; PRELUDE_LEN];
    rng.fill_bytes(&mut bytes);
    match policy {
        PreludePolicy::Full8 => {}
        PreludePolicy::Low7 => {
            for byte in &mut bytes {
                *byte &= 0x7f;
            }
        }
        PreludePolicy::Fade => {
            // `gen_range` on an inclusive integer range is rejection-free and
            // unbiased in rand 0.8, so no modulo bias is introduced here.
            let printable_end = rng.gen_range(8..=12);
            let seven_bit_end = rng.gen_range(16..=32);
            for byte in &mut bytes[..printable_end] {
                *byte = 0x20 + (*byte % 95);
            }
            for byte in &mut bytes[printable_end..seven_bit_end] {
                *byte &= 0x7f;
            }
        }
    }
    bytes
}

#[cfg(test)]
mod tests;
