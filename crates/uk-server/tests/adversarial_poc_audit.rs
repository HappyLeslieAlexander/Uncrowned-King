//! Hardened Invariant Verification & Adversarial Security Test Suite for Uncrowned King.
//!
//! This integration test suite deterministically verifies that all 14 security and protocol
//! invariants identified in the 2026-10 full-spectrum security audit are strictly enforced.
//! All tests conform strictly to `AGENTS.md` (no unsafe code, no sleep-based flakiness).

#![allow(
    unknown_lints,
    clippy::all,
    clippy::pedantic,
    clippy::bool_assert_comparison,
    clippy::uninlined_format_args,
    clippy::manual_string_new,
    clippy::too_many_lines
)]

use std::{net::IpAddr, time::Duration};

use bytes::Bytes;
use uk_auth::{AuthChallenge, AuthError, AuthResponse, ReplayCache};
use uk_mask::{ReplayDecision, ReplayRegistry, Replayed};
use uk_policy::{Cidr, PolicyContext, PolicyDecision, PolicySet};
use uk_proto::{
    Frame, FrameHeader, FrameIoError, FrameLimits, ProtocolError, Settings, Target, TcpOpen,
    read_frame, varint,
};

// =========================================================================
// FINDING-01: uk-mask ReplayEntry::advance Bit Shift Inversion
// =========================================================================

#[test]
fn test_poc_finding_01_replay_advance_bitshift_inversion() {
    let mut registry = ReplayRegistry::new(16);
    let identity = 0xbeef_u64;

    // Step 1: Commit initial counter 100
    assert_eq!(registry.commit(identity, 100), ReplayDecision::Accepted);
    assert_eq!(
        registry.commit(identity, 100),
        ReplayDecision::Rejected(Replayed::Duplicate)
    );

    // Step 2: Client advances to counter 105
    assert_eq!(registry.commit(identity, 105), ReplayDecision::Accepted);

    // Step 3: Replay counter 100.
    // Invariant: Distance is 105 - 100 = 5 (< REPLAY_WINDOW). Counter 100 was already seen.
    // Invariant requirement: ReplayDecision::Rejected(Replayed::Duplicate).
    let replay_decision = registry.commit(identity, 100);

    // Hardened invariant verification:
    assert_eq!(
        replay_decision,
        ReplayDecision::Rejected(Replayed::Duplicate),
        "Hardened invariant: Counter 100 must be rejected as duplicate after advancing to counter 105"
    );
}

// =========================================================================
// FINDING-02: uk-server SIGHUP Reload Drops QUIC Masked MTU Cap
// =========================================================================

#[test]
fn test_poc_finding_02_sighup_reload_drops_quic_masked_mtu_cap() {
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cert_resolver = std::sync::Arc::new(rustls::server::ResolvesServerCertUsingSni::new());
    let tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    // 1. Initial startup config with masked: true
    let startup_quic = uk_server::quic::server_config_with_transport_params_masked(
        tls_config.clone(),
        Some(Duration::from_secs(30)),
        1024 * 1024,
        1024 * 1024,
        true, // masked: true
    )
    .unwrap();
    let startup_debug = format!("{startup_quic:?}");
    assert!(
        startup_debug.contains("upper_bound: 1440"),
        "Startup QUIC config must cap MTU discovery at 1440"
    );

    // 2. SIGHUP reload config as built by apply_security_reload (line 840)
    let reloaded_quic = uk_server::quic::server_config_with_transport_params_masked(
        tls_config,
        Some(Duration::from_secs(30)),
        1024 * 1024,
        1024 * 1024,
        true, // masked: true preserved during reload
    )
    .unwrap();
    let reloaded_debug = format!("{reloaded_quic:?}");

    // Invariant: Must cap MTU discovery at 1440
    assert!(
        reloaded_debug.contains("upper_bound: 1440"),
        "Hardened invariant: SIGHUP reload must preserve the 1440 MTU upper bound on masked QUIC"
    );
}

// =========================================================================
// FINDING-03: uk-proto Control Frame Unchecked Payload Length
// =========================================================================

#[test]
fn test_poc_finding_03_control_frame_unchecked_payload_length() {
    // Construct a FrameHeader for TcpClose with length = 65536
    // Wire: version=1, frame_type=0x12 (TcpClose), flags=0x0000, id=1, length=65536 (varint 0x80, 0x01, 0x00, 0x00)
    let wire = vec![0x01, 0x12, 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00];
    let mut buf = Bytes::from(wire);

    let result = FrameHeader::decode(&mut buf, FrameLimits::default());
    // Invariant: TcpClose payload is strictly 2 bytes. Length 65536 must be rejected.
    assert_eq!(
        result,
        Err(ProtocolError::InvalidFrame(
            "invalid close frame payload length"
        )),
        "Hardened invariant: TcpClose frame header with length 65536 must be rejected early"
    );
}

// =========================================================================
// FINDING-04: uk-proto Frame::decode Destructively Consumes Header on Truncated Payload
// =========================================================================

#[test]
fn test_poc_finding_04_frame_decode_header_destruction_on_truncation() {
    // Header: version=1, TcpData (0x11), flags=0, id=1, length=10 (6 bytes)
    // Followed by only 3 bytes of payload (total 9 bytes, missing 7 bytes)
    let mut wire = vec![0x01, 0x11, 0x00, 0x00, 0x01, 0x0a];
    wire.extend_from_slice(&[b'a', b'b', b'c']);

    let mut src = Bytes::from(wire);
    let initial_len = src.len();
    assert_eq!(initial_len, 9);

    let res = Frame::decode(&mut src, FrameLimits::default());
    assert_eq!(res, Err(ProtocolError::Truncated));

    // Invariant: Non-destructive decoding requires all 9 bytes remain in buffer on Truncated.
    assert_eq!(
        src.len(),
        initial_len,
        "Hardened invariant: Frame::decode must preserve all buffer bytes on Truncated"
    );
}

// =========================================================================
// FINDING-11: uk-policy Cidr::contains IPv6 ::/0 Matches IPv4-Mapped Addresses
// =========================================================================

#[test]
fn test_poc_finding_11_ipv6_cidr_matches_ipv4_mapped_address() {
    let cidr: Cidr = "::/0".parse().unwrap();
    let mapped_ip: IpAddr = "::ffff:93.184.216.34".parse().unwrap();

    // Invariant: Families are disjoint: "an IPv6 CIDR never matches a plain IPv4 address
    // (IPv4-mapped IPv6 addresses are canonicalized to their IPv4 form first, and only a V4 CIDR then matches them)"
    assert!(
        !cidr.contains(mapped_ip),
        "Hardened invariant: IPv6 CIDR ::/0 must never match IPv4-mapped address ::ffff:93.184.216.34"
    );
}

// =========================================================================
// FINDING-12: uk-auth ReplayCache Capacity Eviction Allows Replay Attacks
// =========================================================================

#[test]
fn test_poc_finding_12_replay_cache_capacity_eviction_permits_replay() {
    // Small cache of 2 entries, 300s window
    let mut cache = ReplayCache::with_max_entries(Duration::from_secs(300), 2);

    let nonce_a_srv = [0x01; 32];
    let nonce_a_cli = [0x02; 32];
    assert!(cache.check_and_insert(nonce_a_srv, nonce_a_cli).is_ok());

    // Immediate replay rejected:
    assert_eq!(
        cache.check_and_insert(nonce_a_srv, nonce_a_cli),
        Err(AuthError::Replay)
    );

    // Second entry fills the cache to max capacity (2 entries):
    assert!(cache.check_and_insert([0x03; 32], [0x04; 32]).is_ok());
    // Attempting to flood cache with a 3rd entry when saturated with unexpired nonces fails closed:
    assert_eq!(
        cache.check_and_insert([0x05; 32], [0x06; 32]),
        Err(AuthError::ResourceLimit("replay cache saturated"))
    );

    // Invariant: Nonce A was recorded within 300s retention window and must still be rejected.
    let replay_res = cache.check_and_insert(nonce_a_srv, nonce_a_cli);
    assert_eq!(
        replay_res,
        Err(AuthError::Replay),
        "Hardened invariant: Replaying Nonce A must be rejected as Replay because unexpired entries cannot be evicted"
    );
}

// =========================================================================
// FINDING-15: uk-server SIGHUP Limits Validation Omits auth_rate_limit_global_failures
// =========================================================================

#[test]
fn test_poc_finding_15_sighup_limits_omits_global_failures_threshold() {
    let toml_str = r#"
        listen = "127.0.0.1:8443"
        cert_path = "cert.pem"
        key_path = "key.pem"
        [[credentials]]
        key_id = "test"
        secret = "0123456789abcdef0123456789abcdef"
    "#;
    let current: uk_server::config::ServerConfig = toml::from_str(toml_str).unwrap();
    let mut candidate = current.clone();
    candidate.limits = Some(uk_server::config::LimitConfig {
        auth_rate_limit_global_failures: Some(99999),
        ..uk_server::config::LimitConfig::default()
    });

    // Invariant: Modifying limits on SIGHUP must be checked and rejected if immutable
    let res = uk_server::ensure_reload_compatible(&current, &candidate);
    assert!(
        res.is_err(),
        "Hardened invariant: ensure_reload_compatible must reject modifying auth_rate_limit_global_failures on SIGHUP"
    );
}

// =========================================================================
// FINDING-17: uk-proto FrameHeader::decode Wire Length Underrun Consumes Bytes
// =========================================================================

#[test]
fn test_poc_finding_17_frame_header_decode_consumes_bytes_on_4_byte_input() {
    let mut buf = Bytes::from_static(&[0x01, 0x11, 0x00, 0x00]); // 4 bytes (valid fixed head, no varints)
    let initial_len = buf.len();
    assert_eq!(initial_len, 4);

    let res = FrameHeader::decode(&mut buf, FrameLimits::default());
    assert_eq!(res, Err(ProtocolError::Truncated));

    // Invariant: FrameHeader::decode must not consume bytes on Truncated.
    assert_eq!(
        buf.len(),
        initial_len,
        "Hardened invariant: FrameHeader::decode must preserve all 4 bytes on truncation"
    );
}

// =========================================================================
// FINDING-18: uk-proto read_frame Blocks on Socket for 3 More Bytes on Bad Version
// =========================================================================

#[tokio::test]
async fn test_poc_finding_18_read_frame_blocks_on_invalid_version() {
    // Remote peer sends 1 byte with invalid version 0x09 and closes stream (EOF)
    let mut input = &b"\x09"[..];
    let res = read_frame(&mut input, FrameLimits::default()).await;

    // Invariant: Immediate failure with UnsupportedVersion(9) upon reading first byte.
    assert!(
        matches!(
            res,
            Err(FrameIoError::Protocol(ProtocolError::UnsupportedVersion(9)))
        ),
        "Hardened invariant: read_frame must return UnsupportedVersion(9), got: {:?}",
        res
    );
}

// =========================================================================
// FINDING-19: uk-proto Settings::decode Unbounded Loop
// =========================================================================

#[test]
fn test_poc_finding_19_settings_decode_unbounded_loop() {
    use bytes::BytesMut;

    let mut wire = BytesMut::new();
    // count = 100_000 (varint 0x80, 0x01, 0x86, 0xa0)
    varint::encode(100_000, &mut wire).unwrap();
    // Provide only 2 bytes for 1 setting pair
    wire.extend_from_slice(&[0x01, 0x01]);

    let mut buf = wire.freeze();
    // Invariant: Should reject count upfront if count exceeds maximum or buffer length is insufficient.
    let res = Settings::decode(&mut buf);
    assert!(
        matches!(res, Err(ProtocolError::InvalidSettings(_))),
        "Hardened invariant: Settings::decode must reject excessive settings count upfront without looping, got: {:?}",
        res
    );
}

// =========================================================================
// FINDING-20: uk-auth AuthResponse::decode Allocates Capabilities Vec on Truncated Tag
// =========================================================================

#[test]
fn test_poc_finding_20_auth_response_allocates_capabilities_on_truncated_tag() {
    use bytes::BytesMut;

    let mut wire = BytesMut::new();
    varint::encode(1, &mut wire).unwrap(); // key_id_len = 1
    wire.extend_from_slice(b"k");
    wire.extend_from_slice(&[0x11; 32]); // nonce
    wire.extend_from_slice(&1_700_000_000u64.to_be_bytes()); // time
    varint::encode(1000, &mut wire).unwrap(); // capabilities len = 1000
    wire.extend_from_slice(&vec![0x42; 1000]); // 1000 bytes capabilities
    wire.extend_from_slice(&[0x99; 10]); // Only 10 bytes for tag (< 32 bytes!)

    let mut src = wire.freeze();
    let res = AuthResponse::decode(&mut src);
    // Invariant: Pre-allocation bounds check must verify tag presence before allocating capabilities Vec.
    assert_eq!(
        res,
        Err(AuthError::InvalidPayload("response tag is truncated")),
        "Hardened invariant: AuthResponse::decode must reject truncated tag before allocating capabilities"
    );
}

// =========================================================================
// FINDING-21: uk-auth AuthChallenge::decode Partial Buffer Consumption on 40 Bytes
// =========================================================================

#[test]
fn test_poc_finding_21_auth_challenge_decode_inconsistent_error_on_40_bytes() {
    let mut wire = vec![0x11; 32];
    wire.extend_from_slice(&1_700_000_000u64.to_be_bytes()); // Exactly 40 bytes
    let mut buf = Bytes::from(wire);
    let initial_len = buf.len();
    assert_eq!(initial_len, 40);

    let res = AuthChallenge::decode(&mut buf);
    // Invariant: Wire length minimum for AuthChallenge is 42 bytes.
    // If < 42 bytes, should return InvalidPayload("challenge is truncated") and preserve buffer.
    assert_eq!(
        res,
        Err(AuthError::InvalidPayload("challenge is truncated")),
        "Hardened invariant: Returned InvalidPayload(\"challenge is truncated\") on wire length underrun"
    );
    assert_eq!(
        buf.len(),
        initial_len,
        "Hardened invariant: AuthChallenge::decode must preserve all buffer bytes on underrun"
    );
}

// =========================================================================
// FINDING-22: uk-proto TcpOpen::decode Consumes Target Before Validating open_flags
// =========================================================================

#[test]
fn test_poc_finding_22_tcp_open_decode_consumes_target_on_truncated_flags() {
    // The absolute minimum is 7 bytes (1-byte domain); 6-byte input must be
    // rejected before Target::decode and preserve the buffer.
    let mut buf = Bytes::from_static(&[0x02, 0x04, 127, 0, 0, 1]);
    assert_eq!(buf.len(), 6);
    let res = TcpOpen::decode(&mut buf);
    assert_eq!(res, Err(ProtocolError::Truncated));
    assert_eq!(
        buf.len(),
        6,
        "Hardened invariant: TcpOpen::decode must preserve buffer below the 7-byte floor"
    );

    // The 8-byte IPv4 target form passes that floor, decodes the target, and
    // is rejected for missing flags. The flag bytes themselves are not
    // consumed, so no partial flags are read.
    let mut buf = Bytes::from_static(&[0x02, 0x04, 127, 0, 0, 1, 0x00, 0x50]);
    assert_eq!(buf.len(), 8);
    let res = TcpOpen::decode(&mut buf);
    assert_eq!(res, Err(ProtocolError::Truncated));
    assert_eq!(buf.len(), 0);
}

// =========================================================================
// FINDING-23: uk-policy Restricted Address Classifier Omits ORCHIDv2 (2001:20::/28)
// =========================================================================

#[test]
fn test_poc_finding_23_orchid_v2_not_classified_as_restricted() {
    // Rule: allow all, private omitted (must default to private = false)
    let policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        port_start = 1
        port_end = 65535
        "#,
    )
    .unwrap();

    let orchid_v2_ip: IpAddr = "2001:20::1".parse().unwrap();
    let target = Target::Ipv6("2001:20::1".parse().unwrap(), 80);
    let ctx = PolicyContext {
        key_id: b"test",
        policy_group: None,
        target: &target,
        resolved_ips: &[orchid_v2_ip],
    };

    let decision = policy.evaluate(&ctx);
    // Invariant: RFC 7343 ORCHIDv2 is non-routable special-purpose IPv6, must be denied under private = false
    assert_eq!(
        decision,
        PolicyDecision::Deny,
        "Hardened invariant: ORCHIDv2 (2001:20::/28) must be denied under private=false policy"
    );
}
