//! Adversarial Empirical Challenge Test Suite for Milestone 4:
//! - Frame decoding truncation non-destructiveness (Finding 04, 17, 21, 22)
//! - Replay advance bitshift & cache saturation (Finding 01, Finding 12)
//! - CIDR IPv4-mapped containment & ORCHIDv2 policy denial (Finding 11, Finding 23)
//! - Early version validation & settings limits (Finding 18, Finding 19)
//!
//! Authored by Milestone 4 Challenger 1 (empirical-challenger).

#![allow(
    unknown_lints,
    clippy::all,
    clippy::pedantic,
    clippy::bool_assert_comparison,
    clippy::uninlined_format_args,
    clippy::manual_string_new,
    clippy::too_many_lines
)]

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    time::Duration,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::AsyncRead;
use uk_auth::{AuthChallenge, AuthError, AuthResponse, ReplayCache};
use uk_mask::{REPLAY_WINDOW, ReplayDecision, ReplayRegistry, Replayed};
use uk_policy::{Cidr, PolicyContext, PolicyDecision, PolicySet};
use uk_proto::{
    Frame, FrameHeader, FrameIoError, FrameLimits, FrameType, ProtocolError, Settings, Target,
    TcpOpen, VERSION, read_frame, varint,
};

// =========================================================================
// SECTION 1: Frame Decoding Truncation Non-Destructiveness (Findings 04, 17, 21, 22)
// =========================================================================

#[test]
fn test_challenge_frame_decode_non_destructive_all_frame_types_and_incremental_feed() {
    let limits = FrameLimits::default();

    // Construct representative frames for EVERY standard frame type
    let test_frames: Vec<Frame> = vec![
        Frame::new(FrameType::Ping, 0, 0, Bytes::new()).unwrap(),
        Frame::new(FrameType::Pong, 0, 0, Bytes::new()).unwrap(),
        Frame::new(
            FrameType::TcpData,
            0,
            42,
            Bytes::from_static(b"hello world tcp data payload"),
        )
        .unwrap(),
        Frame::new(
            FrameType::UdpData,
            0,
            99,
            Bytes::from_static(b"udp datagram packet payload"),
        )
        .unwrap(),
        Frame::new(
            FrameType::TcpClose,
            0,
            42,
            Bytes::from_static(&[0x00, 0x01]),
        )
        .unwrap(),
        Frame::new(
            FrameType::UdpClose,
            0,
            99,
            Bytes::from_static(&[0x00, 0x02]),
        )
        .unwrap(),
        Frame::new(FrameType::Error, 0, 0, Bytes::from_static(&[0x01; 4])).unwrap(),
        Frame::new(
            FrameType::PolicyDenied,
            0,
            0,
            Bytes::from_static(&[0x02; 4]),
        )
        .unwrap(),
        Frame::new(
            FrameType::ResourceLimit,
            0,
            0,
            Bytes::from_static(&[0x03; 4]),
        )
        .unwrap(),
    ];

    for frame in test_frames {
        let encoded = frame.encode().expect("frame encodes successfully");
        let total_len = encoded.len();
        assert!(total_len >= 6, "encoded frame must be at least 6 bytes");

        // Step 1: Adversarial truncation challenge across EVERY prefix length 0..total_len - 1
        for prefix_len in 0..total_len {
            let mut buf = Bytes::copy_from_slice(&encoded[..prefix_len]);
            let initial_remaining = buf.remaining();
            assert_eq!(initial_remaining, prefix_len);

            let res = Frame::decode(&mut buf, limits);

            // Invariant: Truncated frame MUST return Err(ProtocolError::Truncated)
            assert!(
                matches!(res, Err(ProtocolError::Truncated)),
                "Frame {:?} at prefix len {} must return Truncated, got: {:?}",
                frame.header.frame_type,
                prefix_len,
                res
            );

            // HARDENED INVARIANT: Truncation MUST BE STRICTLY NON-DESTRUCTIVE!
            // Not a single byte may be consumed, dropped, or advanced from `buf`!
            assert_eq!(
                buf.remaining(),
                initial_remaining,
                "DESTRUCTIVE DECODE BUG: Frame {:?} at prefix len {} consumed bytes! remaining: {}, expected: {}",
                frame.header.frame_type,
                prefix_len,
                buf.remaining(),
                initial_remaining
            );
        }

        // Step 2: Incremental streaming feed simulation
        // Simulate a network socket delivering 1 byte at a time into a dynamic buffer.
        let mut stream_buf = BytesMut::new();
        for (i, &byte) in encoded.iter().enumerate() {
            stream_buf.put_u8(byte);
            let mut cursor = stream_buf.clone().freeze();
            let res = Frame::decode(&mut cursor, limits);

            if i + 1 < total_len {
                assert_eq!(
                    res,
                    Err(ProtocolError::Truncated),
                    "Intermediate feed at byte {} must return Truncated",
                    i + 1
                );
                assert_eq!(
                    cursor.remaining(),
                    i + 1,
                    "Intermediate feed at byte {} must retain all {} bytes",
                    i + 1,
                    i + 1
                );
            } else {
                // Full frame has arrived: decode must succeed cleanly
                let decoded = res.expect("full frame must decode cleanly on final byte");
                assert_eq!(decoded, frame, "decoded frame must match original");
                assert_eq!(
                    cursor.remaining(),
                    0,
                    "all bytes of frame must be consumed on success"
                );
            }
        }
    }
}

#[test]
fn test_challenge_frame_header_decode_all_lengths_and_varint_boundaries() {
    let limits = FrameLimits::default();

    // 1. Lengths strictly under 6 bytes must return Truncated and preserve buffer
    for len in 0..6 {
        let raw = vec![VERSION; len];
        let mut buf = Bytes::copy_from_slice(&raw);
        let res = FrameHeader::decode(&mut buf, limits);
        assert_eq!(
            res,
            Err(ProtocolError::Truncated),
            "FrameHeader::decode on len {} must return Truncated",
            len
        );
        assert_eq!(
            buf.remaining(),
            len,
            "FrameHeader::decode on len {} must preserve all bytes",
            len
        );
    }

    // 2. Multi-byte Varint boundaries
    // Valid fixed head (4 bytes): version=1, TcpData (0x11), flags=0x0000
    // Followed by varint with high 2 bits indicating multi-byte varint:
    // 0x40 -> 2-byte varint
    // 0x80 -> 4-byte varint
    // 0xc0 -> 8-byte varint
    for &(first_varint_byte, expected_varint_len) in &[
        (0x01_u8, 1_usize),
        (0x40_u8, 2_usize),
        (0x80_u8, 4_usize),
        (0xc0_u8, 8_usize),
    ] {
        for available_varint_bytes in 0..expected_varint_len {
            let mut raw = vec![VERSION, FrameType::TcpData as u8, 0x00, 0x00];
            raw.push(first_varint_byte);
            raw.extend(vec![0x00; available_varint_bytes.saturating_sub(1)]);

            // If available bytes is less than expected varint length, varint::decode returns Truncated
            let mut cursor = &raw[..];
            let res = FrameHeader::decode(&mut cursor, limits);
            assert!(
                matches!(res, Err(ProtocolError::Truncated)),
                "Incomplete varint (expected {}, got {}) must return Truncated, got: {:?}",
                expected_varint_len,
                available_varint_bytes,
                res
            );
        }
    }
}

#[test]
fn test_challenge_auth_challenge_decode_non_destructiveness_and_boundaries() {
    // AuthChallenge minimal wire size is 42 bytes:
    // 32 nonce + 8 time + 1 caps len + 1 limits len = 42 bytes
    let nonce = [0x77; 32];
    let time = 1_700_000_000_u64;
    let challenge = AuthChallenge {
        server_nonce: nonce,
        server_time: time,
        server_capabilities: vec![0x01, 0x02],
        limits: vec![0x03],
    };
    let mut encoded = BytesMut::new();
    challenge.encode(&mut encoded).unwrap();
    let wire = encoded.freeze();
    assert!(wire.len() >= 42);

    // Adversarial truncation from 0 up to wire.len() - 1
    for prefix_len in 0..wire.len() {
        let mut buf = Bytes::copy_from_slice(&wire[..prefix_len]);
        let initial_len = buf.remaining();
        assert_eq!(initial_len, prefix_len);

        let res = AuthChallenge::decode(&mut buf);
        assert!(
            res.is_err(),
            "AuthChallenge::decode at len {} must fail, got: {:?}",
            prefix_len,
            res
        );

        if prefix_len < 42 {
            assert_eq!(
                res,
                Err(AuthError::InvalidPayload("challenge is truncated")),
                "Under 42 bytes must return InvalidPayload('challenge is truncated')"
            );
            // Must preserve all buffer bytes
            assert_eq!(
                buf.remaining(),
                initial_len,
                "AuthChallenge::decode must preserve buffer on underrun (<42)"
            );
        }
    }

    // Full decode succeeds
    let mut full_buf = Bytes::copy_from_slice(&wire);
    let decoded = AuthChallenge::decode(&mut full_buf).expect("full challenge decodes");
    assert_eq!(decoded.server_nonce, nonce);
    assert_eq!(decoded.server_time, time);
    assert_eq!(decoded.server_capabilities, vec![0x01, 0x02]);
    assert_eq!(decoded.limits, vec![0x03]);
    assert_eq!(full_buf.remaining(), 0);
}

#[test]
fn test_challenge_auth_response_preallocation_and_tag_truncation() {
    // Construct an AuthResponse with 500 bytes of capabilities
    let key_id = b"test-key-id".to_vec();
    let nonce = [0x55; 32];
    let time = 1_700_000_001_u64;
    let caps = vec![0xaa; 500];
    let tag = [0xbb; 32];
    let response = AuthResponse {
        key_id: key_id.clone(),
        client_nonce: nonce,
        client_time: time,
        client_capabilities: caps.clone(),
        tag,
    };

    let mut encoded = BytesMut::new();
    response.encode(&mut encoded).unwrap();
    let wire = encoded.freeze();

    // The tag is the final 32 bytes of wire
    let wire_without_tag = &wire[..wire.len() - 32];

    // Truncate the tag from 0 bytes up to 31 bytes
    for tag_len in 0..32 {
        let mut truncated = wire_without_tag.to_vec();
        truncated.extend_from_slice(&tag[..tag_len]);

        let mut buf = Bytes::from(truncated);
        let res = AuthResponse::decode(&mut buf);

        // HARDENED INVARIANT: Pre-allocation bounds check MUST reject truncated tag
        // before allocating capabilities Vec!
        assert_eq!(
            res,
            Err(AuthError::InvalidPayload("response tag is truncated")),
            "AuthResponse::decode with tag_len {} must return InvalidPayload('response tag is truncated'), got: {:?}",
            tag_len,
            res
        );
    }
}

#[test]
fn test_challenge_tcp_open_decode_all_target_types_and_truncation_preservation() {
    // Test 3 target variants: IPv4, IPv6, Domain
    let targets = vec![
        Target::Ipv4(Ipv4Addr::new(192, 168, 1, 100), 8080),
        Target::Ipv6("2001:db8::dead:beef".parse().unwrap(), 443),
        Target::Domain("secure.internal.corp".to_string(), 9000),
    ];

    for target in targets {
        let tcp_open = TcpOpen::new(target.clone(), 0);
        let mut wire = BytesMut::new();
        tcp_open.encode(&mut wire).unwrap();
        let encoded = wire.freeze();

        // 1. Inputs strictly under 7 bytes must return Truncated and NOT consume bytes
        for len in 0..7.min(encoded.len()) {
            let mut buf = Bytes::copy_from_slice(&encoded[..len]);
            let initial_len = buf.remaining();
            let res = TcpOpen::decode(&mut buf);
            assert_eq!(
                res,
                Err(ProtocolError::Truncated),
                "TcpOpen::decode on len {} must return Truncated",
                len
            );
            assert_eq!(
                buf.remaining(),
                initial_len,
                "TcpOpen::decode on len {} must preserve buffer",
                len
            );
        }

        // 2. Truncate at open_flags tail:
        // For IPv4 targets (total wire 10 bytes), missing open_flags (8 or 9 bytes)
        // passes the 7-byte floor, decodes the target, and is then rejected
        // for missing flags (FINDING-22).
        if matches!(target, Target::Ipv4(..)) {
            let mut buf_no_flags = Bytes::copy_from_slice(&encoded[..encoded.len() - 2]);
            let res_no_flags = TcpOpen::decode(&mut buf_no_flags);
            assert_eq!(
                res_no_flags,
                Err(ProtocolError::Truncated),
                "IPv4 TcpOpen with missing flags must return Truncated"
            );
            assert_eq!(buf_no_flags.remaining(), 0);

            let mut buf_half_flags = Bytes::copy_from_slice(&encoded[..encoded.len() - 1]);
            let res_half_flags = TcpOpen::decode(&mut buf_half_flags);
            assert_eq!(
                res_half_flags,
                Err(ProtocolError::Truncated),
                "IPv4 TcpOpen with 1 byte of flags must return Truncated"
            );
            assert_eq!(buf_half_flags.remaining(), 1);
        } else {
            // For IPv6 and Domain targets (target len >= 15 bytes), missing flags
            // will decode target and then return Truncated on missing open_flags.
            let mut buf_no_flags = Bytes::copy_from_slice(&encoded[..encoded.len() - 2]);
            let res_no_flags = TcpOpen::decode(&mut buf_no_flags);
            assert_eq!(
                res_no_flags,
                Err(ProtocolError::Truncated),
                "Non-IPv4 TcpOpen with missing flags must return Truncated"
            );
        }

        // Full decode succeeds
        let mut full_buf = Bytes::copy_from_slice(&encoded);
        let decoded = TcpOpen::decode(&mut full_buf).expect("full TcpOpen decodes");
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.open_flags, 0);
        assert_eq!(full_buf.remaining(), 0);
    }
}

// =========================================================================
// SECTION 2: Replay Bitshift Advance & Cache Saturation (Findings 01, 12)
// =========================================================================

/// Oracle model for sliding replay window of size 1024
struct ReplayOracle {
    highest: u64,
    seen: BTreeSet<u64>,
}

impl ReplayOracle {
    fn new(initial_counter: u64) -> Self {
        let mut seen = BTreeSet::new();
        seen.insert(initial_counter);
        Self {
            highest: initial_counter,
            seen,
        }
    }

    fn check(&mut self, counter: u64) -> ReplayDecision {
        if counter == 0 {
            return ReplayDecision::Rejected(Replayed::Zero);
        }
        if counter > self.highest {
            self.highest = counter;
            self.seen.insert(counter);
            // Prune counters outside 1024 window
            let min_tracked = self.highest.saturating_sub(REPLAY_WINDOW - 1);
            self.seen.retain(|&c| c >= min_tracked);
            return ReplayDecision::Accepted;
        }

        let distance = self.highest - counter;
        if distance >= REPLAY_WINDOW {
            return ReplayDecision::Rejected(Replayed::BelowWindow);
        }

        if self.seen.contains(&counter) {
            ReplayDecision::Rejected(Replayed::Duplicate)
        } else {
            self.seen.insert(counter);
            ReplayDecision::Accepted
        }
    }
}

#[test]
fn test_challenge_replay_advance_bitshift_oracle_100k_stress() {
    let mut registry = ReplayRegistry::new(16);
    let identity = 0xcafe_babe_u64;

    let initial = 1000_u64;
    assert_eq!(registry.commit(identity, initial), ReplayDecision::Accepted);
    let mut oracle = ReplayOracle::new(initial);

    // Run 100,000 deterministic adversarial operations
    // Using a fast PRNG (LCG) for deterministic reproducibility without external deps
    let mut seed = 0x123456789abcdef_u64;
    let mut next_rand = || -> u64 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        seed
    };

    let mut current_highest = initial;

    for step in 0..100_000 {
        let op_type = next_rand() % 100;
        let test_counter = match op_type {
            // 0..40: Sequential or small advance (+1..+10)
            0..=40 => {
                let adv = (next_rand() % 10) + 1;
                current_highest += adv;
                current_highest
            }
            // 41..60: Replay a counter recently seen (within 0..100 distance)
            41..=60 => {
                let dist = next_rand() % 100;
                current_highest.saturating_sub(dist)
            }
            // 61..75: Replay a counter deeper in window (100..1023 distance)
            61..=75 => {
                let dist = (next_rand() % (REPLAY_WINDOW - 100)) + 100;
                current_highest.saturating_sub(dist)
            }
            // 76..85: Counter below window (> 1024 distance)
            76..=85 => {
                let dist = (next_rand() % 5000) + 1024;
                current_highest.saturating_sub(dist)
            }
            // 86..92: Counter zero
            86..=92 => 0,
            // 93..97: Moderate forward jump (+50..+500)
            93..=97 => {
                let adv = (next_rand() % 450) + 50;
                current_highest += adv;
                current_highest
            }
            // 98..99: Large forward jump crossing entire 1024 window (+1025..+3000)
            _ => {
                let adv = (next_rand() % 2000) + 1025;
                current_highest += adv;
                current_highest
            }
        };

        let oracle_decision = oracle.check(test_counter);
        let registry_decision = registry.commit(identity, test_counter);

        assert_eq!(
            registry_decision, oracle_decision,
            "Replay decision mismatch at step {} for counter {} (highest {}): registry={:?}, oracle={:?}",
            step, test_counter, current_highest, registry_decision, oracle_decision
        );
    }
}

#[test]
fn test_challenge_replay_cache_saturation_and_prune_adversarial() {
    // Capacity = 50, window = 100s
    let capacity = 50;
    let window = Duration::from_secs(100);
    let mut cache = ReplayCache::with_max_entries(window, capacity);

    // 1. Insert 50 legitimate nonces
    let mut legitimate_pairs = Vec::new();
    for i in 0..capacity {
        let mut srv = [0x11; 32];
        let mut cli = [0x22; 32];
        srv[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        cli[0..8].copy_from_slice(&(i as u64).to_le_bytes());

        assert!(
            cache.check_and_insert(srv, cli).is_ok(),
            "Legitimate insertion {} must succeed",
            i
        );
        legitimate_pairs.push((srv, cli));
    }

    // 2. Attacker floods with 50,000 distinct nonces
    for i in 0..50_000 {
        let mut srv = [0xee; 32];
        let mut cli = [0xff; 32];
        srv[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        cli[0..8].copy_from_slice(&(i as u64).to_le_bytes());

        let res = cache.check_and_insert(srv, cli);
        assert_eq!(
            res,
            Err(AuthError::ResourceLimit("replay cache saturated")),
            "Saturation flood {} must return ResourceLimit",
            i
        );
    }

    // 3. HARDENED INVARIANT: NONE of the 50 legitimate nonces were evicted!
    // Every single one must STILL be rejected as Replay!
    for (i, &(srv, cli)) in legitimate_pairs.iter().enumerate() {
        let replay_res = cache.check_and_insert(srv, cli);
        assert_eq!(
            replay_res,
            Err(AuthError::Replay),
            "INVARIANT VIOLATION: Nonce {} was evicted from saturated cache!",
            i
        );
    }
}

// =========================================================================
// SECTION 3: CIDR IPv4-Mapped Containment & ORCHIDv2 Policy Denial (Findings 11, 23)
// =========================================================================

#[test]
fn test_challenge_cidr_containment_dual_stack_disjointness_matrix() {
    let v6_wildcard = Cidr::from_str("::/0").unwrap();
    let v4_wildcard = Cidr::from_str("0.0.0.0/0").unwrap();
    let v4_private_10 = Cidr::from_str("10.0.0.0/8").unwrap();
    let v4_private_192 = Cidr::from_str("192.168.0.0/16").unwrap();

    let test_ips = [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.1.1",
        "93.184.216.34",
        "169.254.169.254",
        "0.0.0.0",
        "255.255.255.255",
        "1.1.1.1",
        "8.8.8.8",
    ];

    for ip_str in test_ips {
        let v4: Ipv4Addr = ip_str.parse().unwrap();
        let mapped_v6 = IpAddr::V6(v4.to_ipv6_mapped());
        let plain_v4 = IpAddr::V4(v4);

        // HARDENED INVARIANT 1: IPv6 ::/0 must NEVER match an IPv4-mapped address!
        assert!(
            !v6_wildcard.contains(mapped_v6),
            "CRITICAL INVARIANT VIOLATION: ::/0 matched IPv4-mapped address {}",
            ip_str
        );

        // HARDENED INVARIANT 2: IPv4 0.0.0.0/0 MUST match both plain IPv4 and IPv4-mapped IPv6!
        assert!(
            v4_wildcard.contains(mapped_v6),
            "0.0.0.0/0 must match IPv4-mapped address {}",
            ip_str
        );
        assert!(
            v4_wildcard.contains(plain_v4),
            "0.0.0.0/0 must match plain IPv4 address {}",
            ip_str
        );

        // Subnet precision:
        if ip_str.starts_with("10.") {
            assert!(v4_private_10.contains(mapped_v6));
            assert!(v4_private_10.contains(plain_v4));
        } else {
            assert!(!v4_private_10.contains(mapped_v6));
            assert!(!v4_private_10.contains(plain_v4));
        }

        if ip_str.starts_with("192.168.") {
            assert!(v4_private_192.contains(mapped_v6));
            assert!(v4_private_192.contains(plain_v4));
        } else {
            assert!(!v4_private_192.contains(mapped_v6));
            assert!(!v4_private_192.contains(plain_v4));
        }
    }

    // Real IPv6 addresses must match ::/0 and NOT 0.0.0.0/0
    let real_v6_ips = [
        "2001:db8::1",
        "2606:4700:4700::1111",
        "::1",
        "fe80::1",
        "2001:20::1",
    ];
    for v6_str in real_v6_ips {
        let v6: IpAddr = v6_str.parse().unwrap();
        assert!(v6_wildcard.contains(v6));
        assert!(!v4_wildcard.contains(v6));
    }
}

#[test]
fn test_challenge_orchid_v2_boundary_denial_across_policy_modes() {
    // RFC 7343 ORCHIDv2 is 2001:20::/28 (2001:0020::0000..=2001:002f:ffff:ffff:ffff:ffff:ffff:ffff)
    let policy_default_allow = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        port_start = 1
        port_end = 65535
        "#,
    )
    .unwrap();

    let policy_explicit_private_false = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        cidr = "::/0"
        private = false
        "#,
    )
    .unwrap();

    let policy_explicit_private_true = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        cidr = "::/0"
        private = true
        "#,
    )
    .unwrap();

    // ORCHIDv2 boundary and internal test vectors
    let orchid_vectors = [
        ("2001:20::", true),
        ("2001:20::1", true),
        ("2001:25:ffff::1", true),
        ("2001:2a:beef::dead", true),
        ("2001:2f:ffff:ffff:ffff:ffff:ffff:ffff", true),
        // Neighbors outside the /28
        ("2001:1f:ffff:ffff:ffff:ffff:ffff:ffff", false), // ORCHIDv1 boundary (also restricted)
        ("2001:30::0", false),                            // Outside restricted
        ("2001:30::1", false),                            // Outside restricted
        ("2606:4700:4700::1111", false),                  // Public internet
    ];

    for (addr_str, is_orchid_v2) in orchid_vectors {
        let ip: IpAddr = addr_str.parse().unwrap();
        let target = Target::Ipv6(addr_str.parse().unwrap(), 443);
        let ctx = PolicyContext {
            key_id: b"challenger",
            policy_group: None,
            target: &target,
            resolved_ips: &[ip],
        };

        let decision_default = policy_default_allow.evaluate(&ctx);
        let decision_false = policy_explicit_private_false.evaluate(&ctx);
        let decision_true = policy_explicit_private_true.evaluate(&ctx);

        if is_orchid_v2 {
            // HARDENED INVARIANT: ORCHIDv2 MUST BE DENIED under default (private=false)
            assert_eq!(
                decision_default,
                PolicyDecision::Deny,
                "ORCHIDv2 {} was allowed under default allow!",
                addr_str
            );
            assert_eq!(
                decision_false,
                PolicyDecision::Deny,
                "ORCHIDv2 {} was allowed under explicit private=false!",
                addr_str
            );
            // With private=true, matches ::/0 allow
            assert_eq!(
                decision_true,
                PolicyDecision::Allow,
                "ORCHIDv2 {} was denied under explicit private=true!",
                addr_str
            );
        } else if addr_str.starts_with("2001:1f:") {
            // ORCHIDv1 is also restricted, so it must also be denied under private=false
            assert_eq!(decision_default, PolicyDecision::Deny);
            assert_eq!(decision_false, PolicyDecision::Deny);
        } else {
            // Public IPv6 addresses must be allowed under default and private=false
            assert_eq!(
                decision_default,
                PolicyDecision::Allow,
                "Public IPv6 {} was denied under default allow",
                addr_str
            );
            assert_eq!(
                decision_false,
                PolicyDecision::Allow,
                "Public IPv6 {} was denied under private=false",
                addr_str
            );
        }
    }
}

// =========================================================================
// SECTION 4: Early Version Validation & Settings Limits (Findings 18, 19)
// =========================================================================

/// Custom AsyncRead mock that yields 1 byte and then pauses or closes
struct StalledOneByteReader {
    byte: u8,
    read: bool,
}

impl AsyncRead for StalledOneByteReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.read && buf.remaining() > 0 {
            buf.put_slice(&[self.byte]);
            self.read = true;
            std::task::Poll::Ready(Ok(()))
        } else {
            // Does not yield any more bytes (EOF or stall)
            std::task::Poll::Ready(Ok(()))
        }
    }
}

#[tokio::test]
async fn test_challenge_read_frame_early_version_rejection_without_delay() {
    let limits = FrameLimits::default();

    // Test invalid versions: 0, 2, 3, 9, 255
    for invalid_version in [0x00, 0x02, 0x03, 0x09, 0xff] {
        let mut reader = StalledOneByteReader {
            byte: invalid_version,
            read: false,
        };

        // read_frame must return UnsupportedVersion immediately upon reading the first byte,
        // without waiting or failing with UnexpectedEof / Truncated!
        let res = read_frame(&mut reader, limits).await;
        assert!(
            matches!(
                res,
                Err(FrameIoError::Protocol(ProtocolError::UnsupportedVersion(v))) if v == invalid_version
            ),
            "read_frame on version {} must return UnsupportedVersion({}), got: {:?}",
            invalid_version,
            invalid_version,
            res
        );
    }
}

#[test]
fn test_challenge_settings_decode_stress_limits() {
    // 1. Exact boundary at MAX_SETTINGS_COUNT (64)
    let mut buf64 = BytesMut::new();
    varint::encode(64, &mut buf64).unwrap();
    // 64 setting entries (even if unknown keys, they must be parsed without error up to 64)
    for i in 0..64 {
        varint::encode(100 + i, &mut buf64).unwrap(); // key
        varint::encode(1000 + i, &mut buf64).unwrap(); // value
    }
    let mut cursor64 = buf64.freeze();
    let res64 = Settings::decode(&mut cursor64);
    assert!(res64.is_ok(), "64 settings entries must be accepted");

    // 2. Count = 65 (> 64) must be rejected immediately
    let mut buf65 = BytesMut::new();
    varint::encode(65, &mut buf65).unwrap();
    for i in 0..65 {
        varint::encode(100 + i, &mut buf65).unwrap();
        varint::encode(1000 + i, &mut buf65).unwrap();
    }
    let mut cursor65 = buf65.freeze();
    let res65 = Settings::decode(&mut cursor65);
    assert!(
        matches!(res65, Err(ProtocolError::InvalidSettings(msg)) if msg.contains("too many")),
        "65 settings entries must be rejected with 'too many', got: {:?}",
        res65
    );

    // 3. Unbounded loop attack: count = 1_000_000 with insufficient buffer
    let mut buf_dos = BytesMut::new();
    varint::encode(1_000_000, &mut buf_dos).unwrap();
    buf_dos.extend_from_slice(&[0x01; 10]); // only 10 bytes provided
    let mut cursor_dos = buf_dos.freeze();
    let res_dos = Settings::decode(&mut cursor_dos);
    assert!(
        matches!(res_dos, Err(ProtocolError::InvalidSettings(_))),
        "1_000_000 declared settings count must fail immediately without looping"
    );

    // 4. Wire length check upfront: count = 50, but buffer has only 40 bytes (< 50 * 2)
    let mut buf_trunc = BytesMut::new();
    varint::encode(50, &mut buf_trunc).unwrap();
    buf_trunc.extend_from_slice(&[0x01; 40]);
    let mut cursor_trunc = buf_trunc.freeze();
    let res_trunc = Settings::decode(&mut cursor_trunc);
    assert_eq!(
        res_trunc,
        Err(ProtocolError::Truncated),
        "Settings with length < count * 2 must return Truncated upfront"
    );
}
