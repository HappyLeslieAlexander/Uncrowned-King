//! Exhaustive adversarial verification tests for SEC-01, SEC-02, SEC-03, SEC-04.
//! Designed and executed by Challenger 1.

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
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use bytes::Bytes;
use uk_auth::{AuthChallenge, AuthError, AuthResponse, Credential, verify_auth_response_stateless};
use uk_policy::{PolicyContext, PolicyDecision, PolicyRule, PolicySet};
use uk_proto::{ProtocolError, Target};

// =========================================================================
// Helper constructors
// =========================================================================

fn make_context<'a>(
    target: &'a Target,
    policy_group: Option<&'a str>,
    resolved_ips: &'a [IpAddr],
) -> PolicyContext<'a> {
    PolicyContext {
        key_id: b"challenger-client",
        policy_group,
        target,
        resolved_ips,
    }
}

// =========================================================================
// SEC-01 Adversarial Suite: Bypass Policy Rules via Private/Loopback/Unresolved
// =========================================================================

#[test]
fn sec01_adversarial_ipv4_private_and_loopback_denied_when_private_omitted() {
    // Policy with action = "allow", private omitted (must default to private = false)
    let policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        port_start = 1
        port_end = 65535
        "#,
    )
    .expect("policy toml should parse");

    assert_eq!(
        policy.has_unrestricted_private_allow(),
        false,
        "policy must not have unrestricted private allow"
    );

    // Full spectrum of loopback /8
    let loopback_ips = [
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(127, 0, 0, 2),
        Ipv4Addr::new(127, 1, 2, 3),
        Ipv4Addr::new(127, 255, 255, 254),
        Ipv4Addr::new(127, 255, 255, 255),
    ];
    for ip in loopback_ips {
        let target = Target::Ipv4(ip, 80);
        let decision = policy.evaluate(&make_context(&target, None, &[]));
        assert_eq!(
            decision,
            PolicyDecision::Deny,
            "Loopback IP {ip} was not denied under default allow rule"
        );
    }

    // 10.0.0.0/8
    let rfc1918_10 = [
        Ipv4Addr::new(10, 0, 0, 0),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 100, 200, 50),
        Ipv4Addr::new(10, 255, 255, 254),
        Ipv4Addr::new(10, 255, 255, 255),
    ];
    for ip in rfc1918_10 {
        let target = Target::Ipv4(ip, 8080);
        let decision = policy.evaluate(&make_context(&target, None, &[]));
        assert_eq!(
            decision,
            PolicyDecision::Deny,
            "10.0.0.0/8 IP {ip} was not denied under default allow rule"
        );
    }

    // 172.16.0.0/12
    let rfc1918_172 = [
        Ipv4Addr::new(172, 16, 0, 0),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(172, 20, 10, 20),
        Ipv4Addr::new(172, 31, 255, 254),
        Ipv4Addr::new(172, 31, 255, 255),
    ];
    for ip in rfc1918_172 {
        let target = Target::Ipv4(ip, 443);
        let decision = policy.evaluate(&make_context(&target, None, &[]));
        assert_eq!(
            decision,
            PolicyDecision::Deny,
            "172.16.0.0/12 IP {ip} was not denied under default allow rule"
        );
    }

    // 192.168.0.0/16
    let rfc1918_192 = [
        Ipv4Addr::new(192, 168, 0, 0),
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 100, 200),
        Ipv4Addr::new(192, 168, 255, 254),
        Ipv4Addr::new(192, 168, 255, 255),
    ];
    for ip in rfc1918_192 {
        let target = Target::Ipv4(ip, 80);
        let decision = policy.evaluate(&make_context(&target, None, &[]));
        assert_eq!(
            decision,
            PolicyDecision::Deny,
            "192.168.0.0/16 IP {ip} was not denied under default allow rule"
        );
    }

    // Other restricted ranges: Carrier Grade NAT (100.64.0.0/10), Link-Local (169.254.0.0/16), Broadcast, Unspecified
    let other_restricted = [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 127, 255, 254),
        Ipv4Addr::new(169, 254, 1, 1),
        Ipv4Addr::new(169, 254, 254, 254),
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(198, 18, 0, 1),
        Ipv4Addr::new(240, 0, 0, 1),
    ];
    for ip in other_restricted {
        let target = Target::Ipv4(ip, 80);
        let decision = policy.evaluate(&make_context(&target, None, &[]));
        assert_eq!(
            decision,
            PolicyDecision::Deny,
            "Restricted IP {ip} was not denied under default allow rule"
        );
    }
}

#[test]
fn sec01_adversarial_ipv6_private_and_transition_denied_when_private_omitted() {
    let policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        port_start = 1
        port_end = 65535
        "#,
    )
    .expect("policy toml should parse");

    let private_ipv6 = [
        "::1",                  // Loopback
        "::",                   // Unspecified
        "fc00::1",              // Unique local
        "fd00::1",              // Unique local
        "fe80::1",              // Link-local
        "fec0::1",              // Site-local
        "::ffff:127.0.0.1",     // IPv4-mapped loopback
        "::ffff:10.0.0.1",      // IPv4-mapped 10/8
        "::ffff:172.16.0.1",    // IPv4-mapped 172.16/12
        "::ffff:192.168.1.1",   // IPv4-mapped 192.168/16
        "64:ff9b::127.0.0.1",   // NAT64 embedded loopback
        "64:ff9b::10.0.0.1",    // NAT64 embedded private
        "64:ff9b::172.16.0.1",  // NAT64 embedded private
        "64:ff9b::192.168.1.1", // NAT64 embedded private
        "::127.0.0.1",          // IPv4-compatible loopback
        "::10.0.0.1",           // IPv4-compatible private
        "2002:7f00:0001::",     // 6to4 embedded 127.0.0.1
        "2002:0a00:0001::",     // 6to4 embedded 10.0.0.1
        "2002:ac10:0001::",     // 6to4 embedded 172.16.0.1
        "2002:c0a8:0101::",     // 6to4 embedded 192.168.1.1
    ];

    for ip_str in private_ipv6 {
        let ip: Ipv6Addr = ip_str.parse().expect("valid ipv6 test address");
        let target = Target::Ipv6(ip, 80);
        let decision = policy.evaluate(&make_context(&target, None, &[]));
        assert_eq!(
            decision,
            PolicyDecision::Deny,
            "IPv6 private/transition {ip_str} was not denied under default allow rule"
        );
    }
}

#[test]
fn sec01_adversarial_unresolved_domain_completely_denied() {
    // 1. Broad allow-all rule without private
    let broad_policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        "#,
    )
    .expect("policy toml parse");

    let target = Target::Domain("unresolved.example.com".to_owned(), 80);
    // When resolved_ips is empty (unresolved or resolution pending)
    assert_eq!(
        broad_policy.evaluate(&make_context(&target, None, &[])),
        PolicyDecision::Deny,
        "unresolved domain under broad allow rule MUST be denied"
    );

    // 2. Domain-suffix allow rule without private
    let suffix_policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        domain_suffix = ".example.com"
        "#,
    )
    .expect("policy toml parse");

    assert_eq!(
        suffix_policy.evaluate(&make_context(&target, None, &[])),
        PolicyDecision::Deny,
        "unresolved domain matching suffix MUST be denied without resolved IPs"
    );

    // 3. Exact domain allow rule without private
    let exact_policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        domain = "unresolved.example.com"
        "#,
    )
    .expect("policy toml parse");

    assert_eq!(
        exact_policy.evaluate(&make_context(&target, None, &[])),
        PolicyDecision::Deny,
        "unresolved exact domain MUST be denied without resolved IPs"
    );

    // 4. In-memory programmatic PolicyRule where private is None (raw struct)
    let mut raw_rule = PolicyRule::new(PolicyDecision::Allow);
    raw_rule.private = None; // explicitly cleared to simulate uninitialized / legacy construction
    raw_rule.domain_suffix = Some(".example.com".to_owned());
    let raw_policy = PolicySet::new(vec![raw_rule]);

    assert_eq!(
        raw_policy.evaluate(&make_context(&target, None, &[])),
        PolicyDecision::Deny,
        "raw PolicyRule with private=None MUST still deny unresolved domain"
    );
}

#[test]
fn sec01_adversarial_dns_rebinding_mixed_resolution_denied() {
    let policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        domain_suffix = ".example.com"
        "#,
    )
    .expect("policy toml parse");

    let target = Target::Domain("rebind.example.com".to_owned(), 443);

    // Mixed resolutions containing 1 public and 1 private/loopback IP
    let test_cases = [
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // public
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),     // loopback
        ],
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // public
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),      // 10/8
        ],
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // public
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),    // 172.16/12
        ],
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // public
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),   // 192.168/16
        ],
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // public
            IpAddr::V6(Ipv6Addr::LOCALHOST),             // ::1
        ],
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // public
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
        ],
    ];

    for resolved in test_cases {
        assert_eq!(
            policy.evaluate(&make_context(&target, None, &resolved)),
            PolicyDecision::Deny,
            "mixed DNS resolution with private IP was not denied: {:?}",
            resolved
        );
    }
}

// =========================================================================
// SEC-03 Adversarial Suite: Azure WireServer and Metadata Permanent Denial
// =========================================================================

#[test]
fn sec03_adversarial_azure_wireserver_permanently_denied_even_with_private_true() {
    // Permissive policy with explicit private = true opt-in
    let permissive_policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        private = true
        port_start = 1
        port_end = 65535
        "#,
    )
    .expect("policy toml parse");

    // IPv4 Azure WireServer: 168.63.129.16 on various ports (DNS: 53, IMDS: 80, Guest Agent: 32526)
    let wireserver_ports = [53, 80, 443, 32526];
    for port in wireserver_ports {
        let target = Target::Ipv4(Ipv4Addr::new(168, 63, 129, 16), port);
        assert_eq!(
            permissive_policy.evaluate(&make_context(&target, None, &[])),
            PolicyDecision::Deny,
            "Azure WireServer 168.63.129.16:{port} was allowed under private=true"
        );
    }

    // IPv6 representations of Azure WireServer 168.63.129.16
    let wireserver_ipv6_variants = [
        "::ffff:168.63.129.16",   // IPv4-mapped standard
        "64:ff9b::168.63.129.16", // NAT64 well-known prefix
        "::168.63.129.16",        // RFC 4291 compatible
        "2002:a83f:8110::",       // 6to4 representation (168=0xa8, 63=0x3f, 129=0x81, 16=0x10)
    ];

    for ip_str in wireserver_ipv6_variants {
        let ip: Ipv6Addr = ip_str
            .parse()
            .expect("valid wireserver ipv6 representation");
        let target = Target::Ipv6(ip, 80);
        assert_eq!(
            permissive_policy.evaluate(&make_context(&target, None, &[])),
            PolicyDecision::Deny,
            "Azure WireServer variant {ip_str} was allowed under private=true"
        );
    }
}

#[test]
fn sec03_adversarial_azure_wireserver_via_dns_resolution_permanently_denied() {
    let permissive_policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        private = true
        domain_suffix = ".internal"
        "#,
    )
    .expect("policy toml parse");

    let target = Target::Domain("metadata.azure.internal".to_owned(), 80);

    // Direct resolution to 168.63.129.16
    let resolved_v4 = [IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16))];
    assert_eq!(
        permissive_policy.evaluate(&make_context(&target, None, &resolved_v4)),
        PolicyDecision::Deny,
        "Domain resolving to 168.63.129.16 was allowed"
    );

    // Resolution to IPv4-mapped WireServer
    let resolved_v6_mapped = [IpAddr::V6("::ffff:168.63.129.16".parse().unwrap())];
    assert_eq!(
        permissive_policy.evaluate(&make_context(&target, None, &resolved_v6_mapped)),
        PolicyDecision::Deny,
        "Domain resolving to ::ffff:168.63.129.16 was allowed"
    );

    // Resolution to 6to4 WireServer
    let resolved_6to4 = [IpAddr::V6("2002:a83f:8110::".parse().unwrap())];
    assert_eq!(
        permissive_policy.evaluate(&make_context(&target, None, &resolved_6to4)),
        PolicyDecision::Deny,
        "Domain resolving to 2002:a83f:8110:: was allowed"
    );

    // Mixed resolution with public IP and WireServer
    let resolved_mixed = [
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16)),
    ];
    assert_eq!(
        permissive_policy.evaluate(&make_context(&target, None, &resolved_mixed)),
        PolicyDecision::Deny,
        "Domain resolving to mixed public + WireServer was allowed"
    );
}

// =========================================================================
// SEC-04 Adversarial Suite: IP Literals, Malformed Dots & Invalid Characters in Target::Domain
// =========================================================================

#[test]
fn sec04_adversarial_rejects_ip_literal_strings_in_target_domain() {
    let bad_domain_ips = [
        "127.0.0.1",
        "0.0.0.0",
        "10.0.0.1",
        "168.63.129.16",
        "169.254.169.254",
        "192.168.1.1",
        "255.255.255.255",
        "8.8.8.8",
        "::1",
        "::",
        "fe80::1",
        "::ffff:127.0.0.1",
        "2001:db8::1",
    ];

    for ip in bad_domain_ips {
        // 1. Encode path
        let target = Target::Domain(ip.to_owned(), 80);
        let mut out = Vec::new();
        let enc_res = target.encode(&mut out);
        assert!(
            matches!(
                enc_res,
                Err(ProtocolError::InvalidTarget(
                    "domain must not be an IP literal"
                ))
            ),
            "Encoding Target::Domain(\"{ip}\") must fail with IP literal error, got: {:?}",
            enc_res
        );

        // 2. Decode path (wire frame attack)
        let mut wire = Vec::new();
        wire.push(0x01); // ADDR_DOMAIN
        wire.push(ip.len() as u8); // minimal varint
        wire.extend_from_slice(ip.as_bytes());
        wire.extend_from_slice(&80u16.to_be_bytes());

        let mut buf = Bytes::from(wire);
        let dec_res = Target::decode(&mut buf);
        assert!(
            matches!(
                dec_res,
                Err(ProtocolError::InvalidTarget(
                    "domain must not be an IP literal"
                ))
            ),
            "Decoding wire ADDR_DOMAIN with \"{ip}\" must fail with IP literal error, got: {:?}",
            dec_res
        );
    }
}

#[test]
fn sec04_adversarial_rejects_malformed_dot_syntax() {
    let bad_dot_domains = [
        ".com",
        ".example.com",
        ".a",
        "com.",
        "example.com.",
        "a.",
        "a..b",
        "example..com",
        "a...b",
        "..example.com",
        "example.com..",
        "a..b..c",
    ];

    for domain in bad_dot_domains {
        let target = Target::Domain(domain.to_owned(), 80);
        let mut out = Vec::new();
        let enc_res = target.encode(&mut out);
        assert!(
            matches!(
                enc_res,
                Err(ProtocolError::InvalidTarget(
                    "malformed domain dot structure"
                ))
            ),
            "Domain \"{domain}\" must be rejected for malformed dot structure, got: {:?}",
            enc_res
        );

        // Test wire decode
        let mut wire = Vec::new();
        wire.push(0x01);
        wire.push(domain.len() as u8);
        wire.extend_from_slice(domain.as_bytes());
        wire.extend_from_slice(&80u16.to_be_bytes());

        let mut buf = Bytes::from(wire);
        let dec_res = Target::decode(&mut buf);
        assert!(
            matches!(
                dec_res,
                Err(ProtocolError::InvalidTarget(
                    "malformed domain dot structure"
                ))
            ),
            "Decoding wire ADDR_DOMAIN with \"{domain}\" must fail, got: {:?}",
            dec_res
        );
    }
}

#[test]
fn sec04_adversarial_rejects_invalid_characters_and_injections() {
    let invalid_domains = [
        "http://example.com",
        "https://evil.corp",
        "ftp://service.org",
        "example.com:80",
        "example.com:443",
        "user@example.com",
        "admin:pass@example.com",
        "example.com/admin",
        "example.com/../private",
        "example\\domain.com",
        "foo_bar.com",
        "service_name.corp",
        "*.example.com",
        "?example.com",
        "[::1]",
        "example .com",
        " example.com",
        "example.com ",
        "example\t.com",
        "example\x00.com",
        "example;rm -rf /",
        "example' OR 1=1--",
        "example$HOME.com",
    ];

    for domain in invalid_domains {
        let target = Target::Domain(domain.to_owned(), 80);
        let mut out = Vec::new();
        let enc_res = target.encode(&mut out);
        assert!(
            enc_res.is_err(),
            "Invalid character domain \"{domain}\" must be rejected, but was accepted!"
        );

        // Wire decode
        let mut wire = Vec::new();
        wire.push(0x01);
        wire.push(domain.len() as u8);
        wire.extend_from_slice(domain.as_bytes());
        wire.extend_from_slice(&80u16.to_be_bytes());

        let mut buf = Bytes::from(wire);
        let dec_res = Target::decode(&mut buf);
        assert!(
            dec_res.is_err(),
            "Decoding invalid domain \"{domain}\" must fail, but succeeded!"
        );
    }
}

#[test]
fn sec04_adversarial_rejects_hyphen_boundary_and_length_extremes() {
    let boundary_cases = [
        "-example.com",
        "example-.com",
        "sub.-domain.com",
        "sub.domain-.com",
        "-a.com",
        "a-.com",
    ];

    for domain in boundary_cases {
        let target = Target::Domain(domain.to_owned(), 80);
        let mut out = Vec::new();
        let res = target.encode(&mut out);
        assert!(
            matches!(
                res,
                Err(ProtocolError::InvalidTarget(
                    "domain label cannot start or end with hyphen"
                ))
            ),
            "Hyphen boundary violation \"{domain}\" must be rejected, got: {:?}",
            res
        );
    }

    // Empty domain
    let empty_target = Target::Domain("".to_owned(), 80);
    let mut out = Vec::new();
    assert!(empty_target.encode(&mut out).is_err());

    // Label > 63 characters
    let long_label = format!("{}.com", "a".repeat(64));
    let long_label_target = Target::Domain(long_label, 80);
    assert!(long_label_target.encode(&mut out).is_err());

    // Domain > 255 characters
    let long_domain = format!(
        "{}.{}.{}.{}.{}.com",
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60),
        "d".repeat(60),
        "e".repeat(60)
    );
    assert!(long_domain.len() > 255);
    let long_domain_target = Target::Domain(long_domain, 80);
    assert!(long_domain_target.encode(&mut out).is_err());
}

// =========================================================================
// SEC-02 Adversarial Suite: Handshake Freshness, Latency & Expiry Challenge
// =========================================================================

#[test]
fn sec02_adversarial_handshake_freshness_oracle_under_simulated_latency() {
    let exporter = [42u8; 32];
    let key_id = b"sec02-client".to_vec();
    let secret = b"sec02-secret-0123456789abcdef012".to_vec();
    let cred = Credential::active(key_id.clone(), secret.clone()).unwrap();
    let credentials = vec![cred];

    let t0 = 1_700_000_000u64;
    let challenge = AuthChallenge::generate(t0);
    let allowed_skew = Duration::from_secs(2);

    // 1. Normal arrival within allowed skew (1 second latency)
    let t_arrival_ok = t0 + 1;
    let t_client = t0 + 1;
    let response_ok = AuthResponse::for_challenge(
        key_id.clone(),
        &secret,
        &exporter,
        &challenge,
        t_client,
        vec![],
    )
    .unwrap();

    let res_ok = verify_auth_response_stateless(
        &credentials,
        &exporter,
        &challenge,
        &response_ok,
        t_arrival_ok,
        allowed_skew,
    );
    assert!(
        res_ok.is_ok(),
        "Legitimate latency within skew must succeed"
    );

    // 2. Simulated high latency: arrival occurs 5 seconds after challenge (> 2s skew)
    // Client generated response freshly at t_arrival_late, but server challenge is now 5s old!
    let t_arrival_late = t0 + 5;
    let t_client_late = t0 + 5;
    let response_late = AuthResponse::for_challenge(
        key_id.clone(),
        &secret,
        &exporter,
        &challenge,
        t_client_late,
        vec![],
    )
    .unwrap();

    let res_late = verify_auth_response_stateless(
        &credentials,
        &exporter,
        &challenge,
        &response_late,
        t_arrival_late,
        allowed_skew,
    );
    assert_eq!(
        res_late,
        Err(AuthError::ClockSkew),
        "Arrival after challenge expiry MUST be rejected with ClockSkew!"
    );

    // 3. Simulated network replay of a stale challenge (100 seconds old)
    let t_arrival_stale = t0 + 100;
    let res_stale = verify_auth_response_stateless(
        &credentials,
        &exporter,
        &challenge,
        &response_ok,
        t_arrival_stale,
        allowed_skew,
    );
    assert_eq!(
        res_stale,
        Err(AuthError::ClockSkew),
        "Replay of stale challenge against new arrival time MUST fail with ClockSkew!"
    );

    // 4. Future challenge attack: challenge server_time is ahead of server verification clock
    let t_future_challenge = t0 + 50;
    let future_challenge = AuthChallenge::generate(t_future_challenge);
    let response_future = AuthResponse::for_challenge(
        key_id.clone(),
        &secret,
        &exporter,
        &future_challenge,
        t0,
        vec![],
    )
    .unwrap();
    let res_future = verify_auth_response_stateless(
        &credentials,
        &exporter,
        &future_challenge,
        &response_future,
        t0,
        allowed_skew,
    );
    assert_eq!(
        res_future,
        Err(AuthError::ClockSkew),
        "Challenge in the future beyond allowed skew MUST fail with ClockSkew!"
    );

    // 5. Future client time attack: client claims to be in the future
    let response_future_client = AuthResponse::for_challenge(
        key_id.clone(),
        &secret,
        &exporter,
        &challenge,
        t0 + 10,
        vec![],
    )
    .unwrap();
    let res_future_client = verify_auth_response_stateless(
        &credentials,
        &exporter,
        &challenge,
        &response_future_client,
        t0 + 1,
        allowed_skew,
    );
    assert_eq!(
        res_future_client,
        Err(AuthError::ClockSkew),
        "Client time in the future beyond allowed skew MUST fail with ClockSkew!"
    );
}

#[test]
fn sec01_adversarial_cidr_allow_without_private_still_denies_private_ip() {
    // CIDR allow rule with 0.0.0.0/0 and omitted private
    let global_policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        cidr = "0.0.0.0/0"
        "#,
    )
    .expect("policy toml parse");

    assert_eq!(
        global_policy.evaluate(&make_context(
            &Target::Ipv4(Ipv4Addr::new(10, 0, 0, 1), 80),
            None,
            &[]
        )),
        PolicyDecision::Deny,
        "CIDR 0.0.0.0/0 allow rule without private must deny 10.0.0.1"
    );
    assert_eq!(
        global_policy.evaluate(&make_context(
            &Target::Ipv4(Ipv4Addr::LOCALHOST, 80),
            None,
            &[]
        )),
        PolicyDecision::Deny,
        "CIDR 0.0.0.0/0 allow rule without private must deny 127.0.0.1"
    );

    // CIDR 10.0.0.0/8 specifically targeted, but private omitted
    let private_cidr_policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        cidr = "10.0.0.0/8"
        "#,
    )
    .expect("policy toml parse");

    assert_eq!(
        private_cidr_policy.evaluate(&make_context(
            &Target::Ipv4(Ipv4Addr::new(10, 0, 0, 1), 80),
            None,
            &[]
        )),
        PolicyDecision::Deny,
        "CIDR 10.0.0.0/8 allow rule without private=true must be denied by secure-by-default fallback"
    );
}

#[test]
fn sec03_adversarial_all_cloud_metadata_ips_permanent_denial() {
    let permissive_policy = PolicySet::from_toml(
        r#"
        [[rules]]
        action = "allow"
        private = true
        "#,
    )
    .expect("policy toml parse");

    // AWS, GCP, Azure WireServer
    let metadata_targets = [
        Target::Ipv4(Ipv4Addr::new(169, 254, 169, 254), 80), // AWS IMDS
        Target::Ipv4(Ipv4Addr::new(100, 100, 100, 200), 80), // GCP Metadata
        Target::Ipv4(Ipv4Addr::new(168, 63, 129, 16), 80),   // Azure WireServer
        Target::Ipv6("fd00:ec2::254".parse().unwrap(), 80),  // AWS IPv6 IMDS
        Target::Ipv6("::ffff:169.254.169.254".parse().unwrap(), 80),
        Target::Ipv6("::ffff:100.100.100.200".parse().unwrap(), 80),
        Target::Ipv6("::ffff:168.63.129.16".parse().unwrap(), 80),
        Target::Ipv6("64:ff9b::169.254.169.254".parse().unwrap(), 80),
        Target::Ipv6("64:ff9b::100.100.100.200".parse().unwrap(), 80),
        Target::Ipv6("64:ff9b::168.63.129.16".parse().unwrap(), 80),
        Target::Ipv6("2002:a9fe:a9fe::".parse().unwrap(), 80), // 6to4 AWS
        Target::Ipv6("2002:6464:64c8::".parse().unwrap(), 80), // 6to4 GCP
        Target::Ipv6("2002:a83f:8110::".parse().unwrap(), 80), // 6to4 Azure
    ];

    for target in metadata_targets {
        assert_eq!(
            permissive_policy.evaluate(&make_context(&target, None, &[])),
            PolicyDecision::Deny,
            "Metadata target {:?} was not denied under permissive allow rule",
            target
        );
    }
}

#[test]
fn sec04_adversarial_policy_parser_rejects_ip_literals_in_domain_predicates() {
    let toml_ipv4 = r#"
    [[rules]]
    action = "allow"
    domain = "127.0.0.1"
    "#;
    assert!(
        PolicySet::from_toml(toml_ipv4).is_err(),
        "PolicySet must reject IP literal in domain predicate"
    );

    let toml_ipv6 = r#"
    [[rules]]
    action = "allow"
    domain = "::1"
    "#;
    assert!(
        PolicySet::from_toml(toml_ipv6).is_err(),
        "PolicySet must reject IPv6 literal in domain predicate"
    );

    let toml_suffix_ip = r#"
    [[rules]]
    action = "allow"
    domain_suffix = ".10.0.0.1"
    "#;
    assert!(
        PolicySet::from_toml(toml_suffix_ip).is_err(),
        "PolicySet must reject IP literal in domain_suffix predicate"
    );
}
