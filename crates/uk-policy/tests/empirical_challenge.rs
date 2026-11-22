//! Empirical challenge test suite for uk-policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use uk_policy::{Cidr, PolicyContext, PolicyDecision, PolicySet, PreResolveDecision};
use uk_proto::Target;

#[test]
fn cidr_v6_wildcard_never_matches_ipv4_mapped_ipv6() {
    let v6_all = Cidr::from_str("::/0").expect("valid cidr");

    let mapped_test_addrs = [
        "127.0.0.1",
        "0.0.0.0",
        "192.168.1.1",
        "93.184.216.34",
        "10.0.0.1",
        "172.16.0.1",
        "169.254.169.254",
        "255.255.255.255",
        "1.1.1.1",
        "8.8.8.8",
        "224.0.0.1",
    ];

    for ip_str in mapped_test_addrs {
        let v4: Ipv4Addr = ip_str.parse().unwrap();
        let mapped = v4.to_ipv6_mapped();
        let ip_mapped = IpAddr::V6(mapped);

        // ::/0 MUST NOT match IPv4-mapped IPv6
        assert!(
            !v6_all.contains(ip_mapped),
            "::/0 must NEVER match IPv4-mapped address {ip_str} ({mapped})"
        );
    }
}

#[test]
fn cidr_v4_matches_ipv4_mapped_ipv6_consistently() {
    let v4_all = Cidr::from_str("0.0.0.0/0").expect("valid cidr");
    let loopback_cidr = Cidr::from_str("127.0.0.0/8").expect("valid cidr");
    let rfc1918_cidr = Cidr::from_str("192.168.0.0/16").expect("valid cidr");
    let example_cidr = Cidr::from_str("93.184.216.0/24").expect("valid cidr");

    let ip_127 = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
    let ip_192 = IpAddr::V6(Ipv4Addr::new(192, 168, 1, 1).to_ipv6_mapped());
    let ip_93 = IpAddr::V6(Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped());

    // 0.0.0.0/0 matches all IPv4-mapped addresses
    assert!(v4_all.contains(ip_127));
    assert!(v4_all.contains(ip_192));
    assert!(v4_all.contains(ip_93));

    // Specific IPv4 CIDRs match only matching IPv4-mapped addresses
    assert!(loopback_cidr.contains(ip_127));
    assert!(!loopback_cidr.contains(ip_192));
    assert!(!loopback_cidr.contains(ip_93));

    assert!(!rfc1918_cidr.contains(ip_127));
    assert!(rfc1918_cidr.contains(ip_192));
    assert!(!rfc1918_cidr.contains(ip_93));

    assert!(!example_cidr.contains(ip_127));
    assert!(!example_cidr.contains(ip_192));
    assert!(example_cidr.contains(ip_93));
}

#[test]
fn cidr_v6_matches_standard_ipv6_and_ipv4_compatible_ipv6() {
    let v6_all = Cidr::from_str("::/0").expect("valid cidr");
    let v4_all = Cidr::from_str("0.0.0.0/0").expect("valid cidr");
    let doc_cidr = Cidr::from_str("2001:db8::/32").expect("valid cidr");

    // Standard IPv6 addresses
    let cloudflare_dns = IpAddr::V6("2606:4700:4700::1111".parse().unwrap());
    let doc_ip = IpAddr::V6("2001:db8::1".parse().unwrap());
    let loopback_v6 = IpAddr::V6("::1".parse().unwrap());

    assert!(v6_all.contains(cloudflare_dns));
    assert!(v6_all.contains(doc_ip));
    assert!(v6_all.contains(loopback_v6));

    assert!(!v4_all.contains(cloudflare_dns));
    assert!(!v4_all.contains(doc_ip));
    assert!(!v4_all.contains(loopback_v6));

    assert!(doc_cidr.contains(doc_ip));
    assert!(!doc_cidr.contains(cloudflare_dns));

    // IPv4-compatible IPv6 (deprecated RFC 4291 §2.5.5.1: 96 zero bits followed by 32 IPv4 bits)
    // Note: ::127.0.0.1 is not IPv4-mapped (which requires 0xffff in segment 5).
    // Therefore it is purely an IPv6 address and matches ::/0, NOT 0.0.0.0/0.
    let compat_ip = IpAddr::V6("::127.0.0.1".parse().unwrap());
    assert!(v6_all.contains(compat_ip));
    assert!(!v4_all.contains(compat_ip));
}

#[test]
fn orchid_v2_boundary_and_range_classification() {
    // RFC 7343 ORCHIDv2 is 2001:20::/28 (2001:0020:: through 2001:002f:ffff:ffff:ffff:ffff:ffff:ffff)
    let policy_toml = r#"
        [[rules]]
        action = "Allow"
        cidr = "::/0"
        private = false
    "#;
    let policy = PolicySet::from_toml(policy_toml).expect("valid policy");

    // Test addresses within ORCHIDv2 prefix 2001:20::/28
    let orchid_v2_addrs = [
        "2001:20::",
        "2001:20::1",
        "2001:25:beef::1234",
        "2001:2a:0:0:0:0:0:1",
        "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff",
    ];

    for addr_str in orchid_v2_addrs {
        let v6: Ipv6Addr = addr_str.parse().unwrap();
        let target = Target::Ipv6(v6, 443);
        let ctx = PolicyContext {
            key_id: b"test-key",
            policy_group: None,
            target: &target,
            resolved_ips: &[],
        };

        // When private = false, ORCHIDv2 MUST be denied
        let decision = policy.evaluate(&ctx);
        assert_eq!(
            decision,
            PolicyDecision::Deny,
            "ORCHIDv2 address {addr_str} must be rejected under private = false"
        );
    }

    // Addresses OUTSIDE ORCHIDv2 prefix
    let non_orchid_addrs = [
        "2001:30::1",
        "2001:0f:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:200::1", // 0x0200 in segment 1 is NOT 2001:20::/28
        "2606:4700:4700::1111",
    ];

    for addr_str in non_orchid_addrs {
        let v6: Ipv6Addr = addr_str.parse().unwrap();
        let target = Target::Ipv6(v6, 443);
        let ctx = PolicyContext {
            key_id: b"test-key",
            policy_group: None,
            target: &target,
            resolved_ips: &[],
        };

        // These public addresses are not restricted, so they match Allow cidr = "::/0"
        let decision = policy.evaluate(&ctx);
        assert_eq!(
            decision,
            PolicyDecision::Allow,
            "Public address {addr_str} outside restricted ranges must be allowed"
        );
    }

    // Test ORCHIDv1 (2001:10::/28) is also denied
    let orchid_v1_addrs = [
        "2001:10::",
        "2001:10::1",
        "2001:1f:ffff:ffff:ffff:ffff:ffff:ffff",
    ];
    for addr_str in orchid_v1_addrs {
        let v6: Ipv6Addr = addr_str.parse().unwrap();
        let target = Target::Ipv6(v6, 443);
        let ctx = PolicyContext {
            key_id: b"test-key",
            policy_group: None,
            target: &target,
            resolved_ips: &[],
        };
        let decision = policy.evaluate(&ctx);
        assert_eq!(
            decision,
            PolicyDecision::Deny,
            "ORCHIDv1 address {addr_str} must be rejected"
        );
    }
}

#[test]
fn orchid_v2_domain_resolution_and_pre_resolve_behavior() {
    let policy_toml = r#"
        [[rules]]
        action = "Allow"
        domain = "example.com"
        private = false
    "#;
    let policy = PolicySet::from_toml(policy_toml).expect("valid policy");
    let target = Target::Domain("example.com".to_string(), 443);

    // Pre-resolve check needs resolution because an Allow rule matches domain
    let pre = policy.evaluate_pre_resolve(&PolicyContext {
        key_id: b"key",
        policy_group: None,
        target: &target,
        resolved_ips: &[],
    });
    assert_eq!(pre, PreResolveDecision::NeedsResolution);

    // Resolution returns an ORCHIDv2 address
    let orchid_ip: IpAddr = "2001:20::cafe".parse().unwrap();
    let ctx_orchid = PolicyContext {
        key_id: b"key",
        policy_group: None,
        target: &target,
        resolved_ips: &[orchid_ip],
    };
    assert_eq!(
        policy.evaluate(&ctx_orchid),
        PolicyDecision::Deny,
        "Domain resolving to ORCHIDv2 must be rejected under private = false"
    );

    // Dual-stack resolution with one public and one ORCHIDv2 address
    let public_ip: IpAddr = "93.184.216.34".parse().unwrap();
    let ctx_dual_stack = PolicyContext {
        key_id: b"key",
        policy_group: None,
        target: &target,
        resolved_ips: &[public_ip, orchid_ip],
    };
    assert_eq!(
        policy.evaluate(&ctx_dual_stack),
        PolicyDecision::Deny,
        "Dual-stack resolution containing any ORCHIDv2 IP must be rejected"
    );

    // Resolution with purely public IPs succeeds
    let public_v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
    let ctx_public = PolicyContext {
        key_id: b"key",
        policy_group: None,
        target: &target,
        resolved_ips: &[public_ip, public_v6],
    };
    assert_eq!(
        policy.evaluate(&ctx_public),
        PolicyDecision::Allow,
        "Resolution with purely public IPs must be allowed"
    );
}

#[test]
fn ipv4_compatible_ipv6_rejected_by_private_rule() {
    // Test that IPv4-compatible IPv6 to a private IPv4 (::127.0.0.1 or ::10.0.0.1)
    // is correctly recognized as private/restricted via embedded_ipv4
    let policy_toml = r#"
        [[rules]]
        action = "Allow"
        cidr = "::/0"
        private = false
    "#;
    let policy = PolicySet::from_toml(policy_toml).expect("valid policy");

    let compat_private: Ipv6Addr = "::127.0.0.1".parse().unwrap();
    let target = Target::Ipv6(compat_private, 80);
    let ctx = PolicyContext {
        key_id: b"key",
        policy_group: None,
        target: &target,
        resolved_ips: &[],
    };
    assert_eq!(
        policy.evaluate(&ctx),
        PolicyDecision::Deny,
        "IPv4-compatible loopback IPv6 (::127.0.0.1) must be rejected by private = false"
    );
}
