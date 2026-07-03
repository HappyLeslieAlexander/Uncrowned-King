//! Minimal policy engine for Uncrowned King.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
    str::FromStr,
};

use serde::Deserialize;
use thiserror::Error;
use uk_auth::validate_key_id;
use uk_proto::Target;

/// Policy result alias.
pub type PolicyResult<T> = Result<T, PolicyError>;

/// Policy parsing errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Invalid CIDR string.
    #[error("invalid cidr {0}")]
    InvalidCidr(String),
    /// Invalid port range.
    #[error("invalid port range")]
    InvalidPortRange,
    /// Invalid action string.
    #[error("invalid policy action {0}")]
    InvalidAction(String),
    /// Invalid domain predicate.
    #[error("invalid policy domain {0}")]
    InvalidDomain(String),
    /// Invalid key id predicate.
    #[error("invalid policy key id {0}")]
    InvalidKeyId(String),
    /// Invalid policy group predicate.
    #[error("invalid policy group {0}")]
    InvalidPolicyGroup(String),
    /// TOML parse failure.
    #[error("invalid policy toml: {0}")]
    InvalidToml(String),
}

/// Final decision returned by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Access is allowed.
    Allow,
    /// Access is denied.
    Deny,
}

/// Context known when evaluating a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyContext<'a> {
    /// Authenticated key id.
    pub key_id: &'a [u8],
    /// Optional policy group.
    pub policy_group: Option<&'a str>,
    /// Requested target before DNS resolution.
    pub target: &'a Target,
    /// IPs resolved from a domain, if resolution has happened.
    pub resolved_ips: &'a [IpAddr],
}

/// A complete ordered policy set. First matching rule wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySet {
    rules: Vec<PolicyRule>,
}

impl PolicySet {
    /// Creates a policy set from rules.
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    /// Parses a TOML policy set.
    pub fn from_toml(input: &str) -> PolicyResult<Self> {
        let raw: RawPolicySet =
            toml::from_str(input).map_err(|err| PolicyError::InvalidToml(err.to_string()))?;
        raw.try_into()
    }

    /// Evaluates the target. Unmatched requests are denied.
    pub fn evaluate(&self, context: &PolicyContext<'_>) -> PolicyDecision {
        if target_or_resolution_contains_metadata_ip(context.target, context.resolved_ips) {
            return PolicyDecision::Deny;
        }

        for rule in &self.rules {
            if rule.matches(context) {
                return rule.action;
            }
        }

        PolicyDecision::Deny
    }
}

/// One ordered policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// Action returned when all configured predicates match.
    pub action: PolicyDecision,
    /// Optional exact key id match.
    pub key_id: Option<Vec<u8>>,
    /// Optional exact policy group match.
    pub policy_group: Option<String>,
    /// Optional exact domain match.
    pub domain: Option<String>,
    /// Optional domain suffix match.
    pub domain_suffix: Option<String>,
    /// Optional CIDR match against literal or resolved IPs.
    pub cidr: Option<Cidr>,
    /// Optional port range match.
    pub ports: Option<RangeInclusive<u16>>,
    /// Whether private IP targets match.
    pub private: Option<bool>,
}

impl PolicyRule {
    /// Creates a rule with an action and no predicates.
    pub fn new(action: PolicyDecision) -> Self {
        Self {
            action,
            key_id: None,
            policy_group: None,
            domain: None,
            domain_suffix: None,
            cidr: None,
            ports: None,
            private: None,
        }
    }

    fn matches(&self, context: &PolicyContext<'_>) -> bool {
        if self
            .key_id
            .as_ref()
            .is_some_and(|key_id| key_id.as_slice() != context.key_id)
        {
            return false;
        }
        if self.policy_group.as_deref().is_some_and(|group| {
            context
                .policy_group
                .is_none_or(|context_group| context_group != group)
        }) {
            return false;
        }
        if self.domain.as_deref().is_some_and(|want| {
            target_domain(context.target).is_none_or(|domain| !domain_matches_exact(domain, want))
        }) {
            return false;
        }
        if self.domain_suffix.as_deref().is_some_and(|suffix| {
            target_domain(context.target)
                .is_none_or(|domain| !domain_matches_suffix(domain, suffix))
        }) {
            return false;
        }
        if self
            .ports
            .as_ref()
            .is_some_and(|ports| !ports.contains(&context.target.port()))
        {
            return false;
        }
        if self.cidr.as_ref().is_some_and(|cidr| {
            !cidr_matches(self.action, cidr, context.target, context.resolved_ips)
        }) {
            return false;
        }
        if self
            .private
            .is_some_and(|want_private| !private_matches(context, want_private))
        {
            return false;
        }
        true
    }
}

/// IP network matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cidr {
    /// IPv4 CIDR.
    V4(Ipv4Addr, u8),
    /// IPv6 CIDR.
    V6(Ipv6Addr, u8),
}

impl Cidr {
    /// Returns true when `ip` is inside this CIDR.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(network, prefix), IpAddr::V4(ip)) => {
                let mask = ipv4_mask(*prefix);
                u32::from(*network) & mask == u32::from(ip) & mask
            }
            (Self::V6(network, prefix), IpAddr::V6(ip)) => {
                let mask = ipv6_mask(*prefix);
                u128::from(*network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = PolicyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = input
            .split_once('/')
            .ok_or_else(|| PolicyError::InvalidCidr(input.to_owned()))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| PolicyError::InvalidCidr(input.to_owned()))?;
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| PolicyError::InvalidCidr(input.to_owned()))?;
        match ip {
            IpAddr::V4(ip) if prefix <= 32 => Ok(Self::V4(ip, prefix)),
            IpAddr::V6(ip) if prefix <= 128 => Ok(Self::V6(ip, prefix)),
            _ => Err(PolicyError::InvalidCidr(input.to_owned())),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicySet {
    rules: Vec<RawPolicyRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyRule {
    action: String,
    key_id: Option<String>,
    policy_group: Option<String>,
    domain: Option<String>,
    domain_suffix: Option<String>,
    cidr: Option<String>,
    port_start: Option<u16>,
    port_end: Option<u16>,
    private: Option<bool>,
}

impl TryFrom<RawPolicySet> for PolicySet {
    type Error = PolicyError;

    fn try_from(raw: RawPolicySet) -> Result<Self, Self::Error> {
        raw.rules
            .into_iter()
            .map(PolicyRule::try_from)
            .collect::<PolicyResult<Vec<_>>>()
            .map(Self::new)
    }
}

impl TryFrom<RawPolicyRule> for PolicyRule {
    type Error = PolicyError;

    fn try_from(raw: RawPolicyRule) -> Result<Self, Self::Error> {
        let action = if raw.action.eq_ignore_ascii_case("allow") {
            PolicyDecision::Allow
        } else if raw.action.eq_ignore_ascii_case("deny") {
            PolicyDecision::Deny
        } else {
            return Err(PolicyError::InvalidAction(raw.action));
        };
        let ports = match (raw.port_start, raw.port_end) {
            (Some(start), Some(end)) if start <= end && start != 0 => Some(start..=end),
            (None, None) => None,
            _ => return Err(PolicyError::InvalidPortRange),
        };
        Ok(Self {
            action,
            key_id: raw.key_id.map(validate_key_id_match).transpose()?,
            policy_group: raw
                .policy_group
                .map(validate_policy_group_match)
                .transpose()?,
            domain: raw.domain.map(validate_domain_match).transpose()?,
            domain_suffix: raw
                .domain_suffix
                .map(validate_domain_suffix_match)
                .transpose()?,
            cidr: raw.cidr.as_deref().map(Cidr::from_str).transpose()?,
            ports,
            private: raw.private,
        })
    }
}

fn target_domain(target: &Target) -> Option<&str> {
    match target {
        Target::Domain(domain, _) => Some(domain),
        Target::Ipv4(_, _) | Target::Ipv6(_, _) => None,
    }
}

fn validate_key_id_match(key_id: String) -> PolicyResult<Vec<u8>> {
    validate_key_id(key_id.as_bytes()).map_err(|_| PolicyError::InvalidKeyId(key_id.clone()))?;
    Ok(key_id.into_bytes())
}

fn validate_policy_group_match(group: String) -> PolicyResult<String> {
    if group.is_empty() || group.bytes().any(|byte| byte.is_ascii_control()) {
        Err(PolicyError::InvalidPolicyGroup(group))
    } else {
        Ok(group)
    }
}

fn validate_domain_match(domain: String) -> PolicyResult<String> {
    let normalized = normalize_domain(&domain);
    if normalized.is_empty()
        || normalized.starts_with('.')
        || domain.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(PolicyError::InvalidDomain(domain))
    } else {
        Ok(domain)
    }
}

fn validate_domain_suffix_match(suffix: String) -> PolicyResult<String> {
    let normalized = normalize_domain(&suffix);
    if normalized.is_empty() || suffix.bytes().any(|byte| byte.is_ascii_control()) {
        Err(PolicyError::InvalidDomain(suffix))
    } else {
        Ok(suffix)
    }
}

fn domain_matches_exact(domain: &str, want: &str) -> bool {
    let domain = normalize_domain(domain);
    let want = normalize_domain(want);
    !want.is_empty() && domain == want
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let domain = normalize_domain(domain);
    let suffix = normalize_domain(suffix);
    if suffix.is_empty() {
        return false;
    }
    if let Some(stripped) = suffix.strip_prefix('.') {
        return !stripped.is_empty() && domain.len() > stripped.len() && domain.ends_with(&suffix);
    }
    domain == suffix
        || domain
            .strip_suffix(&suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn target_ips(target: &Target, resolved_ips: &[IpAddr]) -> Vec<IpAddr> {
    match target {
        Target::Domain(_, _) => resolved_ips.to_vec(),
        Target::Ipv4(ip, _) => vec![IpAddr::V4(*ip)],
        Target::Ipv6(ip, _) => vec![IpAddr::V6(*ip)],
    }
}

fn cidr_matches(
    action: PolicyDecision,
    cidr: &Cidr,
    target: &Target,
    resolved_ips: &[IpAddr],
) -> bool {
    let ips = target_ips(target, resolved_ips);
    if ips.is_empty() {
        return false;
    }

    match action {
        PolicyDecision::Allow => ips.into_iter().all(|ip| cidr.contains(ip)),
        PolicyDecision::Deny => ips.into_iter().any(|ip| cidr.contains(ip)),
    }
}

fn target_or_resolution_contains_metadata_ip(target: &Target, resolved_ips: &[IpAddr]) -> bool {
    target_ips(target, resolved_ips)
        .into_iter()
        .any(|ip| ip == IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))
}

fn private_matches(context: &PolicyContext<'_>, want_private: bool) -> bool {
    let ips = target_ips(context.target, context.resolved_ips);
    if ips.is_empty() {
        return false;
    }
    if want_private {
        ips.into_iter().any(is_private)
    } else {
        ips.into_iter().all(|ip| !is_private(ip))
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_unique_local() || ip.is_loopback() || is_ipv6_unicast_link_local(ip)
        }
    }
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context<'a>(
        target: &'a Target,
        policy_group: Option<&'a str>,
        resolved_ips: &'a [IpAddr],
    ) -> PolicyContext<'a> {
        PolicyContext {
            key_id: b"client-a",
            policy_group,
            target,
            resolved_ips,
        }
    }

    #[test]
    fn allows_domain_suffix() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.policy_group = Some("default".to_owned());
        rule.domain_suffix = Some(".example.com".to_owned());
        rule.ports = Some(443..=443);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("api.example.com".to_owned(), 443);
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn keeps_domain_suffix_on_label_boundary() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.domain_suffix = Some("example.com".to_owned());
        rule.ports = Some(443..=443);
        let policy = PolicySet::new(vec![rule]);
        let exact = Target::Domain("example.com".to_owned(), 443);
        let subdomain = Target::Domain("api.example.com".to_owned(), 443);
        let false_suffix = Target::Domain("badexample.com".to_owned(), 443);

        assert_eq!(
            policy.evaluate(&context(&exact, Some("default"), &[])),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate(&context(&subdomain, Some("default"), &[])),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate(&context(&false_suffix, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn leading_dot_domain_suffix_matches_subdomains_only() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.domain_suffix = Some(".example.com".to_owned());
        let policy = PolicySet::new(vec![rule]);
        let exact = Target::Domain("example.com".to_owned(), 443);
        let subdomain = Target::Domain("api.example.com".to_owned(), 443);

        assert_eq!(
            policy.evaluate(&context(&exact, Some("default"), &[])),
            PolicyDecision::Deny
        );
        assert_eq!(
            policy.evaluate(&context(&subdomain, Some("default"), &[])),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn allows_exact_domain_only() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.domain = Some("example.com".to_owned());
        rule.ports = Some(443..=443);
        let policy = PolicySet::new(vec![rule]);
        let exact = Target::Domain("example.com".to_owned(), 443);
        let subdomain = Target::Domain("api.example.com".to_owned(), 443);

        assert_eq!(
            policy.evaluate(&context(&exact, Some("default"), &[])),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate(&context(&subdomain, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn matches_domains_case_insensitively() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.domain = Some("Example.COM".to_owned());
        rule.ports = Some(443..=443);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("example.com".to_owned(), 443);

        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn denies_private_ip_by_rule() {
        let mut rule = PolicyRule::new(PolicyDecision::Deny);
        rule.private = Some(true);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Ipv4(Ipv4Addr::new(10, 0, 0, 1), 22);
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_ipv6_link_local_by_private_rule() {
        let mut rule = PolicyRule::new(PolicyDecision::Deny);
        rule.private = Some(true);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Ipv6("fe80::1".parse().unwrap(), 443);

        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn private_true_matches_any_private_resolution() {
        let mut rule = PolicyRule::new(PolicyDecision::Deny);
        rule.private = Some(true);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("mixed.example".to_owned(), 443);
        let resolved = [
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];

        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn private_false_requires_all_public_resolution() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.private = Some(false);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("mixed.example".to_owned(), 443);
        let resolved = [
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];

        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn cidr_allow_requires_all_domain_resolutions_to_match() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.cidr = Some("203.0.113.0/24".parse().unwrap());
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("mixed.example".to_owned(), 443);
        let resolved = [
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        ];

        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn cidr_deny_matches_any_domain_resolution() {
        let mut deny_rule = PolicyRule::new(PolicyDecision::Deny);
        deny_rule.cidr = Some("10.0.0.0/8".parse().unwrap());
        let allow_rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![deny_rule, allow_rule]);
        let target = Target::Domain("mixed.example".to_owned(), 443);
        let resolved = [
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];

        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_metadata_ip_even_when_allow_rule_matches() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Ipv4(Ipv4Addr::new(169, 254, 169, 254), 80);
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_domain_resolving_to_metadata_ip() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("metadata.example".to_owned(), 80);
        let resolved = [IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))];
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_unmatched_target() {
        let policy = PolicySet::default();
        let target = Target::Domain("example.com".to_owned(), 443);
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn parses_toml_policy() {
        let policy = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            policy_group = "ops"
            domain = "bastion.example.com"
            cidr = "10.20.0.0/16"
            port_start = 22
            port_end = 22
            "#,
        )
        .unwrap();
        let target = Target::Domain("bastion.example.com".to_owned(), 22);
        let resolved = [IpAddr::V4(Ipv4Addr::new(10, 20, 1, 2))];
        assert_eq!(
            policy.rules[0].domain.as_deref(),
            Some("bastion.example.com")
        );
        assert_eq!(
            policy.evaluate(&context(&target, Some("ops"), &resolved)),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn parses_example_policy() {
        let policy = PolicySet::from_toml(include_str!("../../../examples/policy.toml")).unwrap();

        assert_eq!(policy.rules.len(), 3);
    }

    #[test]
    fn rejects_unknown_policy_fields() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            domainn = "example.com"
            "#,
        )
        .unwrap_err();

        assert!(matches!(err, PolicyError::InvalidToml(_)));
    }

    #[test]
    fn rejects_unknown_policy_actions() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "alow"
            domain = "example.com"
            "#,
        )
        .unwrap_err();

        assert_eq!(err, PolicyError::InvalidAction("alow".to_owned()));
    }

    #[test]
    fn rejects_empty_policy_key_id() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            key_id = ""
            "#,
        )
        .unwrap_err();

        assert_eq!(err, PolicyError::InvalidKeyId(String::new()));
    }

    #[test]
    fn rejects_long_policy_key_id() {
        let err = PolicySet::from_toml(&format!(
            r#"
            [[rules]]
            action = "allow"
            key_id = "{}"
            "#,
            "k".repeat(65)
        ))
        .unwrap_err();

        assert_eq!(err, PolicyError::InvalidKeyId("k".repeat(65)));
    }

    #[test]
    fn rejects_empty_policy_group() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            policy_group = ""
            "#,
        )
        .unwrap_err();

        assert_eq!(err, PolicyError::InvalidPolicyGroup(String::new()));
    }

    #[test]
    fn rejects_control_character_policy_group() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            policy_group = "ops\nprod"
            "#,
        )
        .unwrap_err();

        assert_eq!(err, PolicyError::InvalidPolicyGroup("ops\nprod".to_owned()));
    }

    #[test]
    fn rejects_empty_policy_domain() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            domain = ""
            "#,
        )
        .unwrap_err();

        assert_eq!(err, PolicyError::InvalidDomain(String::new()));
    }

    #[test]
    fn rejects_empty_policy_domain_suffix() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            domain_suffix = ""
            "#,
        )
        .unwrap_err();

        assert_eq!(err, PolicyError::InvalidDomain(String::new()));
    }

    #[test]
    fn rejects_root_only_policy_domain_suffix() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            domain_suffix = "."
            "#,
        )
        .unwrap_err();

        assert_eq!(err, PolicyError::InvalidDomain(".".to_owned()));
    }

    #[test]
    fn rejects_control_character_policy_domains() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            domain = "bad\nname.example"
            "#,
        )
        .unwrap_err();

        assert_eq!(
            err,
            PolicyError::InvalidDomain("bad\nname.example".to_owned())
        );
    }
}
