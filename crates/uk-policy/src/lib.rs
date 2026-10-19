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
    #[error(
        "invalid policy domain {0} (expected a bare hostname or suffix; glob wildcards, URL schemes, ports and IP literals are not supported and would never match)"
    )]
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
        if target_or_resolution_contains_metadata_service_ip(context.target, context.resolved_ips) {
            return PolicyDecision::Deny;
        }

        for rule in &self.rules {
            if rule.matches(context) {
                if rule.action == PolicyDecision::Allow
                    && rule.private != Some(true)
                    && target_or_resolution_is_private(context.target, context.resolved_ips)
                {
                    return PolicyDecision::Deny;
                }
                return rule.action;
            }
        }

        PolicyDecision::Deny
    }

    /// Checks if the policy set contains any `Allow` rule that explicitly
    /// permits private or loopback destinations (`private = true`) without
    /// being preceded by a blanket `action = "deny", private = true` rule.
    ///
    /// The evaluator already denies private targets for `Allow` rules unless
    /// they opt in with `private = true` (see [`PolicySet::evaluate`]), so
    /// only explicit opt-ins are reported here. Such rules are a deliberate
    /// SSRF surface and deserve a startup warning.
    pub fn has_unrestricted_private_allow(&self) -> bool {
        let mut has_blanket_private_deny = false;
        for rule in &self.rules {
            if rule.is_blanket_private_deny() {
                has_blanket_private_deny = true;
            } else if rule.action == PolicyDecision::Allow
                && !has_blanket_private_deny
                && rule.private == Some(true)
            {
                return true;
            }
        }
        false
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
        let private = match action {
            PolicyDecision::Allow => Some(false),
            PolicyDecision::Deny => None,
        };
        Self {
            action,
            key_id: None,
            policy_group: None,
            domain: None,
            domain_suffix: None,
            cidr: None,
            ports: None,
            private,
        }
    }

    /// Returns whether this rule acts as an unconditional private IP denial.
    pub fn is_blanket_private_deny(&self) -> bool {
        self.action == PolicyDecision::Deny
            && self.private == Some(true)
            && self.key_id.is_none()
            && self.policy_group.is_none()
            && self.domain.is_none()
            && self.domain_suffix.is_none()
            && self.ports.is_none()
            && self.cidr.is_none()
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
///
/// Prefer [`Cidr::new_v4`], [`Cidr::new_v6`] or the [`FromStr`] impl over the
/// tuple variants: they reject an out-of-range prefix up front. A prefix built
/// past the address width is still handled safely, but it
/// matches a single host rather than the network the caller meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cidr {
    /// IPv4 CIDR. The prefix must be `0..=32`.
    V4(Ipv4Addr, u8),
    /// IPv6 CIDR. The prefix must be `0..=128`.
    V6(Ipv6Addr, u8),
}

impl Cidr {
    /// Creates an IPv4 CIDR, rejecting a prefix longer than 32 bits.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidCidr`] when `prefix > 32`.
    pub fn new_v4(network: Ipv4Addr, prefix: u8) -> PolicyResult<Self> {
        if prefix <= 32 {
            Ok(Self::V4(network, prefix))
        } else {
            Err(PolicyError::InvalidCidr(format!("{network}/{prefix}")))
        }
    }

    /// Creates an IPv6 CIDR, rejecting a prefix longer than 128 bits.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidCidr`] when `prefix > 128`.
    pub fn new_v6(network: Ipv6Addr, prefix: u8) -> PolicyResult<Self> {
        if prefix <= 128 {
            Ok(Self::V6(network, prefix))
        } else {
            Err(PolicyError::InvalidCidr(format!("{network}/{prefix}")))
        }
    }

    /// Returns true when `ip` is inside this CIDR.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(network, prefix), IpAddr::V4(ip)) => {
                let mask = ipv4_mask(*prefix);
                u32::from(*network) & mask == u32::from(ip) & mask
            }
            (Self::V4(_, _), IpAddr::V6(ip)) => {
                ipv4_mapped(ip).is_some_and(|mapped_ip| self.contains(IpAddr::V4(mapped_ip)))
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
            IpAddr::V4(ip) => Self::new_v4(ip, prefix),
            IpAddr::V6(ip) => Self::new_v6(ip, prefix),
        }
        .map_err(|_| PolicyError::InvalidCidr(input.to_owned()))
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
        let private = match (action, raw.private) {
            (PolicyDecision::Allow, None) => Some(false),
            (_, other) => other,
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
            private,
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
        || is_unmatchable_domain_pattern(&normalized)
    {
        Err(PolicyError::InvalidDomain(domain))
    } else {
        Ok(domain)
    }
}

fn validate_domain_suffix_match(suffix: String) -> PolicyResult<String> {
    let normalized = normalize_domain(&suffix);
    if normalized.is_empty()
        || suffix.bytes().any(|byte| byte.is_ascii_control())
        || is_unmatchable_domain_pattern(&normalized)
    {
        Err(PolicyError::InvalidDomain(suffix))
    } else {
        Ok(suffix)
    }
}

/// Characters that can never appear in the hostname of a `Target::Domain`.
///
/// A pattern containing one of them is dead: it parses, passes `config-check`
/// and then silently never matches, which turns a deny rule into a no-op. The
/// common mistakes are glob syntax (`*.internal.corp`), a URL instead of a host
/// (`http://x.com`, `x.com:443`) and a mail-style address (`user@x.com`).
const UNMATCHABLE_DOMAIN_CHARS: [char; 4] = ['*', '/', ':', '@'];

/// Returns true when `normalized` can never match a domain target.
///
/// IP literals are rejected as well: an IP target decodes to `Target::Ipv4` or
/// `Target::Ipv6`, so `target_domain` returns `None` and a `domain` predicate
/// holding an address is likewise dead. Use a `cidr` predicate instead.
fn is_unmatchable_domain_pattern(normalized: &str) -> bool {
    normalized
        .chars()
        .any(|character| character.is_whitespace() || UNMATCHABLE_DOMAIN_CHARS.contains(&character))
        || normalized.parse::<IpAddr>().is_ok()
        || normalized
            .strip_prefix('.')
            .is_some_and(|stripped| stripped.parse::<IpAddr>().is_ok())
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

fn target_or_resolution_contains_metadata_service_ip(
    target: &Target,
    resolved_ips: &[IpAddr],
) -> bool {
    target_ips(target, resolved_ips)
        .into_iter()
        .any(is_metadata_service_ip)
}

fn target_or_resolution_is_private(target: &Target, resolved_ips: &[IpAddr]) -> bool {
    match target {
        Target::Ipv4(ip, _) => is_restricted_ipv4(*ip),
        Target::Ipv6(ip, _) => is_private(IpAddr::V6(*ip)),
        Target::Domain(_, _) => {
            if resolved_ips.is_empty() {
                true
            } else {
                resolved_ips.iter().copied().any(is_private)
            }
        }
    }
}

fn is_metadata_service_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip == Ipv4Addr::new(169, 254, 169, 254)
                || ip == Ipv4Addr::new(100, 100, 100, 200)
                || ip == Ipv4Addr::new(168, 63, 129, 16)
        }
        IpAddr::V6(ip) => {
            embedded_ipv4(ip).is_some_and(|ip| is_metadata_service_ip(IpAddr::V4(ip)))
                || ip == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
        }
    }
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
        IpAddr::V4(ip) => is_restricted_ipv4(ip),
        IpAddr::V6(ip) => {
            embedded_ipv4(ip).is_some_and(|ip| is_private(IpAddr::V4(ip)))
                || ip.is_unique_local()
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || is_ipv6_unicast_link_local(ip)
                || is_ipv6_site_local(ip)
                || is_ipv6_documentation(ip)
                || is_ipv6_orchid(ip)
        }
    }
}

fn is_restricted_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || is_ipv4_documentation(ip)
        || is_ipv4_shared_address(ip)
        || is_ipv4_benchmarking(ip)
        || is_ipv4_protocol_assignment(ip)
        || is_ipv4_6to4_relay_anycast(ip)
        || is_ipv4_reserved(ip)
}

fn is_ipv4_documentation(ip: Ipv4Addr) -> bool {
    matches!(
        ip.octets(),
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

fn is_ipv4_shared_address(ip: Ipv4Addr) -> bool {
    let [first, second, _, _] = ip.octets();
    first == 100 && (64..=127).contains(&second)
}

fn is_ipv4_benchmarking(ip: Ipv4Addr) -> bool {
    let [first, second, _, _] = ip.octets();
    first == 198 && matches!(second, 18 | 19)
}

/// 192.0.0.0/24, the IETF protocol assignments block. It holds the NAT64
/// well-known addresses (192.0.0.170/171) and DS-Lite (192.0.0.0/29).
fn is_ipv4_protocol_assignment(ip: Ipv4Addr) -> bool {
    matches!(ip.octets(), [192, 0, 0, _])
}

/// 192.88.99.0/24, the deprecated 6to4 relay anycast block.
fn is_ipv4_6to4_relay_anycast(ip: Ipv4Addr) -> bool {
    matches!(ip.octets(), [192, 88, 99, _])
}

fn is_ipv4_reserved(ip: Ipv4Addr) -> bool {
    ip.octets()[0] >= 240
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// fec0::/10, the deprecated site-local unicast range.
fn is_ipv6_site_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfec0
}

/// 2001:db8::/32 (RFC 3849) and 3fff::/20 (RFC 9637) documentation ranges.
fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
}

/// 2001:10::/28, the ORCHID range (RFC 4843).
fn is_ipv6_orchid(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010
}

/// Returns the IPv4 address embedded in `ip` by any known transition format.
///
/// Deliberately broader than [`ipv4_mapped`], and used only by the deny-side
/// classifiers [`is_private`] and [`is_metadata_service_ip`]: those must be
/// maximally inclusive, since recognizing one extra embedding can only ever add
/// a denial. [`Cidr::contains`] keeps using the strict [`ipv4_mapped`] form
/// because a CIDR predicate also drives allow-rules, where "this IPv6 address is
/// equivalent to that IPv4 address" must stay precise; treating a NAT64 or 6to4
/// address as an address inside `10.0.0.0/8` there would wrongly *allow*
/// traffic, not deny it.
fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if let Some(mapped) = ipv4_mapped(ip) {
        return Some(mapped);
    }
    // RFC 6052 well-known NAT64 prefix. The specification also permits
    // network-specific prefixes at /32, /40, /48, /56, /64 and /96; those are
    // site configuration and cannot be recognized from the address alone.
    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return Some(ipv4_from_segments(segments[6], segments[7]));
    }
    // RFC 4291 IPv4-compatible addresses (deprecated). The unspecified address
    // and the loopback address share this prefix but are not IPv4 embeddings,
    // so they keep their own classification instead of decoding to 0.0.0.0/1.
    if segments[..6] == [0, 0, 0, 0, 0, 0] && !(segments[6] == 0 && segments[7] <= 1) {
        return Some(ipv4_from_segments(segments[6], segments[7]));
    }
    // RFC 3056 6to4, which carries the IPv4 address in the second and third
    // segments rather than the last two.
    if segments[0] == 0x2002 {
        return Some(ipv4_from_segments(segments[1], segments[2]));
    }
    None
}

fn ipv4_mapped(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        Some(ipv4_from_segments(segments[6], segments[7]))
    } else {
        None
    }
}

fn ipv4_from_segments(high: u16, low: u16) -> Ipv4Addr {
    let high = high.to_be_bytes();
    let low = low.to_be_bytes();
    Ipv4Addr::new(high[0], high[1], low[0], low[1])
}

/// Builds the network mask for an IPv4 prefix length.
///
/// `Cidr::new_v4` and `Cidr::from_str` both bound the prefix, but [`Cidr::V4`]
/// is a public tuple variant, so a library consumer can still hand us
/// `Cidr::V4(addr, 33)`. A bare `u32::MAX << (32 - prefix)` is the wrong answer
/// twice over there: it overflows in debug, and in release the shift amount is
/// masked to `<< 1`, silently producing a *wider* mask than requested — which,
/// in an allow rule, over-permits. Clamping to a full-width mask instead makes
/// an out-of-range prefix maximally specific, so misuse can only ever match
/// fewer addresses than intended, never more.
fn ipv4_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        1..=32 => u32::MAX << (32 - prefix),
        _ => u32::MAX,
    }
}

/// Builds the network mask for an IPv6 prefix length.
///
/// Clamps an out-of-range prefix to a full-width mask for the same reason as
/// [`ipv4_mask`].
fn ipv6_mask(prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        1..=128 => u128::MAX << (128 - prefix),
        _ => u128::MAX,
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
        let resolved = [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
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
        let resolved = [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];

        assert_eq!(
            policy.evaluate(&context(&exact, Some("default"), &resolved)),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate(&context(&subdomain, Some("default"), &resolved)),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate(&context(&false_suffix, Some("default"), &resolved)),
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
        let resolved = [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];

        assert_eq!(
            policy.evaluate(&context(&exact, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
        assert_eq!(
            policy.evaluate(&context(&subdomain, Some("default"), &resolved)),
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
        let resolved = [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];

        assert_eq!(
            policy.evaluate(&context(&exact, Some("default"), &resolved)),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate(&context(&subdomain, Some("default"), &resolved)),
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
        let resolved = [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];

        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
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
    fn denies_ipv4_mapped_loopback_by_private_rule() {
        let mut rule = PolicyRule::new(PolicyDecision::Deny);
        rule.private = Some(true);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Ipv6("::ffff:127.0.0.1".parse().unwrap(), 443);

        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn detects_unrestricted_private_allow_rules() {
        // `private` omitted on a programmatic rule: the evaluator treats this
        // as "deny private", so it is not an unrestricted allow.
        let mut allow_rule = PolicyRule::new(PolicyDecision::Allow);
        allow_rule.private = None;
        allow_rule.domain_suffix = Some(".example.com".to_owned());
        let default_policy = PolicySet::new(vec![allow_rule.clone()]);
        assert!(!default_policy.has_unrestricted_private_allow());

        // Explicit `private = true` without a preceding blanket deny: this
        // genuinely permits private/loopback targets and must be reported.
        let mut allow_private = PolicyRule::new(PolicyDecision::Allow);
        allow_private.private = Some(true);
        let insecure_policy = PolicySet::new(vec![allow_private.clone()]);
        assert!(insecure_policy.has_unrestricted_private_allow());

        // A preceding blanket `deny private = true` shadows the allow for
        // private targets, so nothing is reported.
        let mut deny_private = PolicyRule::new(PolicyDecision::Deny);
        deny_private.private = Some(true);
        let secure_policy = PolicySet::new(vec![deny_private, allow_private.clone()]);
        assert!(!secure_policy.has_unrestricted_private_allow());

        let mut allow_public_only = allow_rule;
        allow_public_only.private = Some(false);
        let public_policy = PolicySet::new(vec![allow_public_only]);
        assert!(!public_policy.has_unrestricted_private_allow());
    }

    #[test]
    fn denies_restricted_ipv4_ranges_by_private_rule() {
        let mut rule = PolicyRule::new(PolicyDecision::Deny);
        rule.private = Some(true);
        let policy = PolicySet::new(vec![rule]);
        let restricted = [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
        ];

        for ip in restricted {
            let target = Target::Ipv4(ip, 443);
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &[])),
                PolicyDecision::Deny
            );
        }
    }

    #[test]
    fn private_false_rejects_restricted_ipv6_resolution() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.private = Some(false);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("restricted.example".to_owned(), 443);
        let restricted = [
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6("ff02::1".parse().unwrap()),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
        ];

        for ip in restricted {
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &[ip])),
                PolicyDecision::Deny
            );
        }
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
    fn private_false_rejects_ipv4_mapped_private_resolution() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.private = Some(false);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("mapped.example".to_owned(), 443);
        let resolved = [IpAddr::V6("::ffff:10.0.0.1".parse().unwrap())];

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
    fn cidr_deny_matches_ipv4_mapped_resolution() {
        let mut deny_rule = PolicyRule::new(PolicyDecision::Deny);
        deny_rule.cidr = Some("10.0.0.0/8".parse().unwrap());
        let allow_rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![deny_rule, allow_rule]);
        let target = Target::Domain("mapped.example".to_owned(), 443);
        let resolved = [IpAddr::V6("::ffff:10.0.0.1".parse().unwrap())];

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
    fn denies_ipv4_mapped_metadata_ip_even_when_allow_rule_matches() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Ipv6("::ffff:169.254.169.254".parse().unwrap(), 80);
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
    fn denies_domain_resolving_to_ipv4_mapped_metadata_ip() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("metadata.example".to_owned(), 80);
        let resolved = [IpAddr::V6("::ffff:169.254.169.254".parse().unwrap())];
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_aws_ipv6_metadata_ip_even_when_allow_rule_matches() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Ipv6("fd00:ec2::254".parse().unwrap(), 80);
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_alibaba_metadata_ip_even_when_allow_rule_matches() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Ipv4(Ipv4Addr::new(100, 100, 100, 200), 80);
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_domain_resolving_to_aws_ipv6_metadata_ip() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("metadata.example".to_owned(), 80);
        let resolved = [IpAddr::V6("fd00:ec2::254".parse().unwrap())];
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_domain_resolving_to_alibaba_metadata_ip() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("metadata.example".to_owned(), 80);
        let resolved = [IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200))];
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_embedded_ipv4_metadata_targets() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let embedded = [
            "::ffff:169.254.169.254",
            "64:ff9b::169.254.169.254",
            "::169.254.169.254",
            "2002:a9fe:a9fe::",
            "64:ff9b::100.100.100.200",
            "2002:6464:64c8::",
        ];

        for ip in embedded {
            let target = Target::Ipv6(ip.parse().unwrap(), 80);
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &[])),
                PolicyDecision::Deny,
                "{ip} reached the metadata service"
            );
        }
    }

    #[test]
    fn denies_embedded_private_ipv4_by_private_rule() {
        let mut deny_rule = PolicyRule::new(PolicyDecision::Deny);
        deny_rule.private = Some(true);
        let allow_rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![deny_rule, allow_rule]);
        let embedded = [
            "::ffff:10.0.0.1",
            "64:ff9b::10.0.0.1",
            "::10.0.0.1",
            "2002:0a00:0001::",
            "64:ff9b::127.0.0.1",
            "::192.168.1.1",
        ];

        for ip in embedded {
            let target = Target::Ipv6(ip.parse().unwrap(), 443);
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &[])),
                PolicyDecision::Deny,
                "{ip} escaped the private deny rule"
            );
        }
    }

    #[test]
    fn keeps_public_embedded_ipv4_public() {
        let mut deny_rule = PolicyRule::new(PolicyDecision::Deny);
        deny_rule.private = Some(true);
        let allow_rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![deny_rule, allow_rule]);
        let public = [
            "64:ff9b::93.184.216.34",
            "::93.184.216.34",
            "2002:5db8:d822::",
            "2606:4700::1111",
        ];

        for ip in public {
            let target = Target::Ipv6(ip.parse().unwrap(), 443);
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &[])),
                PolicyDecision::Allow,
                "{ip} was wrongly classified as private"
            );
        }
    }

    #[test]
    fn denies_reserved_ipv6_ranges_by_private_rule() {
        let mut rule = PolicyRule::new(PolicyDecision::Deny);
        rule.private = Some(true);
        let policy = PolicySet::new(vec![rule]);
        let reserved = [
            "fec0::1",
            "2001:10::1",
            "2001:1f:ffff::1",
            "3fff::1",
            "3fff:fff:ffff::1",
        ];

        for ip in reserved {
            let target = Target::Ipv6(ip.parse().unwrap(), 443);
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &[])),
                PolicyDecision::Deny,
                "{ip} escaped the private deny rule"
            );
        }
    }

    #[test]
    fn denies_reserved_ipv4_ranges_by_private_rule() {
        let mut rule = PolicyRule::new(PolicyDecision::Deny);
        rule.private = Some(true);
        let policy = PolicySet::new(vec![rule]);
        let reserved = [
            Ipv4Addr::new(192, 0, 0, 170),
            Ipv4Addr::new(192, 0, 0, 1),
            Ipv4Addr::new(192, 88, 99, 1),
        ];

        for ip in reserved {
            let target = Target::Ipv4(ip, 443);
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &[])),
                PolicyDecision::Deny,
                "{ip} escaped the private deny rule"
            );
        }
    }

    #[test]
    fn keeps_unspecified_and_loopback_classification() {
        assert_eq!(embedded_ipv4(Ipv6Addr::UNSPECIFIED), None);
        assert_eq!(embedded_ipv4(Ipv6Addr::LOCALHOST), None);
        assert!(is_private(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(is_private(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_metadata_service_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_metadata_service_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn keeps_cidr_matching_limited_to_ipv4_mapped() {
        let cidr: Cidr = "10.0.0.0/8".parse().unwrap();

        assert!(cidr.contains(IpAddr::V6("::ffff:10.0.0.1".parse().unwrap())));
        // NAT64 and 6to4 addresses are not members of an IPv4 network, so an
        // allow-rule CIDR must not treat them as equivalent.
        assert!(!cidr.contains(IpAddr::V6("64:ff9b::10.0.0.1".parse().unwrap())));
        assert!(!cidr.contains(IpAddr::V6("2002:0a00:0001::".parse().unwrap())));
        assert!(!cidr.contains(IpAddr::V6("::10.0.0.1".parse().unwrap())));
    }

    #[test]
    fn clamps_out_of_range_cidr_prefix_to_a_single_host() {
        // `Cidr::V4`/`Cidr::V6` are public tuple variants, so an out-of-range
        // prefix can reach the mask helpers even though `from_str` rejects it.
        // It must not panic, and above all must not widen the match.
        assert_eq!(ipv4_mask(33), u32::MAX);
        assert_eq!(ipv6_mask(129), u128::MAX);

        let v4 = Cidr::V4(Ipv4Addr::new(10, 0, 0, 1), 33);
        assert!(v4.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!v4.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

        let v6 = Cidr::V6(Ipv6Addr::LOCALHOST, 129);
        assert!(v6.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!v6.contains(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn rejects_out_of_range_cidr_prefix_at_construction() {
        assert_eq!(
            Cidr::new_v4(Ipv4Addr::new(10, 0, 0, 0), 33),
            Err(PolicyError::InvalidCidr("10.0.0.0/33".to_owned()))
        );
        assert_eq!(
            Cidr::new_v6(Ipv6Addr::LOCALHOST, 129),
            Err(PolicyError::InvalidCidr("::1/129".to_owned()))
        );
        assert_eq!(
            "10.0.0.0/33".parse::<Cidr>(),
            Err(PolicyError::InvalidCidr("10.0.0.0/33".to_owned()))
        );
        assert_eq!(
            "::1/129".parse::<Cidr>(),
            Err(PolicyError::InvalidCidr("::1/129".to_owned()))
        );
        assert_eq!(
            Cidr::new_v4(Ipv4Addr::new(10, 0, 0, 0), 32),
            Ok(Cidr::V4(Ipv4Addr::new(10, 0, 0, 0), 32))
        );
        assert_eq!(
            Cidr::new_v6(Ipv6Addr::LOCALHOST, 128),
            Ok(Cidr::V6(Ipv6Addr::LOCALHOST, 128))
        );
    }

    #[test]
    fn denies_domain_resolving_to_embedded_metadata_ip() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("metadata.example".to_owned(), 80);
        let embedded = [
            "64:ff9b::169.254.169.254",
            "::169.254.169.254",
            "2002:a9fe:a9fe::",
        ];

        for ip in embedded {
            let resolved = [IpAddr::V6(ip.parse().unwrap())];
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &resolved)),
                PolicyDecision::Deny,
                "{ip} reached the metadata service"
            );
        }
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
            private = true
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

    #[test]
    fn rejects_unmatchable_policy_domain_patterns() {
        let unmatchable = [
            "*.internal.corp",
            "*",
            "10.0.0.1",
            "10.0.0.1.",
            "::1",
            "2001:db8::1",
            "[::1]",
            "http://x.com",
            "x.com/path",
            "x.com:443",
            "user@x.com",
            "internal corp",
        ];

        for pattern in unmatchable {
            let err = PolicySet::from_toml(&format!(
                r#"
                [[rules]]
                action = "deny"
                domain = "{pattern}"
                "#
            ))
            .unwrap_err();

            assert_eq!(
                err,
                PolicyError::InvalidDomain(pattern.to_owned()),
                "domain = {pattern} was accepted"
            );

            let err = PolicySet::from_toml(&format!(
                r#"
                [[rules]]
                action = "deny"
                domain_suffix = "{pattern}"
                "#
            ))
            .unwrap_err();

            assert_eq!(
                err,
                PolicyError::InvalidDomain(pattern.to_owned()),
                "domain_suffix = {pattern} was accepted"
            );
        }
    }

    #[test]
    fn rejects_ip_literal_policy_domain_suffix() {
        let err = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "deny"
            domain_suffix = ".10.0.0.1"
            "#,
        )
        .unwrap_err();

        assert_eq!(err, PolicyError::InvalidDomain(".10.0.0.1".to_owned()));
    }

    #[test]
    fn keeps_accepting_plain_policy_domain_patterns() {
        let policy = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            domain = "api.example.com"

            [[rules]]
            action = "allow"
            domain_suffix = ".example.com"

            [[rules]]
            action = "allow"
            domain_suffix = "internal-1.corp."
            "#,
        )
        .unwrap();

        assert_eq!(policy.rules.len(), 3);
    }

    #[test]
    fn allow_rule_defaults_to_private_false_in_toml() {
        let policy = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            domain_suffix = ".example.com"
            "#,
        )
        .unwrap();
        assert_eq!(policy.rules[0].private, Some(false));
    }

    #[test]
    fn default_allow_rule_rejects_private_and_loopback_ips() {
        let policy = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            port_start = 1
            port_end = 65535
            "#,
        )
        .unwrap();
        let private_targets = [
            Target::Ipv4(Ipv4Addr::LOCALHOST, 80),
            Target::Ipv4(Ipv4Addr::new(10, 0, 0, 1), 80),
            Target::Ipv4(Ipv4Addr::new(172, 16, 0, 1), 80),
            Target::Ipv4(Ipv4Addr::new(192, 168, 1, 1), 80),
            Target::Ipv6(Ipv6Addr::LOCALHOST, 80),
        ];
        for target in private_targets {
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &[])),
                PolicyDecision::Deny
            );
        }
    }

    #[test]
    fn default_allow_rule_rejects_domain_resolving_to_private_ip() {
        let policy = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            domain_suffix = ".rebind.example"
            "#,
        )
        .unwrap();
        let target = Target::Domain("rebind.example".to_owned(), 80);
        let resolved = [IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn default_allow_rule_rejects_unresolved_domain_fallback() {
        let policy = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            domain_suffix = ".example.com"
            "#,
        )
        .unwrap();
        let target = Target::Domain("api.example.com".to_owned(), 443);
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn explicit_private_true_permits_private_ip_but_denies_metadata() {
        let policy = PolicySet::from_toml(
            r#"
            [[rules]]
            action = "allow"
            private = true
            port_start = 1
            port_end = 65535
            "#,
        )
        .unwrap();
        let private_target = Target::Ipv4(Ipv4Addr::new(10, 0, 0, 1), 80);
        assert_eq!(
            policy.evaluate(&context(&private_target, Some("default"), &[])),
            PolicyDecision::Allow
        );
        let metadata_target = Target::Ipv4(Ipv4Addr::new(169, 254, 169, 254), 80);
        assert_eq!(
            policy.evaluate(&context(&metadata_target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_azure_wireserver_ip_even_when_allow_rule_matches() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.ports = Some(1..=65535);
        rule.private = Some(true); // Even with explicit private opt-in!
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Ipv4(Ipv4Addr::new(168, 63, 129, 16), 80);
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &[])),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_domain_resolving_to_azure_wireserver_ip() {
        let mut rule = PolicyRule::new(PolicyDecision::Allow);
        rule.ports = Some(1..=65535);
        rule.private = Some(true);
        let policy = PolicySet::new(vec![rule]);
        let target = Target::Domain("metadata.azure.internal".to_owned(), 80);
        let resolved = [IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16))];
        assert_eq!(
            policy.evaluate(&context(&target, Some("default"), &resolved)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denies_embedded_ipv4_azure_wireserver_targets() {
        let rule = PolicyRule::new(PolicyDecision::Allow);
        let policy = PolicySet::new(vec![rule]);
        let embedded = [
            "::ffff:168.63.129.16",
            "64:ff9b::168.63.129.16",
            "::168.63.129.16",
            "2002:a83f:8110::",
        ];
        for ip in embedded {
            let target = Target::Ipv6(ip.parse().unwrap(), 80);
            assert_eq!(
                policy.evaluate(&context(&target, Some("default"), &[])),
                PolicyDecision::Deny,
                "failed to deny {ip}"
            );
        }
    }
}
