//! IP-based rate limiting and authentication brute-force protection.
#![allow(clippy::missing_panics_doc)]

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Configuration for authentication failure rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthRateLimitConfig {
    /// Maximum number of auth failures before banning the IP. Default: 5.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
    /// Time window in seconds for accumulating failures. Default: 60.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Ban duration in seconds when max_failures is exceeded. Default: 300 (5 minutes).
    #[serde(default = "default_ban_secs")]
    pub ban_secs: u64,
    /// Cross-source failure count within the window that engages the global
    /// governor's enhanced mode (accelerated per-source bans, maximal
    /// rejection drain). This is the distributed brute-force defense: per-IP
    /// limits alone cannot see a botnet spreading attempts over many
    /// addresses. `0` disables the governor. Default: 50 (`max_failures × 10`).
    #[serde(default = "default_global_failure_threshold")]
    pub global_failure_threshold: u32,
}

const fn default_max_failures() -> u32 {
    5
}

const fn default_window_secs() -> u64 {
    60
}

const fn default_ban_secs() -> u64 {
    300
}

const fn default_global_failure_threshold() -> u32 {
    50
}

/// Minimum interval between O(N) prune scans to prevent CPU exhaustion
/// when an attacker floods from many distinct IPs.
const PRUNE_INTERVAL: Duration = Duration::from_secs(10);

/// Hard cap on the number of tracked IPs. When reached, older unbanned entries
/// are evicted in batches so new IPs are always tracked and cannot bypass rate limiting.
const MAX_ENTRIES: usize = 65_536;

/// Number of entries to evict at once when `MAX_ENTRIES` is reached, avoiding
/// repeated evictions on consecutive inserts.
const EVICTION_BATCH_SIZE: usize = 128;

/// Absolute ceiling for any ban duration, escalating or not (30 days).
const MAX_BAN_SECS: u64 = 2_592_000;

/// Escalation cap for repeat bans: the ban duration doubles per prior ban up
/// to `ban_secs × 2^MAX_ESCALATION_SHIFT` (and never beyond `MAX_BAN_SECS`).
const MAX_ESCALATION_SHIFT: u32 = 13;

/// Time buckets covering the governor's sliding window. Bucket width is
/// `window_secs / GLOBAL_BUCKET_COUNT` (min 1s), so the deque stays at
/// `GLOBAL_BUCKET_COUNT + 1` entries even for a 30-day window.
const GLOBAL_BUCKET_COUNT: usize = 64;

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self {
            max_failures: default_max_failures(),
            window_secs: default_window_secs(),
            ban_secs: default_ban_secs(),
            global_failure_threshold: default_global_failure_threshold(),
        }
    }
}

/// Key used to aggregate failures by IPv4 address or IPv6 /64 network prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RateLimitKey {
    V4(Ipv4Addr),
    V6Prefix([u8; 8]),
}

impl RateLimitKey {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    Self::V4(v4)
                } else {
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&v6.octets()[..8]);
                    Self::V6Prefix(prefix)
                }
            }
        }
    }
}

#[derive(Debug)]
struct IpFailureRecord {
    failures: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
    /// How many times this source has been banned. Each subsequent ban
    /// doubles the duration (capped), so a sustained attacker earns
    /// progressively longer outages while a one-off offender does not.
    /// Survives ban-expiry resets; decays only when the entry is pruned
    /// (i.e. after the source stays quiet past its window).
    ban_count: u32,
}

/// Cross-source sliding-window failure accounting backing the global
/// governor. Per-source limits cannot see a botnet distributing attempts
/// over many addresses; this dimension can.
#[derive(Debug)]
struct GlobalFailureState {
    bucket_width: Duration,
    window: Duration,
    threshold: u32,
    enhanced_duration: Duration,
    /// `(bucket_start, failures)` in time order; `bucket_start + bucket_width`
    /// bounds each bucket.
    buckets: VecDeque<(Instant, u64)>,
    total: u64,
    enhanced_until: Option<Instant>,
}

impl GlobalFailureState {
    fn new(config: &AuthRateLimitConfig) -> Self {
        let window = Duration::from_secs(config.window_secs.max(1));
        let bucket_width = Duration::from_secs(
            config
                .window_secs
                .div_ceil(GLOBAL_BUCKET_COUNT as u64)
                .max(1),
        );
        Self {
            bucket_width,
            window,
            threshold: config.global_failure_threshold,
            // A governor engagement shorter than the window would flap.
            enhanced_duration: window.max(Duration::from_secs(config.ban_secs)),
            buckets: VecDeque::new(),
            total: 0,
            enhanced_until: None,
        }
    }

    /// Drops buckets that fell out of the sliding window.
    fn advance(&mut self, now: Instant) {
        while let Some((start, count)) = self.buckets.front() {
            match now.checked_duration_since(*start) {
                Some(age) if age >= self.window => {
                    self.total = self.total.saturating_sub(*count);
                    self.buckets.pop_front();
                }
                _ => break,
            }
        }
    }

    /// Records one failure and engages enhanced mode when the threshold is
    /// crossed. Enhanced mode latches for `enhanced_duration` and re-arms on
    /// every further failure, so a sustained distributed attack stays in it.
    fn record(&mut self, now: Instant) {
        self.advance(now);
        match self.buckets.back() {
            Some((start, _))
                if now
                    .checked_duration_since(*start)
                    .is_some_and(|age| age < self.bucket_width) =>
            {
                if let Some((_, count)) = self.buckets.back_mut() {
                    *count = count.saturating_add(1);
                }
            }
            _ => self.buckets.push_back((now, 1)),
        }
        self.total = self.total.saturating_add(1);
        if self.threshold > 0 && self.total >= u64::from(self.threshold) {
            if let Some(until) = now.checked_add(self.enhanced_duration) {
                self.enhanced_until = Some(until);
            }
        }
    }

    fn enhanced(&self, now: Instant) -> bool {
        self.enhanced_until.is_some_and(|until| now < until)
    }
}

#[derive(Debug)]
struct RateLimitState {
    entries: HashMap<RateLimitKey, IpFailureRecord>,
    last_prune: Instant,
    global: GlobalFailureState,
}

/// Thread-safe IP rate limiter protecting against authentication brute-force attacks.
#[derive(Debug)]
pub struct AuthRateLimiter {
    config: AuthRateLimitConfig,
    /// Peers exempt from failure accounting: a shared NAT egress used by many
    /// clients, or a monitoring prober, would otherwise aggregate every
    /// constituent's failures into one ban. Failures from allowlisted peers
    /// are neither counted nor banned.
    allowlist: Vec<uk_policy::Cidr>,
    records: Mutex<RateLimitState>,
}

impl AuthRateLimiter {
    /// Creates a new `AuthRateLimiter` with the given configuration.
    pub fn new(config: AuthRateLimitConfig) -> Self {
        Self::with_allowlist(config, Vec::new())
    }

    /// Creates a new `AuthRateLimiter` that never limits the given networks.
    pub fn with_allowlist(config: AuthRateLimitConfig, allowlist: Vec<uk_policy::Cidr>) -> Self {
        Self {
            config,
            allowlist,
            records: Mutex::new(RateLimitState {
                entries: HashMap::new(),
                last_prune: Instant::now(),
                global: GlobalFailureState::new(&config),
            }),
        }
    }

    fn is_allowlisted(&self, ip: IpAddr) -> bool {
        self.allowlist.iter().any(|cidr| cidr.contains(ip))
    }

    /// Whether the global failure governor is currently in its enhanced mode:
    /// a distributed failure burst crossed `global_failure_threshold` within
    /// the window. Admission paths use this to apply their maximal rejection
    /// posture (e.g. the masking gate pins its drain to the full admission
    /// timeout), and per-source bans accumulate at double weight.
    pub fn enhanced_mode_active(&self) -> bool {
        let state = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.global.enhanced(Instant::now())
    }

    /// Checks whether an IP address is currently allowed to attempt authentication.
    /// Returns `true` if allowed, `false` if currently banned.
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.is_allowlisted(ip) {
            return true;
        }
        if self.config.max_failures == 0 {
            return true;
        }
        let key = RateLimitKey::from_ip(ip);
        let now = Instant::now();
        let mut state = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = state.entries.get_mut(&key) {
            if let Some(banned_until) = record.banned_until {
                if now < banned_until {
                    return false;
                }
                // Ban expired, reset
                record.banned_until = None;
                record.failures = 0;
                record.window_start = now;
            }
        }
        true
    }

    /// Records an authentication failure for `ip`.
    /// Returns `true` if the IP is now banned as a result of this failure.
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        if self.is_allowlisted(ip) {
            return false;
        }
        if self.config.max_failures == 0 {
            return false;
        }
        let key = RateLimitKey::from_ip(ip);
        let now = Instant::now();
        let mut state = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Global governor accounting: per-source limits cannot see a botnet
        // spreading attempts over many addresses. The weight applied to this
        // failure uses the enhanced state *before* it lands; a failure that
        // itself crosses the threshold accelerates the next one.
        let enhanced = state.global.enhanced(now);
        state.global.record(now);

        // Opportunistic prune if map gets large, but strictly throttled to at most once
        // per PRUNE_INTERVAL. This prevents CPU exhaustion under lock when an attacker
        // floods with failures from many distinct IPs.
        if (state.entries.len() > 1024 || state.entries.len() >= MAX_ENTRIES)
            && now.saturating_duration_since(state.last_prune) >= PRUNE_INTERVAL
        {
            state.last_prune = now;
            let window = Duration::from_secs(self.config.window_secs);
            state.entries.retain(|_, rec| {
                if let Some(banned_until) = rec.banned_until {
                    now < banned_until || now.saturating_duration_since(banned_until) < window
                } else {
                    now.checked_duration_since(rec.window_start)
                        .is_some_and(|d| d < window)
                }
            });
        }

        // When at capacity, evict unbanned entries in batches so new failing IPs
        // are always tracked and cannot bypass rate limiting by filling the map.
        // Active bans are NEVER evicted so an attacker cannot wash away legitimate bans.
        if !state.entries.contains_key(&key) && state.entries.len() >= MAX_ENTRIES {
            let mut victims = Vec::with_capacity(EVICTION_BATCH_SIZE);
            for (&entry_key, rec) in &state.entries {
                let is_active_ban = rec.banned_until.is_some_and(|until| now < until);
                if !is_active_ban {
                    victims.push(entry_key);
                    if victims.len() >= EVICTION_BATCH_SIZE {
                        break;
                    }
                }
            }
            for victim in victims {
                state.entries.remove(&victim);
            }
        }

        if !state.entries.contains_key(&key) && state.entries.len() >= MAX_ENTRIES {
            // Saturated with active bans; avoid unbounded memory growth.
            return false;
        }

        let record = state.entries.entry(key).or_insert_with(|| IpFailureRecord {
            failures: 0,
            window_start: now,
            banned_until: None,
            ban_count: 0,
        });

        // If currently banned but ban has expired, reset state
        if let Some(banned_until) = record.banned_until {
            if now >= banned_until {
                record.banned_until = None;
                record.failures = 0;
                record.window_start = now;
            }
        } else if now
            .checked_duration_since(record.window_start)
            .is_some_and(|d| d >= Duration::from_secs(self.config.window_secs))
        {
            record.failures = 0;
            record.window_start = now;
        }

        // In the governor's enhanced mode every failure counts double, so a
        // distributed burst also shortens each individual source's road to a
        // ban.
        let weight = u32::from(enhanced) + 1;
        record.failures = record.failures.saturating_add(weight);

        if record.failures >= self.config.max_failures {
            // Escalating bans: each repeat offense doubles the duration, so a
            // sustained attacker earns progressively longer outages while a
            // one-off offender does not. The count survives ban-expiry
            // resets and decays only when the entry is pruned.
            record.ban_count = record.ban_count.saturating_add(1);
            let escalation = record.ban_count.saturating_sub(1).min(MAX_ESCALATION_SHIFT);
            let ban_secs = self
                .config
                .ban_secs
                .saturating_mul(1_u64 << escalation)
                .min(MAX_BAN_SECS);
            record.banned_until = now.checked_add(Duration::from_secs(ban_secs));
            true
        } else {
            false
        }
    }

    /// Clears any recorded failures for `ip` upon successful authentication.
    pub fn record_success(&self, ip: IpAddr) {
        let key = RateLimitKey::from_ip(ip);
        let mut state = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allows_under_failure_threshold() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 3,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        assert!(limiter.check(ip));
        assert!(!limiter.record_failure(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.record_failure(ip));
        assert!(limiter.check(ip));
    }

    #[test]
    fn bans_when_threshold_reached() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 3,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        });
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        assert!(!limiter.record_failure(ip));
        assert!(!limiter.record_failure(ip));
        assert!(limiter.record_failure(ip)); // 3rd failure bans

        assert!(!limiter.check(ip));
    }

    #[test]
    fn success_resets_failure_count() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 3,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        });
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(!limiter.record_failure(ip));
        assert!(!limiter.record_failure(ip));
        limiter.record_success(ip);

        // Should start from 0 again
        assert!(!limiter.record_failure(ip));
        assert!(limiter.check(ip));
    }

    #[test]
    fn zero_max_failures_disables_rate_limiting() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 0,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        });
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        for _ in 0..10 {
            assert!(!limiter.record_failure(ip));
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn ban_expiration_resets_and_tracks_new_failures() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 2,
            window_secs: 60,
            ban_secs: 0, // 0 sec ban = immediate expiration
            global_failure_threshold: 0,
        });
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        assert!(!limiter.record_failure(ip));
        assert!(limiter.record_failure(ip)); // Banned

        // Since ban_secs is 0, ban is already expired
        assert!(limiter.check(ip)); // Resets ban & failures

        // 1st failure after expiration should not ban
        assert!(!limiter.record_failure(ip));
        assert!(limiter.check(ip));

        // 2nd failure after expiration should ban
        assert!(limiter.record_failure(ip));
    }

    #[test]
    fn record_failure_directly_after_ban_expiration_is_not_wiped_by_check() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 2,
            window_secs: 60,
            ban_secs: 0, // 0 sec ban
            global_failure_threshold: 0,
        });
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));

        assert!(!limiter.record_failure(ip));
        assert!(limiter.record_failure(ip)); // Banned

        // Call record_failure directly after ban expiration (without check() first)
        assert!(!limiter.record_failure(ip)); // resets expired ban and counts 1st failure

        // Next check should still allow
        assert!(limiter.check(ip));

        // 2nd failure should now ban (proving 1st failure was NOT wiped)
        assert!(limiter.record_failure(ip));
    }

    #[test]
    fn tracks_and_bans_new_ips_at_max_capacity() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 2,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        });
        {
            let mut state = limiter.records.lock().unwrap();
            for i in 0..MAX_ENTRIES as u32 {
                let octet2 = (i >> 16) as u8;
                let octet3 = (i >> 8) as u8;
                let octet4 = i as u8;
                let dummy_ip = IpAddr::V4(Ipv4Addr::new(10, octet2, octet3, octet4));
                state.entries.insert(
                    RateLimitKey::from_ip(dummy_ip),
                    IpFailureRecord {
                        failures: 1,
                        window_start: Instant::now(),
                        banned_until: None,
                        ban_count: 0,
                    },
                );
            }
            assert_eq!(state.entries.len(), MAX_ENTRIES);
        }

        let new_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1));
        assert!(limiter.check(new_ip));
        // 1st failure should be recorded despite capacity
        assert!(!limiter.record_failure(new_ip));
        // 2nd failure should ban new_ip
        assert!(limiter.record_failure(new_ip));
        assert!(!limiter.check(new_ip));
    }

    #[test]
    fn aggregates_ipv6_by_64_prefix() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 3,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        });

        // Three different addresses in the same 2001:db8:abcd:0012::/64 subnet
        let ip1: IpAddr = "2001:db8:abcd:12::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8:abcd:12::2".parse().unwrap();
        let ip3: IpAddr = "2001:db8:abcd:12::dead:beef".parse().unwrap();
        // A different subnet
        let ip_other: IpAddr = "2001:db8:abcd:13::1".parse().unwrap();

        assert!(limiter.check(ip1));
        assert!(!limiter.record_failure(ip1)); // 1st failure
        assert!(limiter.check(ip2));
        assert!(!limiter.record_failure(ip2)); // 2nd failure (from different host in same /64)
        assert!(limiter.check(ip3));
        assert!(limiter.record_failure(ip3)); // 3rd failure bans the /64 prefix!

        // All IPs in the /64 are now banned
        assert!(!limiter.check(ip1));
        assert!(!limiter.check(ip2));
        assert!(!limiter.check(ip3));

        // The other subnet is unaffected
        assert!(limiter.check(ip_other));
    }

    #[test]
    fn does_not_evict_active_bans_when_full() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 2,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        });
        let banned_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!limiter.record_failure(banned_ip));
        assert!(limiter.record_failure(banned_ip)); // Banned
        assert!(!limiter.check(banned_ip));

        // Fill table with unbanned records
        {
            let mut state = limiter.records.lock().unwrap();
            for i in 1..MAX_ENTRIES as u32 {
                let octet2 = (i >> 16) as u8;
                let octet3 = (i >> 8) as u8;
                let octet4 = i as u8;
                let ip = IpAddr::V4(Ipv4Addr::new(10, octet2, octet3, octet4));
                state.entries.insert(
                    RateLimitKey::from_ip(ip),
                    IpFailureRecord {
                        failures: 1,
                        window_start: Instant::now(),
                        banned_until: None,
                        ban_count: 0,
                    },
                );
            }
        }

        // Add another failing IP to trigger batch eviction
        let attacker = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        limiter.record_failure(attacker);

        // Active ban for banned_ip must still be enforced!
        assert!(!limiter.check(banned_ip));
    }

    #[test]
    fn allowlisted_peers_are_never_limited() {
        let config = AuthRateLimitConfig {
            max_failures: 3,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        };
        let allowlist = vec!["198.51.100.0/24".parse().unwrap()];
        let limiter = AuthRateLimiter::with_allowlist(config, allowlist);

        let shared_nat = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let unrelated = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        for _ in 0..10 {
            assert!(!limiter.record_failure(shared_nat));
            assert!(limiter.check(shared_nat));
        }

        // Exhausting the allowlisted network must not touch anyone else.
        for _ in 0..2 {
            assert!(!limiter.record_failure(unrelated));
        }
        assert!(limiter.check(unrelated));
        assert!(limiter.record_failure(unrelated));
        assert!(
            !limiter.check(unrelated),
            "non-allowlisted peer must be banned"
        );
    }

    #[test]
    fn bare_ip_allowlist_entry_matches_only_that_host() {
        let config = AuthRateLimitConfig {
            max_failures: 1,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        };
        let limiter = AuthRateLimiter::with_allowlist(
            config,
            vec![uk_policy::Cidr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 32).unwrap()],
        );
        let exempt = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let sibling = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        limiter.record_failure(sibling);
        assert!(!limiter.check(sibling));
        limiter.record_failure(exempt);
        assert!(limiter.check(exempt));
    }

    /// Expires the current ban of `ip` in place so the next failure counts as
    /// a repeat offense without waiting out real wall-clock time.
    fn expire_ban(limiter: &AuthRateLimiter, ip: IpAddr) {
        let mut state = limiter.records.lock().unwrap();
        let record = state
            .entries
            .get_mut(&RateLimitKey::from_ip(ip))
            .expect("banned source must be tracked");
        record.banned_until = Some(Instant::now());
    }

    fn ban_duration(limiter: &AuthRateLimiter, ip: IpAddr) -> u64 {
        let state = limiter.records.lock().unwrap();
        let record = state.entries.get(&RateLimitKey::from_ip(ip)).unwrap();
        record
            .banned_until
            .unwrap()
            .checked_duration_since(Instant::now())
            .map_or(0, |duration| duration.as_secs())
    }

    #[test]
    fn repeat_bans_escalate_exponentially() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 1,
            window_secs: 60,
            ban_secs: 60,
            global_failure_threshold: 0,
        });
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1));

        assert!(limiter.record_failure(ip));
        let mut previous = 0_u64;
        for round in 1..=4_u32 {
            if round > 1 {
                expire_ban(&limiter, ip);
                assert!(limiter.record_failure(ip), "round {round} must ban");
            }
            let duration = ban_duration(&limiter, ip);
            let expected = 60_u64 << (round - 1);
            assert!(
                duration + 1 >= expected && duration <= expected,
                "round {round}: {duration}s, expected ~{expected}s"
            );
            assert!(duration > previous, "durations must grow");
            previous = duration;
        }
    }

    #[test]
    fn escalated_bans_cap_at_thirty_days() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 1,
            window_secs: 60,
            ban_secs: 86_400,
            global_failure_threshold: 0,
        });
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 50, 2));

        let mut last = 0_u64;
        for round in 1..=8_u32 {
            if round > 1 {
                expire_ban(&limiter, ip);
            }
            assert!(limiter.record_failure(ip), "round {round} must ban");
            let duration = ban_duration(&limiter, ip);
            assert!(duration >= last, "durations must never shrink");
            last = duration;
        }
        assert!(
            last + 1 >= MAX_BAN_SECS && last <= MAX_BAN_SECS,
            "escalation must cap at {MAX_BAN_SECS}s, got {last}s"
        );
    }

    #[test]
    fn global_failures_engage_enhanced_mode() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 100,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 5,
        });

        for index in 0..4_u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (index >> 8) as u8, index as u8 + 1));
            assert!(!limiter.record_failure(ip));
        }
        assert!(!limiter.enhanced_mode_active());

        let fifth = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert!(!limiter.record_failure(fifth));
        assert!(
            limiter.enhanced_mode_active(),
            "crossing the global threshold must engage enhanced mode"
        );
    }

    #[test]
    fn enhanced_mode_accelerates_per_source_bans() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 5,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 1,
        });
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

        // The first failure engages the governor but still lands with weight 1.
        assert!(!limiter.record_failure(ip));
        assert!(limiter.enhanced_mode_active());
        assert!(!limiter.record_failure(ip), "1 + 2 = 3 must stay under 5");
        assert!(
            limiter.record_failure(ip),
            "3 + 2 = 5 must reach the per-source threshold"
        );
        assert!(!limiter.check(ip));
    }

    #[test]
    fn zero_global_threshold_disables_the_governor() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 1_000,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 0,
        });
        for index in 0..200_u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, (index >> 8) as u8, index as u8, 1));
            assert!(!limiter.record_failure(ip));
            assert!(!limiter.enhanced_mode_active());
        }
    }

    #[test]
    fn global_governor_counts_only_recent_failures() {
        let limiter = AuthRateLimiter::new(AuthRateLimitConfig {
            max_failures: 1_000,
            window_secs: 60,
            ban_secs: 300,
            global_failure_threshold: 5,
        });
        for index in 0..5_u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, index as u8 + 1));
            let _ = limiter.record_failure(ip);
        }
        assert!(limiter.enhanced_mode_active());

        {
            let mut state = limiter.records.lock().unwrap();
            let global = &mut state.global;
            let now = Instant::now();
            let aged = now
                .checked_sub(global.window)
                .and_then(|rest| rest.checked_sub(global.bucket_width))
                .expect("test window arithmetic cannot underflow");
            global.buckets.clear();
            global.buckets.push_back((aged, 99));
            global.total = 99;
        }

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42));
        let _ = limiter.record_failure(ip);
        let state = limiter.records.lock().unwrap();
        assert_eq!(state.global.total, 1, "stale buckets must be pruned");
        assert_eq!(state.global.buckets.len(), 1);
    }

    #[test]
    fn test_poc_finding_06_opportunistic_prune_erases_escalating_ban_history() {
        let config = AuthRateLimitConfig {
            max_failures: 2,
            window_secs: 60,
            ban_secs: 10,
            global_failure_threshold: 0,
        };
        let limiter = AuthRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let key = RateLimitKey::from_ip(ip);
        let now = Instant::now();

        // 1. Trigger initial ban (10s)
        assert!(!limiter.record_failure(ip));
        assert!(limiter.record_failure(ip));
        assert!(!limiter.check(ip));

        // In the records, ban_count is 1
        {
            let state = limiter.records.lock().unwrap();
            let rec = state.entries.get(&key).unwrap();
            assert_eq!(rec.ban_count, 1);
        }

        // 2. Advance time past ban expiration (e.g. 15s elapsed, within 60s quiet window)
        {
            let mut state = limiter.records.lock().unwrap();
            let expired_time = now.checked_sub(Duration::from_secs(1)).unwrap();
            state.entries.get_mut(&key).unwrap().banned_until = Some(expired_time);

            // Add dummy entries to trigger prune condition (>1024)
            for i in 0_u16..1025_u16 {
                let dummy_ip = IpAddr::V4(Ipv4Addr::new(10, (i >> 8) as u8, i as u8, 1));
                state.entries.insert(
                    RateLimitKey::from_ip(dummy_ip),
                    IpFailureRecord {
                        failures: 1,
                        window_start: now,
                        banned_until: None,
                        ban_count: 0,
                    },
                );
            }
            // Allow opportunistic prune to run by setting last_prune back in time past PRUNE_INTERVAL (10s)
            state.last_prune = now.checked_sub(Duration::from_secs(20)).unwrap();
        }

        // Trigger production prune directly via limiter.record_failure
        let new_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1));
        limiter.record_failure(new_ip);

        // Invariant: The entry should survive until a quiet window (window_secs) has elapsed.
        {
            let state = limiter.records.lock().unwrap();
            assert!(
                state.entries.contains_key(&key),
                "Expired ban entry must survive during quiet window so ban_count escalates!"
            );
        }
    }

    #[test]
    fn test_poc_finding_07_saturation_eviction_ignores_expired_bans() {
        let config = AuthRateLimitConfig {
            max_failures: 2,
            window_secs: 60,
            ban_secs: 10,
            global_failure_threshold: 0,
        };
        let limiter = AuthRateLimiter::new(config);
        let now = Instant::now();

        // Fill table to MAX_ENTRIES with expired bans (banned_until = Some(expired_time))
        let expired_time = now.checked_sub(Duration::from_secs(1)).unwrap();
        {
            let mut state = limiter.records.lock().unwrap();
            for i in 0..MAX_ENTRIES as u32 {
                let octet2 = (i >> 16) as u8;
                let octet3 = (i >> 8) as u8;
                let octet4 = i as u8;
                let dummy_ip = IpAddr::V4(Ipv4Addr::new(10, octet2, octet3, octet4));
                state.entries.insert(
                    RateLimitKey::from_ip(dummy_ip),
                    IpFailureRecord {
                        failures: 2,
                        window_start: now.checked_sub(Duration::from_secs(20)).unwrap(),
                        banned_until: Some(expired_time),
                        ban_count: 1,
                    },
                );
            }
            assert_eq!(state.entries.len(), MAX_ENTRIES);
        }

        // New IP records a failure.
        // Invariant: Table saturation eviction should evict expired bans to accommodate new failing IPs.
        let new_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));
        let record_res = limiter.record_failure(new_ip);
        assert!(
            !record_res,
            "record_failure on first failure returns false (unbanned)"
        );
        {
            let state = limiter.records.lock().unwrap();
            let key = RateLimitKey::from_ip(new_ip);
            assert!(
                state.entries.contains_key(&key),
                "New failing IP must be inserted into rate limit table by evicting expired ban!"
            );
        }
    }

    #[test]
    fn test_poc_finding_13_global_governor_integer_floor_division() {
        let config = AuthRateLimitConfig {
            max_failures: 5,
            window_secs: 120,
            ban_secs: 60,
            global_failure_threshold: 1000,
        };
        let mut state = GlobalFailureState::new(&config);
        assert_eq!(state.bucket_width, Duration::from_secs(2));

        let start = Instant::now();
        // Record 1 failure per second for 120 seconds
        for s in 0..120 {
            let now = start + Duration::from_secs(s);
            state.record(now);
        }

        // Invariant: Memory must stay bounded (<= GLOBAL_BUCKET_COUNT + 1 = 65)
        assert!(
            state.buckets.len() <= GLOBAL_BUCKET_COUNT + 1,
            "Buckets length is {} (must be <= 65)!",
            state.buckets.len()
        );
        assert_eq!(state.buckets.len(), 60);
    }
}
