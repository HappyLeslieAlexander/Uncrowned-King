//! IP-based rate limiting and authentication brute-force protection.
#![allow(clippy::missing_panics_doc)]

use std::{
    collections::HashMap,
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

/// Minimum interval between O(N) prune scans to prevent CPU exhaustion
/// when an attacker floods from many distinct IPs.
const PRUNE_INTERVAL: Duration = Duration::from_secs(10);

/// Hard cap on the number of tracked IPs. When reached, older unbanned entries
/// are evicted in batches so new IPs are always tracked and cannot bypass rate limiting.
const MAX_ENTRIES: usize = 65_536;

/// Number of entries to evict at once when `MAX_ENTRIES` is reached, avoiding
/// repeated evictions on consecutive inserts.
const EVICTION_BATCH_SIZE: usize = 128;

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self {
            max_failures: default_max_failures(),
            window_secs: default_window_secs(),
            ban_secs: default_ban_secs(),
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
}

#[derive(Debug)]
struct RateLimitState {
    entries: HashMap<RateLimitKey, IpFailureRecord>,
    last_prune: Instant,
}

/// Thread-safe IP rate limiter protecting against authentication brute-force attacks.
#[derive(Debug)]
pub struct AuthRateLimiter {
    config: AuthRateLimitConfig,
    records: Mutex<RateLimitState>,
}

impl AuthRateLimiter {
    /// Creates a new `AuthRateLimiter` with the given configuration.
    pub fn new(config: AuthRateLimitConfig) -> Self {
        Self {
            config,
            records: Mutex::new(RateLimitState {
                entries: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    /// Checks whether an IP address is currently allowed to attempt authentication.
    /// Returns `true` if allowed, `false` if currently banned.
    pub fn check(&self, ip: IpAddr) -> bool {
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
        if self.config.max_failures == 0 {
            return false;
        }
        let key = RateLimitKey::from_ip(ip);
        let now = Instant::now();
        let mut state = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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
                    now < banned_until
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
                if rec.banned_until.is_none() {
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

        record.failures = record.failures.saturating_add(1);

        if record.failures >= self.config.max_failures {
            record.banned_until = now.checked_add(Duration::from_secs(self.config.ban_secs));
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
}
