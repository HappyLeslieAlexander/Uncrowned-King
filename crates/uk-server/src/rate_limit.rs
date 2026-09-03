//! IP-based rate limiting and authentication brute-force protection.
#![allow(clippy::missing_panics_doc)]

use std::{
    collections::HashMap,
    net::IpAddr,
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

/// Hard cap on the number of tracked IPs. When reached, new IPs are not
/// tracked rather than allowing unbounded growth.
const MAX_ENTRIES: usize = 65_536;

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self {
            max_failures: default_max_failures(),
            window_secs: default_window_secs(),
            ban_secs: default_ban_secs(),
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
    entries: HashMap<IpAddr, IpFailureRecord>,
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
        let now = Instant::now();
        let mut state = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = state.entries.get_mut(&ip) {
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
        let now = Instant::now();
        let mut state = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Opportunistic prune if map gets large, but throttled to at most once
        // per PRUNE_INTERVAL. Without this throttle, an attacker producing
        // failures from >1024 distinct IPs would trigger an O(N) scan on every
        // single failure, exhausting CPU while holding the mutex.
        if state.entries.len() > 1024
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

        // Hard cap: stop tracking new IPs rather than growing unboundedly.
        // The worst case is a new attacker IP escapes rate-limiting, but they
        // still must authenticate — the real defense.
        if !state.entries.contains_key(&ip) && state.entries.len() >= MAX_ENTRIES {
            return false;
        }

        let record = state.entries.entry(ip).or_insert_with(|| IpFailureRecord {
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
            record.banned_until = Some(now + Duration::from_secs(self.config.ban_secs));
            true
        } else {
            false
        }
    }

    /// Clears any recorded failures for `ip` upon successful authentication.
    pub fn record_success(&self, ip: IpAddr) {
        let mut state = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entries.remove(&ip);
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
}
