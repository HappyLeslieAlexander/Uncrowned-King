//! Pre-authentication connection concurrency limits.
//!
//! Enforces global and per-source (IPv4 address or IPv6 `/64` prefix, with
//! IPv4-mapped IPv6 canonicalization) concurrency caps synchronously on accept,
//! before spawning connection tasks or taking `handshake_permits`.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

/// Default maximum concurrent unauthenticated connections across all sources.
pub(crate) const DEFAULT_MAX_PRE_AUTH_CONNECTIONS: u64 = 256;

/// Default maximum concurrent unauthenticated connections per source.
pub(crate) const DEFAULT_MAX_PRE_AUTH_PER_SOURCE: u64 = 32;

/// Canonical source key matching `rate_limit::RateLimitKey`: IPv4 address
/// (including IPv4-mapped IPv6) or IPv6 `/64` prefix.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SourceKey {
    V4(Ipv4Addr),
    V6Prefix([u8; 8]),
}

impl From<IpAddr> for SourceKey {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    Self::V4(v4)
                } else {
                    let mut prefix = [0_u8; 8];
                    prefix.copy_from_slice(&v6.octets()[..8]);
                    Self::V6Prefix(prefix)
                }
            }
        }
    }
}

#[derive(Debug, Default)]
struct AdmissionState {
    total: usize,
    per_source: HashMap<SourceKey, usize>,
}

/// Bounded pre-authentication concurrency tracker across all sources and per
/// canonical source key.
#[derive(Debug)]
pub(crate) struct PreAdmissionLimiter {
    max_total: usize,
    max_per_source: usize,
    state: Mutex<AdmissionState>,
}

impl PreAdmissionLimiter {
    pub(crate) fn new(max_total: usize, max_per_source: usize) -> Self {
        Self {
            max_total,
            max_per_source,
            state: Mutex::new(AdmissionState::default()),
        }
    }

    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PreAdmissionGuard> {
        let key = SourceKey::from(ip);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let source_count = state.per_source.get(&key).copied().unwrap_or_default();
        if state.total >= self.max_total || source_count >= self.max_per_source {
            return None;
        }
        state.total += 1;
        state.per_source.insert(key, source_count + 1);
        Some(PreAdmissionGuard {
            limiter: Arc::clone(self),
            key,
        })
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .total
    }

    #[cfg(test)]
    pub(crate) fn tracked_sources(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .per_source
            .len()
    }
}

/// RAII guard holding one pre-authentication slot for a source until
/// authentication completes or the connection closes.
#[derive(Debug)]
pub(crate) struct PreAdmissionGuard {
    limiter: Arc<PreAdmissionLimiter>,
    key: SourceKey,
}

impl Drop for PreAdmissionGuard {
    fn drop(&mut self) {
        let mut state = self
            .limiter
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.per_source.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_source.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn enforces_global_limit_and_releases_on_drop() {
        let limiter = Arc::new(PreAdmissionLimiter::new(2, 2));
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

        let g1 = limiter.try_acquire(ip1).expect("first global slot");
        let g2 = limiter.try_acquire(ip2).expect("second global slot");
        assert!(limiter.try_acquire(ip3).is_none(), "global limit reached");
        assert_eq!(limiter.active(), 2);
        assert_eq!(limiter.tracked_sources(), 2);

        drop(g1);
        assert_eq!(limiter.active(), 1);
        assert_eq!(limiter.tracked_sources(), 1);
        let g3 = limiter.try_acquire(ip3).expect("slot freed after drop");
        assert_eq!(limiter.active(), 2);

        drop(g2);
        drop(g3);
        assert_eq!(limiter.active(), 0);
        assert_eq!(limiter.tracked_sources(), 0);
    }

    #[test]
    fn enforces_per_source_ipv4_limit_independently() {
        let limiter = Arc::new(PreAdmissionLimiter::new(4, 2));
        let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

        let g1 = limiter.try_acquire(ip1).unwrap();
        let g2 = limiter.try_acquire(ip1).unwrap();
        assert!(limiter.try_acquire(ip1).is_none(), "ip1 per-source full");

        let g3 = limiter
            .try_acquire(ip2)
            .expect("distinct ipv4 source must still be admitted");
        assert_eq!(limiter.active(), 3);
        assert_eq!(limiter.tracked_sources(), 2);

        drop(g1);
        drop(g2);
        drop(g3);
        assert_eq!(limiter.active(), 0);
        assert_eq!(limiter.tracked_sources(), 0);
    }

    #[test]
    fn groups_ipv6_by_slash64_prefix() {
        let limiter = Arc::new(PreAdmissionLimiter::new(4, 2));
        let a1 = IpAddr::V6("2001:db8:abcd:12::1".parse::<Ipv6Addr>().unwrap());
        let a2 = IpAddr::V6("2001:db8:abcd:12::ffff".parse::<Ipv6Addr>().unwrap());
        let a3 = IpAddr::V6("2001:db8:abcd:12::99".parse::<Ipv6Addr>().unwrap());
        let other_subnet = IpAddr::V6("2001:db8:abcd:13::1".parse::<Ipv6Addr>().unwrap());

        let g1 = limiter.try_acquire(a1).unwrap();
        let g2 = limiter.try_acquire(a2).unwrap();
        assert!(
            limiter.try_acquire(a3).is_none(),
            "same /64 prefix must share per-source bucket"
        );

        let g3 = limiter
            .try_acquire(other_subnet)
            .expect("different /64 prefix must have independent bucket");
        assert_eq!(limiter.tracked_sources(), 2);

        drop(g1);
        drop(g2);
        drop(g3);
        assert_eq!(limiter.tracked_sources(), 0);
    }

    #[test]
    fn canonicalizes_ipv4_mapped_ipv6_addresses() {
        let limiter = Arc::new(PreAdmissionLimiter::new(4, 2));
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let v4_mapped = IpAddr::V6("::ffff:203.0.113.10".parse::<Ipv6Addr>().unwrap());
        let v4_mapped_other = IpAddr::V6("::ffff:203.0.113.11".parse::<Ipv6Addr>().unwrap());

        let g1 = limiter.try_acquire(v4).unwrap();
        let g2 = limiter.try_acquire(v4_mapped).unwrap();
        assert_eq!(limiter.tracked_sources(), 1);
        assert!(
            limiter.try_acquire(v4).is_none(),
            "IPv4 and IPv4-mapped IPv6 must share the same bucket"
        );
        let g3 = limiter
            .try_acquire(v4_mapped_other)
            .expect("different mapped IPv4 must have separate bucket");
        assert_eq!(limiter.tracked_sources(), 2);

        drop(g1);
        drop(g2);
        drop(g3);
        assert_eq!(limiter.active(), 0);
        assert_eq!(limiter.tracked_sources(), 0);
    }

    #[test]
    fn enforces_default_32_per_source_and_256_global_constants() {
        let limiter = Arc::new(PreAdmissionLimiter::new(
            usize::try_from(DEFAULT_MAX_PRE_AUTH_CONNECTIONS).unwrap(),
            usize::try_from(DEFAULT_MAX_PRE_AUTH_PER_SOURCE).unwrap(),
        ));
        let src_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let src_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));

        let mut held = Vec::new();
        for _ in 0..32 {
            held.push(limiter.try_acquire(src_a).expect("within default 32"));
        }
        assert!(
            limiter.try_acquire(src_a).is_none(),
            "33rd slot from same source must fail under default 32"
        );
        let other = limiter
            .try_acquire(src_b)
            .expect("distinct source must still succeed");
        assert_eq!(limiter.active(), 33);
        assert_eq!(limiter.tracked_sources(), 2);

        drop(held);
        drop(other);
        assert_eq!(limiter.active(), 0);
        assert_eq!(limiter.tracked_sources(), 0);
    }
}
