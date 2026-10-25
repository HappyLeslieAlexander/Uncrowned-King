//! Replay registry for masking preludes.
//!
//! Each client process embeds a random 64-bit identity and a monotonic
//! 48-bit counter in every prelude. The registry tracks, per identity, the
//! highest committed counter plus a [`REPLAY_WINDOW`]-bit sliding window of
//! seen counters below it (bit 0 = highest). A counter is admissible when it
//! is fresh (above highest), unseen within the window, or belongs to an
//! unknown identity; zero, duplicates, and counters below the window are
//! rejected.
//!
//! Registry policy mirrors the construction's documented trade-offs:
//! identities enter a bounded FIFO on first registration and are never
//! refreshed; when the FIFO overflows the oldest identity is evicted and may
//! re-register later with a fresh window; nothing is persisted across
//! restarts. Established connections survive eviction — only admission uses
//! this registry.

use std::collections::HashMap;

use crate::REPLAY_WINDOW;

/// Words in a 1024-bit window bitmap.
const WINDOW_WORDS: usize = (REPLAY_WINDOW as usize) / 64;

/// Why a prelude was rejected by replay checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replayed {
    /// The counter was zero.
    Zero,
    /// The counter was already committed.
    Duplicate,
    /// The counter fell below the tracked window.
    BelowWindow,
}

/// Outcome of a replay check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    /// The counter is admissible (and committed, for `commit` calls).
    Accepted,
    /// The counter must be rejected.
    Rejected(Replayed),
}

#[derive(Debug, Clone)]
struct ReplayEntry {
    highest: u64,
    /// Sliding window of seen counters; bit `d` set means `highest - d` was seen.
    seen: [u64; WINDOW_WORDS],
}

impl ReplayEntry {
    fn fresh(counter: u64) -> Self {
        let mut seen = [0; WINDOW_WORDS];
        seen[0] = 1;
        Self {
            highest: counter,
            seen,
        }
    }

    fn bit_is_set(&self, distance: u64) -> bool {
        self.seen[(distance / 64) as usize] & (1 << (distance % 64)) != 0
    }

    fn set_bit(&mut self, distance: u64) {
        self.seen[(distance / 64) as usize] |= 1 << (distance % 64);
    }

    /// Shifts the window down by `advance` counters (a new highest was
    /// committed), clearing bits that slide past the window.
    fn advance(&mut self, advance: u64) {
        if advance >= REPLAY_WINDOW {
            self.seen = [0; WINDOW_WORDS];
            return;
        }
        let mut shifted = [0; WINDOW_WORDS];
        for target in 0..REPLAY_WINDOW {
            let source = target + advance;
            if source < REPLAY_WINDOW && self.bit_is_set(source) {
                shifted[(target / 64) as usize] |= 1 << (target % 64);
            }
        }
        self.seen = shifted;
    }

    fn admits(&self, counter: u64) -> ReplayDecision {
        if counter == 0 {
            return ReplayDecision::Rejected(Replayed::Zero);
        }
        if counter > self.highest {
            return ReplayDecision::Accepted;
        }
        let distance = self.highest - counter;
        if distance == 0 || (distance < REPLAY_WINDOW && self.bit_is_set(distance)) {
            ReplayDecision::Rejected(Replayed::Duplicate)
        } else if distance < REPLAY_WINDOW {
            ReplayDecision::Accepted
        } else {
            ReplayDecision::Rejected(Replayed::BelowWindow)
        }
    }
}

/// Bounded FIFO registry of prelude identities with per-identity sliding
/// replay windows. All state is preallocated at construction; admission
/// commits allocate nothing.
#[derive(Debug)]
pub struct ReplayRegistry {
    order: std::collections::VecDeque<u64>,
    entries: HashMap<u64, ReplayEntry>,
    capacity: usize,
}

impl ReplayRegistry {
    /// Creates a registry tracking up to `capacity` identities.
    ///
    /// # Panics
    /// Panics if `capacity` is zero.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "replay registry capacity must be positive");
        Self {
            order: std::collections::VecDeque::with_capacity(capacity),
            entries: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    /// Number of tracked identities.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no identities are tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Checks admissibility without mutating state.
    pub fn precheck(&self, identity: u64, counter: u64) -> ReplayDecision {
        match self.entries.get(&identity) {
            Some(entry) => entry.admits(counter),
            None if counter == 0 => ReplayDecision::Rejected(Replayed::Zero),
            None => ReplayDecision::Accepted,
        }
    }

    /// Atomically re-validates and commits a counter. Returns
    /// [`ReplayDecision::Accepted`] when committed.
    pub fn commit(&mut self, identity: u64, counter: u64) -> ReplayDecision {
        let decision = self.precheck(identity, counter);
        if !matches!(decision, ReplayDecision::Accepted) {
            return decision;
        }
        if let Some(entry) = self.entries.get_mut(&identity) {
            if counter > entry.highest {
                entry.advance(counter - entry.highest);
                entry.highest = counter;
                entry.set_bit(0);
            } else {
                entry.set_bit(entry.highest - counter);
            }
        } else {
            if self.entries.len() == self.capacity {
                if let Some(evicted) = self.order.pop_front() {
                    self.entries.remove(&evicted);
                }
            }
            self.order.push_back(identity);
            self.entries.insert(identity, ReplayEntry::fresh(counter));
        }
        ReplayDecision::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(registry: &mut ReplayRegistry, identity: u64, counter: u64) -> bool {
        matches!(registry.commit(identity, counter), ReplayDecision::Accepted)
    }

    #[test]
    fn fresh_identity_accepts_any_nonzero_counter() {
        let mut registry = ReplayRegistry::new(4);
        assert!(accepted(&mut registry, 7, 1));
        assert!(accepted(&mut registry, 9, 500));
        assert!(!accepted(&mut registry, 11, 0));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn duplicates_and_zero_are_rejected() {
        let mut registry = ReplayRegistry::new(4);
        assert!(accepted(&mut registry, 1, 10));
        assert!(!accepted(&mut registry, 1, 10));
        assert!(!accepted(&mut registry, 1, 0));
        // Unseen in-window counters still pass.
        assert!(accepted(&mut registry, 1, 9));
        assert!(!accepted(&mut registry, 1, 9));
    }

    #[test]
    fn window_edges_are_exact() {
        let mut registry = ReplayRegistry::new(4);
        assert!(accepted(&mut registry, 1, 2000));
        // 1023 below highest: inside the window, unseen.
        assert!(accepted(&mut registry, 1, 2000 - 1023));
        // 1024 below highest: below the window.
        assert_eq!(
            registry.commit(1, 2000 - 1024),
            ReplayDecision::Rejected(Replayed::BelowWindow)
        );
    }

    #[test]
    fn advancing_far_clears_the_window() {
        let mut registry = ReplayRegistry::new(4);
        assert!(accepted(&mut registry, 1, 100));
        assert!(!accepted(&mut registry, 1, 100));
        // A jump of >= 1024 clears old bits, so the old counter looks fresh
        // again as "below-new-highest-in-window"... it is below the window.
        assert!(accepted(&mut registry, 1, 100 + 1024));
        // Old window cleared: 100 is now 1024 below the new highest.
        assert_eq!(
            registry.commit(1, 100),
            ReplayDecision::Rejected(Replayed::BelowWindow)
        );
        // In-window unseen counters after the jump still work.
        assert!(accepted(&mut registry, 1, 100 + 1024 - 3));
    }

    #[test]
    fn eviction_allows_re_registration_with_fresh_window() {
        let mut registry = ReplayRegistry::new(2);
        assert!(accepted(&mut registry, 1, 10));
        assert!(accepted(&mut registry, 2, 20));
        assert!(!accepted(&mut registry, 1, 10));
        // Evicts identity 1.
        assert!(accepted(&mut registry, 3, 30));
        assert_eq!(registry.len(), 2);
        // Identity 1 re-registers fresh: the duplicate counter is admitted
        // again because its window was discarded with eviction.
        assert!(accepted(&mut registry, 1, 10));
    }

    #[test]
    fn precheck_does_not_mutate() {
        let mut registry = ReplayRegistry::new(4);
        assert_eq!(registry.precheck(5, 2), ReplayDecision::Accepted);
        assert!(registry.is_empty());
        assert!(accepted(&mut registry, 5, 2));
        // In-window, unseen: precheck must not burn the counter.
        assert_eq!(registry.precheck(5, 1), ReplayDecision::Accepted);
        assert!(accepted(&mut registry, 5, 1));
        assert_eq!(
            registry.precheck(5, 1),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
    }

    #[test]
    fn concurrent_counter_allocation_is_unique() {
        use std::sync::Arc;
        let sequence = Arc::new(crate::ClientSequence::new(&mut rand::rngs::OsRng));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let sequence = Arc::clone(&sequence);
            handles.push(std::thread::spawn(move || {
                (0..1000)
                    .map(|_| sequence.allocate().unwrap())
                    .collect::<Vec<_>>()
            }));
        }
        let mut all: Vec<u64> = handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect();
        all.sort_unstable();
        let before = all.len();
        all.dedup();
        assert_eq!(all.len(), before);
    }
}
