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

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

use crate::REPLAY_WINDOW;

/// Words in a 1024-bit window bitmap.
const WINDOW_WORDS: usize = (REPLAY_WINDOW as usize) / 64;
const EMPTY: u32 = u32::MAX;

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

#[derive(Debug, Clone, Copy)]
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
        let words = (advance / 64) as usize;
        let bits = (advance % 64) as u32;
        for index in (0..WINDOW_WORDS).rev() {
            self.seen[index] = if index < words {
                0
            } else {
                let mut value = self.seen[index - words] << bits;
                if bits != 0 && index > words {
                    value |= self.seen[index - words - 1] >> (64 - bits);
                }
                value
            };
        }
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

#[derive(Debug, Clone, Copy)]
struct Slot {
    identity: u64,
    entry: ReplayEntry,
    next: u32,
}

/// Bounded FIFO registry of prelude identities with per-identity sliding
/// replay windows. All state is preallocated at construction; admission
/// commits allocate nothing.
#[derive(Debug)]
pub struct ReplayRegistry {
    entries: Box<[Slot]>,
    buckets: Box<[u32]>,
    hash: RandomState,
    len: usize,
    oldest: usize,
}

impl ReplayRegistry {
    /// Creates a registry tracking up to `capacity` identities.
    ///
    /// # Panics
    /// Panics if `capacity` is zero, does not fit in `u32` index space, or if
    /// the power-of-two bucket table size overflows `usize`.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "replay registry capacity must be positive");
        assert!(
            capacity < u32::MAX as usize,
            "replay registry capacity must fit in u32 index space"
        );
        let bucket_count = capacity
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .expect("replay registry bucket count overflow");
        Self {
            entries: vec![
                Slot {
                    identity: 0,
                    entry: ReplayEntry {
                        highest: 0,
                        seen: [0; WINDOW_WORDS],
                    },
                    next: EMPTY,
                };
                capacity
            ]
            .into_boxed_slice(),
            buckets: vec![EMPTY; bucket_count].into_boxed_slice(),
            hash: RandomState::new(),
            len: 0,
            oldest: 0,
        }
    }

    /// Number of tracked identities.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no identities are tracked.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn bucket(&self, identity: u64) -> usize {
        (self.hash.hash_one(identity) as usize) & (self.buckets.len() - 1)
    }

    fn find(&self, identity: u64) -> Option<usize> {
        let mut index = self.buckets[self.bucket(identity)];
        while index != EMPTY {
            let slot = &self.entries[index as usize];
            if slot.identity == identity {
                return Some(index as usize);
            }
            index = slot.next;
        }
        None
    }

    fn unlink(&mut self, index: usize) {
        let bucket = self.bucket(self.entries[index].identity);
        let mut current = self.buckets[bucket];
        let mut previous = None;
        while current as usize != index {
            assert!(current != EMPTY, "replay bucket chain is corrupt");
            previous = Some(current as usize);
            current = self.entries[current as usize].next;
        }
        let next = self.entries[index].next;
        if let Some(previous) = previous {
            self.entries[previous].next = next;
        } else {
            self.buckets[bucket] = next;
        }
    }

    /// Checks admissibility without mutating state.
    pub fn precheck(&self, identity: u64, counter: u64) -> ReplayDecision {
        match self.find(identity) {
            Some(index) => self.entries[index].entry.admits(counter),
            None if counter == 0 => ReplayDecision::Rejected(Replayed::Zero),
            None => ReplayDecision::Accepted,
        }
    }

    /// Atomically re-validates and commits a counter. Returns
    /// [`ReplayDecision::Accepted`] when committed.
    pub fn commit(&mut self, identity: u64, counter: u64) -> ReplayDecision {
        if let Some(index) = self.find(identity) {
            let entry = &mut self.entries[index].entry;
            let decision = entry.admits(counter);
            if !matches!(decision, ReplayDecision::Accepted) {
                return decision;
            }
            if counter > entry.highest {
                entry.advance(counter - entry.highest);
                entry.highest = counter;
                entry.set_bit(0);
            } else {
                entry.set_bit(entry.highest - counter);
            }
            return ReplayDecision::Accepted;
        }
        if counter == 0 {
            return ReplayDecision::Rejected(Replayed::Zero);
        }
        let index = if self.len < self.entries.len() {
            let index = self.len;
            self.len += 1;
            index
        } else {
            let index = self.oldest;
            self.unlink(index);
            self.oldest = (index + 1) % self.entries.len();
            index
        };
        let bucket = self.bucket(identity);
        self.entries[index] = Slot {
            identity,
            entry: ReplayEntry::fresh(counter),
            next: self.buckets[bucket],
        };
        self.buckets[bucket] = index as u32;
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

    #[test]
    fn replay_advance_preserves_old_highest_and_in_window_counters() {
        let mut registry = ReplayRegistry::new(4);
        assert!(accepted(&mut registry, 1, 100));
        assert!(accepted(&mut registry, 1, 105));
        // 100 was old highest, now at distance 5. Must be rejected as duplicate.
        assert_eq!(
            registry.commit(1, 100),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
        // Unseen in-between counter 102 must be accepted.
        assert_eq!(registry.commit(1, 102), ReplayDecision::Accepted);
        // Replaying 102 must now be rejected.
        assert_eq!(
            registry.commit(1, 102),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
    }

    #[test]
    #[should_panic(expected = "replay registry capacity must be positive")]
    fn zero_capacity_panics() {
        let _ = ReplayRegistry::new(0);
    }

    #[test]
    #[should_panic(expected = "replay registry capacity must fit in u32 index space")]
    fn oversized_capacity_panics() {
        let _ = ReplayRegistry::new(u32::MAX as usize);
    }

    #[test]
    fn non_power_of_two_capacity_and_zero_identity() {
        for capacity in [1_usize, 3, 5] {
            let mut registry = ReplayRegistry::new(capacity);
            assert!(registry.is_empty());
            assert!(accepted(&mut registry, 0, 10));
            assert_eq!(
                registry.commit(0, 10),
                ReplayDecision::Rejected(Replayed::Duplicate)
            );
            assert!(accepted(&mut registry, 0, 9));
            for offset in 1..=capacity as u64 {
                assert!(accepted(&mut registry, offset, 1));
            }
            assert_eq!(registry.len(), capacity);
            // Identity 0 was the oldest and should be evicted once capacity+1
            // distinct identities have been committed.
            assert_eq!(registry.precheck(0, 10), ReplayDecision::Accepted);
            assert!(accepted(&mut registry, 0, 10));
            assert_eq!(
                registry.commit(0, 10),
                ReplayDecision::Rejected(Replayed::Duplicate)
            );
        }
    }

    #[test]
    fn capacity_fifo_and_repeated_rotation_keep_storage_fixed() {
        let capacity = 64_usize;
        let mut registry = ReplayRegistry::new(capacity);
        let entries_ptr = registry.entries.as_ptr();
        let buckets_ptr = registry.buckets.as_ptr();

        for identity in 0..capacity as u64 {
            assert!(accepted(&mut registry, identity, 1));
        }
        // In-place update of identity 0 must not refresh its FIFO position.
        assert!(accepted(&mut registry, 0, 2));
        // Inserting capacity evicts identity 0.
        assert!(accepted(&mut registry, capacity as u64, 1));
        assert_eq!(registry.precheck(0, 1), ReplayDecision::Accepted);
        assert_eq!(
            registry.precheck(1, 1),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
        // Re-inserting identity 0 evicts identity 1.
        assert!(accepted(&mut registry, 0, 1));
        assert_eq!(registry.precheck(1, 1), ReplayDecision::Accepted);

        for identity in (capacity as u64 + 1)..(capacity as u64 * 5) {
            assert!(accepted(&mut registry, identity, 1));
        }
        assert_eq!(registry.len(), capacity);
        assert_eq!(registry.entries.len(), capacity);
        assert_eq!(registry.entries.as_ptr(), entries_ptr);
        assert_eq!(registry.buckets.as_ptr(), buckets_ptr);
        for identity in (capacity as u64 * 4)..(capacity as u64 * 5) {
            assert!(registry.find(identity).is_some());
        }
    }

    #[test]
    fn collisions_preserve_links_when_fifo_removes_head_middle_and_tail() {
        let mut registry = ReplayRegistry::new(8);
        let colliding: Vec<u64> = (0_u64..)
            .filter(|&identity| registry.bucket(identity) == 0)
            .take(4)
            .collect();
        for &identity in &colliding {
            assert!(accepted(&mut registry, identity, 1));
        }
        // Bucket 0 chain is head -> colliding[3] -> colliding[2] -> colliding[1] -> colliding[0].
        // Unlink middle (slot 1 = colliding[1]), head (slot 3 = colliding[3]), tail (slot 0 = colliding[0]).
        registry.unlink(1);
        registry.unlink(3);
        registry.unlink(0);
        assert!(registry.find(colliding[1]).is_none());
        assert!(registry.find(colliding[3]).is_none());
        assert!(registry.find(colliding[0]).is_none());
        assert_eq!(registry.find(colliding[2]), Some(2));
    }

    #[test]
    fn commit_evicts_and_reinserts_colliding_bucket_entries() {
        let mut registry = ReplayRegistry::new(8);
        let colliding: Vec<u64> = (0_u64..)
            .filter(|&identity| registry.bucket(identity) == 0)
            .take(5)
            .collect();
        let non_colliding: Vec<u64> = (0_u64..)
            .filter(|&identity| registry.bucket(identity) != 0)
            .take(6)
            .collect();

        // Fill capacity=8: [c0, c1, c2, n0, n1, n2, n3, n4].
        for &id in &colliding[..3] {
            assert!(accepted(&mut registry, id, 1));
        }
        for &id in &non_colliding[..5] {
            assert!(accepted(&mut registry, id, 1));
        }
        assert_eq!(registry.len(), 8);

        // Committing c3 into bucket 0 evicts oldest FIFO slot (c0, tail of bucket 0).
        assert!(accepted(&mut registry, colliding[3], 1));
        assert_eq!(registry.precheck(colliding[0], 1), ReplayDecision::Accepted);
        for &id in &[colliding[1], colliding[2], colliding[3]] {
            assert_eq!(
                registry.precheck(id, 1),
                ReplayDecision::Rejected(Replayed::Duplicate)
            );
        }

        // Evict c1 (via n5) and c2 (via c4 into same bucket 0), then re-insert c0.
        assert!(accepted(&mut registry, non_colliding[5], 1));
        assert_eq!(registry.precheck(colliding[1], 1), ReplayDecision::Accepted);
        assert!(accepted(&mut registry, colliding[4], 1));
        assert_eq!(registry.precheck(colliding[2], 1), ReplayDecision::Accepted);
        for &id in &[colliding[3], colliding[4]] {
            assert_eq!(
                registry.precheck(id, 1),
                ReplayDecision::Rejected(Replayed::Duplicate)
            );
        }

        assert!(accepted(&mut registry, colliding[0], 1));
        assert_eq!(
            registry.commit(colliding[0], 1),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
    }

    #[test]
    fn every_window_advance_matches_individual_bit_reference() {
        let seen: [u64; WINDOW_WORDS] = std::array::from_fn(|index| {
            0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(index as u64 + 1) | 1
        });
        for advance in 0..=(REPLAY_WINDOW * 2) {
            let mut entry = ReplayEntry {
                highest: 10_000,
                seen,
            };
            let new_highest = entry.highest + advance;
            entry.advance(advance);
            entry.highest = new_highest;
            entry.set_bit(0);
            for offset in 0..REPLAY_WINDOW {
                let expected_seen = offset == 0
                    || (offset >= advance && {
                        let old = (offset - advance) as usize;
                        seen[old / 64] & (1_u64 << (old % 64)) != 0
                    });
                let expected = if expected_seen {
                    ReplayDecision::Rejected(Replayed::Duplicate)
                } else {
                    ReplayDecision::Accepted
                };
                assert_eq!(
                    entry.admits(new_highest - offset),
                    expected,
                    "advance={advance}, offset={offset}"
                );
            }
            assert_eq!(
                entry.admits(new_highest - REPLAY_WINDOW),
                ReplayDecision::Rejected(Replayed::BelowWindow)
            );
        }
    }
}
