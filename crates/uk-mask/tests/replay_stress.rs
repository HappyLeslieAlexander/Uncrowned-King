//! Empirical stress tests and adversarial verification for uk-mask replay protection.

use std::collections::HashSet;

use uk_mask::REPLAY_WINDOW;
use uk_mask::replay::{ReplayDecision, ReplayRegistry, Replayed};

#[test]
fn test_advance_1_word_boundary_and_exact_tracking() {
    let mut registry = ReplayRegistry::new(4);
    let id = 1001_u64;

    // Start with counter 500
    assert_eq!(registry.commit(id, 500), ReplayDecision::Accepted);
    assert_eq!(
        registry.commit(id, 500),
        ReplayDecision::Rejected(Replayed::Duplicate)
    );

    // Advance by 1 across 130 steps (crossing word 0 -> word 1 -> word 2 boundaries)
    for step in 1..=130 {
        let counter = 500 + step;
        assert_eq!(registry.commit(id, counter), ReplayDecision::Accepted);
        // Replaying immediate counter is rejected as duplicate
        assert_eq!(
            registry.commit(id, counter),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
        // All previously committed counters remain rejected as duplicate
        assert_eq!(
            registry.commit(id, 500),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
        assert_eq!(
            registry.commit(id, counter - 1),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
    }
}

#[test]
fn test_advance_500_multi_counter_preservation() {
    let mut registry = ReplayRegistry::new(4);
    let id = 1002_u64;

    // Commit baseline counter 2000
    assert_eq!(registry.commit(id, 2000), ReplayDecision::Accepted);

    // Commit several in-window counters below 2000
    let in_window = [1999, 1900, 1750, 1600, 1501, 1477, 1000, 977];
    for &c in &in_window {
        assert_eq!(registry.commit(id, c), ReplayDecision::Accepted);
        assert_eq!(
            registry.commit(id, c),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
    }

    // Now advance by 500: new highest is 2500
    assert_eq!(registry.commit(id, 2500), ReplayDecision::Accepted);
    assert_eq!(
        registry.commit(id, 2500),
        ReplayDecision::Rejected(Replayed::Duplicate)
    );

    // Check counters that are still within distance < 1024 from 2500:
    // 2000 -> dist 500 (Duplicate)
    // 1999 -> dist 501 (Duplicate)
    // 1900 -> dist 600 (Duplicate)
    // 1750 -> dist 750 (Duplicate)
    // 1600 -> dist 900 (Duplicate)
    // 1501 -> dist 999 (Duplicate)
    // 1477 -> dist 1023 (Duplicate)
    let still_in_window = [2000, 1999, 1900, 1750, 1600, 1501, 1477];
    for &c in &still_in_window {
        assert_eq!(
            registry.commit(id, c),
            ReplayDecision::Rejected(Replayed::Duplicate),
            "Counter {c} at distance {} must be Duplicate",
            2500 - c
        );
    }

    // Counters that fell below window (distance >= 1024):
    // 1000 -> dist 1500 (BelowWindow)
    // 977  -> dist 1523 (BelowWindow)
    let fallen_off = [1000, 977];
    for &c in &fallen_off {
        assert_eq!(
            registry.commit(id, c),
            ReplayDecision::Rejected(Replayed::BelowWindow),
            "Counter {c} at distance {} must be BelowWindow",
            2500 - c
        );
    }

    // Unseen counters within window must be accepted
    let unseen = [2499, 2100, 2001, 1850, 1478];
    for &c in &unseen {
        assert_eq!(
            registry.precheck(id, c),
            ReplayDecision::Accepted,
            "Unseen counter {c} should be Accepted"
        );
        assert_eq!(registry.commit(id, c), ReplayDecision::Accepted);
        assert_eq!(
            registry.commit(id, c),
            ReplayDecision::Rejected(Replayed::Duplicate)
        );
    }
}

#[test]
fn test_advance_1023_exact_edge_tracking() {
    let mut registry = ReplayRegistry::new(4);
    let id = 1003_u64;

    // Start with counter 5000
    assert_eq!(registry.commit(id, 5000), ReplayDecision::Accepted);

    // Commit counter 5000 - 1 = 4999 (was distance 1)
    assert_eq!(registry.commit(id, 4999), ReplayDecision::Accepted);

    // Advance by exactly 1023 to 6023 (5000 + 1023)
    assert_eq!(registry.commit(id, 6023), ReplayDecision::Accepted);

    // 5000 is now at distance 6023 - 5000 = 1023 (maximum possible in-window distance).
    // MUST be tracked and rejected as Duplicate!
    assert_eq!(
        registry.commit(id, 5000),
        ReplayDecision::Rejected(Replayed::Duplicate),
        "Counter 5000 at distance 1023 must be Duplicate"
    );

    // 6023 (the new highest) must be Duplicate
    assert_eq!(
        registry.commit(id, 6023),
        ReplayDecision::Rejected(Replayed::Duplicate)
    );

    // 4999 is now at distance 6023 - 4999 = 1024 (below window).
    // MUST be rejected as BelowWindow!
    assert_eq!(
        registry.commit(id, 4999),
        ReplayDecision::Rejected(Replayed::BelowWindow),
        "Counter 4999 at distance 1024 must be BelowWindow"
    );

    // Unseen in-window counter 5001 (distance 1022) must be Accepted
    assert_eq!(registry.commit(id, 5001), ReplayDecision::Accepted);
    assert_eq!(
        registry.commit(id, 5001),
        ReplayDecision::Rejected(Replayed::Duplicate)
    );
}

#[test]
fn test_advance_1024_and_2000_clears_window() {
    let mut registry = ReplayRegistry::new(4);
    let id = 1004_u64;

    // 1. Advance = 1024
    assert_eq!(registry.commit(id, 5000), ReplayDecision::Accepted);
    assert_eq!(registry.commit(id, 5000 + 1024), ReplayDecision::Accepted);

    // 5000 is at distance 1024 -> BelowWindow
    assert_eq!(
        registry.commit(id, 5000),
        ReplayDecision::Rejected(Replayed::BelowWindow)
    );
    // Unseen counter at distance 1023 (5001) is fresh
    assert_eq!(registry.commit(id, 5000 + 1), ReplayDecision::Accepted);

    // 2. Advance = 2000
    let current_highest = 5000 + 1024;
    assert_eq!(
        registry.commit(id, current_highest + 2000),
        ReplayDecision::Accepted
    );

    // Old highest is at distance 2000 -> BelowWindow
    assert_eq!(
        registry.commit(id, current_highest),
        ReplayDecision::Rejected(Replayed::BelowWindow)
    );
    // Unseen in-window counter is Accepted
    assert_eq!(
        registry.commit(id, current_highest + 2000 - 500),
        ReplayDecision::Accepted
    );
}

#[test]
fn test_counter_zero_always_rejected_at_all_stages() {
    let mut registry = ReplayRegistry::new(4);
    let id = 1005_u64;

    // Before any registration
    assert_eq!(
        registry.precheck(id, 0),
        ReplayDecision::Rejected(Replayed::Zero)
    );
    assert_eq!(
        registry.commit(id, 0),
        ReplayDecision::Rejected(Replayed::Zero)
    );

    // After first commit
    assert_eq!(registry.commit(id, 100), ReplayDecision::Accepted);
    assert_eq!(
        registry.commit(id, 0),
        ReplayDecision::Rejected(Replayed::Zero)
    );

    // After advance 500
    assert_eq!(registry.commit(id, 600), ReplayDecision::Accepted);
    assert_eq!(
        registry.commit(id, 0),
        ReplayDecision::Rejected(Replayed::Zero)
    );

    // After advance 1023
    assert_eq!(registry.commit(id, 600 + 1023), ReplayDecision::Accepted);
    assert_eq!(
        registry.commit(id, 0),
        ReplayDecision::Rejected(Replayed::Zero)
    );

    // After advance 2000
    assert_eq!(
        registry.commit(id, 600 + 1023 + 2000),
        ReplayDecision::Accepted
    );
    assert_eq!(
        registry.commit(id, 0),
        ReplayDecision::Rejected(Replayed::Zero)
    );
}

#[test]
fn test_exhaustive_all_1024_distances_and_sliding_oracle() {
    let mut registry = ReplayRegistry::new(4);
    let id = 1006_u64;

    let base = 50_000_u64;
    assert_eq!(registry.commit(id, base), ReplayDecision::Accepted);

    // Commit a deterministic pattern: every 3rd counter in window [base - 1023 .. base]
    let mut committed = HashSet::new();
    committed.insert(base);

    for dist in 1..REPLAY_WINDOW {
        if dist % 3 == 0 {
            let c = base - dist;
            assert_eq!(registry.commit(id, c), ReplayDecision::Accepted);
            committed.insert(c);
        }
    }

    // Now test a sequence of advances: +1, +7, +64, +127, +500, +300
    let advance_steps = [1_u64, 7, 64, 127, 500, 300];
    let mut current_highest = base;

    for advance in advance_steps {
        current_highest += advance;
        assert_eq!(
            registry.commit(id, current_highest),
            ReplayDecision::Accepted
        );
        committed.insert(current_highest);

        // Verify oracle against all distances in 0..1050
        for dist in 0..1050_u64 {
            let c = current_highest - dist;
            let decision = registry.precheck(id, c);

            if dist >= REPLAY_WINDOW {
                assert_eq!(
                    decision,
                    ReplayDecision::Rejected(Replayed::BelowWindow),
                    "Counter {c} (dist {dist}) must be BelowWindow"
                );
            } else if committed.contains(&c) {
                assert_eq!(
                    decision,
                    ReplayDecision::Rejected(Replayed::Duplicate),
                    "Counter {c} (dist {dist}) must be Duplicate"
                );
            } else {
                assert_eq!(
                    decision,
                    ReplayDecision::Accepted,
                    "Counter {c} (dist {dist}) must be Accepted"
                );
            }
        }
    }
}
