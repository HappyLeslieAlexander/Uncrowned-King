//! Empirical stress tests and adversarial verification for uk-auth ReplayCache saturation.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use uk_auth::{AuthError, ReplayCache};

#[test]
fn test_replay_cache_capacity_saturation_flood() {
    const CAPACITY: usize = 100;
    const FLOOD_COUNT: usize = 10_000;

    let mut cache = ReplayCache::with_max_entries(Duration::from_secs(300), CAPACITY);

    // Step 1: Fill cache up to exact capacity
    let mut legitimate_nonces = Vec::with_capacity(CAPACITY);
    for i in 0..CAPACITY {
        let mut srv = [0u8; 32];
        let mut cli = [0u8; 32];
        srv[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        cli[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        srv[8] = 0xAA;
        cli[8] = 0xBB;

        assert!(
            cache.check_and_insert(srv, cli).is_ok(),
            "Initial insertion {i} should succeed"
        );
        legitimate_nonces.push((srv, cli));
    }

    // Step 2: Flood with 10,000 additional distinct nonces
    for i in 0..FLOOD_COUNT {
        let mut srv = [0u8; 32];
        let mut cli = [0u8; 32];
        srv[0..8].copy_from_slice(&((CAPACITY + i) as u64).to_be_bytes());
        cli[0..8].copy_from_slice(&((CAPACITY + i) as u64).to_be_bytes());
        srv[8] = 0xEE;
        cli[8] = 0xFF;

        let res = cache.check_and_insert(srv, cli);
        assert_eq!(
            res,
            Err(AuthError::ResourceLimit("replay cache saturated")),
            "Flood insertion {i} beyond capacity must fail closed with ResourceLimit"
        );
    }

    // Step 3: Verify that NONE of the legitimate nonces were evicted
    for (i, &(srv, cli)) in legitimate_nonces.iter().enumerate() {
        let replay_res = cache.check_and_insert(srv, cli);
        assert_eq!(
            replay_res,
            Err(AuthError::Replay),
            "Legitimate nonce {i} was evicted! Replay should return Err(AuthError::Replay)"
        );
    }
}

#[test]
fn test_adversary_cannot_evict_victim_nonce_via_flooding() {
    let mut cache = ReplayCache::with_max_entries(Duration::from_secs(300), 10);

    // Victim Alice authenticates
    let alice_srv = [0x11; 32];
    let alice_cli = [0x22; 32];
    assert!(cache.check_and_insert(alice_srv, alice_cli).is_ok());

    // Alice's immediate replay is blocked
    assert_eq!(
        cache.check_and_insert(alice_srv, alice_cli),
        Err(AuthError::Replay)
    );

    // Adversary Eve attempts to evict Alice's nonce by spamming 500 distinct authentications
    for i in 0..500_u32 {
        let mut srv = [0xEE; 32];
        let mut cli = [0x33; 32];
        srv[0..4].copy_from_slice(&i.to_be_bytes());
        cli[0..4].copy_from_slice(&i.to_be_bytes());

        let _ = cache.check_and_insert(srv, cli);
    }

    // Adversary Eve now attempts to replay Alice's authentication
    // Invariant: Alice's entry MUST NOT have been purged. Replay must be rejected as Replay!
    assert_eq!(
        cache.check_and_insert(alice_srv, alice_cli),
        Err(AuthError::Replay),
        "CRITICAL INVARIANT VIOLATION: Alice's nonce was evicted by adversarial flood!"
    );
}

#[test]
fn test_replay_cache_zero_and_minimal_capacity_limits() {
    // 0 capacity is treated as 1
    let mut cache = ReplayCache::with_max_entries(Duration::from_secs(300), 0);

    let n1_s = [0x01; 32];
    let n1_c = [0x02; 32];
    assert!(cache.check_and_insert(n1_s, n1_c).is_ok());

    // Replay 1st nonce
    assert_eq!(cache.check_and_insert(n1_s, n1_c), Err(AuthError::Replay));

    // 2nd nonce rejected due to saturation
    let n2_s = [0x03; 32];
    let n2_c = [0x04; 32];
    assert_eq!(
        cache.check_and_insert(n2_s, n2_c),
        Err(AuthError::ResourceLimit("replay cache saturated"))
    );

    // 1st nonce still active
    assert_eq!(cache.check_and_insert(n1_s, n1_c), Err(AuthError::Replay));
}

#[test]
fn test_replay_cache_concurrent_multithreaded_flood() {
    const CAPACITY: usize = 50;
    const THREADS: usize = 8;
    const INSERTS_PER_THREAD: usize = 200;

    let cache = Arc::new(Mutex::new(ReplayCache::with_max_entries(
        Duration::from_secs(300),
        CAPACITY,
    )));

    // Pre-insert 10 victim nonces
    let mut victims = Vec::new();
    {
        let mut guard = cache.lock().unwrap();
        for i in 0..10_u8 {
            let srv = [i; 32];
            let cli = [i.wrapping_add(100); 32];
            assert!(guard.check_and_insert(srv, cli).is_ok());
            victims.push((srv, cli));
        }
    }

    // Spawn worker threads to flood
    let mut handles = Vec::new();
    for thread_id in 0..THREADS {
        let cache_clone = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for i in 0..INSERTS_PER_THREAD {
                let mut srv = [0xFF; 32];
                let mut cli = [0xEE; 32];
                srv[0..2].copy_from_slice(&(thread_id as u16).to_be_bytes());
                cli[0..2].copy_from_slice(&(thread_id as u16).to_be_bytes());
                srv[2..4].copy_from_slice(&(i as u16).to_be_bytes());
                cli[2..4].copy_from_slice(&(i as u16).to_be_bytes());

                let mut guard = cache_clone.lock().unwrap();
                let _ = guard.check_and_insert(srv, cli);
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all 10 victim nonces are STILL rejected as Replay
    let mut guard = cache.lock().unwrap();
    for (i, &(srv, cli)) in victims.iter().enumerate() {
        assert_eq!(
            guard.check_and_insert(srv, cli),
            Err(AuthError::Replay),
            "Victim nonce {i} was evicted under concurrent flood!"
        );
    }
}
