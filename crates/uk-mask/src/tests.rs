//! Unit tests for the prelude codec and key schedule.

use rand::SeedableRng;
use rand::rngs::StdRng;

use super::*;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn rng() -> StdRng {
    StdRng::seed_from_u64(0x5eed)
}

fn encode(keys: &MaskKeys, policy: PreludePolicy, identity: u64, counter: u64) -> ClientPrelude {
    keys.encode_prelude(policy, &mut rng(), identity, counter)
        .unwrap()
}

fn round_trip(keys: &MaskKeys, policy: PreludePolicy) {
    let prelude = encode(keys, policy, 0x0102_0304_0506_0708, 42);
    let authenticated = keys.decode_prelude(&prelude.bytes, &prelude.nonce).unwrap();
    assert_eq!(authenticated.identity, 0x0102_0304_0506_0708);
    assert_eq!(authenticated.counter, 42);
}

#[test]
fn prelude_round_trips_for_every_policy() {
    let keys = MaskKeys::derive(b"key-a", SECRET);
    round_trip(&keys, PreludePolicy::Fade);
    round_trip(&keys, PreludePolicy::Full8);
    round_trip(&keys, PreludePolicy::Low7);
}

#[test]
fn wrong_credential_rejects() {
    let keys = MaskKeys::derive(b"key-a", SECRET);
    let other = MaskKeys::derive(b"key-b", SECRET);
    let other_secret = MaskKeys::derive(b"key-a", b"fedcba9876543210fedcba9876543210");
    let prelude = encode(&keys, PreludePolicy::Fade, 1, 1);
    assert!(keys.decode_prelude(&prelude.bytes, &prelude.nonce).is_ok());
    assert!(
        other
            .decode_prelude(&prelude.bytes, &prelude.nonce)
            .is_err()
    );
    assert!(
        other_secret
            .decode_prelude(&prelude.bytes, &prelude.nonce)
            .is_err()
    );
}

#[test]
fn tampering_any_region_rejects() {
    let keys = MaskKeys::derive(b"key-a", SECRET);
    let prelude = encode(&keys, PreludePolicy::Full8, 0xabcd, 9);
    let mut nonce = prelude.nonce;

    // Flip a prefix byte (P).
    let mut tampered = prelude.bytes;
    tampered[5] ^= 1;
    assert!(keys.decode_prelude(&tampered, &nonce).is_err());

    // Flip a high bit in the tail (H).
    let mut tampered = prelude.bytes;
    tampered[40] ^= 0x80;
    assert!(keys.decode_prelude(&tampered, &nonce).is_err());

    // Flip a payload bit in the tail low 7 bits.
    let mut tampered = prelude.bytes;
    tampered[50] ^= 0x01;
    assert!(keys.decode_prelude(&tampered, &nonce).is_err());

    // Flip a nonce byte.
    nonce[3] ^= 1;
    assert!(keys.decode_prelude(&prelude.bytes, &nonce).is_err());
}

#[test]
fn zero_and_out_of_range_counters_rejected() {
    let keys = MaskKeys::derive(b"key-a", SECRET);
    assert!(matches!(
        keys.encode_prelude(PreludePolicy::Full8, &mut rng(), 1, 0),
        Err(MaskError::InvalidCounter)
    ));
    assert!(matches!(
        keys.encode_prelude(PreludePolicy::Full8, &mut rng(), 1, MAX_COUNTER + 1),
        Err(MaskError::InvalidCounter)
    ));

    let top = keys
        .encode_prelude(PreludePolicy::Full8, &mut rng(), 1, MAX_COUNTER)
        .unwrap();
    assert_eq!(
        keys.decode_prelude(&top.bytes, &top.nonce).unwrap().counter,
        MAX_COUNTER
    );
}

/// A credential holder can craft a zero counter with a *valid* tag (the keys
/// are known). Decoding must still reject it, and it must reject through the
/// same post-tag path as every other failure: the tag is computed and compared
/// before the counter is judged, so no cheap check answers ahead of the HMAC.
#[test]
fn zero_counter_with_a_valid_tag_is_rejected_after_full_verification() {
    let keys = MaskKeys::derive(b"key-a", SECRET);
    let valid = encode(&keys, PreludePolicy::Full8, 0x1122_3344_5566_7788, 9);

    // Rebuild the tail payload with counter = 0 and a freshly computed,
    // genuinely valid tag over (nonce, P, H, identity, counter=0).
    let nonce = valid.nonce;
    let prefix = &valid.bytes[..PREFIX_LEN];
    let high_bits = pack_high_bits(&valid.bytes[PREFIX_LEN..]);
    let identity_bytes = 0x1122_3344_5566_7788_u64.to_be_bytes();
    let counter_bytes = [0_u8; COUNTER_LEN];
    let tag = keys.authentication_tag(&nonce, prefix, high_bits, identity_bytes, counter_bytes);
    let mut payload = [0_u8; TAIL_PAYLOAD_LEN];
    payload[..IDENTITY_LEN].copy_from_slice(&identity_bytes);
    payload[IDENTITY_LEN..IDENTITY_LEN + COUNTER_LEN].copy_from_slice(&counter_bytes);
    payload[IDENTITY_LEN + COUNTER_LEN..].copy_from_slice(&tag[..TAG_LEN]);
    let mask = keys.prelude_mask(&nonce, prefix, high_bits);
    for (byte, mask_byte) in payload.iter_mut().zip(mask.iter()) {
        *byte ^= mask_byte;
    }

    let mut forged = valid.bytes;
    write_tail_payload(&mut forged[PREFIX_LEN..], &payload);

    assert!(matches!(
        keys.decode_prelude(&forged, &nonce),
        Err(MaskError::PreludeRejected)
    ));
}

/// Regression guard for the Fade filler distribution: every printable value
/// must appear with substantial frequency. A coarse modulo mapping (e.g.
/// `% 64`) or a narrowed range collapses part of the value space to zero.
#[test]
fn fade_printable_filler_spreads_across_the_printable_range() {
    let keys = MaskKeys::derive(b"key-a", SECRET);
    let seeds = 8_u64;
    let preludes_per_seed = 5_000_u64;
    let mut counts = [0_usize; 95];
    for seed in 0..seeds {
        let mut seeded = StdRng::seed_from_u64(seed);
        for _ in 0..preludes_per_seed {
            let prelude = keys
                .encode_prelude(PreludePolicy::Fade, &mut seeded, 1, 1)
                .unwrap();
            // The first 8 bytes are guaranteed printable under Fade.
            for byte in &prelude.bytes[..8] {
                assert!(
                    (0x20..=0x7e).contains(byte),
                    "Fade filler byte {byte:#04x} outside printable range"
                );
                counts[(byte - 0x20) as usize] += 1;
            }
        }
    }
    // Expected count per value: 8 × 5000 × 8 / 95 ≈ 3368 (σ ≈ 58). A floor
    // of 2500 is far below the uniform mean yet far above what any obvious
    // mapping regression would leave behind.
    let total: usize = counts.iter().sum();
    assert_eq!(total, (seeds * preludes_per_seed * 8) as usize);
    let floor = 2500;
    for (index, count) in counts.iter().enumerate() {
        assert!(
            *count >= floor,
            "printable value {:#04x} appeared only {count} times (floor {floor})",
            0x20 + index as u8
        );
    }
}

#[test]
fn bit_packing_round_trips() {
    let mut payload = [0u8; TAIL_PAYLOAD_LEN];
    rng().fill_bytes(&mut payload);
    let mut tail = [0u8; TAIL_LEN];
    rng().fill_bytes(&mut tail);
    let high_before = pack_high_bits(&tail);
    write_tail_payload(&mut tail, &payload);
    // High bits are preserved.
    assert_eq!(pack_high_bits(&tail), high_before);
    assert_eq!(read_tail_payload(&tail), payload);
}

#[test]
fn key_derivation_is_deterministic_and_domain_separated() {
    let a1 = MaskKeys::derive(b"key-a", SECRET);
    let a2 = MaskKeys::derive(b"key-a", SECRET);
    assert_eq!(a1.c2s(), a2.c2s());
    assert_eq!(a1.s2c(), a2.s2c());
    // Direction keys differ from each other (c2s vs s2c).
    assert_ne!(a1.c2s(), a1.s2c());
    // Different key_id or secret yields different keys.
    let b = MaskKeys::derive(b"key-b", SECRET);
    assert_ne!(a1.c2s(), b.c2s());
}

#[test]
fn verify_prelude_scans_all_credentials() {
    let keys_a = MaskKeys::derive(b"key-a", SECRET);
    let keys_b = MaskKeys::derive(b"key-b", SECRET);
    let set = vec![keys_a, keys_b];
    let prelude = encode(&set[0], PreludePolicy::Fade, 3, 7);
    let (matched, authenticated) = verify_prelude(&set, &prelude.bytes, &prelude.nonce).unwrap();
    assert_eq!(authenticated.identity, 3);
    assert_eq!(authenticated.counter, 7);
    // The returned keys are the matching credential's.
    let recheck = matched
        .decode_prelude(&prelude.bytes, &prelude.nonce)
        .unwrap();
    assert_eq!(recheck.counter, 7);

    // A prelude from an unknown credential matches nothing.
    let stranger = MaskKeys::derive(b"stranger", SECRET);
    let forged = encode(&stranger, PreludePolicy::Fade, 3, 7);
    assert!(verify_prelude(&set, &forged.bytes, &forged.nonce).is_none());
}

#[test]
fn policy_shapes_first_bytes() {
    let keys = MaskKeys::derive(b"key-a", SECRET);
    let fade = encode(&keys, PreludePolicy::Fade, 1, 1);
    // With fade, the first boundary (8..=12 bytes) is printable ASCII.
    // Deterministic seed makes gen_range stable; just assert the invariant
    // loosely over several seeds.
    for seed in 0..64u64 {
        let mut seeded = StdRng::seed_from_u64(seed);
        let prelude = keys
            .encode_prelude(PreludePolicy::Fade, &mut seeded, 1, 1)
            .unwrap();
        assert!(
            prelude
                .bytes
                .iter()
                .take(8)
                .all(|byte| (0x20..0x7f).contains(byte))
        );
    }

    let low7 = encode(&keys, PreludePolicy::Low7, 1, 1);
    // Tail low 7 bits carry payload, so only the prefix is guaranteed 7-bit
    // clean (the payload bits are random); the *prefix* is all &= 0x7f.
    assert!(low7.bytes[..PREFIX_LEN].iter().all(|byte| byte & 0x80 == 0));
    let _ = fade;
}

#[test]
fn client_sequence_allocates_monotonic_unique_values() {
    let sequence = ClientSequence::new(&mut rng());
    let identity = sequence.identity();
    assert_eq!(sequence.allocate().unwrap(), 1);
    assert_eq!(sequence.allocate().unwrap(), 2);
    // Identity is a fresh random value; two differently-seeded sequences
    // must differ (same-seed determinism is covered by derive tests above).
    let other = ClientSequence::new(&mut StdRng::seed_from_u64(99));
    assert_ne!(identity, other.identity());
}

#[test]
fn client_sequence_exhaustion_is_reported() {
    let mut sequence = ClientSequence::new(&mut rng());
    sequence.next = std::sync::atomic::AtomicU64::new(MAX_COUNTER);
    assert_eq!(sequence.allocate().unwrap(), MAX_COUNTER);
    assert!(matches!(
        sequence.allocate(),
        Err(MaskError::CounterExhausted)
    ));
}

#[test]
fn policy_parse_round_trips() {
    for policy in [
        PreludePolicy::Fade,
        PreludePolicy::Full8,
        PreludePolicy::Low7,
    ] {
        assert_eq!(PreludePolicy::parse(policy.as_str()), Some(policy));
    }
    assert_eq!(PreludePolicy::parse("bogus"), None);
    assert_eq!(PreludePolicy::parse(" LOW7 "), Some(PreludePolicy::Low7));
    assert_eq!(PreludePolicy::default(), PreludePolicy::Fade);
}

fn bit_reference_encode_tail(
    high_bits: [u8; 4],
    masked_payload: [u8; TAIL_PAYLOAD_LEN],
) -> [u8; TAIL_LEN] {
    let mut tail = [0_u8; TAIL_LEN];
    for (index, slot) in tail.iter_mut().enumerate() {
        let high = ((high_bits[index / 8] >> (index % 8)) & 1) << 7;
        let low = (0..7).fold(0_u8, |value, bit| {
            let offset = index * 7 + bit;
            let payload_bit = (masked_payload[offset / 8] >> (7 - (offset % 8))) & 1;
            (value << 1) | payload_bit
        });
        *slot = high | low;
    }
    tail
}

#[test]
fn extreme_field_encodings_match_independent_vectors() {
    let keys = MaskKeys::derive(b"extreme-key", SECRET);
    let cases = [
        (
            [0xff_u8; PREFIX_LEN],
            [0xff_u8; NONCE_LEN],
            [0xff_u8; 4],
            u64::MAX,
            MAX_COUNTER,
        ),
        (
            [0_u8; PREFIX_LEN],
            [0_u8; NONCE_LEN],
            [0_u8; 4],
            0_u64,
            1_u64,
        ),
        (
            std::array::from_fn(|index| 31_u8 - index as u8),
            std::array::from_fn(|index| 11_u8 - index as u8),
            [0x80, 0x00, 0x00, 0x01],
            0x8000_0000_0000_0001_u64,
            0x8000_0000_0001_u64,
        ),
    ];

    for (prefix, nonce, high_bits, identity, counter) in cases {
        let identity_bytes = identity.to_be_bytes();
        let counter_bytes = counter_to_be_bytes(counter);
        let tag =
            keys.authentication_tag(&nonce, &prefix, high_bits, identity_bytes, counter_bytes);
        let mask = keys.prelude_mask(&nonce, &prefix, high_bits);

        let mut payload = [0_u8; TAIL_PAYLOAD_LEN];
        payload[..IDENTITY_LEN].copy_from_slice(&identity_bytes);
        payload[IDENTITY_LEN..IDENTITY_LEN + COUNTER_LEN].copy_from_slice(&counter_bytes);
        payload[IDENTITY_LEN + COUNTER_LEN..].copy_from_slice(&tag[..TAG_LEN]);
        let masked_payload: [u8; TAIL_PAYLOAD_LEN] =
            std::array::from_fn(|index| payload[index] ^ mask[index]);

        let expected_tail = bit_reference_encode_tail(high_bits, masked_payload);
        let mut prelude = [0_u8; PRELUDE_LEN];
        prelude[..PREFIX_LEN].copy_from_slice(&prefix);
        prelude[PREFIX_LEN..].copy_from_slice(&expected_tail);

        assert_eq!(pack_high_bits(&prelude[PREFIX_LEN..]), high_bits);
        assert_eq!(read_tail_payload(&prelude[PREFIX_LEN..]), masked_payload);

        let mut rewritten_tail = std::array::from_fn(|index| expected_tail[index] & 0x80);
        write_tail_payload(&mut rewritten_tail, &masked_payload);
        assert_eq!(rewritten_tail, expected_tail);

        let decoded = keys.decode_prelude(&prelude, &nonce).unwrap();
        assert_eq!(decoded.identity, identity);
        assert_eq!(decoded.counter, counter);

        let credential_set = [MaskKeys::derive(b"decoy", SECRET), keys.clone()];
        let (_, verified) = verify_prelude(&credential_set, &prelude, &nonce).unwrap();
        assert_eq!(verified, decoded);
    }
}

#[test]
fn concurrent_client_sequence_exhaustion_saturates() {
    use std::sync::{Arc, Barrier};

    let mut sequence = ClientSequence::new(&mut rng());
    sequence.next = std::sync::atomic::AtomicU64::new(MAX_COUNTER - 1);
    let sequence = Arc::new(sequence);
    let workers = 16_usize;
    let barrier = Arc::new(Barrier::new(workers));

    let handles: Vec<_> = (0..workers)
        .map(|_| {
            let sequence = Arc::clone(&sequence);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                sequence.allocate()
            })
        })
        .collect();

    let mut successes = Vec::new();
    let mut exhausted = 0_usize;
    for handle in handles {
        match handle.join().unwrap() {
            Ok(counter) => successes.push(counter),
            Err(MaskError::CounterExhausted) => exhausted += 1,
            Err(other) => panic!("unexpected allocation error: {other}"),
        }
    }

    successes.sort_unstable();
    assert_eq!(successes, vec![MAX_COUNTER - 1, MAX_COUNTER]);
    assert_eq!(exhausted, workers - 2);
    assert!(matches!(
        sequence.allocate(),
        Err(MaskError::CounterExhausted)
    ));
    assert_eq!(sequence.next.load(Ordering::Relaxed), MAX_COUNTER + 1);
}
