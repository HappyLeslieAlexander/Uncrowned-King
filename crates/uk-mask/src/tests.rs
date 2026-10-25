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
