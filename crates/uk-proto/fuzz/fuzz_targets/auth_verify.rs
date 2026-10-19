#![no_main]

//! Fuzzes the authentication verification paths with arbitrary bytes.
//!
//! A decoded (or synthesized) challenge/response pair is run through the
//! stateless verifiers and the replay cache. Verification must never panic;
//! it may only return `Ok` or an `AuthError`. This exercises HMAC tag
//! checking, timestamp skew checks, credential lookup, and replay detection
//! on hostile inputs.

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use uk_auth::{
    compute_auth_tag, verify_auth_response_identity_stateless, verify_auth_response_stateless,
    AuthChallenge, AuthResponse, Credential, ReplayCache,
};

/// Fixed credential valid under `Credential::active` (key id within limits,
/// 32-byte secret that is not a single repeated byte).
fn fuzz_credential() -> Credential {
    let mut secret = [0u8; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    Credential::active(b"fuzz-key-01".to_vec(), secret.to_vec())
        .expect("fixed fuzz credential is valid")
}

fn u64_from(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = data.len().min(8);
    buf[..n].copy_from_slice(&data[..n]);
    u64::from_le_bytes(buf)
}

fuzz_target!(|data: &[u8]| {
    // Split the input: challenge bytes, response bytes, control bytes.
    let third = data.len() / 3;
    let (chal_bytes, rest) = data.split_at(third);
    let (resp_bytes, ctrl) = rest.split_at(rest.len() / 2);

    let credential = fuzz_credential();
    let credentials = [credential];
    let exporter = [0x5au8; 32];
    // `now` swings over a wide range, including extremes, to stress the
    // timestamp skew checks.
    let now = u64_from(ctrl);
    let allowed_skew = Duration::from_secs(60 + (u64_from(ctrl) % 3600));

    // Decode both payloads; fall back to a generated challenge so the verify
    // path is still exercised when the challenge bytes are malformed.
    let mut chal_input = chal_bytes;
    let challenge =
        AuthChallenge::decode(&mut chal_input).unwrap_or_else(|_| AuthChallenge::generate(now));

    let mut resp_input = resp_bytes;
    if let Ok(response) = AuthResponse::decode(&mut resp_input) {
        let _ = verify_auth_response_stateless(
            &credentials,
            &exporter,
            &challenge,
            &response,
            now,
            allowed_skew,
        );
        let _ = verify_auth_response_identity_stateless(
            &credentials,
            &exporter,
            &challenge,
            &response,
            now,
            allowed_skew,
        );

        // Exercise the tag computation and replay cache on the same values.
        let _ = compute_auth_tag(
            &credentials[0].secret,
            &exporter,
            &challenge,
            &response.key_id,
            &response.client_nonce,
            response.client_time,
            &response.client_capabilities,
        );
        let mut replay = ReplayCache::with_max_entries(Duration::from_secs(300), 16);
        let _ = replay.check_and_insert(challenge.server_nonce, response.client_nonce);
        // Inserting twice must report a replay, never panic.
        let _ = replay.check_and_insert(challenge.server_nonce, response.client_nonce);
    }
});
