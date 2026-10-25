#![no_main]

//! Fuzzes the authentication challenge and response payload decoders.

use libfuzzer_sys::fuzz_target;
use uk_auth::{AuthChallenge, AuthResponse};

fuzz_target!(|data: &[u8]| {
    let mut challenge_input = data;
    let _ = AuthChallenge::decode(&mut challenge_input);

    let mut response_input = data;
    let _ = AuthResponse::decode(&mut response_input);
});
