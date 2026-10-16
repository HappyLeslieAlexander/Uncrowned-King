#![no_main]

//! Fuzzes SETTINGS payload decoding and v1.0 negotiation.
//!
//! Decoding must never panic on arbitrary input. Successfully decoded
//! settings are additionally run through `negotiated_v1_0`, which enforces
//! the peer-advertised upper bounds (max streams/flows, idle timeout) — the
//! bound checks themselves must not panic or overflow on hostile values.

use libfuzzer_sys::fuzz_target;
use uk_proto::Settings;

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    if let Ok(settings) = Settings::decode(&mut input) {
        let _ = settings.negotiated_v1_0();
    }
});
