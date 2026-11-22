#![no_main]

//! Fuzzes `ErrorPayload` decoding.
//!
//! The payload is a varint error code that must map to a known `ErrorCode`.
//! Decoding must never panic on arbitrary input; it may only return a decode
//! error or a valid payload.

use libfuzzer_sys::fuzz_target;
use uk_proto::ErrorPayload;

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let _ = ErrorPayload::decode(&mut input);
});
