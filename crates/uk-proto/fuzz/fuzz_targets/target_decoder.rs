#![no_main]

//! Fuzzes the strict target (address) decoder.

use libfuzzer_sys::fuzz_target;
use uk_proto::Target;

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let _ = Target::decode(&mut input);
});
