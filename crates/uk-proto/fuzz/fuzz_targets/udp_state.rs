#![no_main]

//! Fuzzes the UDP relay control payloads (`UDP_OPEN` / `UDP_CLOSE`) that drive
//! the UDP relay flow state machine. These decoders gate every UDP flow
//! transition, so they must reject arbitrary input without panicking.

use libfuzzer_sys::fuzz_target;
use uk_proto::{UdpClose, UdpOpen};

fuzz_target!(|data: &[u8]| {
    let mut open_input = data;
    let _ = UdpOpen::decode(&mut open_input);

    let mut close_input = data;
    let _ = UdpClose::decode(&mut close_input);
});
