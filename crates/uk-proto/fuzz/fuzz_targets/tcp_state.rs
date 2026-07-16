#![no_main]

//! Fuzzes the TCP relay control payloads (`TCP_OPEN` / `TCP_CLOSE`) that drive
//! the TCP relay state machine. These decoders gate every TCP flow transition,
//! so they must reject arbitrary input without panicking.

use libfuzzer_sys::fuzz_target;
use uk_proto::{TcpClose, TcpOpen};

fuzz_target!(|data: &[u8]| {
    let mut open_input = data;
    let _ = TcpOpen::decode(&mut open_input);

    let mut close_input = data;
    let _ = TcpClose::decode(&mut close_input);
});
