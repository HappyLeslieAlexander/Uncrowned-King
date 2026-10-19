#![no_main]

//! Fuzzes the UK frame header/frame parser. Strict parsing must never panic on
//! arbitrary input; it may only return a decode error or a valid frame.

use libfuzzer_sys::fuzz_target;
use uk_proto::{Frame, FrameHeader, FrameLimits};

fuzz_target!(|data: &[u8]| {
    let limits = FrameLimits {
        max_frame_size: 65_536,
    };
    let mut header_input = data;
    let _ = FrameHeader::decode(&mut header_input, limits);

    let mut frame_input = data;
    let _ = Frame::decode(&mut frame_input, limits);
});
