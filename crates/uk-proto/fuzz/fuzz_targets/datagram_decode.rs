#![no_main]

//! Fuzzes UDP datagram decoding (`uk_proto::datagram::decode`).
//!
//! A datagram is a varint flow-id prefix followed by an arbitrary payload
//! (which may be empty). Decoding must never panic on arbitrary input; it
//! may only return a decode error or a `(flow_id, payload)` pair.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use uk_proto::datagram;

fuzz_target!(|data: &[u8]| {
    let _ = datagram::decode(Bytes::copy_from_slice(data));
});
