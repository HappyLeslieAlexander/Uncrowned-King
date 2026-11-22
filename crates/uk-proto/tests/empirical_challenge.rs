//! Empirical challenge test suite for uk-proto.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use uk_proto::{
    Frame, FrameHeader, FrameLimits, FrameType, ProtocolError, Settings, TcpOpen, VERSION,
    io::{FrameIoError, read_frame},
    varint,
};

#[test]
fn frame_header_decode_rejects_truncated_wire_lengths_under_six_bytes() {
    let limits = FrameLimits::default();

    // Any input strictly under 6 bytes must be rejected as Truncated without panicking
    for len in 0..6 {
        let buf = vec![VERSION; len];
        let mut cursor = &buf[..];
        let res = FrameHeader::decode(&mut cursor, limits);
        assert!(
            matches!(res, Err(ProtocolError::Truncated)),
            "length {len} must return Truncated, got: {res:?}"
        );
        // Ensure no bytes consumed on error when < 6
        assert_eq!(cursor.len(), len);
    }
}

#[test]
fn frame_header_decode_rejects_unsupported_version_and_unknown_frame_type() {
    let limits = FrameLimits::default();

    // Unsupported version
    for v in [0x00, 0x02, 0x7f, 0xff] {
        let buf = [v, FrameType::TcpData as u8, 0x00, 0x00, 0x01, 0x05];
        let mut cursor = &buf[..];
        let res = FrameHeader::decode(&mut cursor, limits);
        assert!(
            matches!(res, Err(ProtocolError::UnsupportedVersion(bad_v)) if bad_v == v),
            "expected UnsupportedVersion({v}), got: {res:?}"
        );
    }

    // Unknown frame type
    for ft in [0x00, 0x0f, 0x55, 0xff] {
        let buf = [VERSION, ft, 0x00, 0x00, 0x01, 0x05];
        let mut cursor = &buf[..];
        let res = FrameHeader::decode(&mut cursor, limits);
        assert!(
            matches!(res, Err(ProtocolError::UnknownFrameType(bad_ft)) if bad_ft == ft),
            "expected UnknownFrameType({ft}), got: {res:?}"
        );
    }
}

#[test]
fn frame_header_decode_rejects_non_minimal_varints() {
    let limits = FrameLimits::default();

    // Canonical varint check: id = 1 encoded as 2 bytes [0x40, 0x01] instead of [0x01]
    let mut buf = vec![VERSION, FrameType::TcpData as u8, 0x00, 0x00];
    buf.extend_from_slice(&[0x40, 0x01]); // non-minimal id
    buf.push(0x05); // length 5
    let mut cursor = &buf[..];
    let res = FrameHeader::decode(&mut cursor, limits);
    assert!(
        matches!(res, Err(ProtocolError::InvalidVarint)),
        "non-minimal id varint must be rejected with InvalidVarint, got: {res:?}"
    );

    // length = 2 encoded as 2 bytes [0x40, 0x02] instead of [0x02]
    let mut buf2 = vec![VERSION, FrameType::TcpData as u8, 0x00, 0x00];
    buf2.push(0x01); // minimal id 1
    buf2.extend_from_slice(&[0x40, 0x02]); // non-minimal length
    let mut cursor2 = &buf2[..];
    let res2 = FrameHeader::decode(&mut cursor2, limits);
    assert!(
        matches!(res2, Err(ProtocolError::InvalidVarint)),
        "non-minimal length varint must be rejected with InvalidVarint, got: {res2:?}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn frame_header_decode_enforces_control_frame_payload_bounds() {
    let limits = FrameLimits::default();

    // TcpClose / UdpClose must have length == 2
    for ft in [FrameType::TcpClose, FrameType::UdpClose] {
        for len in [0, 1, 3, 4, 10, 100] {
            let mut buf = BytesMut::new();
            buf.put_u8(VERSION);
            buf.put_u8(ft as u8);
            buf.put_u16(0); // flags
            varint::encode(1, &mut buf).unwrap(); // id
            varint::encode(len, &mut buf).unwrap(); // length
            let mut cursor = buf.freeze();
            let res = FrameHeader::decode(&mut cursor, limits);
            assert!(
                matches!(res, Err(ProtocolError::InvalidFrame(_))),
                "{ft:?} with invalid length {len} must be rejected, got: {res:?}"
            );
        }

        // length == 2 succeeds
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(ft as u8);
        buf.put_u16(0);
        varint::encode(1, &mut buf).unwrap();
        varint::encode(2, &mut buf).unwrap();
        let mut cursor = buf.freeze();
        let res = FrameHeader::decode(&mut cursor, limits);
        assert!(res.is_ok(), "{ft:?} with length 2 must succeed");
    }

    // TcpOpen: length 6..=262
    for len in [0, 1, 5, 263, 264, 1000] {
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(FrameType::TcpOpen as u8);
        buf.put_u16(0);
        varint::encode(1, &mut buf).unwrap();
        varint::encode(len, &mut buf).unwrap();
        let mut cursor = buf.freeze();
        let res = FrameHeader::decode(&mut cursor, limits);
        assert!(
            matches!(res, Err(ProtocolError::InvalidFrame(_))),
            "TcpOpen with length {len} must be rejected"
        );
    }
    for len in [6, 10, 100, 262] {
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(FrameType::TcpOpen as u8);
        buf.put_u16(0);
        varint::encode(1, &mut buf).unwrap();
        varint::encode(len, &mut buf).unwrap();
        let mut cursor = buf.freeze();
        let res = FrameHeader::decode(&mut cursor, limits);
        assert!(res.is_ok(), "TcpOpen with length {len} must succeed");
    }

    // UdpOpen: length 4..=260
    for len in [0, 1, 3, 261, 262, 500] {
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(FrameType::UdpOpen as u8);
        buf.put_u16(0);
        varint::encode(1, &mut buf).unwrap();
        varint::encode(len, &mut buf).unwrap();
        let mut cursor = buf.freeze();
        let res = FrameHeader::decode(&mut cursor, limits);
        assert!(
            matches!(res, Err(ProtocolError::InvalidFrame(_))),
            "UdpOpen with length {len} must be rejected"
        );
    }
    for len in [4, 8, 50, 260] {
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(FrameType::UdpOpen as u8);
        buf.put_u16(0);
        varint::encode(1, &mut buf).unwrap();
        varint::encode(len, &mut buf).unwrap();
        let mut cursor = buf.freeze();
        let res = FrameHeader::decode(&mut cursor, limits);
        assert!(res.is_ok(), "UdpOpen with length {len} must succeed");
    }

    // Status frames (Error, PolicyDenied, ResourceLimit): 1..=8
    for ft in [
        FrameType::Error,
        FrameType::PolicyDenied,
        FrameType::ResourceLimit,
    ] {
        for len in [0, 9, 10, 50] {
            let mut buf = BytesMut::new();
            buf.put_u8(VERSION);
            buf.put_u8(ft as u8);
            buf.put_u16(0);
            varint::encode(1, &mut buf).unwrap();
            varint::encode(len, &mut buf).unwrap();
            let mut cursor = buf.freeze();
            let res = FrameHeader::decode(&mut cursor, limits);
            assert!(
                matches!(res, Err(ProtocolError::InvalidFrame(_))),
                "{ft:?} with length {len} must be rejected"
            );
        }
        for len in [1, 4, 8] {
            let mut buf = BytesMut::new();
            buf.put_u8(VERSION);
            buf.put_u8(ft as u8);
            buf.put_u16(0);
            varint::encode(1, &mut buf).unwrap();
            varint::encode(len, &mut buf).unwrap();
            let mut cursor = buf.freeze();
            let res = FrameHeader::decode(&mut cursor, limits);
            assert!(res.is_ok(), "{ft:?} with length {len} must succeed");
        }
    }
}

#[test]
fn frame_decode_preserves_buffer_on_truncated_payload() {
    let limits = FrameLimits::default();

    // Build a TcpData frame with 20 bytes of payload
    let payload_data = vec![0x42; 20];
    let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from(payload_data)).unwrap();
    let encoded = frame.encode().unwrap();
    assert_eq!(encoded.len(), 6 + 20); // 6 bytes header + 20 bytes payload

    // Provide only 15 bytes total (6 bytes header + 9 bytes payload, truncated by 11 bytes)
    let truncated_bytes = &encoded[..15];
    let mut buf = Bytes::copy_from_slice(truncated_bytes);
    let initial_len = buf.len();

    let res = Frame::decode(&mut buf, limits);
    assert!(
        matches!(res, Err(ProtocolError::Truncated)),
        "truncated frame must return ProtocolError::Truncated, got: {res:?}"
    );

    // CRITICAL: The buffer must NOT be consumed or advanced!
    assert_eq!(
        buf.remaining(),
        initial_len,
        "Buffer was consumed by decode on truncation! Remaining: {}, expected: {}",
        buf.remaining(),
        initial_len
    );

    // Now supply the full buffer and decode successfully
    let mut full_buf = Bytes::copy_from_slice(&encoded);
    let decoded_frame = Frame::decode(&mut full_buf, limits).expect("full frame decodes");
    assert_eq!(decoded_frame, frame);
    assert_eq!(full_buf.remaining(), 0);
}

#[tokio::test]
async fn read_frame_stream_truncation_and_version_checks() {
    let limits = FrameLimits::default();

    // 1. Immediate EOF
    let mut empty_stream = &b""[..];
    let res = read_frame(&mut empty_stream, limits).await;
    assert!(
        matches!(res, Err(FrameIoError::Closed)),
        "immediate EOF must return Closed, got: {res:?}"
    );

    // 2. Unsupported version on first byte
    let mut bad_ver_stream = &[0x02][..];
    let res = read_frame(&mut bad_ver_stream, limits).await;
    assert!(
        matches!(
            res,
            Err(FrameIoError::Protocol(ProtocolError::UnsupportedVersion(2)))
        ),
        "invalid version byte must fail immediately, got: {res:?}"
    );

    // 3. Truncated header (2 bytes then EOF)
    let mut trunc_hdr_stream = &[VERSION, FrameType::TcpData as u8][..];
    let res = read_frame(&mut trunc_hdr_stream, limits).await;
    assert!(
        matches!(res, Err(FrameIoError::Protocol(ProtocolError::Truncated))),
        "truncated header stream must return Truncated, got: {res:?}"
    );

    // 4. Header ok, but stream ends prematurely during payload
    let mut buf = BytesMut::new();
    buf.put_u8(VERSION);
    buf.put_u8(FrameType::TcpData as u8);
    buf.put_u16(0);
    varint::encode(1, &mut buf).unwrap();
    varint::encode(50, &mut buf).unwrap(); // Declares 50 bytes payload
    buf.extend_from_slice(&[0xaa; 10]); // Only sends 10 bytes then EOF

    let mut trunc_payload_stream = &buf[..];
    let res = read_frame(&mut trunc_payload_stream, limits).await;
    assert!(
        matches!(res, Err(FrameIoError::Protocol(ProtocolError::Truncated))),
        "truncated payload must return Truncated, got: {res:?}"
    );
}

#[test]
fn settings_decode_bounds_and_truncation_checks() {
    // 1. Oversized settings count > 64
    let mut buf = BytesMut::new();
    varint::encode(65, &mut buf).unwrap(); // count = 65
    for _ in 0..65 {
        varint::encode(1, &mut buf).unwrap();
        varint::encode(1000, &mut buf).unwrap();
    }
    let mut cursor = buf.freeze();
    let res = Settings::decode(&mut cursor);
    assert!(
        matches!(res, Err(ProtocolError::InvalidSettings(msg)) if msg.contains("too many")),
        "count > 64 must be rejected with 'too many settings entries', got: {res:?}"
    );

    // 2. Truncated buffer check upfront: count = 50, but buffer has only 10 bytes (< 50*2)
    let mut buf2 = BytesMut::new();
    varint::encode(50, &mut buf2).unwrap();
    buf2.extend_from_slice(&[0x01; 10]); // only 10 bytes
    let mut cursor2 = buf2.freeze();
    let res2 = Settings::decode(&mut cursor2);
    assert!(
        matches!(res2, Err(ProtocolError::Truncated)),
        "buffer shorter than count*2 must return Truncated upfront, got: {res2:?}"
    );

    // 3. Duplicate key rejection
    let mut buf3 = BytesMut::new();
    varint::encode(2, &mut buf3).unwrap();
    varint::encode(1, &mut buf3).unwrap(); // MaxFrameSize
    varint::encode(16384, &mut buf3).unwrap();
    varint::encode(1, &mut buf3).unwrap(); // Duplicate MaxFrameSize
    varint::encode(32768, &mut buf3).unwrap();
    let mut cursor3 = buf3.freeze();
    let res3 = Settings::decode(&mut cursor3);
    assert!(
        matches!(res3, Err(ProtocolError::InvalidSettings(msg)) if msg.contains("duplicate")),
        "duplicate setting key must be rejected, got: {res3:?}"
    );

    // 4. Trailing settings bytes
    let mut buf4 = BytesMut::new();
    varint::encode(1, &mut buf4).unwrap();
    varint::encode(1, &mut buf4).unwrap();
    varint::encode(16384, &mut buf4).unwrap();
    buf4.put_u8(0xff); // trailing byte
    let mut cursor4 = buf4.freeze();
    let res4 = Settings::decode(&mut cursor4);
    assert!(
        matches!(res4, Err(ProtocolError::InvalidSettings(msg)) if msg.contains("trailing")),
        "trailing settings bytes must be rejected, got: {res4:?}"
    );
}

#[test]
#[allow(clippy::similar_names)]
fn tcp_open_decode_bounds_and_truncation_checks() {
    // 1. Truncated wire length < 7 bytes upfront; the smallest legal payload
    // is a 1-byte domain form with wire length 7.
    for len in 0..7 {
        let buf = vec![0x02; len];
        let mut cursor = &buf[..];
        let res = TcpOpen::decode(&mut cursor);
        assert!(
            matches!(res, Err(ProtocolError::Truncated)),
            "TcpOpen with length {len} (<7) must return Truncated, got: {res:?}"
        );
    }

    // 2. Minimum valid IPv4 TcpOpen is exactly 10 bytes:
    // addr_type (1) + host_len (1) + ipv4 (4) + port (2) + flags (2) = 10
    let mut buf = BytesMut::new();
    buf.put_u8(0x02); // ADDR_IPV4
    varint::encode(4, &mut buf).unwrap(); // host_len = 4
    buf.extend_from_slice(&[127, 0, 0, 1]); // ipv4
    buf.put_u16(8080); // port
    buf.put_u16(0); // open_flags = 0
    assert_eq!(buf.len(), 10);

    let mut cursor = buf.freeze();
    let decoded = TcpOpen::decode(&mut cursor).expect("10-byte TcpOpen decodes");
    assert_eq!(decoded.open_flags, 0);
    assert_eq!(decoded.target.port(), 8080);

    // 3. Truncated flags: 9 bytes of target + 1 byte of flags
    let mut buf_trunc_flags = BytesMut::new();
    buf_trunc_flags.put_u8(0x02);
    varint::encode(4, &mut buf_trunc_flags).unwrap();
    buf_trunc_flags.extend_from_slice(&[127, 0, 0, 1]);
    buf_trunc_flags.put_u16(8080);
    buf_trunc_flags.put_u8(0); // only 1 byte of flags instead of 2
    let mut cursor_flags_trunc = buf_trunc_flags.freeze();
    let res_flags_trunc = TcpOpen::decode(&mut cursor_flags_trunc);
    assert!(
        matches!(res_flags_trunc, Err(ProtocolError::Truncated)),
        "truncated open_flags must return Truncated, got: {res_flags_trunc:?}"
    );

    // 4. Non-zero open_flags rejected
    let mut buf_bad_flags = BytesMut::new();
    buf_bad_flags.put_u8(0x02);
    varint::encode(4, &mut buf_bad_flags).unwrap();
    buf_bad_flags.extend_from_slice(&[127, 0, 0, 1]);
    buf_bad_flags.put_u16(8080);
    buf_bad_flags.put_u16(0x0001); // invalid non-zero flags
    let mut cursor_flags_bad = buf_bad_flags.freeze();
    let res_flags_bad = TcpOpen::decode(&mut cursor_flags_bad);
    assert!(
        matches!(res_flags_bad, Err(ProtocolError::InvalidTcpPayload(_))),
        "non-zero open_flags must be rejected, got: {res_flags_bad:?}"
    );

    // 5. Trailing bytes rejected
    let mut buf_trailing = BytesMut::new();
    buf_trailing.put_u8(0x02);
    varint::encode(4, &mut buf_trailing).unwrap();
    buf_trailing.extend_from_slice(&[127, 0, 0, 1]);
    buf_trailing.put_u16(8080);
    buf_trailing.put_u16(0);
    buf_trailing.put_u8(0xee); // trailing garbage
    let mut cursor_trail = buf_trailing.freeze();
    let res_trail = TcpOpen::decode(&mut cursor_trail);
    assert!(
        matches!(res_trail, Err(ProtocolError::InvalidTcpPayload(msg)) if msg.contains("trailing")),
        "trailing tcp open bytes must be rejected, got: {res_trail:?}"
    );

    // 6. Target bounds: unknown address type rejected early
    let mut buf_bad_type = BytesMut::new();
    buf_bad_type.put_u8(0x99); // unknown address type
    varint::encode(100, &mut buf_bad_type).unwrap();
    buf_bad_type.extend_from_slice(&[0x00; 20]);
    let mut cursor_type_bad = buf_bad_type.freeze();
    let res_type_bad = TcpOpen::decode(&mut cursor_type_bad);
    assert!(
        matches!(res_type_bad, Err(ProtocolError::InvalidTarget(msg)) if msg.contains("unknown address type")),
        "unknown address type must be rejected, got: {res_type_bad:?}"
    );
}
