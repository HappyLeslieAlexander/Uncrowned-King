//! TCP relay payload encoding.

use bytes::{Buf, BufMut};

use crate::{ProtocolError, ProtocolResult, Target};

/// No TCP open flags are defined in v0.1.
pub const TCP_OPEN_FLAGS_NONE: u16 = 0;

/// Normal TCP flow close.
pub const TCP_CLOSE_NORMAL: u16 = 0;

/// Generic TCP flow close caused by an error.
pub const TCP_CLOSE_ERROR: u16 = 1;

/// Minimum `max_frame_size` that can carry every valid v0.1 TCP control payload.
pub const MIN_TCP_RELAY_FRAME_SIZE: u64 = 262;

/// Payload carried by a `TCP_OPEN` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOpen {
    /// Target address requested by the client.
    pub target: Target,
    /// Open flags. v0.1 defines no non-zero flags.
    pub open_flags: u16,
}

impl TcpOpen {
    /// Creates a TCP open payload.
    pub fn new(target: Target, open_flags: u16) -> Self {
        Self { target, open_flags }
    }

    /// Encodes this payload into `dst`.
    pub fn encode(&self, dst: &mut impl BufMut) -> ProtocolResult<()> {
        validate_open_flags(self.open_flags)?;
        self.target.encode(dst)?;
        dst.put_u16(self.open_flags);
        Ok(())
    }

    /// Decodes a TCP open payload.
    pub fn decode(src: &mut impl Buf) -> ProtocolResult<Self> {
        // The smallest legal payload is a 1-byte domain target:
        // type (1) + host_len (1) + "a" (1) + port (2) + open_flags (2) = 7.
        // Do not re-impose the IPv4 form's 10-byte floor here; that would
        // reject those legal TcpOpen payloads before Target::decode runs.
        if src.remaining() < 7 {
            return Err(ProtocolError::Truncated);
        }
        let target = Target::decode(src)?;
        if src.remaining() < 2 {
            return Err(ProtocolError::Truncated);
        }
        let open_flags = src.get_u16();
        validate_open_flags(open_flags)?;
        if src.has_remaining() {
            return Err(ProtocolError::InvalidTcpPayload("trailing tcp open bytes"));
        }
        Ok(Self { target, open_flags })
    }
}

/// Payload carried by a `TCP_CLOSE` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpClose {
    /// Close reason code.
    pub close_code: u16,
}

impl TcpClose {
    /// Creates a TCP close payload.
    pub fn new(close_code: u16) -> Self {
        Self { close_code }
    }

    /// Encodes this payload into `dst`.
    pub fn encode(&self, dst: &mut impl BufMut) -> ProtocolResult<()> {
        validate_close_code(self.close_code)?;
        dst.put_u16(self.close_code);
        Ok(())
    }

    /// Decodes a TCP close payload.
    pub fn decode(src: &mut impl Buf) -> ProtocolResult<Self> {
        if src.remaining() < 2 {
            return Err(ProtocolError::Truncated);
        }
        if src.remaining() > 2 {
            return Err(ProtocolError::InvalidTcpPayload("trailing tcp close bytes"));
        }
        let close_code = src.get_u16();
        validate_close_code(close_code)?;
        Ok(Self { close_code })
    }
}

fn validate_open_flags(open_flags: u16) -> ProtocolResult<()> {
    if open_flags == TCP_OPEN_FLAGS_NONE {
        Ok(())
    } else {
        Err(ProtocolError::InvalidTcpPayload("unknown tcp open flags"))
    }
}

fn validate_close_code(close_code: u16) -> ProtocolResult<()> {
    if crate::is_valid_close_code(close_code) {
        Ok(())
    } else {
        Err(ProtocolError::InvalidTcpPayload("unknown tcp close code"))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use super::*;

    #[test]
    fn roundtrips_tcp_open() {
        let open = TcpOpen::new(
            Target::Domain("example.com".to_owned(), 443),
            TCP_OPEN_FLAGS_NONE,
        );
        let mut out = Vec::new();
        open.encode(&mut out).unwrap();
        let mut bytes = Bytes::from(out);
        assert_eq!(TcpOpen::decode(&mut bytes).unwrap(), open);
    }

    #[test]
    fn encodes_ipv6_tcp_open_vector() {
        let open = TcpOpen::new(Target::Ipv6(Ipv6Addr::LOCALHOST, 5353), TCP_OPEN_FLAGS_NONE);
        let mut out = Vec::new();
        open.encode(&mut out).unwrap();
        assert_eq!(
            out,
            [
                0x03, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x14, 0xe9, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn roundtrips_tcp_close() {
        let close = TcpClose::new(TCP_CLOSE_NORMAL);
        let mut out = Vec::new();
        close.encode(&mut out).unwrap();
        let mut bytes = Bytes::from(out);
        assert_eq!(TcpClose::decode(&mut bytes).unwrap(), close);
    }

    #[test]
    fn rejects_trailing_tcp_open_bytes() {
        let mut bytes =
            Bytes::from_static(&[0x02, 0x04, 127, 0, 0, 1, 0x1f, 0x90, 0x00, 0x00, 0xff]);
        assert_eq!(
            TcpOpen::decode(&mut bytes),
            Err(ProtocolError::InvalidTcpPayload("trailing tcp open bytes"))
        );
    }

    #[test]
    fn rejects_unknown_tcp_open_flags() {
        let mut bytes = Bytes::from_static(&[0x02, 0x04, 127, 0, 0, 1, 0x1f, 0x90, 0x00, 0x01]);
        assert_eq!(
            TcpOpen::decode(&mut bytes),
            Err(ProtocolError::InvalidTcpPayload("unknown tcp open flags"))
        );
    }

    #[test]
    fn rejects_encoding_unknown_tcp_open_flags() {
        let open = TcpOpen::new(Target::Ipv4(Ipv4Addr::LOCALHOST, 8080), 1);
        let mut out = Vec::new();
        assert_eq!(
            open.encode(&mut out),
            Err(ProtocolError::InvalidTcpPayload("unknown tcp open flags"))
        );
    }

    #[test]
    fn rejects_unknown_tcp_close_code() {
        let mut bytes = Bytes::from_static(&[0x00, 0x02]);
        assert_eq!(
            TcpClose::decode(&mut bytes),
            Err(ProtocolError::InvalidTcpPayload("unknown tcp close code"))
        );
    }

    #[test]
    fn rejects_truncated_tcp_close() {
        let mut bytes = Bytes::from_static(&[0x00]);
        assert_eq!(TcpClose::decode(&mut bytes), Err(ProtocolError::Truncated));
    }

    #[test]
    fn rejects_trailing_tcp_close_bytes() {
        let mut bytes = Bytes::from_static(&[0x00, 0x00, 0xff]);
        assert_eq!(
            TcpClose::decode(&mut bytes),
            Err(ProtocolError::InvalidTcpPayload("trailing tcp close bytes"))
        );
    }

    #[test]
    fn rejects_encoding_unknown_tcp_close_code() {
        let close = TcpClose::new(2);
        let mut out = Vec::new();
        assert_eq!(
            close.encode(&mut out),
            Err(ProtocolError::InvalidTcpPayload("unknown tcp close code"))
        );
    }

    #[test]
    fn rejects_truncated_tcp_open() {
        // The absolute minimum is 7 bytes (1-byte domain + target header +
        // port + flags); 6-byte input is truncated before Target::decode and
        // must not consume the buffer (FINDING-22).
        let mut bytes = Bytes::from_static(&[0x02, 0x04, 127, 0, 0, 1]);
        assert_eq!(TcpOpen::decode(&mut bytes), Err(ProtocolError::Truncated));
        assert_eq!(bytes.remaining(), 6);
        // The 8-byte IPv4 form passes the 7-byte floor, decodes the target,
        // and is then rejected for missing flags without consuming those two
        // flag bytes. Non-destructive truncation is preserved by
        // Target::decode's pre-consumption checks and the explicit
        // remaining-bytes check before reading open_flags.
        let mut bytes = Bytes::from_static(&[0x02, 0x04, 127, 0, 0, 1, 0x00, 0x50]);
        assert_eq!(TcpOpen::decode(&mut bytes), Err(ProtocolError::Truncated));
        assert_eq!(bytes.remaining(), 0);
    }

    #[test]
    fn roundtrips_minimal_domain_tcp_open() {
        // A single-character domain is the smallest Target::Domain form and
        // must survive TcpOpen::decode as a 7-byte payload.
        let open = TcpOpen::new(Target::Domain("a".to_owned(), 443), TCP_OPEN_FLAGS_NONE);
        let mut out = Vec::new();
        open.encode(&mut out).unwrap();
        assert_eq!(out, [0x01, 0x01, b'a', 0x01, 0xbb, 0x00, 0x00]);
        let mut bytes = Bytes::from(out);
        assert_eq!(TcpOpen::decode(&mut bytes).unwrap(), open);
        assert!(!bytes.has_remaining());
    }
}
