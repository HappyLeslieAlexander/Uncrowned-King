//! UDP relay payload encoding.

use bytes::{Buf, BufMut};

use crate::{ProtocolError, ProtocolResult, Target};

/// Normal UDP flow close.
pub const UDP_CLOSE_NORMAL: u16 = 0;

/// Generic UDP flow close caused by an error.
pub const UDP_CLOSE_ERROR: u16 = 1;

/// Minimum `max_frame_size` that can carry every valid v0.1 UDP control payload.
pub const MIN_UDP_RELAY_FRAME_SIZE: u64 = 260;

/// Payload carried by a `UDP_OPEN` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpOpen {
    /// Target address requested by the client.
    pub target: Target,
}

impl UdpOpen {
    /// Creates a UDP open payload.
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Encodes this payload into `dst`.
    pub fn encode(&self, dst: &mut impl BufMut) -> ProtocolResult<()> {
        self.target.encode(dst)
    }

    /// Decodes a UDP open payload.
    pub fn decode(src: &mut impl Buf) -> ProtocolResult<Self> {
        let target = Target::decode(src)?;
        if src.has_remaining() {
            return Err(ProtocolError::InvalidUdpPayload("trailing udp open bytes"));
        }
        Ok(Self { target })
    }
}

/// Payload carried by a `UDP_CLOSE` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpClose {
    /// Close reason code.
    pub close_code: u16,
}

impl UdpClose {
    /// Creates a UDP close payload.
    pub fn new(close_code: u16) -> Self {
        Self { close_code }
    }

    /// Encodes this payload into `dst`.
    pub fn encode(&self, dst: &mut impl BufMut) -> ProtocolResult<()> {
        validate_close_code(self.close_code)?;
        dst.put_u16(self.close_code);
        Ok(())
    }

    /// Decodes a UDP close payload.
    pub fn decode(src: &mut impl Buf) -> ProtocolResult<Self> {
        if src.remaining() < 2 {
            return Err(ProtocolError::Truncated);
        }
        if src.remaining() > 2 {
            return Err(ProtocolError::InvalidUdpPayload("trailing udp close bytes"));
        }
        let close_code = src.get_u16();
        validate_close_code(close_code)?;
        Ok(Self { close_code })
    }
}

fn validate_close_code(close_code: u16) -> ProtocolResult<()> {
    match close_code {
        UDP_CLOSE_NORMAL | UDP_CLOSE_ERROR => Ok(()),
        _ => Err(ProtocolError::InvalidUdpPayload("unknown udp close code")),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use super::*;

    #[test]
    fn roundtrips_udp_open() {
        let open = UdpOpen::new(Target::Domain("example.com".to_owned(), 53));
        let mut out = Vec::new();
        open.encode(&mut out).unwrap();
        let mut bytes = Bytes::from(out);
        assert_eq!(UdpOpen::decode(&mut bytes).unwrap(), open);
    }

    #[test]
    fn encodes_ipv6_udp_open_vector() {
        let open = UdpOpen::new(Target::Ipv6(Ipv6Addr::LOCALHOST, 5353));
        let mut out = Vec::new();
        open.encode(&mut out).unwrap();
        assert_eq!(
            out,
            [
                0x03, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x14, 0xe9,
            ]
        );
    }

    #[test]
    fn roundtrips_udp_close() {
        let close = UdpClose::new(UDP_CLOSE_NORMAL);
        let mut out = Vec::new();
        close.encode(&mut out).unwrap();
        let mut bytes = Bytes::from(out);
        assert_eq!(UdpClose::decode(&mut bytes).unwrap(), close);
    }

    #[test]
    fn rejects_trailing_udp_open_bytes() {
        let mut bytes = Bytes::from_static(&[0x02, 0x04, 127, 0, 0, 1, 0x00, 0x35, 0xff]);
        assert_eq!(
            UdpOpen::decode(&mut bytes),
            Err(ProtocolError::InvalidUdpPayload("trailing udp open bytes"))
        );
    }

    #[test]
    fn rejects_trailing_udp_close_bytes() {
        let mut bytes = Bytes::from_static(&[0x00, 0x00, 0xff]);
        assert_eq!(
            UdpClose::decode(&mut bytes),
            Err(ProtocolError::InvalidUdpPayload("trailing udp close bytes"))
        );
    }

    #[test]
    fn rejects_unknown_udp_close_code() {
        let mut bytes = Bytes::from_static(&[0x00, 0x02]);
        assert_eq!(
            UdpClose::decode(&mut bytes),
            Err(ProtocolError::InvalidUdpPayload("unknown udp close code"))
        );
    }

    #[test]
    fn rejects_encoding_unknown_udp_close_code() {
        let close = UdpClose::new(2);
        let mut out = Vec::new();
        assert_eq!(
            close.encode(&mut out),
            Err(ProtocolError::InvalidUdpPayload("unknown udp close code"))
        );
    }

    #[test]
    fn rejects_truncated_udp_open() {
        let mut bytes = Bytes::from_static(&[0x02, 0x04, 127]);
        assert_eq!(UdpOpen::decode(&mut bytes), Err(ProtocolError::Truncated));
    }

    #[test]
    fn rejects_truncated_udp_close() {
        let mut bytes = Bytes::from_static(&[0x00]);
        assert_eq!(UdpClose::decode(&mut bytes), Err(ProtocolError::Truncated));
    }

    #[test]
    fn encodes_ipv4_udp_open_vector() {
        let open = UdpOpen::new(Target::Ipv4(Ipv4Addr::LOCALHOST, 53));
        let mut out = Vec::new();
        open.encode(&mut out).unwrap();
        assert_eq!(out, [0x02, 0x04, 127, 0, 0, 1, 0x00, 0x35]);
    }
}
