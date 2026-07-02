//! UK frame header and frame encoding.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{ProtocolError, ProtocolResult, varint};

/// Wire protocol version implemented by this crate.
pub const VERSION: u8 = 1;

/// Required flags occupy bits `0x0100..=0xffff`.
pub const REQUIRED_FLAG_MASK: u16 = 0xff00;

/// Default maximum payload length accepted for a frame.
pub const DEFAULT_MAX_FRAME_SIZE: u64 = 65_536;

/// Limits applied while reading frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    /// Maximum payload length in bytes.
    pub max_frame_size: u64,
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }
}

/// UK frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Server authentication challenge.
    AuthChallenge = 0x01,
    /// Client authentication response.
    AuthResponse = 0x02,
    /// Connection settings.
    Settings = 0x03,
    /// Ping keepalive.
    Ping = 0x04,
    /// Pong keepalive response.
    Pong = 0x05,
    /// Open a TCP flow.
    TcpOpen = 0x10,
    /// TCP flow data.
    TcpData = 0x11,
    /// Close a TCP flow.
    TcpClose = 0x12,
    /// Open a UDP flow.
    UdpOpen = 0x20,
    /// UDP flow data.
    UdpData = 0x21,
    /// Close a UDP flow.
    UdpClose = 0x22,
    /// Generic error.
    Error = 0x30,
    /// Policy denied.
    PolicyDenied = 0x31,
    /// Resource limit exceeded.
    ResourceLimit = 0x32,
}

impl TryFrom<u8> for FrameType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0x01 => Ok(Self::AuthChallenge),
            0x02 => Ok(Self::AuthResponse),
            0x03 => Ok(Self::Settings),
            0x04 => Ok(Self::Ping),
            0x05 => Ok(Self::Pong),
            0x10 => Ok(Self::TcpOpen),
            0x11 => Ok(Self::TcpData),
            0x12 => Ok(Self::TcpClose),
            0x20 => Ok(Self::UdpOpen),
            0x21 => Ok(Self::UdpData),
            0x22 => Ok(Self::UdpClose),
            0x30 => Ok(Self::Error),
            0x31 => Ok(Self::PolicyDenied),
            0x32 => Ok(Self::ResourceLimit),
            other => Err(ProtocolError::UnknownFrameType(other)),
        }
    }
}

/// Decoded UK frame header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    /// Protocol version. Must be `1`.
    pub version: u8,
    /// Frame type.
    pub frame_type: FrameType,
    /// Frame flags.
    pub flags: u16,
    /// Stream or flow id.
    pub id: u64,
    /// Payload length in bytes.
    pub length: u64,
}

impl FrameHeader {
    /// Creates a new validated header.
    pub fn new(frame_type: FrameType, flags: u16, id: u64, length: u64) -> ProtocolResult<Self> {
        validate_flags(flags)?;
        varint::encoded_len(id)?;
        varint::encoded_len(length)?;
        Ok(Self {
            version: VERSION,
            frame_type,
            flags,
            id,
            length,
        })
    }

    /// Encodes this header into `dst`.
    pub fn encode(&self, dst: &mut impl BufMut) -> ProtocolResult<()> {
        if self.version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        validate_flags(self.flags)?;
        dst.put_u8(self.version);
        dst.put_u8(self.frame_type as u8);
        dst.put_u16(self.flags);
        varint::encode(self.id, dst)?;
        varint::encode(self.length, dst)?;
        Ok(())
    }

    /// Decodes and validates a frame header.
    pub fn decode(src: &mut impl Buf, limits: FrameLimits) -> ProtocolResult<Self> {
        if src.remaining() < 4 {
            return Err(ProtocolError::Truncated);
        }

        let version = src.get_u8();
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        let frame_type = FrameType::try_from(src.get_u8())?;
        let flags = src.get_u16();
        validate_flags(flags)?;
        let id = varint::decode(src)?;
        let length = varint::decode(src)?;
        if length > limits.max_frame_size {
            return Err(ProtocolError::OversizedFrame {
                length,
                limit: limits.max_frame_size,
            });
        }

        Ok(Self {
            version,
            frame_type,
            flags,
            id,
            length,
        })
    }
}

/// A complete in-memory UK frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame header.
    pub header: FrameHeader,
    /// Frame payload.
    pub payload: Bytes,
}

impl Frame {
    /// Creates a frame and validates that the payload length can be represented.
    pub fn new(frame_type: FrameType, flags: u16, id: u64, payload: Bytes) -> ProtocolResult<Self> {
        let length = u64::try_from(payload.len()).map_err(|_| ProtocolError::InvalidVarint)?;
        let header = FrameHeader::new(frame_type, flags, id, length)?;
        Ok(Self { header, payload })
    }

    /// Encodes the complete frame into a new byte buffer.
    pub fn encode(&self) -> ProtocolResult<Bytes> {
        let mut out = BytesMut::new();
        self.header.encode(&mut out)?;
        out.extend_from_slice(&self.payload);
        Ok(out.freeze())
    }

    /// Decodes one complete frame from `src`.
    pub fn decode(src: &mut impl Buf, limits: FrameLimits) -> ProtocolResult<Self> {
        let header = FrameHeader::decode(src, limits)?;
        let length = usize::try_from(header.length).map_err(|_| ProtocolError::InvalidVarint)?;
        if src.remaining() < length {
            return Err(ProtocolError::Truncated);
        }
        let payload = src.copy_to_bytes(length);
        Ok(Self { header, payload })
    }
}

fn validate_flags(flags: u16) -> ProtocolResult<()> {
    let required = flags & REQUIRED_FLAG_MASK;
    if required == 0 {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedFlag(required))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn encodes_known_tcp_data_frame() {
        let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"abc")).unwrap();
        assert_eq!(
            frame.encode().unwrap().as_ref(),
            &[0x01, 0x11, 0x00, 0x00, 0x01, 0x03, b'a', b'b', b'c']
        );
    }

    #[test]
    fn decodes_known_tcp_data_header() {
        let mut bytes = Bytes::from_static(&[0x01, 0x11, 0x00, 0x00, 0x01, 0x03]);
        let header = FrameHeader::decode(&mut bytes, FrameLimits::default()).unwrap();
        assert_eq!(header.frame_type, FrameType::TcpData);
        assert_eq!(header.id, 1);
        assert_eq!(header.length, 3);
    }

    #[test]
    fn rejects_unknown_required_flag() {
        let mut bytes = Bytes::from_static(&[0x01, 0x11, 0x01, 0x00, 0x01, 0x00]);
        assert_eq!(
            FrameHeader::decode(&mut bytes, FrameLimits::default()),
            Err(ProtocolError::UnsupportedFlag(0x0100))
        );
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut bytes = Bytes::from_static(&[0x01, 0x11, 0x00, 0x00, 0x01, 0x40, 0x41]);
        assert_eq!(
            FrameHeader::decode(&mut bytes, FrameLimits { max_frame_size: 64 }),
            Err(ProtocolError::OversizedFrame {
                length: 65,
                limit: 64
            })
        );
    }

    #[test]
    fn rejects_truncated_frame_payload() {
        let mut bytes = Bytes::from_static(&[0x01, 0x11, 0x00, 0x00, 0x01, 0x03, b'a']);
        assert_eq!(
            Frame::decode(&mut bytes, FrameLimits::default()),
            Err(ProtocolError::Truncated)
        );
    }
}
