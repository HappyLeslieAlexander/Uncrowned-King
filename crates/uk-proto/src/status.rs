//! Error, policy-denied, and resource-limit payload encoding.

use bytes::{Buf, BufMut};

use crate::{ProtocolError, ProtocolResult, varint};

/// v0.1 coarse error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ErrorCode {
    /// Unsupported protocol version.
    UnsupportedVersion = 1,
    /// Unsupported required flag.
    UnsupportedFlag = 2,
    /// Frame exceeded configured limits.
    OversizedFrame = 3,
    /// Frame ended before a complete value arrived.
    TruncatedFrame = 4,
    /// Target payload was invalid.
    InvalidTarget = 5,
    /// Authentication failed.
    AuthFailed = 6,
    /// Policy denied the target.
    PolicyDenied = 7,
    /// Session or flow resource limit was exceeded.
    ResourceLimit = 8,
    /// Generic protocol violation.
    Protocol = 9,
    /// Target could not be reached or connected.
    TargetUnavailable = 10,
    /// Target DNS resolution or TCP connect timed out.
    TargetTimeout = 11,
}

impl ErrorCode {
    /// Maps a local protocol decode error to the closest wire error code.
    pub fn from_protocol_error(error: &ProtocolError) -> Self {
        match error {
            ProtocolError::UnsupportedVersion(_) => Self::UnsupportedVersion,
            ProtocolError::UnsupportedFlag(_) => Self::UnsupportedFlag,
            ProtocolError::OversizedFrame { .. } => Self::OversizedFrame,
            ProtocolError::Truncated => Self::TruncatedFrame,
            ProtocolError::InvalidTarget(_) => Self::InvalidTarget,
            ProtocolError::InvalidVarint
            | ProtocolError::UnknownFrameType(_)
            | ProtocolError::InvalidFrame(_)
            | ProtocolError::InvalidSettings(_)
            | ProtocolError::InvalidTcpPayload(_)
            | ProtocolError::InvalidErrorPayload(_) => Self::Protocol,
        }
    }
}

impl TryFrom<u64> for ErrorCode {
    type Error = ProtocolError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::UnsupportedFlag),
            3 => Ok(Self::OversizedFrame),
            4 => Ok(Self::TruncatedFrame),
            5 => Ok(Self::InvalidTarget),
            6 => Ok(Self::AuthFailed),
            7 => Ok(Self::PolicyDenied),
            8 => Ok(Self::ResourceLimit),
            9 => Ok(Self::Protocol),
            10 => Ok(Self::TargetUnavailable),
            11 => Ok(Self::TargetTimeout),
            _ => Err(ProtocolError::InvalidErrorPayload("unknown error code")),
        }
    }
}

/// Payload carried by `ERROR`, `POLICY_DENIED`, and `RESOURCE_LIMIT` frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorPayload {
    /// Coarse error code.
    pub code: ErrorCode,
}

impl ErrorPayload {
    /// Creates an error payload.
    pub fn new(code: ErrorCode) -> Self {
        Self { code }
    }

    /// Encodes this payload into `dst`.
    pub fn encode(&self, dst: &mut impl BufMut) -> ProtocolResult<()> {
        varint::encode(self.code as u64, dst)
    }

    /// Decodes an error payload.
    pub fn decode(src: &mut impl Buf) -> ProtocolResult<Self> {
        let code = ErrorCode::try_from(varint::decode(src)?)?;
        if src.has_remaining() {
            return Err(ProtocolError::InvalidErrorPayload(
                "trailing error payload bytes",
            ));
        }
        Ok(Self { code })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn encodes_policy_denied_vector() {
        let mut out = Vec::new();
        ErrorPayload::new(ErrorCode::PolicyDenied)
            .encode(&mut out)
            .unwrap();
        assert_eq!(out, [0x07]);
    }

    #[test]
    fn roundtrips_resource_limit() {
        let payload = ErrorPayload::new(ErrorCode::ResourceLimit);
        let mut out = Vec::new();
        payload.encode(&mut out).unwrap();
        let mut bytes = Bytes::from(out);
        assert_eq!(ErrorPayload::decode(&mut bytes).unwrap(), payload);
    }

    #[test]
    fn encodes_target_timeout_vector() {
        let mut out = Vec::new();
        ErrorPayload::new(ErrorCode::TargetTimeout)
            .encode(&mut out)
            .unwrap();
        assert_eq!(out, [0x0b]);
    }

    #[test]
    fn maps_protocol_errors_to_wire_error_codes() {
        assert_eq!(
            ErrorCode::from_protocol_error(&ProtocolError::UnsupportedVersion(2)),
            ErrorCode::UnsupportedVersion
        );
        assert_eq!(
            ErrorCode::from_protocol_error(&ProtocolError::UnsupportedFlag(0x0100)),
            ErrorCode::UnsupportedFlag
        );
        assert_eq!(
            ErrorCode::from_protocol_error(&ProtocolError::OversizedFrame {
                length: 2,
                limit: 1,
            }),
            ErrorCode::OversizedFrame
        );
        assert_eq!(
            ErrorCode::from_protocol_error(&ProtocolError::Truncated),
            ErrorCode::TruncatedFrame
        );
        assert_eq!(
            ErrorCode::from_protocol_error(&ProtocolError::InvalidTarget("bad target")),
            ErrorCode::InvalidTarget
        );
        assert_eq!(
            ErrorCode::from_protocol_error(&ProtocolError::InvalidFrame("bad frame")),
            ErrorCode::Protocol
        );
    }

    #[test]
    fn rejects_unknown_error_code() {
        let mut bytes = Bytes::from_static(&[0x3f]);
        assert_eq!(
            ErrorPayload::decode(&mut bytes),
            Err(ProtocolError::InvalidErrorPayload("unknown error code"))
        );
    }

    #[test]
    fn rejects_truncated_error_payload() {
        for payload in [b"".as_slice(), &[0x40]] {
            let mut bytes = Bytes::copy_from_slice(payload);
            assert_eq!(
                ErrorPayload::decode(&mut bytes),
                Err(ProtocolError::Truncated)
            );
        }
    }

    #[test]
    fn rejects_trailing_error_payload_bytes() {
        let mut bytes = Bytes::from_static(&[0x07, 0x00]);
        assert_eq!(
            ErrorPayload::decode(&mut bytes),
            Err(ProtocolError::InvalidErrorPayload(
                "trailing error payload bytes"
            ))
        );
    }
}
