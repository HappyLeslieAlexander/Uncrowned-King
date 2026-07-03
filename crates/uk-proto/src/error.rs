//! Protocol-level errors.

use thiserror::Error;

/// Convenient result alias for protocol operations.
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Errors that can be detected while encoding or decoding UK protocol data.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// A frame or payload used a protocol version other than `1`.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    /// A peer set a required flag unknown to this implementation.
    #[error("unsupported required flag bits 0x{0:04x}")]
    UnsupportedFlag(u16),
    /// A frame exceeded the configured frame size limit.
    #[error("oversized frame length {length} exceeds limit {limit}")]
    OversizedFrame {
        /// Payload length from the frame header.
        length: u64,
        /// Configured maximum payload length.
        limit: u64,
    },
    /// The input ended before a complete value could be decoded.
    #[error("truncated input")]
    Truncated,
    /// A varint value was outside the range allowed by the protocol.
    #[error("invalid varint")]
    InvalidVarint,
    /// A target address was malformed or forbidden by the wire rules.
    #[error("invalid target: {0}")]
    InvalidTarget(&'static str),
    /// A frame type value is unknown.
    #[error("unknown frame type 0x{0:02x}")]
    UnknownFrameType(u8),
    /// A settings payload was malformed.
    #[error("invalid settings: {0}")]
    InvalidSettings(&'static str),
    /// A TCP relay payload was malformed.
    #[error("invalid tcp payload: {0}")]
    InvalidTcpPayload(&'static str),
}
