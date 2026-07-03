//! Core UncrownedKing wire encoding.

pub mod error;
pub mod frame;
pub mod io;
pub mod settings;
pub mod status;
pub mod target;
pub mod tcp;
pub mod varint;

pub use error::{ProtocolError, ProtocolResult};
pub use frame::{Frame, FrameHeader, FrameLimits, FrameType};
pub use io::{FrameIoError, FrameIoResult, read_frame, write_frame};
pub use settings::{SettingKey, Settings};
pub use status::{ErrorCode, ErrorPayload};
pub use target::Target;
pub use tcp::{TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, TcpClose, TcpOpen};
