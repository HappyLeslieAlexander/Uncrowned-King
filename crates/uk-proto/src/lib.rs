//! Core UncrownedKing wire encoding.

pub mod error;
pub mod frame;
pub mod settings;
pub mod target;
pub mod varint;

pub use error::{ProtocolError, ProtocolResult};
pub use frame::{Frame, FrameHeader, FrameLimits, FrameType};
pub use settings::{SettingKey, Settings};
pub use target::Target;
