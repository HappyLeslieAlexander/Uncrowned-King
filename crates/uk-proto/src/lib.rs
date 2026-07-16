//! Core Uncrowned King wire encoding.

/// TLS/QUIC ALPN protocol identifier for Uncrowned King v0.1.
pub const ALPN_PROTOCOL: &[u8] = b"uk/1";

pub mod carrier;
pub mod endpoint;
pub mod error;
pub mod flow;
pub mod frame;
pub mod io;
pub mod settings;
pub mod status;
pub mod target;
pub mod tcp;
pub mod udp;
pub mod varint;

pub use carrier::{BoxedCarrierReader, BoxedCarrierWriter};
pub use endpoint::{EndpointError, validate_host_port_endpoint};
pub use error::{ProtocolError, ProtocolResult};
pub use flow::{
    FIRST_CLIENT_FLOW_ID, FLOW_ID_STEP, is_client_initiated_flow_id, is_server_initiated_flow_id,
};
pub use frame::{
    Frame, FrameHeader, FrameLimits, FrameType, MAX_FRAME_PAYLOAD_SIZE, validate_connection_frame,
};
pub use io::{FrameIoError, FrameIoResult, read_frame, write_frame};
pub use settings::{
    DEFAULT_MAX_STREAMS, NegotiatedSettings, PROTOCOL_REVISION_V0_1, SettingKey, Settings,
};
pub use status::{ErrorCode, ErrorPayload};
pub use target::Target;
pub use tcp::{
    MIN_TCP_RELAY_FRAME_SIZE, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, TcpClose,
    TcpOpen,
};
pub use udp::{MIN_UDP_RELAY_FRAME_SIZE, UDP_CLOSE_ERROR, UDP_CLOSE_NORMAL, UdpClose, UdpOpen};
