//! Carrier-neutral channel types shared by client and server relays.
//!
//! A UK session runs over a carrier that provides a reliable, ordered,
//! bidirectional control/frame channel. The relay layers work against boxed
//! trait objects so the same code drives every carrier (TLS/TCP, QUIC, and
//! future HTTP/2 or WebSocket carriers) without monomorphizing over each
//! concrete stream type. Dynamic dispatch here is negligible next to the
//! per-frame transport encryption and socket syscalls.

use tokio::io::{AsyncRead, AsyncWrite};

/// Owned read half of a carrier's reliable control/frame channel.
pub type BoxedCarrierReader = Box<dyn AsyncRead + Send + Unpin>;

/// Owned write half of a carrier's reliable control/frame channel.
pub type BoxedCarrierWriter = Box<dyn AsyncWrite + Send + Unpin>;
