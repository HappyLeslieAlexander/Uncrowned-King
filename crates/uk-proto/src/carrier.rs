//! Carrier-neutral channel types shared by client and server relays.
//!
//! A UK session runs over a carrier that provides a reliable, ordered,
//! bidirectional control/frame channel. The relay layers work against boxed
//! trait objects so the same code drives every carrier (TLS/TCP, QUIC, and
//! future HTTP/2 or WebSocket carriers) without monomorphizing over each
//! concrete stream type. Dynamic dispatch here is negligible next to the
//! per-frame transport encryption and socket syscalls.

use std::{future::Future, io, pin::Pin, sync::Arc};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

/// Owned read half of a carrier's reliable control/frame channel.
pub type BoxedCarrierReader = Box<dyn AsyncRead + Send + Unpin>;

/// Owned write half of a carrier's reliable control/frame channel.
pub type BoxedCarrierWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// A carrier's optional unreliable datagram channel, used for UDP relay over
/// QUIC DATAGRAM. Shared across the relay session's send and receive tasks.
pub type BoxedDatagramChannel = Arc<dyn DatagramChannel>;

/// Outcome of attempting to send one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramSendOutcome {
    /// The datagram was queued for transmission.
    Sent,
    /// The datagram (flow-id prefix plus payload) exceeds the peer's maximum
    /// datagram size. The caller must fall back to the reliable `UDP_DATA`
    /// frame path for this payload.
    TooLarge,
    /// Datagrams are unavailable on this connection (the peer did not enable
    /// the QUIC datagram extension, or the connection is closing). The caller
    /// must fall back to the reliable path and should stop attempting
    /// datagrams for the session.
    Unavailable,
}

/// An unreliable, unordered datagram channel over a carrier.
///
/// Only QUIC provides this today. The relay uses it for the UDP data plane
/// when both peers advertise `supports_udp_datagram`; the reliable control
/// channel still carries `UDP_OPEN`/`UDP_CLOSE` and flow-id negotiation.
pub trait DatagramChannel: Send + Sync {
    /// Sends one already-encoded datagram (flow-id prefix plus payload).
    fn send(&self, datagram: Bytes) -> DatagramSendOutcome;

    /// Receives the next inbound datagram. Resolves to an error when the
    /// datagram channel is permanently closed.
    fn recv(&self) -> Pin<Box<dyn Future<Output = io::Result<Bytes>> + Send + '_>>;

    /// The maximum datagram size the peer will currently accept, if datagrams
    /// are enabled. `None` means datagrams are unavailable.
    fn max_datagram_size(&self) -> Option<usize>;
}
