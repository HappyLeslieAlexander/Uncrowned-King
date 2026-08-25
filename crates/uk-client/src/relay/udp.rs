#![allow(unused_imports, clippy::wildcard_imports)]

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{Id, JoinError, JoinSet},
    time,
};
use tracing::{Instrument, debug, error, info, info_span, warn};
use uk_auth::{AuthenticatedIdentity, unix_now};
use uk_proto::{
    BoxedCarrierReader, BoxedCarrierWriter, BoxedDatagramChannel, DatagramSendOutcome, ErrorCode,
    ErrorPayload, FIRST_CLIENT_FLOW_ID, FLOW_ID_STEP, Frame, FrameIoError, FrameLimits, FrameType,
    NegotiatedSettings, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target, TcpClose,
    TcpOpen, UDP_CLOSE_ERROR, UDP_CLOSE_NORMAL, UdpClose, UdpOpen, datagram,
    is_client_initiated_flow_id, read_frame, validate_connection_frame, varint::MAX_VARINT,
    write_frame,
};

use super::carrier::*;
use super::context::*;
use super::listener::*;
use super::session_manager::*;
use super::tcp::*;
use crate::{
    ClientReloadReceiver, ClientReloadRequest,
    config::{ClientConfig, validate_endpoint},
    config_state::{ClientConfigSnapshot, ClientConfigState},
    observability::{ActiveFlowGuard, ClientMetrics, RelayDirection, RelayProtocol},
    session, socks5,
};
pub(crate) struct UdpAssociation {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) flow_event_tx: mpsc::Sender<UdpAssociationFlowEvent>,
    pub(crate) client_endpoint: UdpClientEndpoint,
    pub(crate) flows_by_target: HashMap<Target, UdpAssociationFlow>,
    pub(crate) flow_tasks: JoinSet<UdpFlowTaskResult>,
}

#[derive(Debug, Clone)]
pub(crate) struct UdpClientEndpoint {
    pub(crate) requested: socks5::SocksEndpoint,
    /// Source IP of the SOCKS control connection that created this association.
    ///
    /// RFC 1928 lets a client that does not yet know the source address it will
    /// send UDP from advertise all zeros, and virtually every client does. The
    /// association socket is bound to the SOCKS listener's IP rather than
    /// loopback, so without this the first datagram from *any* host that can
    /// reach the bound port would be "learned" as the client and would then
    /// relay UDP under the real client's credentials.
    pub(crate) control_peer_ip: IpAddr,
    pub(crate) learned: Option<SocketAddr>,
}

#[derive(Clone)]
pub(crate) struct UdpAssociationFlow {
    pub(crate) id: u64,
    pub(crate) session: Arc<ClientSession>,
    pub(crate) last_activity: time::Instant,
}

pub(crate) struct UdpFlowTaskResult {
    pub(crate) flow_id: u64,
    pub(crate) target: Target,
    pub(crate) outcome: Result<(), AnyError>,
}

pub(crate) async fn deliver_inbound_udp_datagram(
    session: &ClientSession,
    flow_id: u64,
    payload: Bytes,
) {
    let mut flows = session.flows.lock().await;
    if !route_inbound_datagram(
        flow_id,
        payload,
        &mut flows,
        session.session_buffer.clone(),
        session.max_buffered_bytes_per_flow,
        session.max_buffered_bytes_per_session,
    ) {
        debug!(event = "client.datagram.dropped", flow_id);
    }
}

/// Routes an inbound UDP datagram to its flow queue without ever mutating the
/// flow table. Returns `true` when the payload was enqueued.
pub(crate) fn route_inbound_datagram(
    flow_id: u64,
    payload: Bytes,
    flows: &mut HashMap<u64, ClientFlowRoute>,
    session_buffer: ClientSessionBufferControl,
    flow_byte_limit: usize,
    session_byte_limit: usize,
) -> bool {
    if !is_client_initiated_flow_id(flow_id) {
        return false;
    }
    let Some(route) = flows.get(&flow_id) else {
        return false;
    };
    if !matches!(route.protocol, FlowProtocol::Udp) {
        return false;
    }
    let Ok(frame) = Frame::new(FrameType::UdpData, 0, flow_id, payload) else {
        return false;
    };
    let Ok(buffered_frame) = BufferedFlowFrame::new(
        frame,
        route.flow_buffer.clone(),
        session_buffer,
        flow_byte_limit,
        session_byte_limit,
    ) else {
        return false;
    };
    route.sender.try_send(buffered_frame).is_ok()
}

pub(crate) async fn relay_udp_association(
    mut local: TcpStream,
    sessions: Arc<ClientSessionManager>,
    client_endpoint: socks5::SocksEndpoint,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    if *shutdown_rx.borrow() {
        return Ok(());
    }

    let supports_udp_relay = tokio::select! {
        result = sessions.supports_udp_relay() => result,
        changed = shutdown_rx.changed() => {
            let _ = changed;
            return Ok(());
        }
    };
    match supports_udp_relay {
        Ok(true) => {}
        Ok(false) => {
            // The server does not offer UDP relay at all, which is exactly what
            // `CommandNotSupported` (0x07) means; 0x01 would invite the client
            // to retry the same unsupported command.
            socks5::send_reply(&mut local, socks5::Reply::CommandNotSupported).await?;
            return Ok(());
        }
        Err(err) => {
            let _ = socks5::send_reply(&mut local, socks5::Reply::GeneralFailure).await;
            return Err(err);
        }
    }

    // The association is only ever usable by the host that opened this control
    // connection, so pin the accepted datagram source to its IP.
    let control_peer_ip = local.peer_addr()?.ip();
    let bind_addr = udp_association_bind_addr(local.local_addr()?);
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let bound_endpoint = socks5::SocksEndpoint::from(socket.local_addr()?);
    socks5::send_reply_with_endpoint(&mut local, socks5::Reply::Succeeded, &bound_endpoint).await?;

    let (flow_event_tx, mut flow_event_rx) = mpsc::channel(UDP_ASSOCIATION_EVENT_QUEUE_CAPACITY);
    let mut association = UdpAssociation::new(
        socket,
        sessions.udp_flow_idle_timeout(),
        flow_event_tx,
        client_endpoint,
        control_peer_ip,
    );
    let mut idle_interval = udp_idle_interval(association.idle_timeout);
    let mut udp_buf = vec![0_u8; UDP_ASSOCIATION_BUFFER_SIZE].into_boxed_slice();
    let mut tcp_buf = [0_u8; 1];

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                break;
            }
            read = local.read(&mut tcp_buf) => {
                if read? == 0 {
                    break;
                }
                debug!(event = "socks5.udp_associate.control_data_ignored");
            }
            received = association.socket.recv_from(udp_buf.as_mut()) => {
                let (read, peer) = received?;
                if !association
                    .handle_local_udp_datagram(
                        peer,
                        &udp_buf[..read],
                        &mut local,
                        &mut tcp_buf,
                        &sessions,
                        &mut shutdown_rx,
                    )
                    .await?
                {
                    break;
                }
            }
            joined = association.flow_tasks.join_next(), if !association.flow_tasks.is_empty() => {
                association.handle_flow_task_result(joined);
            }
            event = flow_event_rx.recv() => {
                association.handle_flow_event(event);
            }
            () = tick_udp_idle_interval(&mut idle_interval), if idle_interval.is_some() => {
                association.close_idle_flows().await;
            }
        }
    }

    association.close().await;
    Ok(())
}

impl UdpAssociation {
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        idle_timeout: Option<Duration>,
        flow_event_tx: mpsc::Sender<UdpAssociationFlowEvent>,
        client_endpoint: socks5::SocksEndpoint,
        control_peer_ip: IpAddr,
    ) -> Self {
        Self {
            socket,
            idle_timeout,
            flow_event_tx,
            client_endpoint: UdpClientEndpoint::new(client_endpoint, control_peer_ip),
            flows_by_target: HashMap::new(),
            flow_tasks: JoinSet::new(),
        }
    }

    pub(crate) async fn handle_local_udp_datagram(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        local: &mut TcpStream,
        tcp_buf: &mut [u8; 1],
        sessions: &Arc<ClientSessionManager>,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<bool, AnyError> {
        if !self.accept_client_endpoint(peer) {
            debug!(event = "socks5.udp_associate.peer_ignored", peer = %peer);
            return Ok(true);
        }

        let datagram = match socks5::decode_udp_datagram(packet) {
            Ok(datagram) => datagram,
            Err(err) => {
                debug!(event = "socks5.udp.datagram.invalid", error = %err);
                return Ok(true);
            }
        };

        // Size the datagram *before* touching a flow: `flow_for_target` opens a
        // UK UDP flow on demand, so checking afterwards would leave an idle
        // flow holding a `max_udp_flows` slot for the whole idle timeout every
        // time a client's first datagram to a target is oversized.
        // Sizing a first datagram may have to wait for a session, so keep the
        // wait cancellable: shutdown must not be held up by a pending dial.
        let max_payload_len = tokio::select! {
            result = self.max_udp_payload_len(&datagram.target, sessions) => result?,
            changed = shutdown_rx.changed() => {
                let _ = changed;
                return Ok(false);
            }
        };
        if udp_payload_exceeds_frame_limit(datagram.payload.len(), max_payload_len) {
            warn_oversized_udp_datagram(&datagram.target, datagram.payload.len(), max_payload_len);
            return Ok(true);
        }

        let mut last_error = None;
        for attempt in 0..UDP_SEND_ATTEMPTS {
            let flow = match self
                .flow_for_target(
                    datagram.target.clone(),
                    local,
                    tcp_buf,
                    sessions,
                    shutdown_rx,
                )
                .await?
            {
                UdpAssociationFlowLookup::Open(flow) => flow,
                UdpAssociationFlowLookup::NoFlow => return Ok(true),
                UdpAssociationFlowLookup::Cancelled => return Ok(false),
            };
            match flow
                .session
                .send_udp_data(flow.id, datagram.payload.clone())
                .await
            {
                Ok(()) => return Ok(true),
                Err(err) => {
                    warn!(
                        event = "client.udp_flow.send.error",
                        flow_id = flow.id,
                        target = %datagram.target.log_safe(),
                        attempt,
                        error = %err
                    );
                    self.remove_flow_if_matches(&datagram.target, flow.id);
                    flow.session.remove_flow(flow.id).await;
                    last_error = Some(err);
                }
            }
        }

        // Drop this datagram rather than failing the association. Returning an
        // error here propagates out of `relay_udp_association` and tears down
        // the SOCKS control connection along with every other target's flow —
        // so one unreachable target would take out an application's entire UDP
        // relay. UDP is best-effort and the failed flow has already been
        // removed, so the next datagram to this target opens a fresh one. This
        // matches the reliable path, where a per-flow failure closes only that
        // flow.
        warn!(
            event = "socks5.udp_associate.datagram_dropped",
            target = %datagram.target.log_safe(),
            attempts = UDP_SEND_ATTEMPTS,
            error = %last_error
                .map_or_else(|| "no send attempt succeeded".to_owned(), |err| err.to_string())
        );
        Ok(true)
    }

    pub(crate) fn accept_client_endpoint(&mut self, peer: SocketAddr) -> bool {
        self.client_endpoint.accepts(peer)
    }

    /// Largest UDP payload this association can relay to `target`: the data
    /// frame size of the target's existing flow, or — for a target with no flow
    /// yet — of a session that could carry one. Queried without opening a flow
    /// so an oversized datagram cannot strand UDP flow capacity.
    pub(crate) async fn max_udp_payload_len(
        &self,
        target: &Target,
        sessions: &ClientSessionManager,
    ) -> Result<usize, AnyError> {
        if let Some(flow) = self.flows_by_target.get(target) {
            return Ok(flow.session.max_udp_payload_len_for(flow.id));
        }
        let session = sessions.current_session().await?;
        // No flow yet, so no flow id: size against the first id this session
        // would allocate, which bounds the varint overhead.
        Ok(session.max_udp_payload_len_for(FIRST_CLIENT_FLOW_ID))
    }

    pub(crate) async fn flow_for_target(
        &mut self,
        target: Target,
        local: &mut TcpStream,
        tcp_buf: &mut [u8; 1],
        sessions: &Arc<ClientSessionManager>,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<UdpAssociationFlowLookup, AnyError> {
        if let Some(flow) = self.flows_by_target.get_mut(&target) {
            flow.record_activity();
            return Ok(UdpAssociationFlowLookup::Open(flow.clone()));
        }

        let flow = match sessions
            .open_udp_flow(target.clone(), local, tcp_buf, shutdown_rx)
            .await?
        {
            OpenOutcome::Open(flow) => flow,
            OpenOutcome::Rejected(reply) => {
                debug!(
                    event = "client.udp_flow.open.rejected",
                    target = %target.log_safe(),
                    reply = ?reply
                );
                return Ok(UdpAssociationFlowLookup::NoFlow);
            }
            OpenOutcome::Cancelled => return Ok(UdpAssociationFlowLookup::Cancelled),
        };
        let association_flow = UdpAssociationFlow {
            id: flow.id,
            session: Arc::clone(&flow.session),
            last_activity: time::Instant::now(),
        };
        self.flows_by_target
            .insert(target.clone(), association_flow.clone());
        self.spawn_flow_task(flow, target, shutdown_rx.clone());
        Ok(UdpAssociationFlowLookup::Open(association_flow))
    }

    pub(crate) fn spawn_flow_task(
        &mut self,
        flow: ClientFlow,
        target: Target,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        let socket = Arc::clone(&self.socket);
        let flow_event_tx = self.flow_event_tx.clone();
        let Some(client_endpoint) = self.client_endpoint.learned() else {
            warn!(
                event = "client.udp_flow.missing_client_endpoint",
                flow_id = flow.id,
                target = %target.log_safe()
            );
            self.spawn_udp_flow_cleanup(flow, target);
            return;
        };
        self.flow_tasks.spawn(async move {
            relay_udp_flow_to_client(
                flow,
                target,
                socket,
                client_endpoint,
                shutdown_rx,
                flow_event_tx,
            )
            .await
        });
    }

    pub(crate) fn spawn_udp_flow_cleanup(&mut self, flow: ClientFlow, target: Target) {
        self.flow_tasks.spawn(async move {
            let flow_id = flow.id;
            let session = Arc::clone(&flow.session);
            let outcome = async {
                session.send_udp_close(flow_id, UDP_CLOSE_ERROR).await?;
                session.remove_flow(flow_id).await;
                Ok(())
            }
            .await;
            UdpFlowTaskResult {
                flow_id,
                target,
                outcome,
            }
        });
    }

    pub(crate) fn handle_flow_task_result(
        &mut self,
        joined: Option<Result<UdpFlowTaskResult, tokio::task::JoinError>>,
    ) {
        let Some(joined) = joined else {
            return;
        };
        match joined {
            Ok(result) => {
                self.remove_flow_if_matches(&result.target, result.flow_id);
                if let Err(err) = result.outcome {
                    warn!(
                        event = "client.udp_flow.task_error",
                        flow_id = result.flow_id,
                        target = %result.target.log_safe(),
                        error = %err
                    );
                }
            }
            Err(err) => {
                warn!(event = "client.udp_flow.join_error", error = %err);
            }
        }
    }

    pub(crate) fn remove_flow_if_matches(&mut self, target: &Target, flow_id: u64) -> bool {
        let current_flow_id = self.flows_by_target.get(target).map(|flow| flow.id);
        if udp_flow_id_matches(current_flow_id, flow_id) {
            self.flows_by_target.remove(target);
            true
        } else {
            false
        }
    }

    pub(crate) fn handle_flow_event(&mut self, event: Option<UdpAssociationFlowEvent>) {
        let Some(UdpAssociationFlowEvent::Activity { flow_id, target }) = event else {
            return;
        };
        let Some(flow) = self.flows_by_target.get_mut(&target) else {
            return;
        };
        if flow.id == flow_id {
            flow.record_activity();
        }
    }

    pub(crate) async fn close(&mut self) {
        for flow in self.flows_by_target.values().cloned().collect::<Vec<_>>() {
            let _ = flow.session.send_udp_close(flow.id, UDP_CLOSE_NORMAL).await;
            flow.session.remove_flow(flow.id).await;
        }
        self.flows_by_target.clear();
        self.flow_tasks.abort_all();
        while self.flow_tasks.join_next().await.is_some() {}
    }

    pub(crate) async fn close_idle_flows(&mut self) {
        let Some(idle_timeout) = self.idle_timeout else {
            return;
        };
        let now = time::Instant::now();
        let expired = self
            .flows_by_target
            .iter()
            .filter(|(_, flow)| now.duration_since(flow.last_activity) >= idle_timeout)
            .map(|(target, flow)| (target.clone(), flow.clone()))
            .collect::<Vec<_>>();

        for (target, flow) in expired {
            if self.flows_by_target.remove(&target).is_some() {
                debug!(
                    event = "client.udp_flow.idle_timeout",
                    flow_id = flow.id,
                    target = %target.log_safe()
                );
                let _ = flow.session.send_udp_close(flow.id, UDP_CLOSE_NORMAL).await;
                flow.session.remove_flow(flow.id).await;
            }
        }
    }
}

pub(crate) fn udp_flow_id_matches(current_flow_id: Option<u64>, candidate_flow_id: u64) -> bool {
    current_flow_id == Some(candidate_flow_id)
}

impl UdpClientEndpoint {
    pub(crate) fn new(requested: socks5::SocksEndpoint, control_peer_ip: IpAddr) -> Self {
        Self {
            requested,
            control_peer_ip,
            learned: None,
        }
    }

    pub(crate) fn accepts(&mut self, peer: SocketAddr) -> bool {
        if !self.matches_requested(peer) {
            return false;
        }

        if let Some(learned) = self.learned {
            learned == peer
        } else {
            self.learned = Some(peer);
            true
        }
    }

    pub(crate) fn learned(&self) -> Option<SocketAddr> {
        self.learned
    }

    /// Decides whether `peer` may be the client of this association.
    ///
    /// An explicitly advertised address is honoured as-is. An unspecified
    /// address — and the domain form, which names the client rather than a
    /// source the datagrams can be checked against — falls back to the control
    /// connection's peer IP so only the host that authenticated the association
    /// can use it. The port stays learnable either way, since a client that
    /// advertised `0` genuinely does not know it yet.
    pub(crate) fn matches_requested(&self, peer: SocketAddr) -> bool {
        match &self.requested {
            socks5::SocksEndpoint::Ipv4(addr, port) => {
                self.matches_source_ip(peer, Some(IpAddr::V4(*addr)))
                    && matches_requested_port(peer, *port)
            }
            socks5::SocksEndpoint::Ipv6(addr, port) => {
                self.matches_source_ip(peer, Some(IpAddr::V6(*addr)))
                    && matches_requested_port(peer, *port)
            }
            socks5::SocksEndpoint::Domain(_, port) => {
                self.matches_source_ip(peer, None) && matches_requested_port(peer, *port)
            }
        }
    }

    pub(crate) fn matches_source_ip(&self, peer: SocketAddr, requested_ip: Option<IpAddr>) -> bool {
        match requested_ip {
            Some(requested_ip) if !requested_ip.is_unspecified() => {
                ip_matches(peer.ip(), requested_ip)
            }
            _ => ip_matches(peer.ip(), self.control_peer_ip),
        }
    }
}

pub(crate) fn matches_requested_port(peer: SocketAddr, requested_port: u16) -> bool {
    requested_port == 0 || peer.port() == requested_port
}

/// Compares two IPs, treating an IPv4-mapped IPv6 address as its IPv4 form so a
/// dual-stack SOCKS listener (whose control peer reads as `::ffff:a.b.c.d`)
/// still matches the plain IPv4 source of the same client's datagrams.
pub(crate) fn ip_matches(left: IpAddr, right: IpAddr) -> bool {
    canonical_ip(left) == canonical_ip(right)
}

pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(addr) => addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4),
        IpAddr::V4(addr) => IpAddr::V4(addr),
    }
}

pub(crate) fn udp_payload_exceeds_frame_limit(payload_len: usize, max_payload_len: usize) -> bool {
    payload_len > max_payload_len
}

pub(crate) fn warn_oversized_udp_datagram(
    target: &Target,
    payload_len: usize,
    max_payload_len: usize,
) {
    warn!(
        event = "client.udp.datagram.too_large",
        target = %target.log_safe(),
        payload_len,
        max_payload_len
    );
}

impl UdpAssociationFlow {
    pub(crate) fn record_activity(&mut self) {
        self.last_activity = time::Instant::now();
    }
}

pub(crate) async fn relay_udp_flow_to_client(
    flow: ClientFlow,
    target: Target,
    socket: Arc<UdpSocket>,
    client_endpoint: SocketAddr,
    shutdown_rx: watch::Receiver<bool>,
    flow_event_tx: mpsc::Sender<UdpAssociationFlowEvent>,
) -> UdpFlowTaskResult {
    let flow_id = flow.id;
    let session = Arc::clone(&flow.session);
    let outcome = relay_udp_flow_to_client_inner(
        flow,
        target.clone(),
        socket,
        client_endpoint,
        shutdown_rx,
        flow_event_tx,
    )
    .await;
    session.remove_flow(flow_id).await;
    UdpFlowTaskResult {
        flow_id,
        target,
        outcome,
    }
}

pub(crate) async fn relay_udp_flow_to_client_inner(
    mut flow: ClientFlow,
    target: Target,
    socket: Arc<UdpSocket>,
    client_endpoint: SocketAddr,
    mut shutdown_rx: watch::Receiver<bool>,
    flow_event_tx: mpsc::Sender<UdpAssociationFlowEvent>,
) -> Result<(), AnyError> {
    let flow_id = flow.id;
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                return Ok(());
            }
            frame = flow.frames.recv() => {
                let Some(frame) = frame else {
                    return Ok(());
                };
                let frame = frame.into_frame()?;
                match frame.header.frame_type {
                    FrameType::UdpData => {
                        let payload_len = frame.payload.len();
                        let packet = socks5::encode_udp_datagram(&target, &frame.payload)?;
                        socket.send_to(&packet, client_endpoint).await?;
                        flow.session.metrics.record_relay_bytes(
                            RelayProtocol::Udp,
                            RelayDirection::ServerToLocal,
                            payload_len,
                        );
                        try_record_udp_association_activity(&flow_event_tx, flow_id, &target);
                    }
                    FrameType::UdpClose => {
                        let mut payload = frame.payload;
                        UdpClose::decode(&mut payload)?;
                        return Ok(());
                    }
                    FrameType::Error | FrameType::PolicyDenied | FrameType::ResourceLimit => {
                        validate_flow_status(frame.header.frame_type, frame.payload)?;
                        return Ok(());
                    }
                    _ => return Err("unexpected frame while relaying udp flow".into()),
                }
            }
        }
    }
}

pub(crate) fn udp_association_bind_addr(tcp_local_addr: SocketAddr) -> SocketAddr {
    match tcp_local_addr.ip() {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), 0),
        IpAddr::V6(ip) => SocketAddr::new(IpAddr::V6(ip), 0),
    }
}

pub(crate) fn try_record_udp_association_activity(
    flow_event_tx: &mpsc::Sender<UdpAssociationFlowEvent>,
    flow_id: u64,
    target: &Target,
) {
    let _ = flow_event_tx.try_send(UdpAssociationFlowEvent::Activity {
        flow_id,
        target: target.clone(),
    });
}

pub(crate) fn udp_idle_interval(idle_timeout: Option<Duration>) -> Option<time::Interval> {
    let idle_timeout = idle_timeout?;
    Some(time::interval(idle_timeout.min(Duration::from_secs(1))))
}

pub(crate) async fn tick_udp_idle_interval(interval: &mut Option<time::Interval>) {
    if let Some(interval) = interval {
        interval.tick().await;
    } else {
        std::future::pending::<()>().await;
    }
}
