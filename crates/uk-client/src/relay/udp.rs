use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
    sync::{mpsc, watch},
    task::JoinSet,
    time,
};
use tracing::{debug, warn};
use uk_proto::{
    FIRST_CLIENT_FLOW_ID, Frame, FrameType, Target, UDP_CLOSE_ERROR, UDP_CLOSE_NORMAL, UdpClose,
    is_client_initiated_flow_id,
};

use super::carrier::validate_flow_status;
use super::context::{
    AnyError, BufferedFlowFrame, ClientFlow, ClientFlowRoute, ClientSessionBufferControl,
    FlowProtocol, OpenOutcome, UDP_ASSOCIATION_BUFFER_SIZE, UDP_SEND_ATTEMPTS,
};
use super::session_manager::{ClientSession, ClientSessionManager};
use crate::{
    observability::{ClientMetrics, RelayDirection, RelayProtocol},
    socks5,
};

/// Per-target outbound queue depth.
///
/// One worker per target owns the flow to that target, so a datagram to a
/// healthy target is never queued behind a target whose open or carrier
/// write is stalled. The queue is bounded: UDP is best-effort, and overflow
/// drops (counted by `uncrowned_king_client_udp_association_queue_full_total`)
/// rather than growing memory.
pub(crate) const UDP_TARGET_QUEUE_CAPACITY: usize = 8;

/// Upper bound on how long association teardown waits for workers to close
/// their flows cleanly before aborting stragglers. Worker waits are already
/// internally bounded (open timeout, carrier write timeout); this is the
/// belt-and-braces bound for the control-EOF path, which has no outer
/// shutdown budget.
const UDP_WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct UdpAssociation {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) client_endpoint: UdpClientEndpoint,
    /// Feed side of each target's bounded outbound queue.
    pub(crate) senders: HashMap<Target, mpsc::Sender<Bytes>>,
    /// One worker per seen target; each worker owns that target's UK flow and
    /// its inbound relay task.
    workers: JoinSet<()>,
    /// Fires when the association ends (listener shutdown or SOCKS control
    /// disconnect): cancels in-flight opens and stops every worker.
    closed_tx: watch::Sender<bool>,
    pub(crate) metrics: Arc<ClientMetrics>,
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
    /// Shared with the inbound relay task so datagrams from the server keep
    /// the flow's idle deadline fresh without a cross-task event channel.
    pub(crate) activity: Arc<StdMutex<time::Instant>>,
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

#[allow(clippy::too_many_lines)]
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

    let metrics = Arc::clone(&sessions.metrics);
    let mut association = UdpAssociation::new(
        socket,
        sessions.udp_flow_idle_timeout(),
        client_endpoint,
        control_peer_ip,
        metrics,
    );
    let mut udp_buf = vec![0_u8; UDP_ASSOCIATION_BUFFER_SIZE].into_boxed_slice();
    let mut tcp_buf = [0_u8; 1];
    let mut termination_error = None;

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                break;
            }
            read = local.read(&mut tcp_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(_) => {
                        debug!(event = "socks5.udp_associate.control_data_ignored");
                    }
                    Err(err) => {
                        debug!(event = "socks5.udp_associate.control_read_error", error = %err);
                        termination_error = Some(err.into());
                        break;
                    }
                }
            }
            received = association.socket.recv_from(udp_buf.as_mut()) => {
                match received {
                    Ok((read, peer)) => {
                        // Never awaits worker progress: the per-target queues
                        // accept or drop, so one slow target cannot stall the
                        // association's receive loop.
                        match association
                            .handle_local_udp_datagram(peer, &udp_buf[..read], &sessions)
                            .await
                        {
                            Ok(()) => {}
                            Err(err) => {
                                termination_error = Some(err);
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        debug!(event = "socks5.udp.recv_error", error = %err);
                    }
                }
            }
            joined = association.workers.join_next(), if !association.workers.is_empty() => {
                let _ = joined;
            }
        }
    }

    association.close().await;
    if let Some(err) = termination_error {
        Err(err)
    } else {
        Ok(())
    }
}

impl UdpAssociation {
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        idle_timeout: Option<Duration>,
        client_endpoint: socks5::SocksEndpoint,
        control_peer_ip: IpAddr,
        metrics: Arc<ClientMetrics>,
    ) -> Self {
        let (closed_tx, _) = watch::channel(false);
        Self {
            socket,
            idle_timeout,
            client_endpoint: UdpClientEndpoint::new(client_endpoint, control_peer_ip),
            senders: HashMap::new(),
            workers: JoinSet::new(),
            closed_tx,
            metrics,
        }
    }

    /// Validates, screens and enqueues one datagram from the SOCKS client.
    ///
    /// Every await here is bounded and never touches a target's flow: the
    /// only suspension point is the (pool-only, non-dialling) live-session
    /// lookup used for the size screen, so datagram handling cannot be held
    /// up by a slow open or carrier write elsewhere.
    pub(crate) async fn handle_local_udp_datagram(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        sessions: &Arc<ClientSessionManager>,
    ) -> Result<(), AnyError> {
        if !self.accept_client_endpoint(peer) {
            debug!(event = "socks5.udp_associate.peer_ignored", peer = %peer);
            return Ok(());
        }

        let datagram = match socks5::decode_udp_datagram(packet) {
            Ok(datagram) => datagram,
            Err(err) => {
                debug!(event = "socks5.udp.datagram.invalid", error = %err);
                return Ok(());
            }
        };

        // Size screen against any live session (pool-only lookup, no dial).
        // With no live carrier the screen is skipped rather than the datagram
        // dropped: the worker re-dials on demand and re-checks the size
        // precisely against the session it actually opens, which is also what
        // recovers an association whose carrier died.
        if let Some(session) = sessions.first_live_session().await {
            let max_payload_len = session.max_udp_payload_len_for(FIRST_CLIENT_FLOW_ID);
            if udp_payload_exceeds_frame_limit(datagram.payload.len(), max_payload_len) {
                warn_oversized_udp_datagram(
                    &datagram.target,
                    datagram.payload.len(),
                    max_payload_len,
                );
                return Ok(());
            }
        }

        self.enqueue_datagram(&datagram.target, datagram.payload, sessions);
        Ok(())
    }

    /// Hands the datagram to its target's worker, spawning the worker (and
    /// its bounded queue) on first sight of the target.
    pub(crate) fn enqueue_datagram(
        &mut self,
        target: &Target,
        payload: Bytes,
        sessions: &Arc<ClientSessionManager>,
    ) {
        if !self.senders.contains_key(target) {
            if let Some(sender) = self.spawn_target_worker(target, sessions) {
                self.senders.insert(target.clone(), sender);
            }
        }
        if let Some(sender) = self.senders.get(target) {
            let _ = try_enqueue_datagram(sender, target, payload, &self.metrics);
        }
        // No worker could be spawned (no learned client endpoint yet): drop.
    }

    fn spawn_target_worker(
        &mut self,
        target: &Target,
        sessions: &Arc<ClientSessionManager>,
    ) -> Option<mpsc::Sender<Bytes>> {
        // The learned endpoint is fixed by the first accepted datagram, which
        // is what spawned this worker, so it is always known here in practice.
        let client_endpoint = self.client_endpoint.learned()?;
        let (tx, rx) = mpsc::channel(UDP_TARGET_QUEUE_CAPACITY);
        self.workers.spawn(udp_target_worker(
            target.clone(),
            rx,
            Arc::clone(sessions),
            Arc::clone(&self.socket),
            client_endpoint,
            self.idle_timeout,
            self.closed_tx.subscribe(),
        ));
        Some(tx)
    }

    pub(crate) fn accept_client_endpoint(&mut self, peer: SocketAddr) -> bool {
        self.client_endpoint.accepts(peer)
    }

    /// Stops every worker, letting each close its own flow, and drops the
    /// queue feeds. Bounded: stragglers are aborted rather than awaited
    /// forever, and the listener's drain budget still applies above this.
    pub(crate) async fn close(&mut self) {
        let _ = self.closed_tx.send(true);
        self.senders.clear();
        let drained = time::timeout(UDP_WORKER_JOIN_TIMEOUT, async {
            while self.workers.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            self.workers.abort_all();
            while self.workers.join_next().await.is_some() {}
        }
    }
}

/// Enqueues one datagram into a target's bounded queue, counting a drop when
/// the queue is full.
///
/// Returns whether the datagram was accepted.
pub(crate) fn try_enqueue_datagram(
    sender: &mpsc::Sender<Bytes>,
    target: &Target,
    payload: Bytes,
    metrics: &ClientMetrics,
) -> bool {
    if sender.try_send(payload).is_ok() {
        return true;
    }
    metrics.record_udp_association_queue_full();
    warn!(event = "socks5.udp_associate.queue_full", target = %target.log_safe());
    false
}

/// What happened to a datagram inside a target worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpWorkerSend {
    Sent,
    Dropped,
    Cancelled,
}

/// Owns one target's UK flow: opens it on demand, sends every queued
/// datagram, keeps the inbound relay task, and closes the flow on idle,
/// inbound termination or association shutdown.
#[allow(clippy::too_many_lines)]
async fn udp_target_worker(
    target: Target,
    mut queue: mpsc::Receiver<Bytes>,
    sessions: Arc<ClientSessionManager>,
    socket: Arc<UdpSocket>,
    client_endpoint: SocketAddr,
    idle_timeout: Option<Duration>,
    mut cancel: watch::Receiver<bool>,
) {
    let mut current: Option<UdpAssociationFlow> = None;
    let mut inbound = JoinSet::new();
    let mut idle_interval = udp_idle_interval(idle_timeout);
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                let _ = changed;
                break;
            }
            payload = queue.recv() => {
                let Some(payload) = payload else {
                    // Association dropped the feed: nothing can arrive again.
                    break;
                };
                let mut worker = UdpTargetWorker {
                    target: &target,
                    current: &mut current,
                    inbound: &mut inbound,
                    sessions: &sessions,
                    socket: &socket,
                    client_endpoint,
                    cancel: &mut cancel,
                };
                match send_datagram_with_attempts(&mut worker, payload).await {
                    UdpWorkerSend::Cancelled => break,
                    UdpWorkerSend::Sent | UdpWorkerSend::Dropped => {}
                }
            }
            () = tick_udp_idle_interval(&mut idle_interval), if idle_interval.is_some() => {
                let Some(timeout) = idle_timeout else {
                    continue;
                };
                // With no flow there is nothing to keep alive; exiting frees
                // the task, and the association respawns it on demand.
                let Some(flow) = current.as_ref() else {
                    break;
                };
                if flow.idle_for() >= timeout {
                    debug!(
                        event = "client.udp_flow.idle_timeout",
                        flow_id = flow.id,
                        target = %target.log_safe()
                    );
                    break;
                }
            }
            joined = inbound.join_next(), if !inbound.is_empty() => {
                // Mirror the close only for the flow whose inbound relay
                // *actually* ended. The JoinSet can still hold the previous
                // flow's finished relay task — for example one ended by the
                // old carrier's death — and closing `current` for it would
                // tear down a healthy flow on the new carrier right after
                // its first datagram, silently dropping the reply that is
                // already in flight. The worker itself stays alive for the
                // next datagram to this target either way.
                match joined {
                    Some(Ok(ended)) => {
                        let matches_current = current.as_ref().is_some_and(|flow| {
                            flow.id == ended.flow_id
                                && flow.session.correlation_id == ended.session_correlation
                        });
                        if matches_current {
                            close_worker_flow(&mut current).await;
                        } else {
                            debug!(
                                event = "client.udp_flow.inbound.stale_relay_reaped",
                                flow_id = ended.flow_id,
                                session_correlation = ended.session_correlation,
                                target = %target.log_safe()
                            );
                        }
                    }
                    Some(Err(err)) => {
                        warn!(
                            event = "client.udp_flow.inbound.join_error",
                            target = %target.log_safe(),
                            error = %err
                        );
                    }
                    None => {}
                }
            }
        }
    }
    close_worker_flow(&mut current).await;
    inbound.abort_all();
    while inbound.join_next().await.is_some() {}
}

/// Everything a target worker needs besides the datagram at hand; bundling
/// these keeps the send/open helpers under clippy's argument budget.
struct UdpTargetWorker<'a> {
    target: &'a Target,
    current: &'a mut Option<UdpAssociationFlow>,
    inbound: &'a mut JoinSet<EndedUdpRelay>,
    sessions: &'a Arc<ClientSessionManager>,
    socket: &'a Arc<UdpSocket>,
    client_endpoint: SocketAddr,
    cancel: &'a mut watch::Receiver<bool>,
}

#[allow(clippy::too_many_lines)]
async fn send_datagram_with_attempts(
    worker: &mut UdpTargetWorker<'_>,
    payload: Bytes,
) -> UdpWorkerSend {
    let mut last_error = None;
    for attempt in 0..UDP_SEND_ATTEMPTS {
        if *worker.cancel.borrow() {
            return UdpWorkerSend::Cancelled;
        }
        let Some(flow) = ensure_worker_flow(worker, &payload).await else {
            if *worker.cancel.borrow() {
                return UdpWorkerSend::Cancelled;
            }
            // Rejected, no capacity, or oversized: drop this datagram rather
            // than failing the whole association (one unreachable target must
            // not take out an application's entire UDP relay).
            return UdpWorkerSend::Dropped;
        };
        match flow.session.send_udp_data(flow.id, payload.clone()).await {
            Ok(()) => {
                flow.record_activity();
                return UdpWorkerSend::Sent;
            }
            Err(err) => {
                warn!(
                    event = "client.udp_flow.send.error",
                    flow_id = flow.id,
                    target = %worker.target.log_safe(),
                    attempt,
                    error = %err
                );
                // The flow is dead; the inbound relay task notices its route
                // disappearing and ends by itself.
                flow.session.remove_flow(flow.id).await;
                *worker.current = None;
                last_error = Some(err);
            }
        }
    }

    warn!(
        event = "socks5.udp_associate.datagram_dropped",
        target = %worker.target.log_safe(),
        attempts = UDP_SEND_ATTEMPTS,
        error = %last_error
            .map_or_else(|| "no send attempt succeeded".to_owned(), |err| err.to_string())
    );
    UdpWorkerSend::Dropped
}

/// Returns the target's live flow, opening one on demand.
///
/// Opening goes through [`ClientSessionManager::open_udp_flow`], whose
/// admission path prefers an already-pooled live session and only dials under
/// the connect lock after rechecking the pool — so a datagram racing the
/// health-maintainer's re-dial reuses that session instead of piling a second
/// carrier onto the server.
///
/// The precise payload size is checked against the flow's own session right
/// after the open, closing the flow immediately on an oversized datagram so
/// no `max_udp_flows` slot is stranded for the idle timeout.
#[allow(clippy::too_many_lines)]
async fn ensure_worker_flow(
    worker: &mut UdpTargetWorker<'_>,
    payload: &Bytes,
) -> Option<UdpAssociationFlow> {
    let target = worker.target;
    if let Some(flow) = worker.current {
        flow.record_activity();
        return Some(flow.clone());
    }

    let flow = match worker
        .sessions
        .open_udp_flow(target.clone(), worker.cancel)
        .await
    {
        Ok(OpenOutcome::Open(flow)) => flow,
        Ok(OpenOutcome::Rejected(reply)) => {
            debug!(
                event = "client.udp_flow.open.rejected",
                target = %target.log_safe(),
                reply = ?reply
            );
            return None;
        }
        Ok(OpenOutcome::Cancelled) => return None,
        Err(err) => {
            warn!(
                event = "client.udp_flow.open.error",
                target = %target.log_safe(),
                error = %err
            );
            return None;
        }
    };

    // Precise size screen against the session that actually carries the flow.
    // The association's receive loop already screens opportunistically, so
    // reaching here oversized means no session existed at enqueue time.
    let max_payload_len = flow.session.max_udp_payload_len_for(flow.id);
    if udp_payload_exceeds_frame_limit(payload.len(), max_payload_len) {
        warn_oversized_udp_datagram(target, payload.len(), max_payload_len);
        let _ = flow.session.send_udp_close(flow.id, UDP_CLOSE_ERROR).await;
        flow.session.remove_flow(flow.id).await;
        return None;
    }

    let activity = Arc::new(StdMutex::new(time::Instant::now()));
    let association_flow = UdpAssociationFlow {
        id: flow.id,
        session: Arc::clone(&flow.session),
        activity: Arc::clone(&activity),
    };
    // The relay task reports which flow it belonged to when it ends, so the
    // worker can mirror a close onto the matching flow instead of onto
    // whichever flow happens to be current when it gets around to joining
    // (see the `inbound.join_next` branch in `udp_target_worker`).
    let relay_session_correlation = flow.session.correlation_id;
    let relay_flow_id = flow.id;
    let relay_socket = Arc::clone(worker.socket);
    let relay_cancel = worker.cancel.clone();
    let relay_client_endpoint = worker.client_endpoint;
    let relay_target = target.clone();
    worker.inbound.spawn(async move {
        relay_udp_flow_to_client(
            flow,
            relay_target,
            relay_socket,
            relay_client_endpoint,
            relay_cancel,
            Arc::clone(&activity),
        )
        .await;
        EndedUdpRelay {
            session_correlation: relay_session_correlation,
            flow_id: relay_flow_id,
        }
    });
    *worker.current = Some(association_flow.clone());
    Some(association_flow)
}

/// Identity of an inbound relay task that has finished, letting the worker
/// tell a stale task (one that belonged to a flow it already replaced) apart
/// from the end of the flow it currently owns.
#[derive(Debug)]
struct EndedUdpRelay {
    session_correlation: u64,
    flow_id: u64,
}

/// Closes the worker's flow (if any) and leaves the inbound relay to end on
/// its own: removing the route drops its frame channel.
async fn close_worker_flow(current: &mut Option<UdpAssociationFlow>) {
    let Some(flow) = current.take() else {
        return;
    };
    let _ = flow.session.send_udp_close(flow.id, UDP_CLOSE_NORMAL).await;
    flow.session.remove_flow(flow.id).await;
}

#[cfg(test)]
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
    pub(crate) fn record_activity(&self) {
        record_udp_activity(&self.activity);
    }

    /// How long since either direction last moved on this flow.
    pub(crate) fn idle_for(&self) -> Duration {
        let last = match self.activity.lock() {
            Ok(last) => *last,
            Err(poisoned) => *poisoned.into_inner(),
        };
        time::Instant::now().saturating_duration_since(last)
    }
}

fn record_udp_activity(activity: &StdMutex<time::Instant>) {
    let mut last = match activity.lock() {
        Ok(last) => last,
        Err(poisoned) => poisoned.into_inner(),
    };
    *last = time::Instant::now();
}

/// Relays one flow's server-to-client datagrams back to the SOCKS client.
///
/// Pure relay: the owning worker is the sole closer of the flow, so this task
/// has no teardown side effects of its own.
pub(crate) async fn relay_udp_flow_to_client(
    flow: ClientFlow,
    target: Target,
    socket: Arc<UdpSocket>,
    client_endpoint: SocketAddr,
    mut cancel: watch::Receiver<bool>,
    activity: Arc<StdMutex<time::Instant>>,
) {
    let _ = relay_udp_flow_to_client_inner(
        flow,
        target,
        socket,
        client_endpoint,
        &mut cancel,
        &activity,
    )
    .await;
}

pub(crate) async fn relay_udp_flow_to_client_inner(
    mut flow: ClientFlow,
    target: Target,
    socket: Arc<UdpSocket>,
    client_endpoint: SocketAddr,
    cancel: &mut watch::Receiver<bool>,
    activity: &StdMutex<time::Instant>,
) -> Result<(), AnyError> {
    loop {
        tokio::select! {
            changed = cancel.changed() => {
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
                        record_udp_activity(activity);
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
