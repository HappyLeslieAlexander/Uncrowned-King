#![allow(unused_imports, clippy::wildcard_imports)]

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        TcpStream, UdpSocket, lookup_host,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{AbortHandle, Id, JoinError, JoinSet},
    time,
};
use tracing::{Instrument, Span, debug, info, warn};
use uk_auth::{AuthenticatedIdentity, unix_now};
use uk_policy::{PolicyContext, PolicyDecision, PolicySet};
use uk_proto::{
    BoxedCarrierReader, BoxedCarrierWriter, BoxedDatagramChannel, DatagramSendOutcome, ErrorCode,
    ErrorPayload, Frame, FrameIoError, FrameLimits, FrameReader, FrameType, TCP_CLOSE_ERROR,
    TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target, TcpClose, TcpOpen, UDP_CLOSE_ERROR,
    UDP_CLOSE_NORMAL, UdpClose, UdpOpen, datagram, is_client_initiated_flow_id,
    validate_connection_frame, write_frame,
};

use super::context::*;
use super::dialer::*;
use super::session::*;
use super::tcp::*;
use super::udp::*;

use crate::observability::{
    ActiveFlowGuard, FlowOpenFailure, RelayDirection, RelayProtocol, ServerMetrics,
};
use crate::security::SecurityState;
pub(crate) struct ConnectTasks<T: 'static> {
    pub(crate) tasks: JoinSet<(SocketAddr, io::Result<T>)>,
    pub(crate) permits: HashMap<Id, OpenDialPermit>,
}

impl<T: 'static> Drop for ConnectTasks<T> {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

pub(crate) struct SessionTasks {
    pub(crate) tasks: JoinSet<SessionTaskKind>,
    pub(crate) kinds: HashMap<Id, SessionTaskKind>,
    pub(crate) cancelled: HashMap<Id, Arc<AtomicBool>>,
}

impl Drop for SessionTasks {
    fn drop(&mut self) {
        self.abort_all();
    }
}

impl Default for SessionTasks {
    fn default() -> Self {
        Self {
            tasks: JoinSet::new(),
            kinds: HashMap::new(),
            cancelled: HashMap::new(),
        }
    }
}

impl SessionTasks {
    pub(crate) fn spawn<F>(&mut self, kind: SessionTaskKind, task: F) -> SessionTaskHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.reap_completed();
        let span = Span::current();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_for_task = Arc::clone(&cancelled);
        let handle = self.tasks.spawn(
            async move {
                task.await;
                cancelled_for_task.store(true, Ordering::Release);
                kind
            }
            .instrument(span),
        );
        let task_handle = SessionTaskHandle::new(handle.clone(), Arc::clone(&cancelled));
        self.kinds.insert(handle.id(), kind);
        self.cancelled.insert(handle.id(), cancelled);
        task_handle
    }

    pub(crate) fn reap_completed(&mut self) {
        while let Some(result) = self.tasks.try_join_next_with_id() {
            match result {
                Ok((id, kind)) => {
                    self.kinds.remove(&id);
                    self.cancelled.remove(&id);
                    debug!(event = "server.session.task.done", kind = ?kind);
                }
                Err(err) => {
                    let kind = self.kinds.remove(&err.id());
                    self.cancelled.remove(&err.id());
                    log_session_task_error(kind, &err);
                }
            }
        }
    }

    pub(crate) fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    pub(crate) fn len(&mut self) -> usize {
        self.reap_completed();
        self.kinds
            .keys()
            .filter(|id| {
                self.cancelled
                    .get(id)
                    .is_some_and(|c| !c.load(Ordering::Acquire))
            })
            .count()
    }

    pub(crate) async fn join_next(&mut self) {
        let Some(result) = self.tasks.join_next_with_id().await else {
            return;
        };
        match result {
            Ok((id, kind)) => {
                self.kinds.remove(&id);
                self.cancelled.remove(&id);
                debug!(event = "server.session.task.done", kind = ?kind);
            }
            Err(err) => {
                let kind = self.kinds.remove(&err.id());
                self.cancelled.remove(&err.id());
                log_session_task_error(kind, &err);
            }
        }
    }

    pub(crate) async fn join_all(&mut self) {
        while !self.tasks.is_empty() {
            self.join_next().await;
        }
    }

    pub(crate) fn abort_all(&mut self) {
        for cancelled in self.cancelled.values() {
            cancelled.store(true, Ordering::Release);
        }
        self.tasks.abort_all();
    }
}

pub(crate) struct TargetOpenTask {
    pub(crate) flow_id: u64,
    pub(crate) target: Target,
    pub(crate) identity: AuthenticatedIdentity,
    pub(crate) policy_set: Arc<PolicySet>,
    pub(crate) open_dial_limiter: OpenDialLimiter,
    pub(crate) target_connect_timeout: Option<Duration>,
    pub(crate) event_tx: FlowEventSender,
    pub(crate) shutdown: SessionShutdown,
    pub(crate) cancel: OpenFlowCancel,
}

pub(crate) struct UdpOpenTask {
    pub(crate) flow_id: u64,
    pub(crate) target: Target,
    pub(crate) identity: AuthenticatedIdentity,
    pub(crate) policy_set: Arc<PolicySet>,
    pub(crate) open_dial_limiter: OpenDialLimiter,
    pub(crate) target_connect_timeout: Option<Duration>,
    pub(crate) event_tx: FlowEventSender,
    pub(crate) shutdown: SessionShutdown,
    pub(crate) cancel: OpenFlowCancel,
}

pub(crate) struct TargetReaderTask {
    pub(crate) identity: TargetFlowIdentity,
    pub(crate) target_reader: OwnedReadHalf,
    pub(crate) flow_control: TargetFlowControl,
    pub(crate) carrier_writer: CarrierWriter,
    pub(crate) event_tx: FlowEventSender,
    pub(crate) shutdown: SessionShutdown,
    pub(crate) data_frame_size: usize,
}

pub(crate) struct UdpReaderTask {
    pub(crate) flow_id: u64,
    pub(crate) token: FlowToken,
    pub(crate) target_socket: Arc<UdpSocket>,
    pub(crate) flow_control: TargetFlowControl,
    pub(crate) carrier_writer: CarrierWriter,
    pub(crate) datagrams: Option<BoxedDatagramChannel>,
    pub(crate) event_tx: FlowEventSender,
    pub(crate) shutdown: SessionShutdown,
    pub(crate) data_frame_size: usize,
}

pub(crate) struct TargetWriterTask {
    pub(crate) identity: TargetFlowIdentity,
    pub(crate) target_writer: OwnedWriteHalf,
    pub(crate) commands: mpsc::Receiver<TargetCommand>,
    pub(crate) flow_control: TargetFlowControl,
    pub(crate) carrier_writer: CarrierWriter,
    pub(crate) event_tx: FlowEventSender,
    pub(crate) shutdown: SessionShutdown,
    pub(crate) write_timeout: Option<Duration>,
}

pub(crate) fn spawn_target_open(session_tasks: &mut SessionTasks, task: TargetOpenTask) {
    session_tasks.spawn(SessionTaskKind::TcpOpen, async move {
        let result = wait_for_open_task(
            connect_allowed_target(
                &task.target,
                &task.identity,
                &task.policy_set,
                &task.open_dial_limiter,
                task.target_connect_timeout,
            ),
            &task.shutdown,
            &task.cancel,
        )
        .await;
        if let Some(result) = result {
            if task.cancel.is_cancelled() {
                return;
            }
            send_flow_event_or_shutdown(
                &task.event_tx,
                FlowEvent::OpenCompleted {
                    flow_id: task.flow_id,
                    token: task.cancel.token,
                    target: task.target,
                    result,
                },
                &task.shutdown,
            )
            .await;
        }
    });
}

pub(crate) fn spawn_udp_open(session_tasks: &mut SessionTasks, task: UdpOpenTask) {
    session_tasks.spawn(SessionTaskKind::UdpOpen, async move {
        let result = wait_for_open_task(
            connect_allowed_udp_target(
                &task.target,
                &task.identity,
                &task.policy_set,
                &task.open_dial_limiter,
                task.target_connect_timeout,
            ),
            &task.shutdown,
            &task.cancel,
        )
        .await;
        if let Some(result) = result {
            if task.cancel.is_cancelled() {
                return;
            }
            send_flow_event_or_shutdown(
                &task.event_tx,
                FlowEvent::UdpOpenCompleted {
                    flow_id: task.flow_id,
                    token: task.cancel.token,
                    target: task.target,
                    result,
                },
                &task.shutdown,
            )
            .await;
        }
    });
}

pub(crate) async fn wait_for_open_task<F, T>(
    future: F,
    shutdown: &SessionShutdown,
    cancel: &OpenFlowCancel,
) -> Option<T>
where
    F: Future<Output = T>,
{
    tokio::select! {
        result = future => Some(result),
        () = shutdown.closed() => None,
        () = cancel.cancelled() => None,
    }
}

pub(crate) fn spawn_target_reader(session_tasks: &mut SessionTasks, task: TargetReaderTask) {
    session_tasks.spawn(SessionTaskKind::TargetReader, async move {
        let flow_id = task.identity.flow_id;
        match relay_target_to_client(
            flow_id,
            task.target_reader,
            task.flow_control,
            &task.carrier_writer,
            &task.event_tx,
            &task.shutdown,
            task.data_frame_size,
        )
        .await
        {
            Err(err) if !task.shutdown.is_closed() => {
                warn!(event = "tcp.target.read.error", flow_id, error = %err);
                let _ =
                    send_error(&task.carrier_writer, flow_id, ErrorCode::TargetUnavailable).await;
                let _ = send_tcp_close(&task.carrier_writer, flow_id, TCP_CLOSE_ERROR).await;
            }
            _ => {}
        }
        send_flow_event_or_shutdown(
            &task.event_tx,
            FlowEvent::ReadClosed {
                flow_id,
                token: task.identity.token,
            },
            &task.shutdown,
        )
        .await;
    });
}

/// Starts the datagram receiver before the session loop when the carrier
/// exposes a datagram channel, so inbound datagrams reach the flow table
/// through the same event channel as `UDP_DATA` frames. The reliable control
/// channel still carries `UDP_OPEN`/`UDP_CLOSE`.
pub(crate) fn maybe_spawn_datagram_reader(
    session_tasks: &mut SessionTasks,
    datagrams: Option<&BoxedDatagramChannel>,
    event_tx: &FlowEventSender,
    shutdown: &SessionShutdown,
) {
    if let Some(channel) = datagrams {
        spawn_datagram_reader(
            session_tasks,
            channel.clone(),
            event_tx.clone(),
            shutdown.clone(),
        );
    }
}

/// Receives inbound QUIC datagrams for the session and routes each to the flow
/// table via the shared flow-event channel, alongside `UDP_DATA` frames.
pub(crate) fn spawn_datagram_reader(
    session_tasks: &mut SessionTasks,
    channel: BoxedDatagramChannel,
    event_tx: FlowEventSender,
    shutdown: SessionShutdown,
) {
    session_tasks.spawn(SessionTaskKind::DatagramReader, async move {
        loop {
            if shutdown.is_closed() {
                return;
            }
            let datagram = tokio::select! {
                result = channel.recv() => match result {
                    Ok(datagram) => datagram,
                    Err(_) => return,
                },
                () = shutdown.closed() => return,
            };
            match datagram::decode(datagram) {
                Ok((flow_id, payload)) => {
                    if !is_client_initiated_flow_id(flow_id) {
                        debug!(event = "udp.datagram.invalid_flow_id", flow_id);
                        continue;
                    }
                    send_flow_event_or_shutdown(
                        &event_tx,
                        FlowEvent::InboundDatagram { flow_id, payload },
                        &shutdown,
                    )
                    .await;
                }
                Err(err) => {
                    debug!(event = "udp.datagram.decode_error", error = %err);
                }
            }
        }
    });
}

pub(crate) fn spawn_udp_reader(session_tasks: &mut SessionTasks, task: UdpReaderTask) {
    session_tasks.spawn(SessionTaskKind::UdpReader, async move {
        match relay_udp_target_to_client(
            task.flow_id,
            task.target_socket,
            task.flow_control,
            &task.carrier_writer,
            task.datagrams.as_ref(),
            &task.event_tx,
            &task.shutdown,
            task.data_frame_size,
        )
        .await
        {
            Err(err) if !task.shutdown.is_closed() => {
                let flow_id = task.flow_id;
                warn!(event = "udp.target.read.error", flow_id, error = %err);
                let _ =
                    send_error(&task.carrier_writer, flow_id, ErrorCode::TargetUnavailable).await;
                let _ = send_udp_close(&task.carrier_writer, flow_id, UDP_CLOSE_ERROR).await;
            }
            _ => {}
        }
        send_flow_event_or_shutdown(
            &task.event_tx,
            FlowEvent::UdpReadClosed {
                flow_id: task.flow_id,
                token: task.token,
            },
            &task.shutdown,
        )
        .await;
    });
}

pub(crate) fn spawn_target_writer(session_tasks: &mut SessionTasks, task: TargetWriterTask) {
    session_tasks.spawn(SessionTaskKind::TargetWriter, async move {
        let flow_id = task.identity.flow_id;
        match relay_client_to_target(
            task.target_writer,
            task.commands,
            task.flow_control,
            &task.event_tx,
            &task.shutdown,
            &task.carrier_writer.metrics,
            task.write_timeout,
        )
        .await
        {
            Err(err) if !task.shutdown.is_closed() => {
                warn!(event = "tcp.target.write.error", flow_id, error = %err);
                let _ =
                    send_error(&task.carrier_writer, flow_id, ErrorCode::TargetUnavailable).await;
                let _ = send_tcp_close(&task.carrier_writer, flow_id, TCP_CLOSE_ERROR).await;
            }
            _ => {}
        }
        send_flow_event_or_shutdown(
            &task.event_tx,
            FlowEvent::WriteClosed {
                flow_id,
                token: task.identity.token,
            },
            &task.shutdown,
        )
        .await;
    });
}

pub(crate) fn spawn_half_close_timer(
    session_tasks: &mut SessionTasks,
    flow_id: u64,
    token: FlowToken,
    closed_side: HalfCloseSide,
    timeout: Duration,
    event_tx: FlowEventSender,
    shutdown: SessionShutdown,
) -> SessionTaskHandle {
    session_tasks.spawn(SessionTaskKind::HalfCloseTimer, async move {
        tokio::select! {
            () = tokio::time::sleep(timeout) => {
                send_flow_event_or_shutdown(
                    &event_tx,
                    FlowEvent::HalfCloseDrainExpired {
                        flow_id,
                        token,
                        closed_side,
                    },
                    &shutdown,
                )
                .await;
            }
            () = shutdown.closed() => {}
        }
    })
}

async fn write_target_command(
    command: TargetCommand,
    target_writer: &mut OwnedWriteHalf,
    flow_control: &TargetFlowControl,
    event_tx: &FlowEventSender,
    metrics: &ServerMetrics,
    write_timeout: Option<Duration>,
) -> Result<bool, AnyError> {
    match command {
        TargetCommand::Data(buffered_data) => {
            if flow_control.is_aborted() {
                return Ok(true);
            }
            let payload_len = buffered_data.payload().len();
            let write_fut = target_writer.write_all(buffered_data.payload());
            let write_result: Result<(), AnyError> = match write_timeout {
                Some(timeout) => {
                    tokio::select! {
                        res = write_fut => res.map_err(|e| -> AnyError { e.into() }),
                        () = flow_control.aborted() => return Ok(true),
                        () = tokio::time::sleep(timeout) => {
                            Err(io::Error::new(io::ErrorKind::TimedOut, "target write timed out").into())
                        }
                    }
                }
                None => {
                    tokio::select! {
                        res = write_fut => res.map_err(|e| -> AnyError { e.into() }),
                        () = flow_control.aborted() => return Ok(true),
                    }
                }
            };
            write_result?;
            metrics.record_relay_bytes(
                RelayProtocol::Tcp,
                RelayDirection::ClientToTarget,
                payload_len,
            );
            try_record_flow_activity(event_tx, FlowEvent::Activity);
            Ok(false)
        }
        TargetCommand::Close => {
            flow_control.close();
            target_writer.shutdown().await?;
            Ok(true)
        }
    }
}

pub(crate) async fn relay_client_to_target(
    mut target_writer: OwnedWriteHalf,
    mut commands: mpsc::Receiver<TargetCommand>,
    flow_control: TargetFlowControl,
    event_tx: &FlowEventSender,
    shutdown: &SessionShutdown,
    metrics: &ServerMetrics,
    write_timeout: Option<Duration>,
) -> Result<(), AnyError> {
    loop {
        if flow_control.is_aborted() {
            return Ok(());
        }
        let command = tokio::select! {
            biased;
            () = flow_control.aborted() => return Ok(()),
            command = commands.recv() => command,
            () = shutdown.closed() => {
                while let Ok(command) = commands.try_recv() {
                    if write_target_command(
                        command,
                        &mut target_writer,
                        &flow_control,
                        event_tx,
                        metrics,
                        write_timeout,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                }
                if flow_control.is_closed() && !flow_control.is_aborted() {
                    target_writer.shutdown().await?;
                }
                return Ok(());
            }
        };
        let Some(command) = command else {
            break;
        };
        if write_target_command(
            command,
            &mut target_writer,
            &flow_control,
            event_tx,
            metrics,
            write_timeout,
        )
        .await?
        {
            return Ok(());
        }
    }
    if flow_control.is_closed() && !flow_control.is_aborted() {
        target_writer.shutdown().await?;
    }
    Ok(())
}

pub(crate) async fn relay_target_to_client(
    flow_id: u64,
    mut target_reader: OwnedReadHalf,
    flow_control: TargetFlowControl,
    carrier_writer: &CarrierWriter,
    event_tx: &FlowEventSender,
    shutdown: &SessionShutdown,
    data_frame_size: usize,
) -> Result<(), AnyError> {
    let mut target_buf = vec![0_u8; data_frame_size].into_boxed_slice();
    loop {
        if shutdown.is_closed() || flow_control.is_aborted() {
            return Ok(());
        }
        let read = tokio::select! {
            read = target_reader.read(target_buf.as_mut()) => read?,
            () = shutdown.closed() => return Ok(()),
            () = flow_control.aborted() => return Ok(()),
        };
        if shutdown.is_closed() || flow_control.is_aborted() {
            return Ok(());
        }
        if read == 0 {
            send_tcp_close(carrier_writer, flow_id, TCP_CLOSE_NORMAL).await?;
            return Ok(());
        }
        send_tcp_data(
            carrier_writer,
            flow_id,
            Bytes::copy_from_slice(&target_buf[..read]),
            &flow_control,
        )
        .await?;
        carrier_writer.metrics.record_relay_bytes(
            RelayProtocol::Tcp,
            RelayDirection::TargetToClient,
            read,
        );
        try_record_flow_activity(event_tx, FlowEvent::Activity);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_udp_target_to_client(
    flow_id: u64,
    target_socket: Arc<UdpSocket>,
    flow_control: TargetFlowControl,
    carrier_writer: &CarrierWriter,
    datagrams: Option<&BoxedDatagramChannel>,
    event_tx: &FlowEventSender,
    shutdown: &SessionShutdown,
    data_frame_size: usize,
) -> Result<(), AnyError> {
    let mut target_buf = vec![0_u8; UDP_TARGET_BUFFER_SIZE].into_boxed_slice();
    loop {
        if shutdown.is_closed() || flow_control.is_aborted() {
            return Ok(());
        }
        let read = tokio::select! {
            read = target_socket.recv(target_buf.as_mut()) => read?,
            () = shutdown.closed() => return Ok(()),
            () = flow_control.aborted() => return Ok(()),
        };
        if shutdown.is_closed() || flow_control.is_aborted() {
            return Ok(());
        }
        let payload = &target_buf[..read];
        match emit_udp_to_client(carrier_writer, datagrams, flow_id, payload, data_frame_size)
            .await?
        {
            UdpEmit::Sent => {
                carrier_writer.metrics.record_relay_bytes(
                    RelayProtocol::Udp,
                    RelayDirection::TargetToClient,
                    read,
                );
                try_record_flow_activity(event_tx, FlowEvent::UdpActivity(flow_id));
            }
            UdpEmit::DroppedTooLarge => {
                warn!(
                    event = "udp.target.datagram.too_large",
                    flow_id,
                    payload_len = read,
                    max_payload_len = data_frame_size
                );
            }
        }
    }
}
