use std::{io, sync::Arc, time::Duration};

use bytes::BytesMut;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch},
    task::JoinError,
    time,
};
use tracing::{debug, info, warn};
use uk_auth::AuthenticatedIdentity;
use uk_proto::{
    BoxedCarrierReader, ErrorCode, ErrorPayload, Frame, FrameIoError, FrameReader, FrameType,
    TCP_CLOSE_ERROR, UDP_CLOSE_ERROR, is_client_initiated_flow_id, validate_connection_frame,
    write_frame,
};

use super::context::{
    AnyError, CarrierWriter, FlowEvent, FlowEventReceiver, FlowEventSender, FlowIdRejection,
    FlowSlot, FlowTable, FlowTokenAllocator, OpenDialLimiter, RelayLimits, RelaySessionContext,
    SESSION_EVENT_QUEUE_BASE_CAPACITY, SESSION_EVENT_QUEUE_MAX_CAPACITY,
    SESSION_EVENT_QUEUE_PER_FLOW_CAPACITY, ServerCarrier, SessionBufferControl, SessionShutdown,
    SessionTaskKind, TARGET_WRITE_QUEUE_MAX_CAPACITY, TARGET_WRITE_QUEUE_MIN_CAPACITY,
    TARGET_WRITE_QUEUE_NOMINAL_FRAME_BYTES, TargetFlowControl, transition, udp_target_flow_mut,
};
use super::tasks::{SessionTasks, maybe_spawn_datagram_reader};
use super::tcp::{
    handle_client_flow_status_frame, handle_half_close_drain_expired, handle_target_read_closed,
    handle_target_write_closed, handle_tcp_close_frame, handle_tcp_data_frame,
    handle_tcp_open_completed, handle_tcp_open_frame, send_tcp_close,
};
use super::udp::{
    close_idle_udp_flows, forward_udp_datagram, handle_udp_close_frame, handle_udp_data_frame,
    handle_udp_open_completed, handle_udp_open_frame, handle_udp_read_closed, send_udp_close,
};

pub(crate) use super::context::{ServerSessionState, SessionEvent};
use crate::observability::{FlowOpenFailure, RelayProtocol, ServerMetrics};
use crate::security::SecurityState;

pub(crate) async fn relay_session(
    carrier: ServerCarrier,
    identity: AuthenticatedIdentity,
    security: SecurityState,
    limits: RelayLimits,
    idle_timeout: Option<Duration>,
    mut shutdown_rx: watch::Receiver<bool>,
    metrics: Arc<ServerMetrics>,
) -> Result<(), AnyError> {
    let mut state = ServerSessionState::Authenticated;
    transition(&mut state, ServerSessionState::Relaying);

    let ServerCarrier {
        carrier_reader,
        carrier_writer,
        datagrams,
    } = carrier;
    let mut carrier_reader = FrameReader::new(carrier_reader, limits.frame);
    let (event_tx, mut event_rx) = mpsc::channel(session_event_queue_capacity(limits));
    let mut target_writers = FlowTable::new();
    let mut session_tasks = SessionTasks::default();
    let shutdown = SessionShutdown::default();
    let session_buffer = SessionBufferControl::default();
    let open_dial_limiter = OpenDialLimiter::new(limits.max_outbound_dials_per_session);
    let flow_tokens = FlowTokenAllocator::default();
    let carrier_writer = CarrierWriter::new(
        carrier_writer,
        shutdown.clone(),
        Arc::clone(&metrics),
        limits.carrier_write_timeout,
    );
    maybe_spawn_datagram_reader(&mut session_tasks, datagrams.as_ref(), &event_tx, &shutdown);
    let context = RelaySessionContext {
        identity,
        security,
        carrier_writer: &carrier_writer,
        event_tx: &event_tx,
        limits,
        shutdown: shutdown.clone(),
        session_buffer,
        open_dial_limiter,
        flow_tokens,
        metrics,
        datagrams,
    };
    let mut idle_deadline = next_idle_deadline(idle_timeout);
    let mut udp_idle_interval = udp_idle_interval(limits.udp_flow_idle_timeout);
    let mut drain_deadline_set = false;
    let mut drain_deadline: Option<time::Instant> = None;

    let result = loop {
        let is_draining = state == ServerSessionState::Draining;
        let event = match next_session_event(
            &mut carrier_reader,
            &mut event_rx,
            &mut session_tasks,
            idle_deadline,
            &mut udp_idle_interval,
            &mut shutdown_rx,
            &shutdown,
            is_draining,
            drain_deadline,
        )
        .await
        {
            Ok(event) => event,
            Err(err) => break Err(err),
        };
        match handle_session_event(
            event,
            &context,
            &mut target_writers,
            &mut session_tasks,
            &mut state,
        )
        .await
        {
            SessionStep::Continue {
                counts_as_activity: true,
            } => idle_deadline = next_idle_deadline(idle_timeout),
            SessionStep::Continue {
                counts_as_activity: false,
            } => {}
            SessionStep::Stop(result) => break result,
        }

        if state == ServerSessionState::Draining {
            if target_writers.is_empty() {
                info!(event = "server.session.drain_complete");
                break Ok(());
            }
            if !drain_deadline_set {
                drain_deadline_set = true;
                drain_deadline = limits
                    .session_task_shutdown_timeout
                    .and_then(|timeout| time::Instant::now().checked_add(timeout));
            }
        }
    };

    close_session(
        &mut state,
        &shutdown,
        &mut target_writers,
        &mut session_tasks,
        &carrier_writer,
        limits.session_task_shutdown_timeout,
    )
    .await;
    result
}

/// What the session loop should do after handling one event.
pub(crate) enum SessionStep {
    /// Keep relaying; `counts_as_activity` refreshes the idle deadline.
    Continue { counts_as_activity: bool },
    /// Leave the loop with this outcome, then run the shared teardown.
    Stop(Result<(), AnyError>),
}

/// Applies one session event.
///
/// Failures are returned as `SessionStep::Stop(Err(..))` rather than propagated
/// with `?`, so the caller always reaches [`close_session`]. Returning early
/// here would leave target writers mid-write, kill spawned tasks via
/// `JoinSet::drop` instead of draining them, and drop the carrier without a
/// clean shutdown.
pub(crate) async fn handle_session_event(
    event: SessionEvent,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
    state: &mut ServerSessionState,
) -> SessionStep {
    let counts_as_activity = match event {
        SessionEvent::Flow(event) => {
            let counts_as_activity =
                flow_event_counts_as_session_activity(event.as_ref(), target_writers);
            if let Err(err) = handle_flow_event(event, context, target_writers, session_tasks).await
            {
                return SessionStep::Stop(Err(err));
            }
            counts_as_activity
        }
        SessionEvent::Frame(frame) => {
            if let Err(err) =
                handle_session_frame(frame, context, target_writers, session_tasks, *state).await
            {
                return SessionStep::Stop(Err(err));
            }
            session_has_activity_flows(target_writers)
        }
        SessionEvent::SessionTaskCompleted => false,
        SessionEvent::UdpIdleMaintenance => {
            if let Err(err) = close_idle_udp_flows(context, target_writers).await {
                return SessionStep::Stop(Err(err));
            }
            false
        }
        SessionEvent::FrameReadError(err) => {
            report_frame_io_error(context.carrier_writer, &err).await;
            return SessionStep::Stop(Err(err.into()));
        }
        SessionEvent::IdleTimeout => {
            info!(event = "server.session.idle_timeout");
            return SessionStep::Stop(Ok(()));
        }
        SessionEvent::PeerClosed => {
            info!(event = "server.session.peer_closed");
            return SessionStep::Stop(Ok(()));
        }
        SessionEvent::Shutdown => {
            info!(event = "server.session.shutdown");
            if *state == ServerSessionState::Relaying {
                transition(state, ServerSessionState::Draining);
            }
            if target_writers.is_empty() {
                return SessionStep::Stop(Ok(()));
            }
            false
        }
        SessionEvent::DrainTimeout => {
            warn!(
                event = "server.session.drain_timeout",
                remaining_flows = target_writers.len()
            );
            return SessionStep::Stop(Ok(()));
        }
        SessionEvent::CarrierFailed => {
            // A writer hit its deadline and gave up on the carrier. Stop now
            // rather than idling until the session timeout: the carrier may be
            // desynchronised, and the session slot should go back immediately.
            warn!(event = "server.session.carrier_failed");
            return SessionStep::Stop(Err(carrier_unusable_error().into()));
        }
    };
    SessionStep::Continue { counts_as_activity }
}

/// Tears a session down in order: stop accepting work, close the target flows,
/// drain the spawned tasks, then shut the carrier writer down cleanly.
///
/// Every exit from the session loop must run this, which is why the loop breaks
/// with a value rather than returning early — a `?` would skip it and leave
/// target writers mid-write and the carrier closed without a clean shutdown.
pub(crate) async fn close_session(
    state: &mut ServerSessionState,
    shutdown: &SessionShutdown,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
    carrier_writer: &CarrierWriter,
    task_shutdown_timeout: Option<Duration>,
) {
    transition(state, ServerSessionState::Closing);
    shutdown.close();
    close_target_flows(target_writers);
    drain_session_tasks(session_tasks, task_shutdown_timeout).await;
    shutdown_carrier_writer(carrier_writer).await;
    transition(state, ServerSessionState::Closed);
}

pub(crate) async fn handle_flow_event(
    event: Option<FlowEvent>,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
) -> Result<(), AnyError> {
    match event {
        Some(FlowEvent::OpenCompleted {
            flow_id,
            token,
            target,
            result,
        }) => {
            handle_tcp_open_completed(
                flow_id,
                token,
                target,
                result,
                context,
                target_writers,
                session_tasks,
            )
            .await?;
        }
        Some(FlowEvent::UdpOpenCompleted {
            flow_id,
            token,
            target,
            result,
        }) => {
            handle_udp_open_completed(
                flow_id,
                token,
                target,
                result,
                context,
                target_writers,
                session_tasks,
            )
            .await?;
        }
        Some(FlowEvent::ReadClosed { flow_id, token }) => {
            handle_target_read_closed(
                flow_id,
                token,
                context.limits.tcp_half_close_timeout,
                context.event_tx,
                &context.shutdown,
                target_writers,
                session_tasks,
            );
        }
        Some(FlowEvent::UdpReadClosed { flow_id, token }) => {
            handle_udp_read_closed(flow_id, token, target_writers);
        }
        Some(FlowEvent::UdpActivity(flow_id)) => {
            if let Some(target) = udp_target_flow_mut(target_writers, flow_id) {
                target.record_activity();
            }
        }
        Some(FlowEvent::InboundDatagram { flow_id, payload }) => {
            forward_udp_datagram(flow_id, &payload, context, target_writers);
        }
        Some(FlowEvent::HalfCloseDrainExpired {
            flow_id,
            token,
            closed_side,
        }) => {
            handle_half_close_drain_expired(flow_id, token, closed_side, context, target_writers)
                .await?;
        }
        Some(FlowEvent::WriteClosed { flow_id, token }) => {
            handle_target_write_closed(flow_id, token, target_writers);
        }
        Some(FlowEvent::Activity) | None => {}
    }
    Ok(())
}

/// Retires a UDP flow whose reader task has finished.
///
/// The token must match the flow currently occupying `flow_id`: a reader that
/// finishes after its id was closed and re-opened would otherwise tear down the
/// new association, leaving the client sending into a flow the server no longer
/// knows about.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn next_session_event(
    carrier_reader: &mut FrameReader<BoxedCarrierReader>,
    event_rx: &mut FlowEventReceiver,
    session_tasks: &mut SessionTasks,
    idle_deadline: Option<time::Instant>,
    udp_idle_interval: &mut Option<time::Interval>,
    shutdown_rx: &mut watch::Receiver<bool>,
    session_shutdown: &SessionShutdown,
    is_draining: bool,
    drain_deadline: Option<time::Instant>,
) -> Result<SessionEvent, AnyError> {
    if !is_draining && *shutdown_rx.borrow() {
        return Ok(SessionEvent::Shutdown);
    }

    if let Some(idle_deadline) = idle_deadline {
        tokio::select! {
            event = event_rx.recv() => Ok(SessionEvent::Flow(event)),
            frame = carrier_reader.read_frame() => Ok(map_frame_event(frame)),
            () = session_tasks.join_next(), if !session_tasks.is_empty() => {
                Ok(SessionEvent::SessionTaskCompleted)
            }
            changed = shutdown_rx.changed(), if !is_draining => {
                let _ = changed;
                Ok(SessionEvent::Shutdown)
            }
            () = wait_drain_deadline(drain_deadline), if is_draining => {
                Ok(SessionEvent::DrainTimeout)
            }
            () = time::sleep_until(idle_deadline) => Ok(SessionEvent::IdleTimeout),
            () = session_shutdown.closed() => Ok(SessionEvent::CarrierFailed),
            () = tick_udp_idle_interval(udp_idle_interval), if udp_idle_interval.is_some() => {
                Ok(SessionEvent::UdpIdleMaintenance)
            }
        }
    } else {
        tokio::select! {
            event = event_rx.recv() => Ok(SessionEvent::Flow(event)),
            frame = carrier_reader.read_frame() => Ok(map_frame_event(frame)),
            () = session_tasks.join_next(), if !session_tasks.is_empty() => {
                Ok(SessionEvent::SessionTaskCompleted)
            }
            changed = shutdown_rx.changed(), if !is_draining => {
                let _ = changed;
                Ok(SessionEvent::Shutdown)
            }
            () = wait_drain_deadline(drain_deadline), if is_draining => {
                Ok(SessionEvent::DrainTimeout)
            }
            () = tick_udp_idle_interval(udp_idle_interval), if udp_idle_interval.is_some() => {
                Ok(SessionEvent::UdpIdleMaintenance)
            }
            () = session_shutdown.closed() => Ok(SessionEvent::CarrierFailed),
        }
    }
}

async fn wait_drain_deadline(deadline: Option<time::Instant>) {
    match deadline {
        Some(deadline) => time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}

pub(crate) fn session_event_queue_capacity(limits: RelayLimits) -> usize {
    let stream_capacity = usize::try_from(limits.max_streams)
        .unwrap_or(usize::MAX)
        .saturating_mul(SESSION_EVENT_QUEUE_PER_FLOW_CAPACITY);
    SESSION_EVENT_QUEUE_BASE_CAPACITY
        .saturating_add(stream_capacity)
        .min(SESSION_EVENT_QUEUE_MAX_CAPACITY)
}

pub(crate) async fn drain_session_tasks(
    tasks: &mut SessionTasks,
    shutdown_timeout: Option<Duration>,
) {
    if let Some(timeout) = shutdown_timeout {
        if time::timeout(timeout, tasks.join_all()).await.is_err() {
            warn!(
                event = "server.session.task_shutdown.timeout",
                remaining_tasks = tasks.len(),
                timeout_seconds = timeout.as_secs()
            );
            tasks.abort_all();
            tasks.join_all().await;
        }
    } else {
        tasks.join_all().await;
    }
}

pub(crate) fn log_session_task_error(kind: Option<SessionTaskKind>, err: &JoinError) {
    if err.is_cancelled() {
        debug!(event = "server.session.task.cancelled", kind = ?kind, error = %err);
    } else {
        warn!(event = "server.session.task.error", kind = ?kind, error = %err);
    }
}

pub(crate) async fn send_flow_event_or_shutdown(
    event_tx: &FlowEventSender,
    event: FlowEvent,
    shutdown: &SessionShutdown,
) {
    if shutdown.is_closed() {
        return;
    }
    tokio::select! {
        result = event_tx.send(event) => {
            let _ = result;
        }
        () = shutdown.closed() => {}
    }
}

pub(crate) fn try_record_flow_activity(event_tx: &FlowEventSender, event: FlowEvent) {
    debug_assert!(matches!(
        &event,
        FlowEvent::Activity | FlowEvent::UdpActivity(_)
    ));
    let _ = event_tx.try_send(event);
}

pub(crate) fn flow_event_counts_as_session_activity(
    event: Option<&FlowEvent>,
    target_writers: &FlowTable,
) -> bool {
    match event {
        Some(FlowEvent::Activity) => true,
        Some(FlowEvent::UdpActivity(flow_id) | FlowEvent::InboundDatagram { flow_id, .. }) => {
            matches!(target_writers.get(flow_id), Some(FlowSlot::Udp(_)))
        }
        _ => false,
    }
}

pub(crate) fn session_has_activity_flows(target_writers: &FlowTable) -> bool {
    !target_writers.is_empty()
}

pub(crate) fn next_idle_deadline(idle_timeout: Option<Duration>) -> Option<time::Instant> {
    idle_timeout.map(|timeout| {
        time::Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(time::Instant::now)
    })
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

pub(crate) fn map_frame_event(result: Result<Frame, FrameIoError>) -> SessionEvent {
    match result {
        Ok(frame) => SessionEvent::Frame(frame),
        Err(FrameIoError::Closed) => SessionEvent::PeerClosed,
        Err(err) => SessionEvent::FrameReadError(err),
    }
}

pub(crate) async fn handle_session_frame(
    frame: Frame,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
    state: ServerSessionState,
) -> Result<(), AnyError> {
    if state == ServerSessionState::Draining {
        match frame.header.frame_type {
            FrameType::TcpOpen => {
                warn!(
                    event = "server.session.drain.reject_tcp_open",
                    flow_id = frame.header.id
                );
                context
                    .metrics
                    .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::ResourceLimit);
                send_resource_limit(context.carrier_writer, frame.header.id).await?;
                send_tcp_close(context.carrier_writer, frame.header.id, TCP_CLOSE_ERROR).await?;
                return Ok(());
            }
            FrameType::UdpOpen => {
                warn!(
                    event = "server.session.drain.reject_udp_open",
                    flow_id = frame.header.id
                );
                context
                    .metrics
                    .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::ResourceLimit);
                send_resource_limit(context.carrier_writer, frame.header.id).await?;
                send_udp_close(context.carrier_writer, frame.header.id, UDP_CLOSE_ERROR).await?;
                return Ok(());
            }
            _ => {}
        }
    }

    match frame.header.frame_type {
        FrameType::TcpOpen => {
            handle_tcp_open_frame(context, frame, target_writers, session_tasks).await
        }
        FrameType::TcpData => handle_tcp_data_frame(frame, context, target_writers).await,
        FrameType::TcpClose => {
            handle_tcp_close_frame(frame, context, target_writers, session_tasks).await
        }
        FrameType::UdpOpen => {
            handle_udp_open_frame(context, frame, target_writers, session_tasks).await
        }
        FrameType::UdpData => handle_udp_data_frame(frame, context, target_writers).await,
        FrameType::UdpClose => handle_udp_close_frame(frame, context, target_writers).await,
        FrameType::Error | FrameType::PolicyDenied | FrameType::ResourceLimit => {
            handle_client_flow_status_frame(frame, context, target_writers).await
        }
        FrameType::Ping => {
            validate_or_report_session_control_frame(&frame, context, FrameType::Ping).await?;
            write_pong(context.carrier_writer, &frame).await
        }
        FrameType::Pong => {
            validate_or_report_session_control_frame(&frame, context, FrameType::Pong).await?;
            Ok(())
        }
        _ => reject_unexpected_session_frame(&frame, context).await,
    }
}

pub(crate) async fn reject_unexpected_session_frame(
    frame: &Frame,
    context: &RelaySessionContext<'_>,
) -> Result<(), AnyError> {
    send_error(context.carrier_writer, frame.header.id, ErrorCode::Protocol).await?;
    Err("unexpected frame while relaying session".into())
}

pub(crate) async fn report_frame_io_error(writer: &CarrierWriter, error: &FrameIoError) {
    if let FrameIoError::Protocol(error) = error {
        let _ = send_error(writer, 0, ErrorCode::from_protocol_error(error)).await;
    }
}

pub(crate) async fn validate_or_report_session_control_frame(
    frame: &Frame,
    context: &RelaySessionContext<'_>,
    expected_type: FrameType,
) -> Result<(), AnyError> {
    if let Err(err) = validate_connection_frame(frame, expected_type) {
        send_error(context.carrier_writer, 0, ErrorCode::Protocol).await?;
        return Err(err.into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_session_control_frame(
    frame: &Frame,
    expected_type: FrameType,
) -> Result<(), AnyError> {
    validate_connection_frame(frame, expected_type)?;
    Ok(())
}

pub(crate) async fn reject_invalid_client_relay_flow_id(
    context: &RelaySessionContext<'_>,
    flow_id: u64,
    rejection: FlowIdRejection,
    zero_id_error: &'static str,
) -> Result<(), AnyError> {
    send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
    match rejection {
        FlowIdRejection::Zero => Err(zero_id_error.into()),
        FlowIdRejection::Reserved => {
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
            Ok(())
        }
    }
}

pub(crate) async fn reject_invalid_udp_relay_flow_id(
    context: &RelaySessionContext<'_>,
    flow_id: u64,
    rejection: FlowIdRejection,
    zero_id_error: &'static str,
) -> Result<(), AnyError> {
    send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
    match rejection {
        FlowIdRejection::Zero => Err(zero_id_error.into()),
        FlowIdRejection::Reserved => {
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
            Ok(())
        }
    }
}

pub(crate) fn validate_client_relay_flow_id(flow_id: u64) -> Result<(), FlowIdRejection> {
    if flow_id == 0 {
        Err(FlowIdRejection::Zero)
    } else if !is_client_initiated_flow_id(flow_id) {
        Err(FlowIdRejection::Reserved)
    } else {
        Ok(())
    }
}

pub(crate) fn target_write_queue_capacity(max_buffered_bytes_per_flow: usize) -> usize {
    (max_buffered_bytes_per_flow / TARGET_WRITE_QUEUE_NOMINAL_FRAME_BYTES).clamp(
        TARGET_WRITE_QUEUE_MIN_CAPACITY,
        TARGET_WRITE_QUEUE_MAX_CAPACITY,
    )
}

pub(crate) fn close_target_flows(target_writers: &mut FlowTable) {
    for slot in target_writers.drain().map(|(_, target)| target) {
        match slot {
            FlowSlot::OpeningTcp(cancel) | FlowSlot::OpeningUdp(cancel) => cancel.cancel(),
            FlowSlot::Tcp(mut target) => target.close_client_to_target(),
            FlowSlot::Udp(target) => target.abort(),
        }
    }
}

/// Closes the carrier write half, best-effort.
///
/// This runs inside session teardown, which the session permit outlives, so it
/// must not be able to block on the peer that caused the teardown: a client that
/// has stopped reading cannot accept `close_notify`, and waiting for it here
/// would hold the session slot open — the same leak the write deadline exists to
/// prevent, just moved into the close path. A missed `close_notify` only costs
/// the peer a clean shutdown signal; dropping the writer still closes the
/// socket.
pub(crate) async fn shutdown_carrier_writer(carrier_writer: &CarrierWriter) {
    let close = async {
        let mut writer = carrier_writer.inner.lock().await;
        if let Err(err) = writer.shutdown().await {
            debug!(event = "server.session.shutdown.error", error = %err);
        }
    };
    let Some(timeout) = carrier_writer.write_timeout else {
        close.await;
        return;
    };
    if time::timeout(timeout, close).await.is_err() {
        warn!(
            event = "server.session.shutdown.timeout",
            timeout_seconds = timeout.as_secs()
        );
    }
}

pub(crate) async fn send_policy_denied(
    writer: &CarrierWriter,
    flow_id: u64,
) -> Result<(), AnyError> {
    send_status_frame(
        writer,
        FrameType::PolicyDenied,
        flow_id,
        ErrorCode::PolicyDenied,
    )
    .await
}

pub(crate) async fn send_resource_limit(
    writer: &CarrierWriter,
    flow_id: u64,
) -> Result<(), AnyError> {
    send_status_frame(
        writer,
        FrameType::ResourceLimit,
        flow_id,
        ErrorCode::ResourceLimit,
    )
    .await
}

pub(crate) async fn send_error(
    writer: &CarrierWriter,
    flow_id: u64,
    code: ErrorCode,
) -> Result<(), AnyError> {
    send_status_frame(writer, FrameType::Error, flow_id, code).await
}

pub(crate) async fn send_status_frame(
    writer: &CarrierWriter,
    frame_type: FrameType,
    flow_id: u64,
    code: ErrorCode,
) -> Result<(), AnyError> {
    let mut payload = BytesMut::new();
    ErrorPayload::new(code).encode(&mut payload)?;
    let frame = Frame::new(frame_type, 0, flow_id, payload.freeze())?;
    write_frame_locked(writer, &frame).await
}

pub(crate) async fn write_pong(
    writer: &CarrierWriter,
    request_frame: &Frame,
) -> Result<(), AnyError> {
    let pong_frame = Frame::new(
        FrameType::Pong,
        0,
        request_frame.header.id,
        request_frame.payload.clone(),
    )?;
    write_frame_locked(writer, &pong_frame).await
}

/// Writes one frame to the carrier, serialised against the other writers.
///
/// The deadline covers only the write itself, not the wait for the lock. A peer
/// that stops reading stalls whichever writer holds the lock, so measuring the
/// holder is what detects it; timing out the waiters as well would fail healthy
/// sessions merely because several flows queued behind one large frame. Waiters
/// need no deadline of their own because the timeout closes the session, and
/// their `shutdown` arm then releases them immediately.
pub(crate) async fn write_frame_locked(
    writer: &CarrierWriter,
    frame: &Frame,
) -> Result<(), AnyError> {
    let mut guard = tokio::select! {
        guard = writer.inner.lock() => guard,
        () = writer.shutdown.closed() => return Err(session_shutdown_error().into()),
    };
    if writer.shutdown.is_closed() {
        return Err(session_shutdown_error().into());
    }
    let write = write_frame_or_shutdown(&mut *guard, frame, &writer.shutdown);
    let Some(timeout) = writer.write_timeout else {
        write.await?;
        return Ok(());
    };
    let Ok(result) = time::timeout(timeout, write).await else {
        // An unknown-length prefix of the frame may already be on the wire, so
        // the carrier can never be trusted again. Closing the session is both
        // the correct response and what releases the writers queued behind this
        // one, along with the session slot and its sockets.
        writer.shutdown.close();
        warn!(
            event = "server.carrier.write_timeout",
            timeout_seconds = timeout.as_secs()
        );
        return Err(carrier_write_timeout_error(timeout).into());
    };
    result?;
    Ok(())
}

/// Writes a frame for a target flow to the carrier writer under lock, verifying
/// that the flow has not been aborted both while waiting for the lock and after
/// acquiring it. If the flow has been aborted, the frame is discarded.
pub(crate) async fn write_flow_frame_locked(
    writer: &CarrierWriter,
    frame: &Frame,
    flow_control: &TargetFlowControl,
) -> Result<(), AnyError> {
    if writer.shutdown.is_closed() || flow_control.is_aborted() {
        return Ok(());
    }
    let mut guard = tokio::select! {
        guard = writer.inner.lock() => guard,
        () = writer.shutdown.closed() => return Err(session_shutdown_error().into()),
        () = flow_control.aborted() => return Ok(()),
    };
    if writer.shutdown.is_closed() || flow_control.is_aborted() {
        return Ok(());
    }
    let write = write_frame_or_shutdown(&mut *guard, frame, &writer.shutdown);
    let Some(timeout) = writer.write_timeout else {
        write.await?;
        return Ok(());
    };
    let Ok(result) = time::timeout(timeout, write).await else {
        writer.shutdown.close();
        warn!(
            event = "server.carrier.write_timeout",
            timeout_seconds = timeout.as_secs()
        );
        return Err(carrier_write_timeout_error(timeout).into());
    };
    result?;
    Ok(())
}

pub(crate) fn carrier_unusable_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "carrier is unusable after a write deadline expired",
    )
}

pub(crate) fn carrier_write_timeout_error(timeout: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "carrier write exceeded {}s; peer is not reading",
            timeout.as_secs()
        ),
    )
}

/// Writes one frame, refusing to start if the session is already closing.
///
/// The write itself is *not* raced against shutdown. `write_frame` is
/// `write_all` + `flush` and is not cancellation safe, so dropping it mid-frame
/// would leave an unknown-length prefix on the wire and desynchronise the peer's
/// framing — trading a clean close for a corrupt one. Callers bound the write
/// with the carrier write deadline instead, which is what stops a peer that has
/// stopped reading from parking it forever.
pub(crate) async fn write_frame_or_shutdown<W>(
    writer: &mut W,
    frame: &Frame,
    shutdown: &SessionShutdown,
) -> Result<(), AnyError>
where
    W: AsyncWrite + Unpin,
{
    if shutdown.is_closed() {
        return Err(session_shutdown_error().into());
    }
    write_frame(writer, frame).await?;
    Ok(())
}

pub(crate) fn session_shutdown_error() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "session shutdown")
}
