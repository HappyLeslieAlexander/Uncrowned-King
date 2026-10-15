#![allow(unused_imports, clippy::wildcard_imports)]

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use super::context::*;
use super::dialer::*;
use super::session::*;
use super::tasks::*;
use super::tcp::*;
use super::udp::*;
use crate::observability::*;
use crate::security::*;
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        TcpStream, UdpSocket, lookup_host,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{Id, JoinError, JoinSet},
    time,
};
use tracing::{Instrument, Span, debug, info, warn};
use uk_auth::{AuthenticatedIdentity, unix_now};
use uk_policy::{PolicyContext, PolicyDecision, PolicySet};
use uk_proto::*;

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use super::*;

const TEST_FLOW_TOKEN: FlowToken = FlowToken(1);
const STALE_FLOW_TOKEN: FlowToken = FlowToken(2);

/// Stands in for a peer whose socket buffers are full: it never accepts a
/// byte and never finishes shutting down. `tokio::io::duplex` cannot model
/// this, because its `poll_shutdown` completes immediately.
struct StallingWriter;

impl AsyncWrite for StallingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

fn test_target_flow() -> TargetFlow {
    test_target_flow_with_token(TEST_FLOW_TOKEN)
}

fn test_target_flow_with_token(token: FlowToken) -> TargetFlow {
    let (commands, _commands_rx) = mpsc::channel(1);
    TargetFlow::new(token, commands, TargetFlowControl::default())
}

fn test_open_flow_slot() -> FlowSlot {
    FlowSlot::Tcp(test_target_flow())
}

fn test_opening_flow_slot() -> FlowSlot {
    FlowSlot::OpeningTcp(OpenFlowCancel::new(TEST_FLOW_TOKEN))
}

fn test_opening_udp_flow_slot() -> FlowSlot {
    FlowSlot::OpeningUdp(OpenFlowCancel::new(TEST_FLOW_TOKEN))
}

async fn test_udp_flow() -> UdpTargetFlow {
    test_udp_flow_with_token(FlowToken(0)).await
}

async fn test_udp_flow_with_token(token: FlowToken) -> UdpTargetFlow {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    UdpTargetFlow::new(token, Arc::new(socket), TargetFlowControl::default())
}

fn test_relay_limits(max_streams: u64) -> RelayLimits {
    let frame = FrameLimits::default();
    RelayLimits {
        frame,
        max_streams,
        max_udp_flows: max_streams,
        max_outbound_dials_per_session: 1,
        data_frame_size: tcp_data_frame_size(frame, None),
        max_buffered_bytes_per_session: 1024,
        max_buffered_bytes_per_flow: 1024,
        target_connect_timeout: None,
        tcp_half_close_timeout: None,
        carrier_write_timeout: None,
        udp_flow_idle_timeout: None,
        session_task_shutdown_timeout: None,
    }
}

fn control_frame(frame_type: FrameType, flow_id: u64) -> Frame {
    Frame::new(frame_type, 0, flow_id, Bytes::new()).unwrap()
}

fn status_payload(code: ErrorCode) -> Bytes {
    let mut payload = BytesMut::new();
    ErrorPayload::new(code).encode(&mut payload).unwrap();
    payload.freeze()
}

#[test]
fn client_half_close_keeps_flow_reserved_until_target_read_closes() {
    let mut flow = test_target_flow();

    flow.close_client_to_target();

    assert!(!flow.client_to_target_open);
    assert!(flow.target_to_client_open);
    assert!(!flow.is_fully_closed());
    assert!(!flow.control.is_aborted());

    flow.mark_target_to_client_closed();

    assert!(flow.is_fully_closed());
}

#[test]
fn target_read_close_keeps_flow_reserved_until_client_write_closes() {
    let mut flow = test_target_flow();

    flow.mark_target_to_client_closed();

    assert!(flow.client_to_target_open);
    assert!(!flow.target_to_client_open);
    assert!(!flow.is_fully_closed());

    flow.close_client_to_target();

    assert!(flow.is_fully_closed());
}

#[test]
fn abort_marks_both_directions_closed() {
    let mut flow = test_target_flow();

    flow.abort();

    assert!(!flow.client_to_target_open);
    assert!(!flow.target_to_client_open);
    assert!(flow.is_fully_closed());
    assert!(flow.control.is_aborted());
}

#[test]
fn dropping_open_target_flow_aborts_control() {
    let flow = test_target_flow();
    let control = flow.control.clone();

    drop(flow);

    assert!(control.is_aborted());
}

#[test]
fn dropping_fully_closed_target_flow_does_not_abort_control() {
    let mut flow = test_target_flow();
    let control = flow.control.clone();
    flow.mark_target_to_client_closed();
    flow.mark_client_to_target_closed();

    drop(flow);

    assert!(!control.is_aborted());
}

#[test]
fn stale_half_close_timer_does_not_affect_reused_flow_id() {
    let mut target_writers = FlowTable::new();
    let mut flow = test_target_flow_with_token(TEST_FLOW_TOKEN);
    flow.mark_target_to_client_closed();
    target_writers.insert(1, FlowSlot::Tcp(flow));

    assert_eq!(
        expire_half_close_drain(
            1,
            STALE_FLOW_TOKEN,
            HalfCloseSide::TargetToClient,
            &mut target_writers
        ),
        HalfCloseDrainDecision::Ignored
    );

    let target = open_target_flow_mut(&mut target_writers, 1).expect("flow should remain open");
    assert!(target.client_to_target_open);
    assert!(!target.control.is_closed());
}

#[test]
fn stale_target_read_close_does_not_affect_reused_flow_id() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(
        1,
        FlowSlot::Tcp(test_target_flow_with_token(TEST_FLOW_TOKEN)),
    );
    let (event_tx, _event_rx) = mpsc::channel(1);
    let shutdown = SessionShutdown::default();
    let mut session_tasks = SessionTasks::default();

    handle_target_read_closed(
        1,
        STALE_FLOW_TOKEN,
        Some(Duration::from_secs(1)),
        &event_tx,
        &shutdown,
        &mut target_writers,
        &mut session_tasks,
    );

    let target = open_target_flow_mut(&mut target_writers, 1).expect("flow should remain open");
    assert!(target.target_to_client_open);
    assert!(target.client_to_target_open);
}

/// A connect task that finishes after its flow id was closed and re-opened
/// must not have its result wired into the new flow. The slot's token
/// distinguishes the two open attempts; matching on "some open is pending"
/// alone would attach the wrong target.
#[test]
fn stale_open_completion_is_rejected_for_a_reused_flow_id() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_opening_flow_slot());

    let slot = target_writers.get(&1);
    let matches_stale = matches!(
        slot,
        Some(FlowSlot::OpeningTcp(cancel)) if cancel.token == STALE_FLOW_TOKEN
    );
    let matches_current = matches!(
        slot,
        Some(FlowSlot::OpeningTcp(cancel)) if cancel.token == TEST_FLOW_TOKEN
    );

    assert!(!matches_stale, "a superseded open attempt must not match");
    assert!(matches_current, "the current open attempt must still match");
}

#[test]
fn open_flow_cancel_tokens_are_unique_per_attempt() {
    let tokens = FlowTokenAllocator::default();
    let first = OpenFlowCancel::new(tokens.next());
    let second = OpenFlowCancel::new(tokens.next());

    assert_ne!(first.token, second.token);
    // Cancelling the superseded attempt must not affect the new one.
    first.cancel();
    assert!(first.is_cancelled());
    assert!(!second.is_cancelled());
}

#[tokio::test]
async fn stale_udp_read_close_does_not_remove_reused_flow_id() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(
        1,
        FlowSlot::Udp(test_udp_flow_with_token(TEST_FLOW_TOKEN).await),
    );

    handle_udp_read_closed(1, STALE_FLOW_TOKEN, &mut target_writers);

    assert!(
        matches!(target_writers.get(&1), Some(FlowSlot::Udp(_))),
        "a stale reader must not retire the re-opened flow"
    );
}

#[tokio::test]
async fn matching_udp_read_close_removes_flow() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(
        1,
        FlowSlot::Udp(test_udp_flow_with_token(TEST_FLOW_TOKEN).await),
    );

    handle_udp_read_closed(1, TEST_FLOW_TOKEN, &mut target_writers);

    assert!(!target_writers.contains_key(&1));
}

#[test]
fn half_close_drain_timer_starts_once_per_flow() {
    let mut flow = test_target_flow_with_token(TEST_FLOW_TOKEN);
    assert!(
        should_start_half_close_drain(&flow),
        "the first client close half-closes the flow"
    );

    flow.close_client_to_target();

    assert!(
        !should_start_half_close_drain(&flow),
        "a duplicate TCP_CLOSE must not arm another drain timer"
    );
}

#[test]
fn half_close_drain_timer_skipped_when_target_read_already_closed() {
    let mut flow = test_target_flow_with_token(TEST_FLOW_TOKEN);
    flow.mark_target_to_client_closed();

    assert!(!should_start_half_close_drain(&flow));
}

#[test]
fn matching_target_read_close_updates_original_flow() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(
        1,
        FlowSlot::Tcp(test_target_flow_with_token(TEST_FLOW_TOKEN)),
    );
    let (event_tx, _event_rx) = mpsc::channel(1);
    let shutdown = SessionShutdown::default();
    let mut session_tasks = SessionTasks::default();

    handle_target_read_closed(
        1,
        TEST_FLOW_TOKEN,
        None,
        &event_tx,
        &shutdown,
        &mut target_writers,
        &mut session_tasks,
    );

    let target = open_target_flow_mut(&mut target_writers, 1).expect("flow should remain open");
    assert!(!target.target_to_client_open);
    assert!(target.client_to_target_open);
}

#[test]
fn stale_target_write_close_does_not_affect_reused_flow_id() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(
        1,
        FlowSlot::Tcp(test_target_flow_with_token(TEST_FLOW_TOKEN)),
    );

    handle_target_write_closed(1, STALE_FLOW_TOKEN, &mut target_writers);

    let target = open_target_flow_mut(&mut target_writers, 1).expect("flow should remain open");
    assert!(target.target_to_client_open);
    assert!(target.client_to_target_open);
}

#[test]
fn matching_target_write_close_updates_original_flow() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(
        1,
        FlowSlot::Tcp(test_target_flow_with_token(TEST_FLOW_TOKEN)),
    );

    handle_target_write_closed(1, TEST_FLOW_TOKEN, &mut target_writers);

    let target = open_target_flow_mut(&mut target_writers, 1).expect("flow should remain open");
    assert!(target.target_to_client_open);
    assert!(!target.client_to_target_open);
}

#[test]
fn matching_half_close_timer_closes_original_flow() {
    let mut target_writers = FlowTable::new();
    let mut flow = test_target_flow_with_token(TEST_FLOW_TOKEN);
    flow.mark_target_to_client_closed();
    target_writers.insert(1, FlowSlot::Tcp(flow));

    assert_eq!(
        expire_half_close_drain(
            1,
            TEST_FLOW_TOKEN,
            HalfCloseSide::TargetToClient,
            &mut target_writers
        ),
        HalfCloseDrainDecision::ClosePeer { remove: false }
    );

    let target = open_target_flow_mut(&mut target_writers, 1).expect("removal is caller-owned");
    assert!(!target.client_to_target_open);
    assert!(target.control.is_closed());
}

#[test]
fn matching_half_close_client_to_target_timer_aborts_and_removes() {
    let mut target_writers = FlowTable::new();
    let mut flow = test_target_flow_with_token(TEST_FLOW_TOKEN);
    flow.mark_client_to_target_closed();
    target_writers.insert(1, FlowSlot::Tcp(flow));

    assert_eq!(
        expire_half_close_drain(
            1,
            TEST_FLOW_TOKEN,
            HalfCloseSide::ClientToTarget,
            &mut target_writers
        ),
        HalfCloseDrainDecision::ClosePeer { remove: true }
    );
}

#[test]
fn target_flow_control_tracks_buffered_bytes() {
    let session = SessionBufferControl::default();
    let control = TargetFlowControl::new(session.clone());

    assert!(control.reserve_bytes(8, 10, 16));
    assert_eq!(control.buffered_bytes(), 8);
    assert_eq!(session.buffered_bytes(), 8);
    assert!(!control.reserve_bytes(3, 10, 16));
    assert_eq!(control.buffered_bytes(), 8);
    assert_eq!(session.buffered_bytes(), 8);

    control.release_bytes(4);
    assert_eq!(control.buffered_bytes(), 4);
    assert_eq!(session.buffered_bytes(), 4);
    assert!(control.reserve_bytes(6, 10, 16));
    assert_eq!(control.buffered_bytes(), 10);
    assert_eq!(session.buffered_bytes(), 10);
}

#[test]
fn target_flow_control_rejects_session_buffer_limit() {
    let session = SessionBufferControl::default();
    let first = TargetFlowControl::new(session.clone());
    let second = TargetFlowControl::new(session.clone());

    assert!(first.reserve_bytes(8, 10, 10));
    assert!(!second.reserve_bytes(3, 10, 10));

    assert_eq!(first.buffered_bytes(), 8);
    assert_eq!(second.buffered_bytes(), 0);
    assert_eq!(session.buffered_bytes(), 8);
}

#[test]
fn target_flow_control_release_saturates_at_zero() {
    let session = SessionBufferControl::default();
    let control = TargetFlowControl::new(session.clone());

    control.release_bytes(1);
    assert_eq!(control.buffered_bytes(), 0);
    assert_eq!(session.buffered_bytes(), 0);

    assert!(control.reserve_bytes(5, 10, 10));
    control.release_bytes(8);
    assert_eq!(control.buffered_bytes(), 0);
    assert_eq!(session.buffered_bytes(), 0);
}

#[tokio::test]
async fn session_shutdown_notifies_waiters() {
    let shutdown = SessionShutdown::default();
    let waiter = shutdown.clone();
    let task = tokio::spawn(async move {
        waiter.closed().await;
    });

    shutdown.close();

    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn open_task_wait_returns_completed_result() {
    let shutdown = SessionShutdown::default();
    let cancel = OpenFlowCancel::new(TEST_FLOW_TOKEN);

    let result = wait_for_open_task(async { 7_u8 }, &shutdown, &cancel).await;

    assert_eq!(result, Some(7));
}

#[tokio::test]
async fn open_task_wait_exits_on_session_shutdown() {
    let shutdown = SessionShutdown::default();
    let shutdown_handle = shutdown.clone();
    let cancel = OpenFlowCancel::new(TEST_FLOW_TOKEN);
    let task = tokio::spawn(async move {
        wait_for_open_task(std::future::pending::<u8>(), &shutdown, &cancel).await
    });

    shutdown_handle.close();

    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("open task wait should finish")
        .expect("open task wait should not panic");
    assert_eq!(result, None);
}

#[tokio::test]
async fn open_task_wait_exits_on_pending_open_cancel() {
    let shutdown = SessionShutdown::default();
    let cancel = OpenFlowCancel::new(TEST_FLOW_TOKEN);
    let cancel_handle = cancel.clone();
    let task = tokio::spawn(async move {
        wait_for_open_task(std::future::pending::<u8>(), &shutdown, &cancel).await
    });

    cancel_handle.cancel();

    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("open task wait should finish")
        .expect("open task wait should not panic");
    assert_eq!(result, None);
}

#[tokio::test]
async fn carrier_write_is_refused_once_the_session_is_closing() {
    let (mut writer, mut reader) = tokio::io::duplex(1024);
    let shutdown = SessionShutdown::default();
    shutdown.close();
    let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"abc")).unwrap();

    let err = write_frame_or_shutdown(&mut writer, &frame, &shutdown)
        .await
        .unwrap_err();

    let io_error = err.downcast_ref::<io::Error>().unwrap();
    assert_eq!(io_error.kind(), io::ErrorKind::Interrupted);

    // Nothing was emitted, so the peer's framing is untouched.
    drop(writer);
    let mut written = Vec::new();
    reader.read_to_end(&mut written).await.unwrap();
    assert!(written.is_empty(), "expected no bytes written");
}

/// Shutdown must not truncate a frame that is already going out: dropping
/// `write_all` mid-frame would leave an unknown-length prefix on the wire
/// and desynchronise the peer, which is worse than a late clean close.
#[tokio::test]
async fn carrier_write_in_flight_is_not_truncated_by_shutdown() {
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let shutdown = SessionShutdown::default();
    let shutdown_handle = shutdown.clone();
    let payload = vec![0xaa_u8; 1024];
    let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from(payload.clone())).unwrap();
    let encoded_len = frame.encode().unwrap().len();

    let write_task =
        tokio::spawn(async move { write_frame_or_shutdown(&mut writer, &frame, &shutdown).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !write_task.is_finished(),
        "the 1-byte duplex should stall it"
    );

    shutdown_handle.close();

    // Drain the peer: the whole frame must still arrive.
    let mut received = vec![0_u8; encoded_len];
    tokio::time::timeout(Duration::from_secs(5), reader.read_exact(&mut received))
        .await
        .expect("the in-flight frame must complete")
        .unwrap();
    assert_eq!(&received[received.len() - payload.len()..], &payload[..]);

    tokio::time::timeout(Duration::from_secs(5), write_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

/// A peer that stops reading must not be able to park a carrier write for
/// the lifetime of the process: the write is bounded, and blowing the
/// deadline closes the session so its slot and sockets are released.
#[tokio::test]
async fn carrier_write_gives_up_on_a_peer_that_stops_reading() {
    let (writer, _reader) = tokio::io::duplex(1);
    let shutdown = SessionShutdown::default();
    let carrier = CarrierWriter::new(
        Box::new(writer),
        shutdown.clone(),
        Arc::new(ServerMetrics::default()),
        Some(Duration::from_millis(200)),
    );
    let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from(vec![0xaa; 4096])).unwrap();

    let err = tokio::time::timeout(
        Duration::from_secs(10),
        write_frame_locked(&carrier, &frame),
    )
    .await
    .expect("a stalled carrier write must not block forever")
    .unwrap_err();

    assert!(
        err.to_string().contains("carrier write"),
        "unexpected error: {err}"
    );
    assert!(
        shutdown.is_closed(),
        "a timed-out write leaves the carrier desynchronised, so the session must be closed"
    );
}

/// Writers queued behind a stalled one carry no deadline of their own, so
/// they must be released by the timeout closing the session. Otherwise a
/// stalled peer would strand every flow task on the carrier lock.
#[tokio::test]
async fn carrier_write_timeout_releases_writers_queued_behind_it() {
    let (writer, _reader) = tokio::io::duplex(1);
    let shutdown = SessionShutdown::default();
    let carrier = CarrierWriter::new(
        Box::new(writer),
        shutdown.clone(),
        Arc::new(ServerMetrics::default()),
        Some(Duration::from_millis(200)),
    );
    let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from(vec![0xaa; 4096])).unwrap();

    let stalled = {
        let carrier = carrier.clone();
        let frame = frame.clone();
        tokio::spawn(async move { write_frame_locked(&carrier, &frame).await })
    };
    // Let the first writer take the lock and park inside the write.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let queued = {
        let carrier = carrier.clone();
        let frame = frame.clone();
        tokio::spawn(async move { write_frame_locked(&carrier, &frame).await })
    };

    let stalled_err = tokio::time::timeout(Duration::from_secs(5), stalled)
        .await
        .expect("the holder must hit its deadline")
        .unwrap()
        .unwrap_err();
    assert!(stalled_err.to_string().contains("carrier write"));

    let queued_err = tokio::time::timeout(Duration::from_secs(5), queued)
        .await
        .expect("the queued writer must be released, not left on the lock")
        .unwrap()
        .unwrap_err();
    let io_error = queued_err.downcast_ref::<io::Error>().unwrap();
    assert_eq!(io_error.kind(), io::ErrorKind::Interrupted);
}

/// Teardown runs while the session permit is still held, so closing the
/// carrier must not block on a peer that has stopped reading.
#[tokio::test]
async fn carrier_shutdown_gives_up_on_a_peer_that_stops_reading() {
    let carrier = CarrierWriter::new(
        Box::new(StallingWriter),
        SessionShutdown::default(),
        Arc::new(ServerMetrics::default()),
        Some(Duration::from_millis(200)),
    );

    tokio::time::timeout(Duration::from_secs(10), shutdown_carrier_writer(&carrier))
        .await
        .expect("carrier shutdown must not block teardown forever");
}

#[tokio::test]
async fn target_flow_abort_notifies_waiters() {
    let control = TargetFlowControl::default();
    let waiter = control.clone();
    let task = tokio::spawn(async move {
        waiter.aborted().await;
    });

    control.abort();

    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn half_close_drops_full_target_queue_sender() {
    let (commands, mut commands_rx) = mpsc::channel(1);
    let mut flow = TargetFlow::new(TEST_FLOW_TOKEN, commands, TargetFlowControl::default());

    flow.enqueue_data(Bytes::from_static(b"queued"), 1024, 1024)
        .unwrap();
    flow.close_client_to_target();

    assert!(flow.commands.is_none());
    assert!(flow.control.is_closed());
    match commands_rx.recv().await {
        Some(TargetCommand::Data(payload)) => {
            assert_eq!(payload.payload(), b"queued");
        }
        other => panic!("unexpected target command: {other:?}"),
    }
    assert!(commands_rx.recv().await.is_none());
}

#[test]
fn dropped_queued_target_data_releases_session_buffer() {
    let session = SessionBufferControl::default();
    let control = TargetFlowControl::new(session.clone());
    let (commands, commands_rx) = mpsc::channel(1);
    let mut flow = TargetFlow::new(TEST_FLOW_TOKEN, commands, control.clone());

    flow.enqueue_data(Bytes::from_static(b"queued"), 1024, 1024)
        .unwrap();
    assert_eq!(control.buffered_bytes(), 6);
    assert_eq!(session.buffered_bytes(), 6);

    drop(commands_rx);

    assert_eq!(control.buffered_bytes(), 0);
    assert_eq!(session.buffered_bytes(), 0);
}

#[tokio::test]
async fn half_close_enqueues_close_when_target_queue_has_capacity() {
    let (commands, mut commands_rx) = mpsc::channel(1);
    let mut flow = TargetFlow::new(TEST_FLOW_TOKEN, commands, TargetFlowControl::default());

    flow.close_client_to_target();

    assert!(flow.commands.is_some());
    assert!(flow.control.is_closed());
    assert!(matches!(
        commands_rx.recv().await,
        Some(TargetCommand::Close)
    ));
}

#[tokio::test]
async fn target_writer_exits_when_session_shutdown_notifies() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let target_stream = TcpStream::connect(addr).await.unwrap();
    let (_target_peer, _) = listener.accept().await.unwrap();
    let (_target_reader, target_writer) = target_stream.into_split();
    let (_commands_tx, commands_rx) = mpsc::channel(1);
    let (event_tx, _event_rx) = mpsc::channel(1);
    let flow_control = TargetFlowControl::default();
    let shutdown = SessionShutdown::default();
    let shutdown_handle = shutdown.clone();
    let metrics = Arc::new(ServerMetrics::default());

    let writer = tokio::spawn(async move {
        relay_client_to_target(
            target_writer,
            commands_rx,
            flow_control,
            &event_tx,
            &shutdown,
            &metrics,
            None,
        )
        .await
    });
    shutdown_handle.close();

    tokio::time::timeout(Duration::from_secs(1), writer)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn target_writer_reports_activity_after_payload_write() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let target_stream = TcpStream::connect(addr).await.unwrap();
    let (mut target_peer, _) = listener.accept().await.unwrap();
    let (_target_reader, target_writer) = target_stream.into_split();
    let (commands_tx, commands_rx) = mpsc::channel(1);
    let (event_tx, mut event_rx) = mpsc::channel(1);
    let flow_control = TargetFlowControl::default();
    let shutdown = SessionShutdown::default();
    let metrics = ServerMetrics::default();
    let payload = Bytes::from_static(b"writer activity");
    let buffered_payload =
        BufferedTargetData::new(payload.clone(), flow_control.clone(), 1024, 1024).unwrap();

    commands_tx
        .send(TargetCommand::Data(buffered_payload))
        .await
        .unwrap();
    drop(commands_tx);

    let writer = relay_client_to_target(
        target_writer,
        commands_rx,
        flow_control,
        &event_tx,
        &shutdown,
        &metrics,
        None,
    );
    let reader = async {
        let mut received = vec![0_u8; payload.len()];
        target_peer.read_exact(&mut received).await?;
        Ok::<_, io::Error>(received)
    };
    let (writer_result, reader_result) = tokio::join!(writer, reader);

    writer_result.unwrap();
    assert_eq!(reader_result.unwrap(), payload);
    assert!(matches!(event_rx.recv().await, Some(FlowEvent::Activity)));
}

#[tokio::test]
async fn target_writer_times_out_when_target_stalled() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let target_stream = TcpStream::connect(addr).await.unwrap();
    let (_target_peer, _) = listener.accept().await.unwrap();
    let (_target_reader, target_writer) = target_stream.into_split();
    let (commands_tx, commands_rx) = mpsc::channel(1);
    let (event_tx, _event_rx) = mpsc::channel(1);
    let flow_control = TargetFlowControl::default();
    let shutdown = SessionShutdown::default();
    let metrics = ServerMetrics::default();
    let payload = vec![0xcc_u8; 10 * 1024 * 1024]; // 10MB to fill OS buffer
    let buffered_payload = BufferedTargetData::new(
        Bytes::from(payload),
        flow_control.clone(),
        20 * 1024 * 1024,
        20 * 1024 * 1024,
    )
    .unwrap();

    commands_tx
        .send(TargetCommand::Data(buffered_payload))
        .await
        .unwrap();

    let writer = relay_client_to_target(
        target_writer,
        commands_rx,
        flow_control,
        &event_tx,
        &shutdown,
        &metrics,
        Some(Duration::from_millis(50)),
    );

    let err = writer.await.unwrap_err();
    let io_err = err.downcast_ref::<io::Error>().unwrap();
    assert_eq!(io_err.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn duplicate_open_slot_is_protocol_error_before_stream_limit() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_open_flow_slot());

    assert_eq!(
        check_open_slot(1, &target_writers, 1),
        Err(OpenSlotRejection::DuplicateFlowId)
    );
}

#[test]
fn new_open_slot_rejects_resource_limit() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_open_flow_slot());

    assert_eq!(
        check_open_slot(3, &target_writers, 1),
        Err(OpenSlotRejection::ResourceLimit)
    );
}

#[test]
fn reserved_open_slot_is_left_for_protocol_validation() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_open_flow_slot());

    assert_eq!(check_open_slot(2, &target_writers, 1), Ok(()));
}

#[test]
fn udp_open_slot_rejects_duplicate_before_udp_limit() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_opening_udp_flow_slot());

    assert_eq!(
        check_udp_open_slot(1, &target_writers, 8, 0),
        Err(UdpOpenSlotRejection::DuplicateFlowId)
    );
}

#[test]
fn udp_open_slot_rejects_total_stream_limit() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_open_flow_slot());

    assert_eq!(
        check_udp_open_slot(3, &target_writers, 1, 8),
        Err(UdpOpenSlotRejection::ResourceLimit)
    );
}

#[test]
fn udp_open_slot_enforces_udp_flow_limit() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_opening_udp_flow_slot());
    target_writers.insert(3, test_open_flow_slot());

    assert_eq!(
        check_udp_open_slot(5, &target_writers, 8, 1),
        Err(UdpOpenSlotRejection::UdpFlowLimit)
    );
}

#[test]
fn zero_udp_flow_limit_disables_new_udp_flows() {
    let target_writers = FlowTable::new();

    assert_eq!(
        check_udp_open_slot(1, &target_writers, 8, 0),
        Err(UdpOpenSlotRejection::UdpFlowLimit)
    );
}

#[test]
fn reserved_udp_open_slot_is_left_for_protocol_validation() {
    let target_writers = FlowTable::new();

    assert_eq!(check_udp_open_slot(2, &target_writers, 8, 0), Ok(()));
}

#[test]
fn validates_client_relay_flow_ids() {
    assert_eq!(validate_client_relay_flow_id(0), Err(FlowIdRejection::Zero));
    assert_eq!(
        validate_client_relay_flow_id(2),
        Err(FlowIdRejection::Reserved)
    );
    assert_eq!(validate_client_relay_flow_id(1), Ok(()));
}

#[test]
fn validates_client_flow_status_payloads() {
    assert!(
        validate_client_flow_status_payload(FrameType::Error, status_payload(ErrorCode::Protocol))
            .is_ok()
    );
    assert!(
        validate_client_flow_status_payload(
            FrameType::ResourceLimit,
            status_payload(ErrorCode::ResourceLimit)
        )
        .is_ok()
    );
    assert!(
        validate_client_flow_status_payload(
            FrameType::PolicyDenied,
            status_payload(ErrorCode::PolicyDenied)
        )
        .is_ok()
    );
    assert!(
        validate_client_flow_status_payload(
            FrameType::ResourceLimit,
            status_payload(ErrorCode::Protocol)
        )
        .is_err()
    );
    assert!(validate_client_flow_status_payload(FrameType::TcpData, Bytes::new()).is_err());
}

#[test]
fn client_flow_status_aborts_open_flow() {
    let flow = test_target_flow();
    let control = flow.control.clone();
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, FlowSlot::Tcp(flow));

    abort_client_flow(1, &mut target_writers);

    assert!(target_writers.is_empty());
    assert!(control.is_aborted());
}

#[test]
fn client_flow_status_cancels_pending_open() {
    let cancel = OpenFlowCancel::new(TEST_FLOW_TOKEN);
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, FlowSlot::OpeningTcp(cancel.clone()));

    abort_client_flow(1, &mut target_writers);

    assert!(target_writers.is_empty());
    assert!(cancel.is_cancelled());
}

#[test]
fn client_flow_status_cancels_pending_udp_open() {
    let cancel = OpenFlowCancel::new(TEST_FLOW_TOKEN);
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, FlowSlot::OpeningUdp(cancel.clone()));

    abort_client_flow(1, &mut target_writers);

    assert!(target_writers.is_empty());
    assert!(cancel.is_cancelled());
}

#[test]
fn client_flow_status_ignores_unknown_flow() {
    let mut target_writers = FlowTable::new();

    abort_client_flow(1, &mut target_writers);

    assert!(target_writers.is_empty());
}

#[test]
fn maps_clean_carrier_eof_to_peer_closed() {
    assert!(matches!(
        map_frame_event(Err(FrameIoError::Closed)),
        SessionEvent::PeerClosed
    ));
}

#[test]
fn peer_frames_count_as_session_activity_only_with_flows() {
    let mut target_writers = FlowTable::new();

    assert!(!session_has_activity_flows(&target_writers));

    target_writers.insert(1, test_open_flow_slot());

    assert!(session_has_activity_flows(&target_writers));
}

#[tokio::test]
async fn target_data_events_count_as_session_activity() {
    let mut target_writers = FlowTable::new();
    assert!(flow_event_counts_as_session_activity(
        Some(&FlowEvent::Activity),
        &target_writers
    ));
    assert!(!flow_event_counts_as_session_activity(
        Some(&FlowEvent::UdpActivity(1)),
        &target_writers
    ));

    target_writers.insert(1, test_opening_udp_flow_slot());

    assert!(!flow_event_counts_as_session_activity(
        Some(&FlowEvent::UdpActivity(1)),
        &target_writers
    ));

    target_writers.insert(1, FlowSlot::Udp(test_udp_flow().await));

    assert!(flow_event_counts_as_session_activity(
        Some(&FlowEvent::UdpActivity(1)),
        &target_writers
    ));
}

#[test]
fn session_event_queue_capacity_scales_with_stream_limit_and_caps() {
    assert_eq!(
        session_event_queue_capacity(test_relay_limits(1)),
        SESSION_EVENT_QUEUE_BASE_CAPACITY + SESSION_EVENT_QUEUE_PER_FLOW_CAPACITY
    );
    assert_eq!(
        session_event_queue_capacity(test_relay_limits(64)),
        SESSION_EVENT_QUEUE_BASE_CAPACITY + 64 * SESSION_EVENT_QUEUE_PER_FLOW_CAPACITY
    );
    assert_eq!(
        session_event_queue_capacity(test_relay_limits(u64::MAX)),
        SESSION_EVENT_QUEUE_MAX_CAPACITY
    );
}

#[tokio::test]
async fn activity_events_are_lossy_when_session_event_queue_is_full() {
    let (event_tx, mut event_rx) = mpsc::channel(1);

    try_record_flow_activity(&event_tx, FlowEvent::Activity);
    try_record_flow_activity(&event_tx, FlowEvent::UdpActivity(1));

    assert!(matches!(event_rx.recv().await, Some(FlowEvent::Activity)));
    assert!(event_rx.try_recv().is_err());
}

#[tokio::test]
async fn reliable_flow_event_send_exits_on_session_shutdown() {
    let (event_tx, _event_rx) = mpsc::channel(1);
    event_tx.try_send(FlowEvent::Activity).unwrap();
    let shutdown = SessionShutdown::default();
    let shutdown_handle = shutdown.clone();

    let sender = tokio::spawn(async move {
        send_flow_event_or_shutdown(
            &event_tx,
            FlowEvent::UdpReadClosed {
                flow_id: 1,
                token: FlowToken(0),
            },
            &shutdown,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!sender.is_finished());

    shutdown_handle.close();

    tokio::time::timeout(Duration::from_secs(1), sender)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn session_tasks_reap_completed_tasks() {
    let mut tasks = SessionTasks::default();

    tasks.spawn(SessionTaskKind::HalfCloseTimer, async {});
    tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
        .await
        .expect("completed session task should be reaped");

    assert!(tasks.is_empty());
    assert!(tasks.kinds.is_empty());
}

#[tokio::test]
async fn session_tasks_is_empty_and_len_are_consistent() {
    let mut tasks = SessionTasks::default();
    assert!(tasks.is_empty());
    assert_eq!(tasks.len(), 0);

    let handle = tasks.spawn(
        SessionTaskKind::HalfCloseTimer,
        std::future::pending::<()>(),
    );
    assert!(!tasks.is_empty());
    assert_eq!(tasks.len(), 1);

    handle.abort();
    assert_eq!(tasks.len(), 0);
    assert!(tasks.is_empty());

    tasks.join_all().await;
    assert!(tasks.is_empty());
    assert_eq!(tasks.len(), 0);
}

#[tokio::test]
async fn session_task_drain_aborts_pending_tasks_after_timeout() {
    let mut tasks = SessionTasks::default();

    tasks.spawn(SessionTaskKind::TargetReader, async {
        std::future::pending::<()>().await;
    });
    drain_session_tasks(&mut tasks, Some(Duration::from_millis(10))).await;

    assert!(tasks.is_empty());
    assert!(tasks.kinds.is_empty());
}

#[tokio::test]
async fn dropping_session_tasks_aborts_inflight_tasks() {
    struct DropGuard(Arc<AtomicBool>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let started = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let started_clone = Arc::clone(&started);
    let cancelled_clone = Arc::clone(&cancelled);

    let mut tasks = SessionTasks::default();
    tasks.spawn(SessionTaskKind::TargetReader, async move {
        let _guard = DropGuard(cancelled_clone);
        started_clone.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    for _ in 0..100 {
        if started.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(started.load(Ordering::SeqCst));
    assert!(!cancelled.load(Ordering::SeqCst));

    drop(tasks);

    for _ in 0..100 {
        if cancelled.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        cancelled.load(Ordering::SeqCst),
        "in-flight session task was not aborted upon drop"
    );
}

#[test]
fn internal_flow_events_do_not_count_as_session_activity() {
    let target_writers = FlowTable::new();

    assert!(!flow_event_counts_as_session_activity(
        Some(&FlowEvent::ReadClosed {
            flow_id: 1,
            token: TEST_FLOW_TOKEN,
        }),
        &target_writers
    ));
    assert!(!flow_event_counts_as_session_activity(
        Some(&FlowEvent::HalfCloseDrainExpired {
            flow_id: 1,
            token: TEST_FLOW_TOKEN,
            closed_side: HalfCloseSide::ClientToTarget,
        }),
        &target_writers
    ));
}

#[test]
fn accepts_zero_id_session_control_frame() {
    assert!(
        validate_session_control_frame(&control_frame(FrameType::Ping, 0), FrameType::Ping).is_ok()
    );
    assert!(
        validate_session_control_frame(&control_frame(FrameType::Pong, 0), FrameType::Pong).is_ok()
    );
}

#[test]
fn rejects_nonzero_id_session_control_frame() {
    assert!(
        validate_session_control_frame(&control_frame(FrameType::Ping, 1), FrameType::Ping)
            .is_err()
    );
    assert!(
        validate_session_control_frame(&control_frame(FrameType::Pong, 1), FrameType::Pong)
            .is_err()
    );
}

#[test]
fn classifies_tcp_data_for_known_and_unknown_flows() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_open_flow_slot());

    assert_eq!(
        tcp_data_disposition(3, &Bytes::from_static(b"data"), &target_writers),
        TcpDataDisposition::UnknownFlow
    );
    assert_eq!(
        tcp_data_disposition(1, &Bytes::new(), &target_writers),
        TcpDataDisposition::EmptyPayload
    );
    assert_eq!(
        tcp_data_disposition(1, &Bytes::from_static(b"data"), &target_writers),
        TcpDataDisposition::ForwardPayload
    );
}

#[tokio::test]
async fn classifies_tcp_data_for_udp_flow_as_other_protocol() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, FlowSlot::Udp(test_udp_flow().await));

    assert_eq!(
        tcp_data_disposition(1, &Bytes::from_static(b"data"), &target_writers),
        TcpDataDisposition::OtherProtocolFlow
    );
}

#[tokio::test]
async fn classifies_udp_data_for_flow_kinds() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, FlowSlot::Udp(test_udp_flow().await));
    target_writers.insert(
        3,
        FlowSlot::OpeningUdp(OpenFlowCancel::new(TEST_FLOW_TOKEN)),
    );
    target_writers.insert(5, test_open_flow_slot());
    target_writers.insert(7, test_opening_flow_slot());

    assert_eq!(
        udp_data_disposition(9, &target_writers),
        UdpDataDisposition::UnknownFlow
    );
    assert_eq!(
        udp_data_disposition(1, &target_writers),
        UdpDataDisposition::ForwardPayload
    );
    assert_eq!(
        udp_data_disposition(3, &target_writers),
        UdpDataDisposition::OpeningFlow
    );
    assert_eq!(
        udp_data_disposition(5, &target_writers),
        UdpDataDisposition::TcpFlow
    );
    assert_eq!(
        udp_data_disposition(7, &target_writers),
        UdpDataDisposition::TcpFlow
    );
}

#[test]
fn pending_open_slot_counts_against_stream_limit() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_opening_flow_slot());

    assert_eq!(
        check_open_slot(3, &target_writers, 1),
        Err(OpenSlotRejection::ResourceLimit)
    );
}

#[test]
fn classifies_tcp_data_for_pending_open_flow() {
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, test_opening_flow_slot());

    assert_eq!(
        tcp_data_disposition(1, &Bytes::from_static(b"early"), &target_writers),
        TcpDataDisposition::OpeningFlow
    );
}

#[test]
fn removing_pending_open_slot_cancels_connect_task() {
    let cancel = OpenFlowCancel::new(TEST_FLOW_TOKEN);
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, FlowSlot::OpeningTcp(cancel.clone()));

    remove_flow_slot(&mut target_writers, 1);

    assert!(cancel.is_cancelled());
    assert!(target_writers.is_empty());
}

#[test]
fn removing_pending_udp_open_slot_cancels_connect_task() {
    let cancel = OpenFlowCancel::new(TEST_FLOW_TOKEN);
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, FlowSlot::OpeningUdp(cancel.clone()));

    remove_flow_slot(&mut target_writers, 1);

    assert!(cancel.is_cancelled());
    assert!(target_writers.is_empty());
}

#[test]
fn closing_session_cancels_pending_open_slots() {
    let cancel = OpenFlowCancel::new(TEST_FLOW_TOKEN);
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, FlowSlot::OpeningTcp(cancel.clone()));
    target_writers.insert(3, test_open_flow_slot());

    close_target_flows(&mut target_writers);

    assert!(cancel.is_cancelled());
    assert!(target_writers.is_empty());
}

#[tokio::test]
async fn closing_session_aborts_udp_flows_and_cancels_pending_udp_opens() {
    let cancel = OpenFlowCancel::new(TEST_FLOW_TOKEN);
    let udp_flow = test_udp_flow().await;
    let control = udp_flow.control.clone();
    let mut target_writers = FlowTable::new();
    target_writers.insert(1, FlowSlot::OpeningUdp(cancel.clone()));
    target_writers.insert(3, FlowSlot::Udp(udp_flow));

    close_target_flows(&mut target_writers);

    assert!(cancel.is_cancelled());
    assert!(control.is_aborted());
    assert!(target_writers.is_empty());
}

#[tokio::test]
async fn target_connect_deadline_maps_elapsed_to_target_timeout() {
    let deadline = time::Instant::now() + Duration::from_millis(1);
    let result = with_target_connect_deadline(Some(deadline), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    })
    .await;

    assert!(matches!(result, Err(OpenFailure::TargetTimeout)));
}

#[test]
fn unrepresentable_target_connect_deadline_disables_timeout() {
    assert_eq!(target_connect_deadline(Some(Duration::MAX)), None);
}

#[tokio::test]
async fn target_connect_timeout_releases_candidate_permits() {
    struct ActiveCandidateGuard {
        active: Arc<AtomicUsize>,
    }

    impl Drop for ActiveCandidateGuard {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let first_addr = SocketAddr::from(([127, 0, 0, 1], 10_001));
    let second_addr = SocketAddr::from(([127, 0, 0, 1], 10_002));
    let addrs = [first_addr, second_addr];
    let limiter = OpenDialLimiter::new(2);
    let active = Arc::new(AtomicUsize::new(0));
    let (started_tx, mut started_rx) = mpsc::channel(2);
    let connector: TargetConnector<SocketAddr> = {
        let active = Arc::clone(&active);
        Arc::new(move |addr| -> BoxedConnectFuture<SocketAddr> {
            let active = Arc::clone(&active);
            let started_tx = started_tx.clone();
            Box::pin(async move {
                active.fetch_add(1, Ordering::SeqCst);
                let _guard = ActiveCandidateGuard { active };
                let _ = started_tx.send(addr).await;
                std::future::pending::<()>().await;
                (addr, Ok(addr))
            })
        })
    };

    let deadline = time::Instant::now() + Duration::from_millis(50);
    let connector_for_task = Arc::clone(&connector);
    let limiter_for_task = limiter.clone();
    let result_task = tokio::spawn(async move {
        connect_first_successful(
            &addrs,
            &connector_for_task,
            &limiter_for_task,
            Some(deadline),
        )
        .await
    });

    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let result = result_task.await.unwrap();

    assert!(matches!(result, Err(OpenFailure::TargetTimeout)));
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(limiter.available_permits(), 2);
}

#[tokio::test]
async fn target_connect_uses_later_candidate_while_first_is_pending() {
    let first_addr = SocketAddr::from(([127, 0, 0, 1], 10_001));
    let second_addr = SocketAddr::from(([127, 0, 0, 1], 10_002));
    let addrs = [first_addr, second_addr];
    let limiter = OpenDialLimiter::new(2);
    let connector: TargetConnector<SocketAddr> =
        Arc::new(move |addr| -> BoxedConnectFuture<SocketAddr> {
            Box::pin(async move {
                if addr == first_addr {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    return (
                        addr,
                        Err(io::Error::new(io::ErrorKind::TimedOut, "still pending")),
                    );
                }
                (addr, Ok(addr))
            })
        });

    let connected = tokio::time::timeout(
        Duration::from_millis(100),
        connect_first_successful(&addrs, &connector, &limiter, None),
    )
    .await
    .expect("later candidate should complete before the first candidate")
    .expect("later candidate should succeed");

    assert_eq!(connected, second_addr);
    assert_eq!(limiter.available_permits(), 2);
}

#[tokio::test]
async fn dropping_connect_tasks_aborts_inflight_tasks() {
    struct DropGuard(Arc<AtomicBool>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let addr = SocketAddr::from(([127, 0, 0, 1], 10_001));
    let limiter = OpenDialLimiter::new(1);
    let permit = limiter.try_acquire().unwrap();

    let started = Arc::new(AtomicBool::new(false));
    let started_clone = Arc::clone(&started);
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancelled_clone = Arc::clone(&cancelled);

    let connector: TargetConnector<SocketAddr> =
        Arc::new(move |addr| -> BoxedConnectFuture<SocketAddr> {
            let started = Arc::clone(&started_clone);
            let cancelled = Arc::clone(&cancelled_clone);
            Box::pin(async move {
                let _guard = DropGuard(cancelled);
                started.store(true, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(60)).await;
                (addr, Ok(addr))
            })
        });

    let mut tasks = ConnectTasks::new();
    tasks.spawn(addr, &connector, permit);

    for _ in 0..100 {
        if started.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(started.load(Ordering::SeqCst));
    assert!(!cancelled.load(Ordering::SeqCst));

    drop(tasks);

    for _ in 0..100 {
        if cancelled.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        cancelled.load(Ordering::SeqCst),
        "in-flight connect task was not aborted upon drop"
    );
}

#[tokio::test]
async fn target_connect_rejects_when_dial_limiter_is_exhausted() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 10_001));
    let addrs = [addr];
    let limiter = OpenDialLimiter::new(0);
    let calls = Arc::new(AtomicUsize::new(0));
    let connector: TargetConnector<SocketAddr> = {
        let calls = Arc::clone(&calls);
        Arc::new(move |addr| -> BoxedConnectFuture<SocketAddr> {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                (addr, Ok(addr))
            })
        })
    };

    let result = connect_first_successful(&addrs, &connector, &limiter, None).await;

    assert!(matches!(result, Err(OpenFailure::ResourceLimit)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn accepts_resolved_target_address_limit() {
    let addrs = (0..TARGET_RESOLUTION_ADDR_LIMIT)
        .map(|index| SocketAddr::from(([127, 0, 0, 1], 10_000 + index as u16)));

    let resolved = collect_resolved_addrs(addrs).unwrap();

    assert_eq!(resolved.len(), TARGET_RESOLUTION_ADDR_LIMIT);
}

#[test]
fn rejects_excessive_resolved_target_addresses() {
    let addrs = (0..=TARGET_RESOLUTION_ADDR_LIMIT)
        .map(|index| SocketAddr::from(([127, 0, 0, 1], 10_000 + index as u16)));

    let error = collect_resolved_addrs(addrs).unwrap_err();

    assert!(matches!(
        error,
        OpenFailure::TargetUnavailable(ref err)
            if err.kind() == io::ErrorKind::InvalidData
                && err.to_string().contains("more than")
    ));
}

#[test]
fn rejects_empty_resolved_target_addresses() {
    let error = collect_resolved_addrs(std::iter::empty()).unwrap_err();

    assert!(matches!(
        error,
        OpenFailure::TargetUnavailable(ref err) if err.kind() == io::ErrorKind::NotFound
    ));
}

#[tokio::test]
async fn target_connect_limits_concurrent_candidate_dials() {
    let first_addr = SocketAddr::from(([127, 0, 0, 1], 10_001));
    let second_addr = SocketAddr::from(([127, 0, 0, 1], 10_002));
    let addrs = [first_addr, second_addr];
    let limiter = OpenDialLimiter::new(1);
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let connector: TargetConnector<SocketAddr> = {
        let active = Arc::clone(&active);
        let max_active = Arc::clone(&max_active);
        Arc::new(move |addr| -> BoxedConnectFuture<SocketAddr> {
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            Box::pin(async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(current, Ordering::SeqCst);
                let result = if addr == first_addr {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Err(io::Error::new(io::ErrorKind::TimedOut, "first failed"))
                } else {
                    Ok(addr)
                };
                active.fetch_sub(1, Ordering::SeqCst);
                (addr, result)
            })
        })
    };

    let connected = tokio::time::timeout(
        Duration::from_secs(1),
        connect_first_successful(&addrs, &connector, &limiter, None),
    )
    .await
    .expect("connect should not hang")
    .expect("second candidate should succeed");

    assert_eq!(connected, second_addr);
    assert_eq!(max_active.load(Ordering::SeqCst), 1);
    assert_eq!(limiter.available_permits(), 1);
}

#[tokio::test]
async fn udp_target_connect_binds_matching_ip_family() {
    let target = SocketAddr::from(([127, 0, 0, 1], 9));

    let (candidate, socket) = connect_udp_socket_addr(target).await;
    let socket = socket.unwrap();

    assert_eq!(candidate, target);
    assert!(socket.local_addr().unwrap().is_ipv4());
    assert_eq!(socket.peer_addr().unwrap(), target);
}

#[test]
fn caps_tcp_data_frame_size_to_frame_limit() {
    assert_eq!(
        tcp_data_frame_size(
            FrameLimits {
                max_frame_size: 1024
            },
            None
        ),
        1024
    );
    assert_eq!(
        tcp_data_frame_size(
            FrameLimits {
                max_frame_size: 65_536
            },
            None
        ),
        RELAY_BUFFER_SIZE
    );
    assert_eq!(
        tcp_data_frame_size(
            FrameLimits {
                max_frame_size: 65_536
            },
            Some(32 * 1024)
        ),
        32 * 1024
    );
}

#[test]
fn udp_payload_frame_limit_allows_boundary_only() {
    assert!(!udp_payload_exceeds_frame_limit(512, 512));
    assert!(udp_payload_exceeds_frame_limit(513, 512));
}

#[test]
fn accepts_server_session_transition_to_relaying() {
    let valid = [
        (
            ServerSessionState::Authenticated,
            ServerSessionState::Relaying,
        ),
        (ServerSessionState::Relaying, ServerSessionState::Draining),
        (ServerSessionState::Relaying, ServerSessionState::Closing),
        (ServerSessionState::Relaying, ServerSessionState::Closed),
        (ServerSessionState::Draining, ServerSessionState::Closing),
        (ServerSessionState::Draining, ServerSessionState::Closed),
        (ServerSessionState::Closing, ServerSessionState::Closed),
    ];

    for (from, next) in valid {
        assert!(is_valid_session_transition(from, next));
    }
}

#[test]
fn rejects_server_session_state_regression() {
    assert!(!is_valid_session_transition(
        ServerSessionState::Relaying,
        ServerSessionState::Authenticated
    ));
    assert!(!is_valid_session_transition(
        ServerSessionState::Closed,
        ServerSessionState::Relaying
    ));
    assert!(!is_valid_session_transition(
        ServerSessionState::Draining,
        ServerSessionState::Relaying
    ));
    assert!(!is_valid_session_transition(
        ServerSessionState::Closing,
        ServerSessionState::Draining
    ));
    assert!(!is_valid_session_transition(
        ServerSessionState::Closed,
        ServerSessionState::Draining
    ));
}

#[tokio::test]
async fn server_session_graceful_drain_completes_active_flows_and_rejects_new() {
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let (client_transport, server_transport) = tokio::io::duplex(65536);
    let (server_reader, server_writer) = tokio::io::split(server_transport);
    let carrier = ServerCarrier::new(Box::new(server_reader), Box::new(server_writer), None);

    let cred = uk_auth::Credential::active(
        b"user".to_vec(),
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let identity = AuthenticatedIdentity::from(&cred);
    let mut policy = uk_policy::PolicyRule::new(uk_policy::PolicyDecision::Allow);
    policy.ports = Some(1..=65535);
    policy.private = Some(true);
    let security = SecurityState::new(
        crate::security::test_tls_acceptor(),
        vec![cred],
        uk_policy::PolicySet::new(vec![policy]),
        Duration::from_secs(30),
    );
    let mut limits = test_relay_limits(10);
    limits.session_task_shutdown_timeout = Some(Duration::from_secs(5));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics = Arc::new(ServerMetrics::default());

    let session_handle = tokio::spawn(async move {
        relay_session(
            carrier,
            identity,
            security,
            limits,
            None,
            shutdown_rx,
            metrics,
        )
        .await
    });

    let (client_reader, mut client_writer) = tokio::io::split(client_transport);
    let mut client_frame_reader = FrameReader::new(Box::pin(client_reader), FrameLimits::default());

    // 1. Open Flow 1 before shutdown
    let target = Target::Ipv4(Ipv4Addr::LOCALHOST, target_addr.port());
    let mut payload = BytesMut::new();
    TcpOpen::new(target, TCP_OPEN_FLAGS_NONE)
        .encode(&mut payload)
        .unwrap();
    let frame = Frame::new(FrameType::TcpOpen, 0, 1, payload.freeze()).unwrap();
    write_frame(&mut client_writer, &frame).await.unwrap();

    let (mut target_stream, _) = target_listener.accept().await.unwrap();
    let open_ack = client_frame_reader.read_frame().await.unwrap();
    assert_eq!(open_ack.header.frame_type, FrameType::TcpData);
    assert_eq!(open_ack.header.id, 1);

    // 2. Trigger graceful shutdown signal
    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Client attempts to open new Flow 2 during Draining -> must be rejected with ResourceLimit
    let target2 = Target::Ipv4(Ipv4Addr::LOCALHOST, target_addr.port());
    let mut payload2 = BytesMut::new();
    TcpOpen::new(target2, TCP_OPEN_FLAGS_NONE)
        .encode(&mut payload2)
        .unwrap();
    let frame2 = Frame::new(FrameType::TcpOpen, 0, 3, payload2.freeze()).unwrap();
    write_frame(&mut client_writer, &frame2).await.unwrap();

    let reject_frame = client_frame_reader.read_frame().await.unwrap();
    assert_eq!(reject_frame.header.frame_type, FrameType::ResourceLimit);
    assert_eq!(reject_frame.header.id, 3);

    let close_frame = client_frame_reader.read_frame().await.unwrap();
    assert_eq!(close_frame.header.frame_type, FrameType::TcpClose);
    assert_eq!(close_frame.header.id, 3);

    // 4. Existing Flow 1 continues duplex data transfer during Draining
    let data_frame =
        Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"ping data")).unwrap();
    write_frame(&mut client_writer, &data_frame).await.unwrap();

    let mut buf = [0u8; 9];
    target_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping data");

    target_stream.write_all(b"pong reply").await.unwrap();
    target_stream.shutdown().await.unwrap();

    let reply_frame = client_frame_reader.read_frame().await.unwrap();
    assert_eq!(reply_frame.header.frame_type, FrameType::TcpData);
    assert_eq!(reply_frame.header.id, 1);
    assert_eq!(&reply_frame.payload[..], b"pong reply");

    // 5. Client finishes Flow 1
    let mut close_payload = BytesMut::new();
    TcpClose::new(TCP_CLOSE_NORMAL)
        .encode(&mut close_payload)
        .unwrap();
    let close_1 = Frame::new(FrameType::TcpClose, 0, 1, close_payload.freeze()).unwrap();
    write_frame(&mut client_writer, &close_1).await.unwrap();

    // 6. Session cleanly finishes drain phase
    let session_res = tokio::time::timeout(Duration::from_secs(2), session_handle)
        .await
        .expect("session should finish draining promptly")
        .expect("task join");
    assert!(session_res.is_ok());
}

#[tokio::test]
async fn server_session_drain_timeout_aborts_hung_flows() {
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let (client_transport, server_transport) = tokio::io::duplex(65536);
    let (server_reader, server_writer) = tokio::io::split(server_transport);
    let carrier = ServerCarrier::new(Box::new(server_reader), Box::new(server_writer), None);

    let cred = uk_auth::Credential::active(
        b"user".to_vec(),
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let identity = AuthenticatedIdentity::from(&cred);
    let mut policy = uk_policy::PolicyRule::new(uk_policy::PolicyDecision::Allow);
    policy.ports = Some(1..=65535);
    policy.private = Some(true);
    let security = SecurityState::new(
        crate::security::test_tls_acceptor(),
        vec![cred],
        uk_policy::PolicySet::new(vec![policy]),
        Duration::from_secs(30),
    );
    let mut limits = test_relay_limits(10);
    // Configure a very short drain timeout (50ms)
    limits.session_task_shutdown_timeout = Some(Duration::from_millis(50));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics = Arc::new(ServerMetrics::default());

    let session_handle = tokio::spawn(async move {
        relay_session(
            carrier,
            identity,
            security,
            limits,
            None,
            shutdown_rx,
            metrics,
        )
        .await
    });

    let (client_reader, mut client_writer) = tokio::io::split(client_transport);
    let mut client_frame_reader = FrameReader::new(Box::pin(client_reader), FrameLimits::default());

    // Open Flow 1
    let target = Target::Ipv4(Ipv4Addr::LOCALHOST, target_addr.port());
    let mut payload = BytesMut::new();
    TcpOpen::new(target, TCP_OPEN_FLAGS_NONE)
        .encode(&mut payload)
        .unwrap();
    let frame = Frame::new(FrameType::TcpOpen, 0, 1, payload.freeze()).unwrap();
    write_frame(&mut client_writer, &frame).await.unwrap();

    let (_target_stream, _) = target_listener.accept().await.unwrap();
    let open_ack = client_frame_reader.read_frame().await.unwrap();
    assert_eq!(open_ack.header.frame_type, FrameType::TcpData);

    // Trigger shutdown — flow remains open and never closes
    shutdown_tx.send(true).unwrap();

    // The session should hit DrainTimeout after ~50ms and forcefully exit
    let session_res = tokio::time::timeout(Duration::from_secs(2), session_handle)
        .await
        .expect("session should time out and exit")
        .expect("task join");
    assert!(session_res.is_ok());
}

#[tokio::test]
async fn server_session_zero_flows_instant_shutdown() {
    let (_client_transport, server_transport) = tokio::io::duplex(65536);
    let (server_reader, server_writer) = tokio::io::split(server_transport);
    let carrier = ServerCarrier::new(Box::new(server_reader), Box::new(server_writer), None);

    let cred = uk_auth::Credential::active(
        b"user".to_vec(),
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let identity = AuthenticatedIdentity::from(&cred);
    let security = SecurityState::new(
        crate::security::test_tls_acceptor(),
        vec![cred],
        uk_policy::PolicySet::default(),
        Duration::from_secs(30),
    );
    let limits = test_relay_limits(10);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics = Arc::new(ServerMetrics::default());

    let session_handle = tokio::spawn(async move {
        relay_session(
            carrier,
            identity,
            security,
            limits,
            None,
            shutdown_rx,
            metrics,
        )
        .await
    });

    // Trigger shutdown immediately with 0 active flows
    shutdown_tx.send(true).unwrap();

    let session_res = tokio::time::timeout(Duration::from_millis(500), session_handle)
        .await
        .expect("zero-flow session should exit instantaneously")
        .expect("task join");
    assert!(session_res.is_ok());
}

#[test]
fn target_write_queue_capacity_tracks_byte_limit() {
    assert_eq!(
        target_write_queue_capacity(1024),
        TARGET_WRITE_QUEUE_MIN_CAPACITY
    );
    assert_eq!(target_write_queue_capacity(2 * 1024 * 1024), 2048);
    assert_eq!(
        target_write_queue_capacity(64 * 1024 * 1024),
        TARGET_WRITE_QUEUE_MAX_CAPACITY
    );
}

#[tokio::test]
async fn review_drain_drops_data_after_both_half_closes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_socket = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut target, _) = listener.accept().await.unwrap();
    let (_, target_writer) = relay_socket.into_split();
    let (tx, rx) = mpsc::channel(10);
    let flow_control = TargetFlowControl::default();
    let mut flow = TargetFlow::new(TEST_FLOW_TOKEN, tx, flow_control.clone());
    flow.mark_target_to_client_closed();
    flow.enqueue_data(Bytes::from_static(b"last request bytes"), 1000, 1000)
        .unwrap();
    flow.close_client_to_target();
    assert!(flow.is_fully_closed());
    drop(flow); // Same remove_flow_slot path after client TCP_CLOSE.
    let (event_tx, _event_rx) = mpsc::channel(10);
    let shutdown = SessionShutdown::default();
    let writer = CarrierWriter::new(
        Box::new(tokio::io::sink()),
        shutdown.clone(),
        Arc::new(ServerMetrics::default()),
        Some(Duration::from_secs(1)),
    );
    let mut tasks = SessionTasks::default();
    spawn_target_writer(
        &mut tasks,
        TargetWriterTask {
            identity: TargetFlowIdentity {
                flow_id: 1,
                token: TEST_FLOW_TOKEN,
            },
            target_writer,
            commands: rx,
            flow_control,
            carrier_writer: writer.clone(),
            event_tx,
            shutdown: shutdown.clone(),
            write_timeout: Some(Duration::from_secs(1)),
        },
    );
    let mut state = ServerSessionState::Draining;
    let mut table = FlowTable::new();
    // Draining loop sees empty table and invokes this while writer has queued bytes.
    close_session(
        &mut state,
        &shutdown,
        &mut table,
        &mut tasks,
        &writer,
        Some(Duration::from_secs(1)),
    )
    .await;
    let mut received = Vec::new();
    target.read_to_end(&mut received).await.unwrap();
    assert_eq!(
        received, b"last request bytes",
        "drain acknowledged both closes but discarded queued target data"
    );
}

#[tokio::test]
async fn review_closed_flows_leave_half_close_timers() {
    let mut tasks = SessionTasks::default();
    let mut table = FlowTable::new();
    let (event_tx, _event_rx) = mpsc::channel(1000);
    let shutdown = SessionShutdown::default();
    for id in (1..=199).step_by(2) {
        assert!(check_open_slot(id, &table, 1).is_ok());
        table.insert(id, test_open_flow_slot());
        handle_target_read_closed(
            id,
            TEST_FLOW_TOKEN,
            Some(Duration::from_secs(30)),
            &event_tx,
            &shutdown,
            &mut table,
            &mut tasks,
        );
        handle_target_write_closed(id, TEST_FLOW_TOKEN, &mut table);
        assert!(table.is_empty());
    }
    tokio::task::yield_now().await;
    assert!(
        tasks.len() <= 1,
        "max_streams=1 but {} timers remain after 100 fully closed flows",
        tasks.len()
    );
}

#[tokio::test]
async fn stress_rapid_flow_churn_and_timer_counts() {
    let mut tasks = SessionTasks::default();
    let mut table = FlowTable::new();
    let (event_tx, _event_rx) = mpsc::channel(10000);
    let shutdown = SessionShutdown::default();

    // Pattern 1: Target read closed first, then target write closed (1000 flows)
    for id in 1..=1000 {
        assert!(check_open_slot(id, &table, 1).is_ok());
        table.insert(id, test_open_flow_slot());
        handle_target_read_closed(
            id,
            TEST_FLOW_TOKEN,
            Some(Duration::from_secs(30)),
            &event_tx,
            &shutdown,
            &mut table,
            &mut tasks,
        );
        assert_eq!(
            tasks.len(),
            1,
            "Active timer count should be 1 during half-close"
        );
        handle_target_write_closed(id, TEST_FLOW_TOKEN, &mut table);
        assert!(table.is_empty());
        assert_eq!(
            tasks.len(),
            0,
            "Timer must be immediately cancelled and reaped upon flow close"
        );
    }

    // Pattern 2: Client TCP_CLOSE first, then target read closed, then target write closed (1000 flows)
    for id in 1001..=2000 {
        assert!(check_open_slot(id, &table, 1).is_ok());
        table.insert(id, test_open_flow_slot());
        if let Some(FlowSlot::Tcp(flow)) = table.get_mut(&id) {
            flow.close_client_to_target();
            let timer = spawn_half_close_timer(
                &mut tasks,
                id,
                TEST_FLOW_TOKEN,
                HalfCloseSide::ClientToTarget,
                Duration::from_secs(30),
                event_tx.clone(),
                shutdown.clone(),
            );
            flow.set_half_close_timer(timer);
        }
        assert_eq!(
            tasks.len(),
            1,
            "Active timer count should be 1 during client half-close"
        );
        handle_target_read_closed(
            id,
            TEST_FLOW_TOKEN,
            Some(Duration::from_secs(30)),
            &event_tx,
            &shutdown,
            &mut table,
            &mut tasks,
        );
        handle_target_write_closed(id, TEST_FLOW_TOKEN, &mut table);
        assert!(table.is_empty());
        assert_eq!(
            tasks.len(),
            0,
            "Timer must be cancelled when write completes"
        );
    }

    // Pattern 3: Flow aborted midway during half-close (1000 flows)
    for id in 2001..=3000 {
        assert!(check_open_slot(id, &table, 1).is_ok());
        table.insert(id, test_open_flow_slot());
        handle_target_read_closed(
            id,
            TEST_FLOW_TOKEN,
            Some(Duration::from_secs(30)),
            &event_tx,
            &shutdown,
            &mut table,
            &mut tasks,
        );
        assert_eq!(tasks.len(), 1);
        if let Some(FlowSlot::Tcp(flow)) = table.get_mut(&id) {
            flow.abort();
        }
        table.remove(&id);
        assert_eq!(tasks.len(), 0, "Timer must be cancelled upon abort");
    }

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(tasks.len(), 0);
    assert_eq!(
        tasks.kinds.len(),
        0,
        "tasks.kinds leaked! length is {}",
        tasks.kinds.len()
    );
    assert_eq!(
        tasks.cancelled.len(),
        0,
        "tasks.cancelled leaked! length is {}",
        tasks.cancelled.len()
    );
}

#[tokio::test]
async fn review_aborted_flow_still_sends_queued_data() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_socket = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut target, _) = listener.accept().await.unwrap();
    let (reader, _) = relay_socket.into_split();
    let shutdown = SessionShutdown::default();
    let control = TargetFlowControl::default();
    let (carrier_output, mut carrier_input) = tokio::io::duplex(1000);
    let writer = CarrierWriter::new(
        Box::new(carrier_output),
        shutdown.clone(),
        Arc::new(ServerMetrics::default()),
        Some(Duration::from_secs(1)),
    );
    let guard = writer.inner.lock().await;
    let (event_tx, _event_rx) = mpsc::channel(10);
    let task_control = control.clone();
    let task_writer = writer.clone();
    let task_shutdown = shutdown.clone();
    target.write_all(b"stale target bytes").await.unwrap();
    let task = tokio::spawn(async move {
        relay_target_to_client(
            1,
            reader,
            task_control,
            &task_writer,
            &event_tx,
            &task_shutdown,
            100,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    control.abort(); // Client closes ID 1 while old reader waits for carrier lock.
    drop(guard);
    task.await.unwrap().unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(30),
            read_frame(&mut carrier_input, FrameLimits::default())
        )
        .await
        .is_err(),
        "old flow emitted data after abort instead of discarding queued frame"
    );
}

#[tokio::test]
async fn review_aborted_flow_contended_locks_drops_only_aborted_data() {
    let shutdown = SessionShutdown::default();
    let (carrier_output, mut carrier_input) = tokio::io::duplex(4096);
    let writer = CarrierWriter::new(
        Box::new(carrier_output),
        shutdown.clone(),
        Arc::new(ServerMetrics::default()),
        Some(Duration::from_secs(1)),
    );

    // Flow 1: holds lock
    let guard = writer.inner.lock().await;

    // Flow 2: will be aborted while waiting
    let control2 = TargetFlowControl::default();
    let writer2 = writer.clone();
    let control2_clone = control2.clone();
    let task2 = tokio::spawn(async move {
        let frame =
            Frame::new(FrameType::TcpData, 0, 2, Bytes::from_static(b"flow 2 data")).unwrap();
        write_flow_frame_locked(&writer2, &frame, &control2_clone).await
    });

    // Flow 3: will be aborted while waiting
    let control3 = TargetFlowControl::default();
    let writer3 = writer.clone();
    let control3_clone = control3.clone();
    let task3 = tokio::spawn(async move {
        let frame =
            Frame::new(FrameType::TcpData, 0, 3, Bytes::from_static(b"flow 3 data")).unwrap();
        write_flow_frame_locked(&writer3, &frame, &control3_clone).await
    });

    // Flow 4: will NOT be aborted
    let control4 = TargetFlowControl::default();
    let writer4 = writer.clone();
    let control4_clone = control4.clone();
    let task4 = tokio::spawn(async move {
        let frame =
            Frame::new(FrameType::TcpData, 0, 4, Bytes::from_static(b"flow 4 data")).unwrap();
        write_flow_frame_locked(&writer4, &frame, &control4_clone).await
    });

    tokio::time::sleep(Duration::from_millis(30)).await;

    // Abort flows 2 and 3
    control2.abort();
    control3.abort();

    // Release carrier lock
    drop(guard);

    task2.await.unwrap().unwrap();
    task3.await.unwrap().unwrap();
    task4.await.unwrap().unwrap();

    // Flow 4 must be received on carrier
    let received = tokio::time::timeout(
        Duration::from_millis(100),
        read_frame(&mut carrier_input, FrameLimits::default()),
    )
    .await
    .expect("must not time out reading valid flow 4 frame")
    .expect("frame read must succeed");

    assert_eq!(received.header.id, 4);
    assert_eq!(received.payload.as_ref(), b"flow 4 data");

    // No further frames should be available (flows 2 and 3 were dropped)
    assert!(
        tokio::time::timeout(
            Duration::from_millis(30),
            read_frame(&mut carrier_input, FrameLimits::default()),
        )
        .await
        .is_err(),
        "aborted flows 2 and 3 must not have sent any frames"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn review_real_relay_drain_loses_tail_of_upload() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, server) = tokio::io::duplex(4 * 1024 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server);
    let carrier = ServerCarrier::new(Box::new(server_reader), Box::new(server_writer), None);
    let cred = uk_auth::Credential::active(
        b"user".to_vec(),
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let identity = AuthenticatedIdentity::from(&cred);
    let mut rule = uk_policy::PolicyRule::new(uk_policy::PolicyDecision::Allow);
    rule.private = Some(true);
    let security = SecurityState::new(
        crate::security::test_tls_acceptor(),
        vec![cred],
        PolicySet::new(vec![rule]),
        Duration::from_secs(30),
    );
    let mut limits = test_relay_limits(1);
    limits.max_buffered_bytes_per_flow = 2 * 1024 * 1024;
    limits.max_buffered_bytes_per_session = 16 * 1024 * 1024;
    limits.carrier_write_timeout = Some(Duration::from_secs(30));
    limits.tcp_half_close_timeout = Some(Duration::from_secs(30));
    limits.session_task_shutdown_timeout = Some(Duration::from_secs(30));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics = Arc::new(ServerMetrics::default());
    let session = tokio::spawn(relay_session(
        carrier,
        identity,
        security,
        limits,
        None,
        shutdown_rx,
        metrics,
    ));
    let (client_reader, mut client_writer) = tokio::io::split(client);
    let mut frames = FrameReader::new(client_reader, FrameLimits::default());
    let mut open = BytesMut::new();
    TcpOpen::new(
        Target::Ipv4(Ipv4Addr::LOCALHOST, address.port()),
        TCP_OPEN_FLAGS_NONE,
    )
    .encode(&mut open)
    .unwrap();
    write_frame(
        &mut client_writer,
        &Frame::new(FrameType::TcpOpen, 0, 1, open.freeze()).unwrap(),
    )
    .await
    .unwrap();
    let (mut target, _) = listener.accept().await.unwrap();
    socket2::SockRef::from(&target)
        .set_recv_buffer_size(1024)
        .unwrap();
    let ack = frames.read_frame().await.unwrap();
    assert_eq!(ack.header.frame_type, FrameType::TcpData);
    target.shutdown().await.unwrap(); // Target sends FIN but can still receive an upload.
    let close = frames.read_frame().await.unwrap();
    assert_eq!(close.header.frame_type, FrameType::TcpClose);
    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let payload = Bytes::from(vec![0x6d; 1024 * 1024]);
    for start in (0..payload.len()).step_by(65536) {
        write_frame(
            &mut client_writer,
            &Frame::new(
                FrameType::TcpData,
                0,
                1,
                payload.slice(start..start + 65536),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    }
    let mut closing = BytesMut::new();
    TcpClose::new(TCP_CLOSE_NORMAL)
        .encode(&mut closing)
        .unwrap();
    write_frame(
        &mut client_writer,
        &Frame::new(FrameType::TcpClose, 0, 1, closing.freeze()).unwrap(),
    )
    .await
    .unwrap();
    // Delay consumption briefly to keep upload writes queued within the 30s drain budget.
    time::sleep(Duration::from_millis(50)).await;
    let _ = socket2::SockRef::from(&target).set_recv_buffer_size(128 * 1024);
    let mut received = Vec::new();
    let _ = time::timeout(Duration::from_secs(5), target.read_to_end(&mut received))
        .await
        .unwrap();
    let session_result = time::timeout(Duration::from_secs(2), session)
        .await
        .unwrap()
        .unwrap();
    assert!(session_result.is_ok(), "session failed: {session_result:?}");
    assert_eq!(
        received.len(),
        payload.len(),
        "graceful shutdown reported success while truncating upload"
    );
}
