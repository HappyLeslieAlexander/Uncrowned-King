#![allow(unused_imports, clippy::wildcard_imports)]

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use super::carrier::*;
use super::context::*;
use super::listener::*;
use super::session_manager::*;
use super::tcp::*;
use super::udp::*;
use crate::{
    ClientReloadReceiver, ClientReloadRequest, config::*, config_state::*, observability::*,
    session, socks5,
};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        TcpListener, TcpStream, UdpSocket,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::{Id, JoinError, JoinSet},
    time,
};
use tracing::{Instrument, Span, debug, error, info, warn};
use uk_auth::{AuthenticatedIdentity, unix_now};
use uk_proto::{varint::MAX_VARINT, *};

const FLOW_ID: u64 = 1;
const CONTROL_PEER_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

fn negotiated_settings_with_idle_timeout(idle_timeout_seconds: u64) -> NegotiatedSettings {
    NegotiatedSettings {
        max_frame_size: FrameLimits::default().max_frame_size,
        max_streams: 64,
        max_udp_flows: 64,
        supports_udp_datagram: false,
        supports_udp_stream_fallback: true,
        idle_timeout_seconds,
    }
}

fn minimal_config() -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1:443".to_owned(),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: "missing-ca.pem".to_owned(),
        key_id: "client".to_owned(),
        secret: "0123456789abcdef0123456789abcdef".to_owned(),
        handshake_timeout_seconds: None,
        server_connect_retry_delay_millis: None,
        socks_handshake_timeout_seconds: None,
        tcp_open_timeout_seconds: None,
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: None,
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
        max_carrier_sessions: None,
        relay_buffer_size: None,
    }
}

fn test_session_manager(config: ClientConfig) -> ClientSessionManager {
    ClientSessionManager::new(config, Arc::new(ClientMetrics::default()))
}

/// Builds a session that is structurally complete but carries no live
/// carrier tasks, for exercising admission and teardown without a server.
fn test_session(max_streams: u64, max_udp_flows: u64) -> Arc<ClientSession> {
    let limits = FrameLimits::default();
    let (carrier_writer, _carrier_reader) = tokio::io::duplex(64);
    Arc::new(ClientSession {
        correlation_id: 1,
        config_generation: 1,
        writer: Arc::new(Mutex::new(Box::new(carrier_writer))),
        flows: Arc::new(Mutex::new(HashMap::new())),
        limits,
        data_frame_size: tcp_data_frame_size(limits, None),
        max_streams,
        max_udp_flows,
        admission: FlowAdmissionControl::new(max_streams, max_udp_flows),
        supports_udp_stream_fallback: true,
        supports_udp_datagram: false,
        datagrams: None,
        max_pending_open_bytes: 1024,
        max_buffered_bytes_per_session: 1024,
        max_buffered_bytes_per_flow: 1024,
        session_buffer: ClientSessionBufferControl::default(),
        open_timeout: None,
        task_shutdown_timeout: Some(Duration::from_millis(50)),
        tasks: Mutex::new(ClientSessionTasks::default()),
        shutdown: ClientSessionShutdown::default(),
        draining: AtomicBool::new(false),
        metrics: Arc::new(ClientMetrics::default()),
        metric_state: StdMutex::new(ClientSessionMetricState::Active),
        next_flow_id: AtomicU64::new(FIRST_CLIENT_FLOW_ID),
        next_ping_nonce: AtomicU64::new(0),
        outstanding_ping_nonce: AtomicU64::new(0),
        last_pong_nonce: AtomicU64::new(0),
        pong_notify: Notify::new(),
    })
}

/// Stands in for a server that never accepts another byte and never
/// completes a shutdown — a peer whose socket buffers are full, or a host
/// blackholing packets. `tokio::io::duplex` cannot model this because its
/// `poll_shutdown` completes immediately.
struct StallingWriter;

impl AsyncWrite for StallingWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Pending
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Pending
    }
}

/// A session whose carrier never finishes closing.
fn test_session_with_stalled_carrier(
    task_shutdown_timeout: Option<Duration>,
) -> Arc<ClientSession> {
    let session = test_session(4, 4);
    let mut session = Arc::try_unwrap(session).ok().expect("sole owner");
    session.writer = Arc::new(Mutex::new(Box::new(StallingWriter)));
    session.task_shutdown_timeout = task_shutdown_timeout;
    Arc::new(session)
}

/// Closing must not hang on a server that cannot accept `close_notify`:
/// this runs from the listener's accept loop on config reload, and from
/// relay tasks when a draining session loses its last flow.
#[tokio::test]
async fn close_gives_up_on_a_carrier_that_never_finishes_closing() {
    let session = test_session_with_stalled_carrier(Some(Duration::from_millis(100)));

    tokio::time::timeout(Duration::from_secs(5), session.close())
        .await
        .expect("close must not block on an unresponsive carrier");

    assert!(session.is_closed());
}

/// Pruning a dead session must not be awaited on the flow-open path — two
/// of those call sites hold `connect_lock`, so one hung carrier would stall
/// every new SOCKS connection.
#[tokio::test]
async fn pruning_a_dead_session_does_not_block_the_flow_open_path() {
    let manager = test_session_manager(minimal_config());
    // No task-drain deadline and a task that never finishes, so this
    // session's teardown would block forever if it were awaited inline.
    let session = test_session_with_stalled_carrier(None);
    session
        .tasks
        .lock()
        .await
        .spawn(ClientSessionTaskKind::CarrierReader, async {
            std::future::pending::<()>().await;
        });
    // Mark it closed directly rather than via `close()`: with no drain
    // deadline `close()` would itself block on the stalled carrier, which
    // is the situation under test, not part of the setup.
    session.shutdown.close();
    assert!(session.is_closed());
    manager.pool.lock().await.push(session);

    let live = tokio::time::timeout(Duration::from_secs(5), manager.live_sessions())
        .await
        .expect("pruning must not await the stale session's teardown");

    assert!(live.is_empty(), "the closed session should be pruned");
}

fn boxed_io_error(kind: io::ErrorKind) -> AnyError {
    io::Error::new(kind, "test error").into()
}

fn expect_session_error(result: Result<Arc<ClientSession>, AnyError>) -> AnyError {
    match result {
        Ok(_) => panic!("session connect unexpectedly succeeded"),
        Err(err) => err,
    }
}

fn status_payload(code: ErrorCode) -> Bytes {
    let mut payload = BytesMut::new();
    ErrorPayload::new(code).encode(&mut payload).unwrap();
    payload.freeze()
}

fn error_frame_for(flow_id: u64, code: ErrorCode) -> Frame {
    Frame::new(FrameType::Error, 0, flow_id, status_payload(code)).unwrap()
}

fn error_frame(code: ErrorCode) -> Frame {
    error_frame_for(FLOW_ID, code)
}

fn data_frame(flow_id: u64, payload: Bytes) -> Frame {
    Frame::new(FrameType::TcpData, 0, flow_id, payload).unwrap()
}

fn close_frame(close_code: u16) -> Frame {
    let mut payload = BytesMut::new();
    TcpClose::new(close_code).encode(&mut payload).unwrap();
    Frame::new(FrameType::TcpClose, 0, FLOW_ID, payload.freeze()).unwrap()
}

fn udp_data_frame(flow_id: u64, payload: Bytes) -> Frame {
    Frame::new(FrameType::UdpData, 0, flow_id, payload).unwrap()
}

fn udp_close_frame(close_code: u16) -> Frame {
    let mut payload = BytesMut::new();
    UdpClose::new(close_code).encode(&mut payload).unwrap();
    Frame::new(FrameType::UdpClose, 0, FLOW_ID, payload.freeze()).unwrap()
}

fn control_frame(frame_type: FrameType, flow_id: u64) -> Frame {
    Frame::new(frame_type, 0, flow_id, Bytes::new()).unwrap()
}

fn route_test_flow_frame(
    frame: Frame,
    flows: &mut HashMap<u64, ClientFlowRoute>,
) -> (u64, FlowFrameRoute) {
    let (flow_id, _protocol, route) = route_flow_frame(
        frame,
        flows,
        ClientSessionBufferControl::default(),
        usize::MAX,
        usize::MAX,
    );
    (flow_id, route)
}

fn buffered_flow_frame(frame: Frame) -> BufferedFlowFrame {
    BufferedFlowFrame::new(
        frame,
        ClientFlowBufferControl::default(),
        ClientSessionBufferControl::default(),
        usize::MAX,
        usize::MAX,
    )
    .unwrap()
}

#[test]
fn reserve_flow_slot_allocates_route_when_capacity_is_available() {
    let mut flows = HashMap::new();
    let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
    let (sender, _receiver) = mpsc::channel(1);

    assert_eq!(
        reserve_flow_slot(
            &mut flows,
            1,
            &next_flow_id,
            sender,
            FlowProtocol::Tcp,
            u64::MAX,
        )
        .unwrap(),
        Some(FIRST_CLIENT_FLOW_ID)
    );

    assert!(flows.contains_key(&FIRST_CLIENT_FLOW_ID));
    assert_eq!(
        next_flow_id.load(Ordering::Relaxed),
        FIRST_CLIENT_FLOW_ID + FLOW_ID_STEP
    );
}

#[test]
fn reserve_flow_slot_does_not_consume_id_when_stream_limit_is_full() {
    let mut flows = HashMap::new();
    let (existing_sender, _existing_receiver) = mpsc::channel(1);
    flows.insert(
        FLOW_ID,
        ClientFlowRoute::new(existing_sender, FlowProtocol::Tcp),
    );
    let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
    let (sender, _receiver) = mpsc::channel(1);

    assert_eq!(
        reserve_flow_slot(
            &mut flows,
            1,
            &next_flow_id,
            sender,
            FlowProtocol::Tcp,
            u64::MAX,
        )
        .unwrap(),
        None
    );

    assert_eq!(flows.len(), 1);
    assert_eq!(next_flow_id.load(Ordering::Relaxed), FIRST_CLIENT_FLOW_ID);
}

#[test]
fn reserve_flow_slot_enforces_udp_flow_limit() {
    let mut flows = HashMap::new();
    let (existing_sender, _existing_receiver) = mpsc::channel(1);
    flows.insert(
        FLOW_ID,
        ClientFlowRoute::new(existing_sender, FlowProtocol::Udp),
    );
    let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
    let (sender, _receiver) = mpsc::channel(1);

    assert_eq!(
        reserve_flow_slot(&mut flows, 8, &next_flow_id, sender, FlowProtocol::Udp, 1,).unwrap(),
        None
    );

    assert_eq!(flows.len(), 1);
    assert_eq!(next_flow_id.load(Ordering::Relaxed), FIRST_CLIENT_FLOW_ID);
}

#[test]
fn reserve_flow_slot_allows_tcp_when_udp_limit_is_full() {
    let mut flows = HashMap::new();
    let (existing_sender, _existing_receiver) = mpsc::channel(1);
    flows.insert(
        FLOW_ID,
        ClientFlowRoute::new(existing_sender, FlowProtocol::Udp),
    );
    let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
    let (sender, _receiver) = mpsc::channel(1);

    assert_eq!(
        reserve_flow_slot(&mut flows, 8, &next_flow_id, sender, FlowProtocol::Tcp, 1,).unwrap(),
        Some(FIRST_CLIENT_FLOW_ID + FLOW_ID_STEP)
    );
}

#[test]
fn zero_udp_flow_limit_disables_client_udp_reservation() {
    let mut flows = HashMap::new();
    let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
    let (sender, _receiver) = mpsc::channel(1);

    assert_eq!(
        reserve_flow_slot(&mut flows, 8, &next_flow_id, sender, FlowProtocol::Udp, 0,).unwrap(),
        None
    );

    assert!(flows.is_empty());
    assert_eq!(next_flow_id.load(Ordering::Relaxed), FIRST_CLIENT_FLOW_ID);
}

#[test]
fn routes_carrier_frame_to_existing_flow() {
    let (sender, mut receiver) = mpsc::channel(1);
    let mut flows = HashMap::new();
    flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));

    assert_eq!(
        route_test_flow_frame(
            data_frame(FLOW_ID, Bytes::from_static(b"hello")),
            &mut flows
        ),
        (FLOW_ID, FlowFrameRoute::Enqueued)
    );

    let frame = receiver.try_recv().unwrap().into_frame().unwrap();
    assert_eq!(frame.header.id, FLOW_ID);
    assert_eq!(frame.payload, Bytes::from_static(b"hello"));
    assert!(flows.contains_key(&FLOW_ID));
}

#[test]
fn rejects_udp_frame_for_tcp_flow_before_queueing() {
    let (sender, mut receiver) = mpsc::channel(1);
    let mut flows = HashMap::new();
    flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));

    assert_eq!(
        route_flow_frame(
            udp_data_frame(FLOW_ID, Bytes::from_static(b"wrong protocol")),
            &mut flows,
            ClientSessionBufferControl::default(),
            usize::MAX,
            usize::MAX,
        ),
        (
            FLOW_ID,
            Some(FlowProtocol::Tcp),
            FlowFrameRoute::ProtocolMismatch
        )
    );

    assert!(receiver.try_recv().is_err());
    assert!(!flows.contains_key(&FLOW_ID));
}

#[test]
fn rejects_tcp_frame_for_udp_flow_before_queueing() {
    let (sender, mut receiver) = mpsc::channel(1);
    let mut flows = HashMap::new();
    flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Udp));

    assert_eq!(
        route_flow_frame(
            data_frame(FLOW_ID, Bytes::from_static(b"wrong protocol")),
            &mut flows,
            ClientSessionBufferControl::default(),
            usize::MAX,
            usize::MAX,
        ),
        (
            FLOW_ID,
            Some(FlowProtocol::Udp),
            FlowFrameRoute::ProtocolMismatch
        )
    );

    assert!(receiver.try_recv().is_err());
    assert!(!flows.contains_key(&FLOW_ID));
}

#[test]
fn routes_flow_status_to_udp_flow() {
    let (sender, mut receiver) = mpsc::channel(1);
    let mut flows = HashMap::new();
    flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Udp));

    assert_eq!(
        route_test_flow_frame(error_frame(ErrorCode::Protocol), &mut flows),
        (FLOW_ID, FlowFrameRoute::Enqueued)
    );

    let frame = receiver.try_recv().unwrap().into_frame().unwrap();
    assert_eq!(frame.header.frame_type, FrameType::Error);
    assert!(flows.contains_key(&FLOW_ID));
}

#[test]
fn ignores_carrier_frame_for_unknown_flow() {
    let mut flows = HashMap::new();

    assert_eq!(
        route_test_flow_frame(data_frame(99, Bytes::from_static(b"late")), &mut flows),
        (99, FlowFrameRoute::UnknownFlow)
    );
    assert!(flows.is_empty());
}

#[test]
fn rejects_zero_id_carrier_flow_frame() {
    let mut flows = HashMap::new();

    assert_eq!(
        route_test_flow_frame(data_frame(0, Bytes::from_static(b"invalid")), &mut flows),
        (0, FlowFrameRoute::InvalidFlowId)
    );
    assert!(flows.is_empty());
}

#[test]
fn rejects_reserved_carrier_flow_frame() {
    let mut flows = HashMap::new();

    assert_eq!(
        route_test_flow_frame(data_frame(2, Bytes::from_static(b"reserved")), &mut flows),
        (2, FlowFrameRoute::InvalidFlowId)
    );
    assert!(flows.is_empty());
}

#[test]
fn removes_closed_flow_sender() {
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let mut flows = HashMap::new();
    flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));

    assert_eq!(
        route_test_flow_frame(data_frame(FLOW_ID, Bytes::from_static(b"late")), &mut flows),
        (FLOW_ID, FlowFrameRoute::FlowClosed)
    );
    assert!(!flows.contains_key(&FLOW_ID));
}

#[test]
fn removes_full_flow_sender() {
    let (sender, mut receiver) = mpsc::channel(1);
    sender
        .try_send(buffered_flow_frame(data_frame(
            FLOW_ID,
            Bytes::from_static(b"queued"),
        )))
        .unwrap();
    let mut flows = HashMap::new();
    flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));

    assert_eq!(
        route_test_flow_frame(
            data_frame(FLOW_ID, Bytes::from_static(b"overflow")),
            &mut flows
        ),
        (FLOW_ID, FlowFrameRoute::FlowQueueFull)
    );
    assert!(!flows.contains_key(&FLOW_ID));
    assert_eq!(
        receiver.try_recv().unwrap().into_frame().unwrap().payload,
        Bytes::from_static(b"queued")
    );
}

#[test]
fn removes_flow_when_flow_buffer_limit_is_exceeded() {
    let (sender, _receiver) = mpsc::channel(1);
    let mut flows = HashMap::new();
    flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));
    let session_buffer = ClientSessionBufferControl::default();

    assert_eq!(
        route_flow_frame(
            data_frame(FLOW_ID, Bytes::from_static(b"overflow")),
            &mut flows,
            session_buffer.clone(),
            4,
            usize::MAX,
        ),
        (
            FLOW_ID,
            Some(FlowProtocol::Tcp),
            FlowFrameRoute::FlowQueueFull
        )
    );

    assert!(!flows.contains_key(&FLOW_ID));
    assert_eq!(session_buffer.buffered_bytes(), 0);
}

#[test]
fn removes_flow_when_session_buffer_limit_is_exceeded() {
    let (sender, _receiver) = mpsc::channel(1);
    let mut flows = HashMap::new();
    flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));
    let session_buffer = ClientSessionBufferControl::default();

    assert_eq!(
        route_flow_frame(
            data_frame(FLOW_ID, Bytes::from_static(b"overflow")),
            &mut flows,
            session_buffer.clone(),
            usize::MAX,
            4,
        ),
        (
            FLOW_ID,
            Some(FlowProtocol::Tcp),
            FlowFrameRoute::SessionQueueFull
        )
    );

    assert!(!flows.contains_key(&FLOW_ID));
    assert_eq!(session_buffer.buffered_bytes(), 0);
}

#[test]
fn buffered_flow_frame_releases_session_bytes_on_drop() {
    let flow_buffer = ClientFlowBufferControl::default();
    let session_buffer = ClientSessionBufferControl::default();
    let buffered = BufferedFlowFrame::new(
        data_frame(FLOW_ID, Bytes::from_static(b"queued")),
        flow_buffer.clone(),
        session_buffer.clone(),
        16,
        16,
    )
    .unwrap();

    assert_eq!(flow_buffer.buffered_bytes(), 6);
    assert_eq!(session_buffer.buffered_bytes(), 6);
    drop(buffered);
    assert_eq!(flow_buffer.buffered_bytes(), 0);
    assert_eq!(session_buffer.buffered_bytes(), 0);
}

#[test]
fn buffered_flow_frame_releases_session_bytes_on_into_frame() {
    let flow_buffer = ClientFlowBufferControl::default();
    let session_buffer = ClientSessionBufferControl::default();
    let buffered = BufferedFlowFrame::new(
        data_frame(FLOW_ID, Bytes::from_static(b"queued")),
        flow_buffer.clone(),
        session_buffer.clone(),
        16,
        16,
    )
    .unwrap();

    let frame = buffered.into_frame().unwrap();

    assert_eq!(frame.payload, Bytes::from_static(b"queued"));
    assert_eq!(flow_buffer.buffered_bytes(), 0);
    assert_eq!(session_buffer.buffered_bytes(), 0);
}

#[test]
fn buffered_flow_frame_missing_inner_frame_returns_error_after_release() {
    let flow_buffer = ClientFlowBufferControl::default();
    let session_buffer = ClientSessionBufferControl::default();
    let mut buffered = BufferedFlowFrame::new(
        data_frame(FLOW_ID, Bytes::from_static(b"queued")),
        flow_buffer.clone(),
        session_buffer.clone(),
        16,
        16,
    )
    .unwrap();

    let removed = buffered.frame.take();
    assert!(removed.is_some());
    assert_eq!(flow_buffer.buffered_bytes(), 6);
    assert_eq!(session_buffer.buffered_bytes(), 6);

    let error = buffered.into_frame().unwrap_err();

    assert_eq!(error.to_string(), "buffered frame missing");
    assert_eq!(flow_buffer.buffered_bytes(), 0);
    assert_eq!(session_buffer.buffered_bytes(), 0);
}

#[test]
fn decodes_open_ack() {
    let frame = Frame::new(FrameType::TcpData, 0, FLOW_ID, Bytes::new()).unwrap();

    assert_eq!(decode_open_response(frame).unwrap(), OpenResponse::Accepted);
}

#[test]
fn decodes_udp_open_ack() {
    let frame = udp_data_frame(FLOW_ID, Bytes::new());

    assert_eq!(
        decode_udp_open_response(frame).unwrap(),
        OpenResponse::Accepted
    );
}

#[test]
fn decodes_policy_denied_open_response() {
    let frame = Frame::new(
        FrameType::PolicyDenied,
        0,
        FLOW_ID,
        status_payload(ErrorCode::PolicyDenied),
    )
    .unwrap();

    assert_eq!(
        decode_open_response(frame).unwrap(),
        OpenResponse::Rejected(socks5::Reply::NotAllowed)
    );
}

#[test]
fn decodes_resource_limit_open_response() {
    let frame = Frame::new(
        FrameType::ResourceLimit,
        0,
        FLOW_ID,
        status_payload(ErrorCode::ResourceLimit),
    )
    .unwrap();

    assert_eq!(
        decode_open_response(frame).unwrap(),
        OpenResponse::Rejected(socks5::Reply::GeneralFailure)
    );
}

#[test]
fn maps_error_open_response_codes_to_socks_replies() {
    let cases = [
        (ErrorCode::UnsupportedVersion, socks5::Reply::GeneralFailure),
        (ErrorCode::UnsupportedFlag, socks5::Reply::GeneralFailure),
        (ErrorCode::OversizedFrame, socks5::Reply::GeneralFailure),
        (ErrorCode::TruncatedFrame, socks5::Reply::GeneralFailure),
        (ErrorCode::InvalidTarget, socks5::Reply::HostUnreachable),
        (ErrorCode::AuthFailed, socks5::Reply::GeneralFailure),
        (ErrorCode::PolicyDenied, socks5::Reply::NotAllowed),
        (ErrorCode::ResourceLimit, socks5::Reply::GeneralFailure),
        (ErrorCode::Protocol, socks5::Reply::GeneralFailure),
        (ErrorCode::TargetUnavailable, socks5::Reply::HostUnreachable),
        (ErrorCode::TargetTimeout, socks5::Reply::HostUnreachable),
    ];

    for (code, expected_reply) in cases {
        assert_eq!(
            decode_open_response(error_frame(code)).unwrap(),
            OpenResponse::Rejected(expected_reply),
            "error code {code:?}"
        );
    }
}

#[test]
fn accepts_matching_flow_status_payloads() {
    assert!(validate_flow_status(FrameType::Error, status_payload(ErrorCode::Protocol)).is_ok());
    assert!(
        validate_flow_status(
            FrameType::PolicyDenied,
            status_payload(ErrorCode::PolicyDenied)
        )
        .is_ok()
    );
    assert!(
        validate_flow_status(
            FrameType::ResourceLimit,
            status_payload(ErrorCode::ResourceLimit)
        )
        .is_ok()
    );
}

#[test]
fn status_frame_encodes_flow_resource_limit() {
    let frame = status_frame(FrameType::ResourceLimit, FLOW_ID, ErrorCode::ResourceLimit).unwrap();

    assert_eq!(frame.header.frame_type, FrameType::ResourceLimit);
    assert_eq!(frame.header.id, FLOW_ID);
    let mut payload = frame.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload).unwrap().code,
        ErrorCode::ResourceLimit
    );
}

#[test]
fn status_frame_encodes_connection_error() {
    let frame = status_frame(FrameType::Error, 0, ErrorCode::Protocol).unwrap();

    assert_eq!(frame.header.frame_type, FrameType::Error);
    assert_eq!(frame.header.id, 0);
    let mut payload = frame.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload).unwrap().code,
        ErrorCode::Protocol
    );
}

#[test]
fn rejects_mismatched_flow_status_payloads() {
    assert!(
        validate_flow_status(
            FrameType::PolicyDenied,
            status_payload(ErrorCode::ResourceLimit)
        )
        .is_err()
    );
    assert!(
        validate_flow_status(
            FrameType::ResourceLimit,
            status_payload(ErrorCode::PolicyDenied)
        )
        .is_err()
    );
}

#[test]
fn rejects_unexpected_flow_status_frame_type() {
    assert!(validate_flow_status(FrameType::TcpData, Bytes::new()).is_err());
}

#[test]
fn rejects_malformed_flow_status_payload() {
    assert!(validate_flow_status(FrameType::Error, Bytes::new()).is_err());
    assert!(validate_flow_status(FrameType::PolicyDenied, Bytes::new()).is_err());
    assert!(validate_flow_status(FrameType::ResourceLimit, Bytes::new()).is_err());
}

#[test]
fn validates_server_flow_frames_before_routing() {
    assert!(validate_server_flow_frame(&data_frame(FLOW_ID, Bytes::new())).is_ok());
    assert!(validate_server_flow_frame(&close_frame(TCP_CLOSE_NORMAL)).is_ok());
    assert!(validate_server_flow_frame(&udp_data_frame(FLOW_ID, Bytes::new())).is_ok());
    assert!(validate_server_flow_frame(&udp_close_frame(UDP_CLOSE_NORMAL)).is_ok());
    assert!(validate_server_flow_frame(&error_frame(ErrorCode::Protocol)).is_ok());
}

#[test]
fn rejects_malformed_server_flow_frames_before_routing() {
    let malformed_close = Frame::new(FrameType::TcpClose, 0, FLOW_ID, Bytes::new()).unwrap();
    let malformed_udp_close = Frame::new(FrameType::UdpClose, 0, FLOW_ID, Bytes::new()).unwrap();
    let malformed_status = Frame::new(FrameType::Error, 0, FLOW_ID, Bytes::new()).unwrap();
    let mismatched_policy_denied = Frame::new(
        FrameType::PolicyDenied,
        0,
        FLOW_ID,
        status_payload(ErrorCode::ResourceLimit),
    )
    .unwrap();

    assert!(validate_server_flow_frame(&malformed_close).is_err());
    assert!(validate_server_flow_frame(&malformed_udp_close).is_err());
    assert!(validate_server_flow_frame(&malformed_status).is_err());
    assert!(validate_server_flow_frame(&mismatched_policy_denied).is_err());
}

#[test]
fn classifies_connection_error_frames() {
    assert!(is_connection_error_frame(&error_frame_for(
        0,
        ErrorCode::Protocol
    )));
    assert!(!is_connection_error_frame(&error_frame(
        ErrorCode::Protocol
    )));
    assert!(!is_connection_error_frame(
        &Frame::new(
            FrameType::PolicyDenied,
            0,
            0,
            status_payload(ErrorCode::PolicyDenied)
        )
        .unwrap()
    ));
}

#[test]
fn decodes_tcp_close_open_response_as_connection_refused() {
    assert_eq!(
        decode_open_response(close_frame(TCP_CLOSE_NORMAL)).unwrap(),
        OpenResponse::Rejected(socks5::Reply::ConnectionRefused)
    );
}

#[test]
fn decodes_udp_close_open_response_as_connection_refused() {
    assert_eq!(
        decode_udp_open_response(udp_close_frame(UDP_CLOSE_NORMAL)).unwrap(),
        OpenResponse::Rejected(socks5::Reply::ConnectionRefused)
    );
}

#[test]
fn maps_tcp_close_error_open_response_to_general_failure() {
    assert_eq!(
        decode_open_response(close_frame(TCP_CLOSE_ERROR)).unwrap(),
        OpenResponse::Rejected(socks5::Reply::GeneralFailure)
    );
}

#[test]
fn rejects_policy_denied_with_wrong_error_code() {
    let frame = Frame::new(
        FrameType::PolicyDenied,
        0,
        FLOW_ID,
        status_payload(ErrorCode::Protocol),
    )
    .unwrap();

    assert!(decode_open_response(frame).is_err());
}

#[test]
fn rejects_resource_limit_with_wrong_error_code() {
    let frame = Frame::new(
        FrameType::ResourceLimit,
        0,
        FLOW_ID,
        status_payload(ErrorCode::PolicyDenied),
    )
    .unwrap();

    assert!(decode_open_response(frame).is_err());
}

#[test]
fn rejects_non_empty_tcp_data_as_open_ack() {
    let frame = Frame::new(
        FrameType::TcpData,
        0,
        FLOW_ID,
        Bytes::from_static(b"early data"),
    )
    .unwrap();

    assert!(decode_open_response(frame).is_err());
}

#[test]
fn rejects_non_empty_udp_data_as_open_ack() {
    let frame = udp_data_frame(FLOW_ID, Bytes::from_static(b"early data"));

    assert!(decode_udp_open_response(frame).is_err());
}

#[test]
fn rejects_unexpected_open_response_frame() {
    let frame = Frame::new(FrameType::Ping, 0, FLOW_ID, Bytes::new()).unwrap();

    assert!(decode_open_response(frame).is_err());
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
        validate_session_control_frame(&control_frame(FrameType::Ping, FLOW_ID), FrameType::Ping)
            .is_err()
    );
    assert!(
        validate_session_control_frame(&control_frame(FrameType::Pong, FLOW_ID), FrameType::Pong)
            .is_err()
    );
}

#[test]
fn rejects_invalid_socks_listen_endpoint() {
    assert!(validate_endpoint("socks listen", "127.0.0.1").is_err());
    assert!(validate_endpoint("socks listen", "127.0.0.1:0").is_err());
    assert!(validate_endpoint("socks listen", "::1:1080").is_err());
}

#[test]
fn udp_association_bind_addr_uses_tcp_local_ip_with_ephemeral_port() {
    let bind_addr = udp_association_bind_addr(SocketAddr::from(([127, 0, 0, 1], 1080)));

    assert_eq!(bind_addr, SocketAddr::from(([127, 0, 0, 1], 0)));
}

#[test]
fn udp_client_endpoint_learns_unspecified_peer() {
    let first_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
    let second_peer = SocketAddr::from(([127, 0, 0, 1], 41001));
    let mut endpoint = UdpClientEndpoint::new(
        socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
        CONTROL_PEER_IP,
    );

    assert!(endpoint.accepts(first_peer));
    assert_eq!(endpoint.learned(), Some(first_peer));
    assert!(endpoint.accepts(first_peer));
    assert!(!endpoint.accepts(second_peer));
}

#[test]
fn udp_client_endpoint_ignores_peer_that_misses_declared_port() {
    let expected_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
    let wrong_peer = SocketAddr::from(([127, 0, 0, 1], 41001));
    let mut endpoint = UdpClientEndpoint::new(
        socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::LOCALHOST, expected_peer.port()),
        CONTROL_PEER_IP,
    );

    assert!(!endpoint.accepts(wrong_peer));
    assert_eq!(endpoint.learned(), None);
    assert!(endpoint.accepts(expected_peer));
    assert_eq!(endpoint.learned(), Some(expected_peer));
}

#[test]
fn udp_client_endpoint_matches_declared_domain_port() {
    let expected_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
    let wrong_peer = SocketAddr::from(([127, 0, 0, 1], 41001));
    let mut endpoint = UdpClientEndpoint::new(
        socks5::SocksEndpoint::Domain("client.local".to_owned(), 41000),
        CONTROL_PEER_IP,
    );

    assert!(!endpoint.accepts(wrong_peer));
    assert!(endpoint.accepts(expected_peer));
}

#[test]
fn udp_client_endpoint_rejects_foreign_source_for_unspecified_request() {
    // RFC 1928 lets the client advertise all zeros, but the association
    // socket is bound to the SOCKS listener's IP, so only the host that
    // opened the control connection may claim it.
    let foreign_peer = SocketAddr::from(([192, 0, 2, 10], 41000));
    let client_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
    let mut endpoint = UdpClientEndpoint::new(
        socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
        CONTROL_PEER_IP,
    );

    assert!(!endpoint.accepts(foreign_peer));
    assert_eq!(endpoint.learned(), None);
    assert!(endpoint.accepts(client_peer));
    assert_eq!(endpoint.learned(), Some(client_peer));
}

#[test]
fn udp_client_endpoint_rejects_foreign_source_for_unspecified_ipv6_request() {
    let foreign_peer = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 41000));
    let client_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
    let mut endpoint = UdpClientEndpoint::new(
        socks5::SocksEndpoint::Ipv6(std::net::Ipv6Addr::UNSPECIFIED, 0),
        CONTROL_PEER_IP,
    );

    assert!(!endpoint.accepts(foreign_peer));
    assert!(endpoint.accepts(client_peer));
}

#[test]
fn udp_client_endpoint_rejects_foreign_source_for_domain_request() {
    // The domain form names the client but says nothing checkable about the
    // datagram source, so it falls back to the control connection's IP.
    let foreign_peer = SocketAddr::from(([192, 0, 2, 10], 41000));
    let client_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
    let mut endpoint = UdpClientEndpoint::new(
        socks5::SocksEndpoint::Domain("client.local".to_owned(), 0),
        CONTROL_PEER_IP,
    );

    assert!(!endpoint.accepts(foreign_peer));
    assert!(endpoint.accepts(client_peer));
}

#[test]
fn udp_client_endpoint_still_honours_an_explicit_client_address() {
    let declared_peer = SocketAddr::from(([203, 0, 113, 5], 41000));
    let control_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
    let mut endpoint = UdpClientEndpoint::new(
        socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::new(203, 0, 113, 5), 0),
        CONTROL_PEER_IP,
    );

    assert!(!endpoint.accepts(control_peer));
    assert!(endpoint.accepts(declared_peer));
}

#[test]
fn udp_client_endpoint_matches_an_ipv4_mapped_control_peer() {
    let client_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
    let mapped_control_ip = IpAddr::V6(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped());
    let mut endpoint = UdpClientEndpoint::new(
        socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
        mapped_control_ip,
    );

    assert!(endpoint.accepts(client_peer));
}

#[test]
fn classifies_clean_socks_disconnects() {
    assert!(is_clean_socks_disconnect(&boxed_io_error(
        io::ErrorKind::UnexpectedEof
    )));
    assert!(is_clean_socks_disconnect(&boxed_io_error(
        io::ErrorKind::ConnectionReset
    )));
    assert!(is_clean_socks_disconnect(&boxed_io_error(
        io::ErrorKind::BrokenPipe
    )));
    assert!(is_clean_socks_disconnect(&boxed_io_error(
        io::ErrorKind::NotConnected
    )));
    assert!(!is_clean_socks_disconnect(&boxed_io_error(
        io::ErrorKind::InvalidData
    )));
}

#[tokio::test]
async fn carrier_write_exits_when_session_shutdown_notifies() {
    let (mut writer, _reader) = tokio::io::duplex(1);
    let shutdown = ClientSessionShutdown::default();
    let shutdown_handle = shutdown.clone();
    let frame = Frame::new(
        FrameType::TcpData,
        0,
        FLOW_ID,
        Bytes::from(vec![0x42; 1024]),
    )
    .unwrap();

    let task =
        tokio::spawn(async move { write_frame_or_shutdown(&mut writer, &frame, &shutdown).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!task.is_finished());

    shutdown_handle.close();

    let err = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    let io_error = err.downcast_ref::<io::Error>().unwrap();
    assert_eq!(io_error.kind(), io::ErrorKind::Interrupted);
}

#[tokio::test]
async fn client_session_tasks_reap_completed_tasks() {
    let mut tasks = ClientSessionTasks::default();

    tasks.spawn(ClientSessionTaskKind::Keepalive, async {});
    tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
        .await
        .expect("completed client session task should be reaped");

    assert!(tasks.is_empty());
    assert!(tasks.kinds.is_empty());
}

#[tokio::test]
async fn client_session_task_drain_aborts_pending_tasks_after_timeout() {
    let mut tasks = ClientSessionTasks::default();

    tasks.spawn(ClientSessionTaskKind::CarrierReader, async {
        std::future::pending::<()>().await;
    });
    drain_client_session_tasks(&mut tasks, Some(Duration::from_millis(10))).await;

    assert!(tasks.is_empty());
    assert!(tasks.kinds.is_empty());
}

#[tokio::test]
async fn socks_shutdown_timeout_aborts_pending_connection_tasks() {
    let mut connections = JoinSet::new();
    connections.spawn(std::future::pending::<()>());

    tokio::time::timeout(
        Duration::from_secs(1),
        drain_socks_tasks(&mut connections, Some(Duration::from_millis(10))),
    )
    .await
    .unwrap();

    assert!(connections.is_empty());
}

#[tokio::test]
async fn socks_shutdown_drain_waits_for_completed_connection_tasks() {
    let mut connections = JoinSet::new();
    connections.spawn(async {});

    drain_socks_tasks(&mut connections, Some(Duration::from_secs(1))).await;

    assert!(connections.is_empty());
}

#[tokio::test]
async fn udp_association_activity_events_are_lossy_when_queue_is_full() {
    let (event_tx, mut event_rx) = mpsc::channel(1);
    let first_target = Target::Domain("first.example".to_owned(), 53);
    let second_target = Target::Domain("second.example".to_owned(), 53);

    try_record_udp_association_activity(&event_tx, 1, &first_target);
    try_record_udp_association_activity(&event_tx, 3, &second_target);

    match event_rx.recv().await {
        Some(UdpAssociationFlowEvent::Activity { flow_id, target }) => {
            assert_eq!(flow_id, 1);
            assert_eq!(target, first_target);
        }
        None => panic!("activity event should be queued"),
    }
    assert!(event_rx.try_recv().is_err());
}

#[test]
fn allocates_client_flow_ids_up_to_varint_limit() {
    let next_flow_id = AtomicU64::new(MAX_VARINT - FLOW_ID_STEP);

    assert_eq!(
        allocate_client_flow_id(&next_flow_id),
        Some(MAX_VARINT - FLOW_ID_STEP)
    );
    assert_eq!(allocate_client_flow_id(&next_flow_id), Some(MAX_VARINT));
    assert_eq!(allocate_client_flow_id(&next_flow_id), None);
}

#[test]
fn allocates_nonzero_keepalive_nonces() {
    let counter = AtomicU64::new(0);

    assert_eq!(next_keepalive_nonce(&counter), Some(1));
    assert_eq!(next_keepalive_nonce(&counter), Some(2));
}

#[test]
fn keepalive_nonce_exhaustion_does_not_wrap() {
    let counter = AtomicU64::new(u64::MAX - 1);

    assert_eq!(next_keepalive_nonce(&counter), Some(u64::MAX));
    assert_eq!(next_keepalive_nonce(&counter), None);
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
}

#[test]
fn decodes_keepalive_nonce_payloads() {
    let payload = keepalive_nonce_payload(42);

    assert_eq!(decode_keepalive_nonce(&payload), Some(42));
    assert_eq!(decode_keepalive_nonce(&Bytes::new()), None);
    assert_eq!(
        decode_keepalive_nonce(&Bytes::from_static(b"too long!")),
        None
    );
}

#[test]
fn records_only_the_outstanding_keepalive_pong() {
    let outstanding = AtomicU64::new(42);
    let last_pong = AtomicU64::new(0);

    assert_eq!(
        record_matching_pong(&outstanding, &last_pong, &keepalive_nonce_payload(42)),
        KeepalivePong::Matched(42)
    );
    assert_eq!(last_pong.load(Ordering::SeqCst), 42);
}

#[test]
fn stale_keepalive_pong_cannot_overwrite_a_match() {
    let outstanding = AtomicU64::new(42);
    let last_pong = AtomicU64::new(42);

    assert_eq!(
        record_matching_pong(&outstanding, &last_pong, &keepalive_nonce_payload(41)),
        KeepalivePong::Unexpected {
            nonce: 41,
            expected_nonce: 42
        }
    );
    assert_eq!(last_pong.load(Ordering::SeqCst), 42);
}

#[test]
fn unsolicited_keepalive_pong_is_ignored() {
    let outstanding = AtomicU64::new(0);
    let last_pong = AtomicU64::new(0);

    assert_eq!(
        record_matching_pong(&outstanding, &last_pong, &keepalive_nonce_payload(1)),
        KeepalivePong::Unexpected {
            nonce: 1,
            expected_nonce: 0
        }
    );
    assert_eq!(last_pong.load(Ordering::SeqCst), 0);
}

#[test]
fn stops_allocating_unrepresentable_client_flow_ids() {
    let next_flow_id = AtomicU64::new(MAX_VARINT + FLOW_ID_STEP);

    assert_eq!(allocate_client_flow_id(&next_flow_id), None);
}

#[tokio::test]
async fn socks_listener_rejects_invalid_backing_config_before_bind() {
    let result = run_socks5_listener_until_shutdown(
        minimal_config(),
        "127.0.0.1:1".to_owned(),
        std::future::pending(),
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn session_manager_reuses_recent_connect_failure_during_retry_delay() {
    let mut config = minimal_config();
    config.server_connect_retry_delay_millis = Some(250);
    let manager = test_session_manager(config);

    let first = expect_session_error(manager.current_session().await);
    assert!(!first.to_string().contains("retry cooldown active"));

    let second = expect_session_error(manager.current_session().await);
    let text = second.to_string();

    assert!(text.contains("retry cooldown active"));
    assert!(text.contains("missing-ca.pem"));
}

#[tokio::test]
async fn session_manager_can_disable_connect_failure_retry_delay() {
    let mut config = minimal_config();
    config.server_connect_retry_delay_millis = Some(0);
    let manager = test_session_manager(config);

    let first = expect_session_error(manager.current_session().await);
    let second = expect_session_error(manager.current_session().await);

    assert!(!first.to_string().contains("retry cooldown active"));
    assert!(!second.to_string().contains("retry cooldown active"));
}

#[tokio::test]
async fn expired_session_connect_failure_cache_is_cleared() {
    let manager = test_session_manager(minimal_config());
    *manager.recent_connect_failure.lock().await = Some(CachedConnectFailure {
        generation: 1,
        message: Arc::from("old failure"),
        expires_at: Some(time::Instant::now() - Duration::from_millis(1)),
    });

    assert!(manager.recent_connect_failure_if_active().await.is_none());
    assert!(manager.recent_connect_failure.lock().await.is_none());
}

#[tokio::test]
async fn previous_generation_connect_failure_cache_is_cleared() {
    let manager = test_session_manager(minimal_config());
    *manager.recent_connect_failure.lock().await = Some(CachedConnectFailure {
        generation: 1,
        message: Arc::from("old failure"),
        expires_at: None,
    });
    manager.config.replace(minimal_config());

    assert!(manager.recent_connect_failure_if_active().await.is_none());
    assert!(manager.recent_connect_failure.lock().await.is_none());
}

#[test]
fn client_reload_rejects_static_listener_changes() {
    let current = minimal_config();
    let mut candidate = current.clone();
    candidate.max_socks_connections = Some(current.max_socks_connections() + 1);

    let error = ensure_reload_compatible(&current, &candidate)
        .unwrap_err()
        .to_string();

    assert!(error.contains("max_socks_connections"));
    assert!(error.contains("requires a restart"));
}

#[test]
fn client_reload_rejects_observability_listener_changes() {
    let current = minimal_config();
    let mut candidate = current.clone();
    candidate.observability_listen = Some("127.0.0.1:9091".to_owned());

    let error = ensure_reload_compatible(&current, &candidate)
        .unwrap_err()
        .to_string();

    assert!(error.contains("observability_listen"));
    assert!(error.contains("requires a restart"));
}

#[test]
fn client_reload_accepts_equivalent_effective_listener_settings() {
    let current = minimal_config();
    let mut candidate = current.clone();
    candidate.socks_handshake_timeout_seconds = Some(current.socks_handshake_timeout_seconds());
    candidate.shutdown_timeout_seconds = Some(current.shutdown_timeout_seconds());
    candidate.max_socks_connections = Some(current.max_socks_connections());

    assert!(ensure_reload_compatible(&current, &candidate).is_ok());
}

#[test]
fn unrepresentable_retry_delay_expiry_is_treated_as_non_expiring() {
    assert_eq!(retry_delay_expires_at(Duration::MAX), None);
}

#[test]
fn listener_accept_backoff_grows_caps_and_resets() {
    let mut backoff = ListenerAcceptBackoff::default();

    assert_eq!(backoff.next_delay(), Duration::from_millis(10));
    assert_eq!(backoff.next_delay(), Duration::from_millis(20));
    assert_eq!(backoff.next_delay(), Duration::from_millis(40));
    for _ in 0..16 {
        let delay = backoff.next_delay();
        assert!(delay <= Duration::from_secs(1));
    }
    assert_eq!(backoff.next_delay(), Duration::from_secs(1));

    backoff.reset();
    assert_eq!(backoff.next_delay(), Duration::from_millis(10));
}

#[test]
fn caps_tcp_data_frame_size_to_peer_limit() {
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
fn late_udp_flow_completion_does_not_match_replacement() {
    assert!(!udp_flow_id_matches(Some(3), 1));
    assert!(udp_flow_id_matches(Some(3), 3));
    assert!(!udp_flow_id_matches(None, 3));
}

#[test]
fn derives_keepalive_interval_from_idle_timeout() {
    let settings = negotiated_settings_with_idle_timeout(30);

    assert_eq!(keepalive_interval(settings), Some(Duration::from_secs(15)));
}

#[test]
fn keeps_one_second_idle_timeout_before_deadline() {
    let settings = negotiated_settings_with_idle_timeout(1);

    assert_eq!(
        keepalive_interval(settings),
        Some(Duration::from_millis(500))
    );
}

#[test]
fn disables_keepalive_for_zero_idle_timeout() {
    let settings = negotiated_settings_with_idle_timeout(0);

    assert_eq!(keepalive_interval(settings), None);
}

#[test]
fn accepts_client_connection_state_transitions() {
    let valid = [
        (
            ClientConnectionState::NegotiatingSocks,
            ClientConnectionState::Opening,
        ),
        (
            ClientConnectionState::NegotiatingSocks,
            ClientConnectionState::Relaying,
        ),
        (
            ClientConnectionState::NegotiatingSocks,
            ClientConnectionState::Closed,
        ),
        (
            ClientConnectionState::Opening,
            ClientConnectionState::Relaying,
        ),
        (
            ClientConnectionState::Opening,
            ClientConnectionState::Closing,
        ),
        (
            ClientConnectionState::Opening,
            ClientConnectionState::Closed,
        ),
        (
            ClientConnectionState::Relaying,
            ClientConnectionState::Closing,
        ),
        (
            ClientConnectionState::Relaying,
            ClientConnectionState::Closed,
        ),
        (
            ClientConnectionState::Closing,
            ClientConnectionState::Closed,
        ),
    ];

    for (from, next) in valid {
        assert!(is_valid_connection_transition(from, next));
    }
}

#[test]
fn rejects_client_connection_state_regressions() {
    assert!(!is_valid_connection_transition(
        ClientConnectionState::Relaying,
        ClientConnectionState::Opening
    ));
    assert!(!is_valid_connection_transition(
        ClientConnectionState::Closed,
        ClientConnectionState::Relaying
    ));
}

#[test]
fn flow_frame_queue_capacity_tracks_byte_limit() {
    // A tiny byte limit falls back to the floor.
    assert_eq!(
        flow_frame_queue_capacity(1024),
        FLOW_FRAME_QUEUE_MIN_CAPACITY
    );
    // The default 2 MiB per-flow limit derives a queue the byte budget can
    // fill (2 MiB / 1 KiB), far above the old fixed depth of 32.
    assert_eq!(flow_frame_queue_capacity(2 * 1024 * 1024), 2048);
    // A large limit is clamped to the ceiling.
    assert_eq!(
        flow_frame_queue_capacity(64 * 1024 * 1024),
        FLOW_FRAME_QUEUE_MAX_CAPACITY
    );
}

#[test]
fn flow_admission_reserves_up_to_the_stream_ceiling() {
    let admission = FlowAdmissionControl::new(2, 2);

    let first = admission.try_admit(FlowProtocol::Tcp).unwrap();
    let second = admission.try_admit(FlowProtocol::Tcp).unwrap();

    assert_eq!(admission.available_streams(), 0);
    assert_eq!(
        admission.try_admit(FlowProtocol::Tcp).unwrap_err(),
        AdmissionRefusal::StreamLimit
    );

    drop(first);
    assert_eq!(admission.available_streams(), 1);
    assert!(admission.try_admit(FlowProtocol::Tcp).is_ok());
    drop(second);
}

#[test]
fn concurrent_flow_admission_never_oversubscribes_a_session() {
    // The old "read `flow_count()`, reserve later" shape let every waiting
    // opener observe spare capacity; reservation at selection time cannot.
    let admission = FlowAdmissionControl::new(64, 64);
    let slots: Vec<FlowSlot> = (0..200)
        .filter_map(|_| admission.try_admit(FlowProtocol::Tcp).ok())
        .collect();

    assert_eq!(slots.len(), 64);
    assert_eq!(admission.available_streams(), 0);

    drop(slots);
    assert_eq!(admission.available_streams(), 64);
}

#[test]
fn udp_admission_consumes_both_ceilings() {
    let admission = FlowAdmissionControl::new(4, 1);

    let slot = admission.try_admit(FlowProtocol::Udp).unwrap();

    assert_eq!(admission.available_streams(), 3);
    assert_eq!(admission.available_udp_flows(), 0);

    drop(slot);
    assert_eq!(admission.available_streams(), 4);
    assert_eq!(admission.available_udp_flows(), 1);
}

#[test]
fn refused_udp_admission_releases_the_stream_slot() {
    let admission = FlowAdmissionControl::new(4, 1);
    let _held = admission.try_admit(FlowProtocol::Udp).unwrap();

    assert_eq!(
        admission.try_admit(FlowProtocol::Udp).unwrap_err(),
        AdmissionRefusal::UdpFlowLimit
    );
    // The stream permit taken before the UDP ceiling was checked must not
    // be leaked, or repeated UDP refusals would starve TCP flows.
    assert_eq!(admission.available_streams(), 3);
    assert!(admission.try_admit(FlowProtocol::Tcp).is_ok());
}

#[test]
fn tcp_admission_ignores_the_udp_flow_ceiling() {
    let admission = FlowAdmissionControl::new(4, 0);

    assert_eq!(
        admission.try_admit(FlowProtocol::Udp).unwrap_err(),
        AdmissionRefusal::UdpFlowLimit
    );
    assert!(admission.try_admit(FlowProtocol::Tcp).is_ok());
}

#[test]
fn clamps_unrepresentable_flow_ceilings_to_the_semaphore_limit() {
    assert_eq!(semaphore_permits(0), 0);
    assert_eq!(semaphore_permits(64), 64);
    assert_eq!(semaphore_permits(u64::MAX), Semaphore::MAX_PERMITS);
}

#[tokio::test]
async fn session_admission_reserves_a_slot_on_a_live_session() {
    let session = test_session(1, 1);

    let admission = session.try_admit(FlowProtocol::Tcp).unwrap();

    assert!(Arc::ptr_eq(&admission.session, &session));
    assert!(matches!(
        session.try_admit(FlowProtocol::Tcp),
        Err(AdmissionRefusal::StreamLimit)
    ));

    drop(admission);
    assert!(session.try_admit(FlowProtocol::Tcp).is_ok());
}

#[tokio::test]
async fn draining_or_closed_sessions_admit_no_flows() {
    let draining = test_session(4, 4);
    draining.begin_drain().await;
    assert!(matches!(
        draining.try_admit(FlowProtocol::Tcp),
        Err(AdmissionRefusal::Unavailable)
    ));

    let closed = test_session(4, 4);
    closed.close().await;
    assert!(matches!(
        closed.try_admit(FlowProtocol::Tcp),
        Err(AdmissionRefusal::Unavailable)
    ));
}

#[tokio::test]
async fn manager_admits_flows_on_the_least_loaded_pooled_session() {
    let manager = test_session_manager(minimal_config());
    let busy = test_session(4, 4);
    let idle = test_session(4, 4);
    // Give `busy` a flow so the ranking has something to order by.
    assert!(
        busy.reserve_flow(FlowProtocol::Tcp)
            .await
            .unwrap()
            .is_some()
    );
    manager
        .pool
        .lock()
        .await
        .extend([Arc::clone(&busy), Arc::clone(&idle)]);

    let admission = manager.admit_flow(FlowProtocol::Tcp).await.unwrap();

    assert!(Arc::ptr_eq(&admission.session, &idle));
}

#[tokio::test]
async fn manager_falls_through_to_the_next_session_when_one_is_saturated() {
    let manager = test_session_manager(minimal_config());
    let full = test_session(1, 1);
    let spare = test_session(4, 4);
    let _held = full.try_admit(FlowProtocol::Tcp).unwrap();
    manager
        .pool
        .lock()
        .await
        .extend([Arc::clone(&full), Arc::clone(&spare)]);

    let admission = manager.admit_flow(FlowProtocol::Tcp).await.unwrap();

    assert!(Arc::ptr_eq(&admission.session, &spare));
}

#[tokio::test]
async fn manager_rejects_new_flows_when_the_whole_pool_is_saturated() {
    let mut config = minimal_config();
    config.max_carrier_sessions = Some(1);
    let manager = test_session_manager(config);
    let full = test_session(1, 1);
    let _held = full.try_admit(FlowProtocol::Tcp).unwrap();
    manager.pool.lock().await.push(Arc::clone(&full));

    // Genuine exhaustion, not a lost race: no dial past
    // `max_carrier_sessions` and no error, so the caller replies to SOCKS.
    let admission = manager
        .admission_for_new_flow(FlowProtocol::Tcp)
        .await
        .unwrap();

    assert!(admission.is_none());
}

#[tokio::test]
async fn manager_rejects_udp_flows_at_the_per_session_udp_ceiling() {
    // `max_carrier_sessions` still has room, but `max_udp_flows` is a
    // per-session server limit: dialling another carrier to get around it
    // would work around the server's policy, so reject instead. (The pool
    // is deliberately left able to grow, and `minimal_config` cannot dial,
    // so a dial attempt would surface as an error rather than `None`.)
    let manager = test_session_manager(minimal_config());
    let session = test_session(4, 1);
    let _held = session.try_admit(FlowProtocol::Udp).unwrap();
    manager.pool.lock().await.push(Arc::clone(&session));

    let admission = manager
        .admission_for_new_flow(FlowProtocol::Udp)
        .await
        .unwrap();

    assert!(admission.is_none());
    // A TCP flow is still admitted on the same session.
    assert!(
        manager
            .admission_for_new_flow(FlowProtocol::Tcp)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn manager_admits_without_dialling_while_the_pool_has_capacity() {
    // `minimal_config` cannot connect (its CA file is missing), so an
    // admission that succeeds here proves no dial was attempted.
    let manager = test_session_manager(minimal_config());
    manager.pool.lock().await.push(test_session(4, 4));

    assert!(
        manager
            .admission_for_new_flow(FlowProtocol::Udp)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn cancelled_pending_session_is_torn_down() {
    let session = test_session(4, 4);

    drop(PendingClientSession::new(Arc::clone(&session)));

    // `Drop` cannot await, so the teardown is handed to the runtime.
    for _ in 0..100 {
        if session.is_closed() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(session.is_closed());
}

#[tokio::test]
async fn pooled_pending_session_is_not_torn_down() {
    let session = test_session(4, 4);
    let pending = PendingClientSession::new(Arc::clone(&session));

    let published = pending.into_session();

    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(Arc::ptr_eq(&published, &session));
    assert!(!session.is_closed());
}

#[tokio::test]
async fn explicitly_closed_pending_session_is_torn_down() {
    let session = test_session(4, 4);

    PendingClientSession::new(Arc::clone(&session))
        .close_and_wait()
        .await;

    assert!(session.is_closed());
}

#[tokio::test]
async fn local_write_finishes_the_payload_before_honouring_shutdown() {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (mut writer, mut reader) = tokio::io::duplex(4);
    let payload = vec![0x42_u8; 1024];
    let task = tokio::spawn(async move {
        write_all_or_shutdown(&mut writer, &payload, &mut shutdown_rx).await
    });

    shutdown_tx.send(true).unwrap();

    // The whole payload lands even though shutdown was signalled mid-write;
    // a cancelled `write_all` would have left a short, unknown-length prefix
    // behind an otherwise clean FIN.
    let mut received = vec![0_u8; 1024];
    tokio::time::timeout(Duration::from_secs(1), reader.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, vec![0x42_u8; 1024]);

    let keep_relaying = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!keep_relaying);
}

/// A local peer that stops reading must not hold shutdown open forever: the
/// in-flight write gets a bounded grace period and then fails the flow,
/// rather than blocking or capping a short write with a clean FIN.
#[tokio::test]
async fn local_write_gives_up_on_a_local_peer_that_stops_reading() {
    let grace = Duration::from_millis(50);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (mut writer, _reader) = tokio::io::duplex(1);
    let payload = vec![0x42_u8; 1024];
    let task = tokio::spawn(async move {
        write_all_or_shutdown_within(&mut writer, &payload, &mut shutdown_rx, grace).await
    });

    shutdown_tx.send(true).unwrap();

    let err = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the write must not outlive the grace period")
        .unwrap()
        .unwrap_err();

    assert!(
        err.to_string().contains("timed out flushing local socket"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn local_write_keeps_relaying_without_shutdown() {
    let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (mut writer, mut reader) = tokio::io::duplex(64);

    let keep_relaying = write_all_or_shutdown(&mut writer, b"payload", &mut shutdown_rx)
        .await
        .unwrap();

    let mut received = [0_u8; 7];
    reader.read_exact(&mut received).await.unwrap();
    assert!(keep_relaying);
    assert_eq!(&received, b"payload");
}

#[tokio::test]
async fn shutdown_flushes_already_buffered_frames_before_closing_local() {
    let (mut writer, mut reader) = tokio::io::duplex(1024);
    let (sender, mut frames) = mpsc::channel(4);
    let metrics = ClientMetrics::default();
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        sender
            .try_send(buffered_flow_frame(data_frame(
                FLOW_ID,
                Bytes::copy_from_slice(payload),
            )))
            .unwrap();
    }
    drop(sender);

    flush_buffered_frames_before_shutdown(&mut writer, &mut frames, &metrics)
        .await
        .unwrap();
    writer.shutdown().await.unwrap();

    let mut received = Vec::new();
    reader.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"firstsecond");
}

#[tokio::test]
async fn shutdown_flush_stops_at_a_non_data_frame() {
    let (mut writer, mut reader) = tokio::io::duplex(1024);
    let (sender, mut frames) = mpsc::channel(4);
    let metrics = ClientMetrics::default();
    sender
        .try_send(buffered_flow_frame(data_frame(
            FLOW_ID,
            Bytes::from_static(b"first"),
        )))
        .unwrap();
    sender
        .try_send(buffered_flow_frame(close_frame(TCP_CLOSE_NORMAL)))
        .unwrap();
    drop(sender);

    flush_buffered_frames_before_shutdown(&mut writer, &mut frames, &metrics)
        .await
        .unwrap();
    writer.shutdown().await.unwrap();

    let mut received = Vec::new();
    reader.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"first");
}

#[tokio::test]
async fn shutdown_flush_is_a_no_op_without_buffered_frames() {
    let (mut writer, mut reader) = tokio::io::duplex(1024);
    let (_sender, mut frames) = mpsc::channel(1);
    let metrics = ClientMetrics::default();

    flush_buffered_frames_before_shutdown(&mut writer, &mut frames, &metrics)
        .await
        .unwrap();
    writer.shutdown().await.unwrap();

    let mut received = Vec::new();
    reader.read_to_end(&mut received).await.unwrap();
    assert!(received.is_empty());
}
