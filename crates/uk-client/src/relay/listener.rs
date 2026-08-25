#![allow(unused_imports)]

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
use super::session_manager::*;
use super::tcp::*;
use super::udp::*;
use crate::{
    ClientReloadReceiver, ClientReloadRequest,
    config::{ClientConfig, validate_endpoint},
    config_state::{ClientConfigSnapshot, ClientConfigState},
    observability::{ActiveFlowGuard, ClientMetrics, RelayDirection, RelayProtocol},
    session, socks5,
};
pub(crate) async fn run_socks5_listener_until_shutdown<F>(
    config: ClientConfig,
    listen: String,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    crate::check_config(&config)?;
    validate_endpoint("socks listen", &listen)?;
    let listener = TcpListener::bind(&listen).await?;
    run_socks5_listener_on_until_shutdown_inner(config, listener, None, shutdown).await
}

pub(crate) async fn run_socks5_listener_until_shutdown_with_reload<F>(
    config: ClientConfig,
    listen: String,
    reload_rx: ClientReloadReceiver,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    crate::check_config(&config)?;
    validate_endpoint("socks listen", &listen)?;
    let listener = TcpListener::bind(&listen).await?;
    run_socks5_listener_on_until_shutdown_inner(config, listener, Some(reload_rx), shutdown).await
}

pub(crate) async fn run_socks5_listener_on_until_shutdown<F>(
    config: ClientConfig,
    listener: TcpListener,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    run_socks5_listener_on_until_shutdown_inner(config, listener, None, shutdown).await
}

pub(crate) async fn run_socks5_listener_on_until_shutdown_with_reload<F>(
    config: ClientConfig,
    listener: TcpListener,
    reload_rx: ClientReloadReceiver,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    run_socks5_listener_on_until_shutdown_inner(config, listener, Some(reload_rx), shutdown).await
}

pub(crate) async fn run_socks5_listener_on_until_shutdown_inner<F>(
    config: ClientConfig,
    listener: TcpListener,
    mut reload_rx: Option<ClientReloadReceiver>,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    crate::check_config(&config)?;
    let listen = listener.local_addr()?;
    let socks_handshake_timeout = timeout(config.socks_handshake_timeout_seconds());
    let shutdown_timeout = timeout(config.shutdown_timeout_seconds());
    let max_socks_connections = usize_limit(config.max_socks_connections())?;
    let metrics = Arc::new(ClientMetrics::default());
    let sessions = Arc::new(ClientSessionManager::new(config, Arc::clone(&metrics)));
    let (observability_shutdown_tx, observability_shutdown_rx) = watch::channel(false);
    let initial_config = sessions.config.snapshot();
    let observability_task = start_observability(
        &initial_config.config,
        Arc::clone(&metrics),
        observability_shutdown_rx,
    )
    .await?;
    drop(initial_config);
    let connection_runtime = SocksConnectionRuntime {
        sessions: Arc::clone(&sessions),
        metrics: Arc::clone(&metrics),
        connection_slots: Arc::new(Semaphore::new(max_socks_connections)),
        handshake_timeout: socks_handshake_timeout,
        max_connections: max_socks_connections,
    };
    info!(event = "socks5.listen", listen = %listen);

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    metrics.set_ready(true);
    let mut connections = JoinSet::new();
    let mut accept_backoff = ListenerAcceptBackoff::default();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!(event = "socks5.shutdown");
                metrics.set_ready(false);
                let _ = shutdown_tx.send(true);
                break;
            }
            accepted = listener.accept() => {
                let (local, peer) = match accepted {
                    Ok(connection) => {
                        accept_backoff.reset();
                        connection
                    }
                    Err(err) => {
                        let retry_delay = accept_backoff.next_delay();
                        warn!(
                            event = "socks5.accept.error",
                            error = %err,
                            retry_delay_ms = retry_delay.as_millis()
                        );
                        time::sleep(retry_delay).await;
                        continue;
                    }
                };
                connection_runtime
                    .spawn_accepted(
                        &mut connections,
                        local,
                        peer,
                        shutdown_tx.subscribe(),
                    )
                    .await;
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                log_socks_task_result(joined);
            }
            reload = receive_reload(&mut reload_rx) => {
                if let Some(request) = reload {
                    handle_reload_request(&sessions, request).await;
                } else {
                    reload_rx = None;
                    debug!(event = "client.config.reload_channel_closed");
                }
            }
        }
    }

    drain_socks_tasks(&mut connections, shutdown_timeout).await;
    sessions.shutdown().await;
    stop_observability(observability_shutdown_tx, observability_task).await;

    Ok(())
}

pub(crate) async fn start_observability(
    config: &ClientConfig,
    metrics: Arc<ClientMetrics>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<Option<tokio::task::JoinHandle<()>>, AnyError> {
    let Some(listen) = &config.observability_listen else {
        return Ok(None);
    };
    let listener = TcpListener::bind(listen).await?;
    Ok(Some(tokio::spawn(crate::observability::serve(
        listener,
        metrics,
        shutdown_rx,
    ))))
}

pub(crate) async fn stop_observability(
    shutdown_tx: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
) {
    let _ = shutdown_tx.send(true);
    if let Some(task) = task {
        if let Err(err) = task.await {
            warn!(event = "client.observability.task_error", error = %err);
        }
    }
}

pub(crate) async fn receive_reload(
    reload_rx: &mut Option<ClientReloadReceiver>,
) -> Option<ClientReloadRequest> {
    match reload_rx {
        Some(reload_rx) => reload_rx.rx.recv().await,
        None => std::future::pending().await,
    }
}

pub(crate) async fn handle_reload_request(
    sessions: &ClientSessionManager,
    request: ClientReloadRequest,
) {
    let result = sessions.reload(request.config).await;
    match &result {
        Ok(generation) => info!(
            event = "client.config.reload_success",
            config_generation = generation
        ),
        Err(err) => warn!(event = "client.config.reload_failure", error = %err),
    }
    let _ = request.response.send(result.map_err(|err| err.to_string()));
}

pub(crate) async fn drain_socks_tasks(
    connections: &mut JoinSet<()>,
    shutdown_timeout: Option<Duration>,
) {
    if let Some(timeout) = shutdown_timeout {
        if time::timeout(timeout, join_socks_tasks(connections))
            .await
            .is_err()
        {
            warn!(
                event = "socks5.shutdown.timeout",
                remaining_connections = connections.len(),
                timeout_seconds = timeout.as_secs()
            );
            connections.abort_all();
            join_socks_tasks(connections).await;
        }
    } else {
        join_socks_tasks(connections).await;
    }
}

pub(crate) async fn drain_client_session_tasks(
    tasks: &mut ClientSessionTasks,
    shutdown_timeout: Option<Duration>,
) {
    if let Some(timeout) = shutdown_timeout {
        if time::timeout(timeout, tasks.join_all()).await.is_err() {
            warn!(
                event = "client.session.task_shutdown.timeout",
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

pub(crate) fn log_client_session_task_error(kind: Option<ClientSessionTaskKind>, err: &JoinError) {
    if err.is_cancelled() {
        debug!(event = "client.session.task.cancelled", kind = ?kind, error = %err);
    } else {
        warn!(event = "client.session.task.error", kind = ?kind, error = %err);
    }
}

pub(crate) async fn join_socks_tasks(connections: &mut JoinSet<()>) {
    while let Some(joined) = connections.join_next().await {
        log_socks_task_result(Some(joined));
    }
}

pub(crate) fn log_socks_task_result(result: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(err)) = result {
        warn!(event = "socks5.connection.task_error", error = %err);
    }
}

pub(crate) fn is_clean_socks_disconnect(error: &AnyError) -> bool {
    error
        .as_ref()
        .downcast_ref::<io::Error>()
        .is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
            )
        })
}
