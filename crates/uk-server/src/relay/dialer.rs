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
    task::{Id, JoinError, JoinSet},
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
use super::session::*;
use super::tasks::*;
use super::tcp::*;
use super::udp::*;

use crate::observability::{
    ActiveFlowGuard, FlowOpenFailure, RelayDirection, RelayProtocol, ServerMetrics,
};
use crate::security::SecurityState;
pub(crate) async fn connect_allowed_target(
    target: &Target,
    identity: &AuthenticatedIdentity,
    policy_set: &PolicySet,
    open_dial_limiter: &OpenDialLimiter,
    target_connect_timeout: Option<Duration>,
) -> Result<TcpStream, OpenFailure> {
    let deadline = target_connect_deadline(target_connect_timeout);
    connect_allowed_target_inner(target, identity, policy_set, open_dial_limiter, deadline).await
}

pub(crate) async fn connect_allowed_target_inner(
    target: &Target,
    identity: &AuthenticatedIdentity,
    policy_set: &PolicySet,
    open_dial_limiter: &OpenDialLimiter,
    target_connect_deadline: Option<time::Instant>,
) -> Result<TcpStream, OpenFailure> {
    let addrs: Vec<SocketAddr> =
        with_target_connect_deadline(target_connect_deadline, resolve_target(target)).await?;
    let resolved_ips = resolved_ips(target, &addrs);
    let context = PolicyContext {
        key_id: &identity.key_id,
        policy_group: identity.policy_group.as_deref(),
        target,
        resolved_ips: &resolved_ips,
    };
    if policy_set.evaluate(&context) != PolicyDecision::Allow {
        return Err(OpenFailure::PolicyDenied);
    }
    connect_socket_addrs(&addrs, open_dial_limiter, target_connect_deadline).await
}

pub(crate) async fn connect_allowed_udp_target(
    target: &Target,
    identity: &AuthenticatedIdentity,
    policy_set: &PolicySet,
    open_dial_limiter: &OpenDialLimiter,
    target_connect_timeout: Option<Duration>,
) -> Result<UdpSocket, OpenFailure> {
    let deadline = target_connect_deadline(target_connect_timeout);
    connect_allowed_udp_target_inner(target, identity, policy_set, open_dial_limiter, deadline)
        .await
}

pub(crate) async fn connect_allowed_udp_target_inner(
    target: &Target,
    identity: &AuthenticatedIdentity,
    policy_set: &PolicySet,
    open_dial_limiter: &OpenDialLimiter,
    target_connect_deadline: Option<time::Instant>,
) -> Result<UdpSocket, OpenFailure> {
    let addrs: Vec<SocketAddr> =
        with_target_connect_deadline(target_connect_deadline, resolve_target(target)).await?;
    let resolved_ips = resolved_ips(target, &addrs);
    let context = PolicyContext {
        key_id: &identity.key_id,
        policy_group: identity.policy_group.as_deref(),
        target,
        resolved_ips: &resolved_ips,
    };
    if policy_set.evaluate(&context) != PolicyDecision::Allow {
        return Err(OpenFailure::PolicyDenied);
    }
    connect_udp_socket_addrs(&addrs, open_dial_limiter, target_connect_deadline).await
}

pub(crate) async fn resolve_target(target: &Target) -> Result<Vec<SocketAddr>, OpenFailure> {
    match target {
        Target::Domain(domain, port) => {
            let addrs = lookup_host((domain.as_str(), *port))
                .await
                .map_err(OpenFailure::TargetUnavailable)?;
            collect_resolved_addrs(addrs)
        }
        Target::Ipv4(ip, port) => Ok(vec![SocketAddr::new(IpAddr::V4(*ip), *port)]),
        Target::Ipv6(ip, port) => Ok(vec![SocketAddr::new(IpAddr::V6(*ip), *port)]),
    }
}

pub(crate) fn collect_resolved_addrs(
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, OpenFailure> {
    let addrs = addrs
        .into_iter()
        .take(TARGET_RESOLUTION_ADDR_LIMIT + 1)
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        Err(OpenFailure::TargetUnavailable(io::Error::new(
            io::ErrorKind::NotFound,
            "target resolved to no addresses",
        )))
    } else if addrs.len() > TARGET_RESOLUTION_ADDR_LIMIT {
        Err(OpenFailure::TargetUnavailable(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("target resolved to more than {TARGET_RESOLUTION_ADDR_LIMIT} addresses"),
        )))
    } else {
        Ok(addrs)
    }
}

pub(crate) fn resolved_ips(target: &Target, addrs: &[SocketAddr]) -> Vec<IpAddr> {
    match target {
        Target::Domain(_, _) => addrs.iter().map(SocketAddr::ip).collect(),
        Target::Ipv4(_, _) | Target::Ipv6(_, _) => Vec::new(),
    }
}

pub(crate) async fn connect_socket_addrs(
    addrs: &[SocketAddr],
    open_dial_limiter: &OpenDialLimiter,
    target_connect_deadline: Option<time::Instant>,
) -> Result<TcpStream, OpenFailure> {
    let connector = target_connector();
    connect_first_successful(
        addrs,
        &connector,
        open_dial_limiter,
        target_connect_deadline,
    )
    .await
}

pub(crate) async fn connect_udp_socket_addrs(
    addrs: &[SocketAddr],
    open_dial_limiter: &OpenDialLimiter,
    target_connect_deadline: Option<time::Instant>,
) -> Result<UdpSocket, OpenFailure> {
    let connector = udp_target_connector();
    connect_first_successful(
        addrs,
        &connector,
        open_dial_limiter,
        target_connect_deadline,
    )
    .await
}

pub(crate) fn target_connector() -> TargetConnector<TcpStream> {
    Arc::new(|addr| -> BoxedConnectFuture<TcpStream> { Box::pin(connect_socket_addr(addr)) })
}

pub(crate) fn udp_target_connector() -> TargetConnector<UdpSocket> {
    Arc::new(|addr| -> BoxedConnectFuture<UdpSocket> { Box::pin(connect_udp_socket_addr(addr)) })
}

pub(crate) async fn connect_socket_addr(addr: SocketAddr) -> (SocketAddr, io::Result<TcpStream>) {
    let result = match TcpStream::connect(addr).await {
        Ok(stream) => {
            let _ = stream.set_nodelay(true);
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(60));
            let _ = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive);
            Ok(stream)
        }
        Err(err) => Err(err),
    };
    (addr, result)
}

pub(crate) async fn connect_udp_socket_addr(
    addr: SocketAddr,
) -> (SocketAddr, io::Result<UdpSocket>) {
    let bind_addr = match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let result = async {
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(addr).await?;
        Ok(socket)
    }
    .await;
    (addr, result)
}

impl<T> ConnectTasks<T>
where
    T: Send + 'static,
{
    pub(crate) fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            permits: HashMap::new(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(crate) fn spawn(
        &mut self,
        addr: SocketAddr,
        connector: &TargetConnector<T>,
        permit: OpenDialPermit,
    ) {
        let connector = Arc::clone(connector);
        let handle = self.tasks.spawn(async move { connector(addr).await });
        self.permits.insert(handle.id(), permit);
    }

    pub(crate) async fn join_next(
        &mut self,
    ) -> Option<Result<(SocketAddr, io::Result<T>), tokio::task::JoinError>> {
        let result = self.tasks.join_next_with_id().await?;
        Some(match result {
            Ok((id, output)) => {
                self.permits.remove(&id);
                Ok(output)
            }
            Err(err) => {
                let id = err.id();
                self.permits.remove(&id);
                Err(err)
            }
        })
    }

    pub(crate) async fn abort_all(&mut self) {
        self.tasks.abort_all();
        while self.join_next().await.is_some() {}
        self.permits.clear();
    }
}

pub(crate) async fn connect_first_successful<T>(
    addrs: &[SocketAddr],
    connector: &TargetConnector<T>,
    open_dial_limiter: &OpenDialLimiter,
    target_connect_deadline: Option<time::Instant>,
) -> Result<T, OpenFailure>
where
    T: Send + 'static,
{
    let mut tasks = ConnectTasks::new();
    let mut next_index = 0;

    let mut last_error = None;
    loop {
        if target_connect_deadline.is_some_and(|deadline| deadline <= time::Instant::now()) {
            abort_connect_tasks(&mut tasks).await;
            return Err(OpenFailure::TargetTimeout);
        }
        spawn_target_connects(
            addrs,
            &mut next_index,
            &mut tasks,
            connector,
            open_dial_limiter,
        );
        if tasks.is_empty() {
            if next_index < addrs.len() {
                return Err(OpenFailure::ResourceLimit);
            }
            break;
        }

        let result = join_next_connect_task(&mut tasks, target_connect_deadline).await?;
        let Some(result) = result else {
            break;
        };
        match result {
            Ok((addr, Ok(stream))) => {
                debug!(event = "target.connect.candidate_success", %addr);
                abort_connect_tasks(&mut tasks).await;
                return Ok(stream);
            }
            Ok((addr, Err(err))) => {
                debug!(event = "target.connect.candidate_failed", %addr, error = %err);
                last_error = Some(err);
            }
            Err(err) => {
                last_error = Some(io::Error::other(err));
            }
        }
    }

    Err(OpenFailure::TargetUnavailable(last_error.unwrap_or_else(
        || io::Error::new(io::ErrorKind::NotFound, "target has no socket addresses"),
    )))
}

pub(crate) async fn join_next_connect_task<T>(
    tasks: &mut ConnectTasks<T>,
    target_connect_deadline: Option<time::Instant>,
) -> Result<Option<Result<(SocketAddr, io::Result<T>), tokio::task::JoinError>>, OpenFailure>
where
    T: Send + 'static,
{
    if let Some(deadline) = target_connect_deadline {
        tokio::select! {
            result = tasks.join_next() => Ok(result),
            () = time::sleep_until(deadline) => {
                abort_connect_tasks(tasks).await;
                Err(OpenFailure::TargetTimeout)
            }
        }
    } else {
        Ok(tasks.join_next().await)
    }
}

pub(crate) async fn abort_connect_tasks<T>(tasks: &mut ConnectTasks<T>)
where
    T: Send + 'static,
{
    tasks.abort_all().await;
}

pub(crate) fn spawn_target_connects<T>(
    addrs: &[SocketAddr],
    next_index: &mut usize,
    tasks: &mut ConnectTasks<T>,
    connector: &TargetConnector<T>,
    open_dial_limiter: &OpenDialLimiter,
) where
    T: Send + 'static,
{
    while *next_index < addrs.len() && tasks.len() < TARGET_CONNECT_PARALLELISM {
        let Some(permit) = open_dial_limiter.try_acquire() else {
            break;
        };
        let addr = addrs[*next_index];
        *next_index += 1;
        tasks.spawn(addr, connector, permit);
    }
}

pub(crate) fn target_connect_deadline(duration: Option<Duration>) -> Option<time::Instant> {
    duration.and_then(|duration| time::Instant::now().checked_add(duration))
}

pub(crate) async fn with_target_connect_deadline<T, F>(
    deadline: Option<time::Instant>,
    future: F,
) -> Result<T, OpenFailure>
where
    F: Future<Output = Result<T, OpenFailure>>,
{
    if let Some(deadline) = deadline {
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| OpenFailure::TargetTimeout)?
    } else {
        future.await
    }
}
