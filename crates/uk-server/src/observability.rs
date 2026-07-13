use std::{
    fmt::Write as _,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
    time,
};
use tracing::{debug, info, warn};

const MAX_CONNECTIONS: usize = 32;
const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

const PROTOCOL_COUNT: usize = 2;
const OPEN_FAILURE_COUNT: usize = 5;
const DIRECTION_COUNT: usize = 2;

#[derive(Debug, Clone, Copy)]
pub(super) enum RelayProtocol {
    Tcp,
    Udp,
}

impl RelayProtocol {
    const ALL: [Self; PROTOCOL_COUNT] = [Self::Tcp, Self::Udp];

    const fn index(self) -> usize {
        match self {
            Self::Tcp => 0,
            Self::Udp => 1,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum FlowOpenFailure {
    Protocol,
    PolicyDenied,
    ResourceLimit,
    TargetUnavailable,
    TargetTimeout,
}

impl FlowOpenFailure {
    const ALL: [Self; OPEN_FAILURE_COUNT] = [
        Self::Protocol,
        Self::PolicyDenied,
        Self::ResourceLimit,
        Self::TargetUnavailable,
        Self::TargetTimeout,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Protocol => 0,
            Self::PolicyDenied => 1,
            Self::ResourceLimit => 2,
            Self::TargetUnavailable => 3,
            Self::TargetTimeout => 4,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::PolicyDenied => "policy_denied",
            Self::ResourceLimit => "resource_limit",
            Self::TargetUnavailable => "target_unavailable",
            Self::TargetTimeout => "target_timeout",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RelayDirection {
    ClientToTarget,
    TargetToClient,
}

impl RelayDirection {
    const ALL: [Self; DIRECTION_COUNT] = [Self::ClientToTarget, Self::TargetToClient];

    const fn index(self) -> usize {
        match self {
            Self::ClientToTarget => 0,
            Self::TargetToClient => 1,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ClientToTarget => "client_to_target",
            Self::TargetToClient => "target_to_client",
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct ServerMetrics {
    ready: AtomicBool,
    security_generation: AtomicU64,
    config_reload_attempts_total: AtomicU64,
    config_reload_successes_total: AtomicU64,
    config_reload_failures_total: AtomicU64,
    accepted_connections_total: AtomicU64,
    rejected_handshakes_total: AtomicU64,
    failed_handshakes_total: AtomicU64,
    active_handshakes: AtomicU64,
    authenticated_sessions_total: AtomicU64,
    rejected_sessions_total: AtomicU64,
    active_sessions: AtomicU64,
    flow_open_requests_total: [AtomicU64; PROTOCOL_COUNT],
    flow_open_failures_total: [[AtomicU64; OPEN_FAILURE_COUNT]; PROTOCOL_COUNT],
    opened_flows_total: [AtomicU64; PROTOCOL_COUNT],
    active_flows: [AtomicU64; PROTOCOL_COUNT],
    relay_bytes_total: [[AtomicU64; DIRECTION_COUNT]; PROTOCOL_COUNT],
}

impl ServerMetrics {
    pub(super) fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub(super) fn set_security_generation(&self, generation: u64) {
        self.security_generation
            .store(generation, Ordering::Release);
    }

    pub(super) fn record_config_reload_success(&self, generation: u64) {
        self.config_reload_attempts_total
            .fetch_add(1, Ordering::Relaxed);
        self.config_reload_successes_total
            .fetch_add(1, Ordering::Relaxed);
        self.set_security_generation(generation);
    }

    pub(super) fn record_config_reload_failure(&self) {
        self.config_reload_attempts_total
            .fetch_add(1, Ordering::Relaxed);
        self.config_reload_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_accepted_connection(&self) {
        self.accepted_connections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_rejected_handshake(&self) {
        self.rejected_handshakes_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_failed_handshake(&self) {
        self.failed_handshakes_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn begin_handshake(self: &Arc<Self>) -> ActiveMetricGuard {
        self.active_handshakes.fetch_add(1, Ordering::Relaxed);
        ActiveMetricGuard::new(Arc::clone(self), ActiveMetric::Handshake)
    }

    pub(super) fn record_rejected_session(&self) {
        self.rejected_sessions_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn begin_session(self: &Arc<Self>) -> ActiveMetricGuard {
        self.authenticated_sessions_total
            .fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
        ActiveMetricGuard::new(Arc::clone(self), ActiveMetric::Session)
    }

    pub(super) fn record_flow_open_request(&self, protocol: RelayProtocol) {
        self.flow_open_requests_total[protocol.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_flow_open_failure(
        &self,
        protocol: RelayProtocol,
        failure: FlowOpenFailure,
    ) {
        self.flow_open_failures_total[protocol.index()][failure.index()]
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn begin_flow(self: &Arc<Self>, protocol: RelayProtocol) -> ActiveFlowGuard {
        self.opened_flows_total[protocol.index()].fetch_add(1, Ordering::Relaxed);
        self.active_flows[protocol.index()].fetch_add(1, Ordering::Relaxed);
        ActiveFlowGuard {
            metrics: Arc::clone(self),
            protocol,
        }
    }

    pub(super) fn record_relay_bytes(
        &self,
        protocol: RelayProtocol,
        direction: RelayDirection,
        bytes: usize,
    ) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.relay_bytes_total[protocol.index()][direction.index()]
            .fetch_add(bytes, Ordering::Relaxed);
    }

    fn render(&self) -> String {
        let ready = u8::from(self.is_ready());
        let mut output = format!(
            concat!(
                "# HELP uncrowned_king_server_ready Whether the relay listener is ready to accept connections.\n",
                "# TYPE uncrowned_king_server_ready gauge\n",
                "uncrowned_king_server_ready {ready}\n",
                "# HELP uncrowned_king_server_security_generation Active TLS, credential, and policy generation.\n",
                "# TYPE uncrowned_king_server_security_generation gauge\n",
                "uncrowned_king_server_security_generation {security_generation}\n",
                "# HELP uncrowned_king_server_config_reload_attempts_total Security config reloads attempted.\n",
                "# TYPE uncrowned_king_server_config_reload_attempts_total counter\n",
                "uncrowned_king_server_config_reload_attempts_total {config_reload_attempts_total}\n",
                "# HELP uncrowned_king_server_config_reload_successes_total Security config reloads applied atomically.\n",
                "# TYPE uncrowned_king_server_config_reload_successes_total counter\n",
                "uncrowned_king_server_config_reload_successes_total {config_reload_successes_total}\n",
                "# HELP uncrowned_king_server_config_reload_failures_total Security config reloads rejected.\n",
                "# TYPE uncrowned_king_server_config_reload_failures_total counter\n",
                "uncrowned_king_server_config_reload_failures_total {config_reload_failures_total}\n",
                "# HELP uncrowned_king_server_accepted_connections_total Accepted TCP carrier connections.\n",
                "# TYPE uncrowned_king_server_accepted_connections_total counter\n",
                "uncrowned_king_server_accepted_connections_total {accepted_connections_total}\n",
                "# HELP uncrowned_king_server_rejected_handshakes_total Carrier connections rejected by the handshake concurrency limit.\n",
                "# TYPE uncrowned_king_server_rejected_handshakes_total counter\n",
                "uncrowned_king_server_rejected_handshakes_total {rejected_handshakes_total}\n",
                "# HELP uncrowned_king_server_failed_handshakes_total TLS or authentication handshakes that failed.\n",
                "# TYPE uncrowned_king_server_failed_handshakes_total counter\n",
                "uncrowned_king_server_failed_handshakes_total {failed_handshakes_total}\n",
                "# HELP uncrowned_king_server_active_handshakes In-flight TLS and authentication handshakes.\n",
                "# TYPE uncrowned_king_server_active_handshakes gauge\n",
                "uncrowned_king_server_active_handshakes {active_handshakes}\n",
                "# HELP uncrowned_king_server_authenticated_sessions_total Authenticated sessions admitted by the relay.\n",
                "# TYPE uncrowned_king_server_authenticated_sessions_total counter\n",
                "uncrowned_king_server_authenticated_sessions_total {authenticated_sessions_total}\n",
                "# HELP uncrowned_king_server_rejected_sessions_total Authenticated sessions rejected by the session concurrency limit.\n",
                "# TYPE uncrowned_king_server_rejected_sessions_total counter\n",
                "uncrowned_king_server_rejected_sessions_total {rejected_sessions_total}\n",
                "# HELP uncrowned_king_server_active_sessions Authenticated relay sessions currently active.\n",
                "# TYPE uncrowned_king_server_active_sessions gauge\n",
                "uncrowned_king_server_active_sessions {active_sessions}\n",
            ),
            ready = ready,
            security_generation = self.security_generation.load(Ordering::Acquire),
            config_reload_attempts_total =
                self.config_reload_attempts_total.load(Ordering::Relaxed),
            config_reload_successes_total =
                self.config_reload_successes_total.load(Ordering::Relaxed),
            config_reload_failures_total =
                self.config_reload_failures_total.load(Ordering::Relaxed),
            accepted_connections_total = self.accepted_connections_total.load(Ordering::Relaxed),
            rejected_handshakes_total = self.rejected_handshakes_total.load(Ordering::Relaxed),
            failed_handshakes_total = self.failed_handshakes_total.load(Ordering::Relaxed),
            active_handshakes = self.active_handshakes.load(Ordering::Relaxed),
            authenticated_sessions_total =
                self.authenticated_sessions_total.load(Ordering::Relaxed),
            rejected_sessions_total = self.rejected_sessions_total.load(Ordering::Relaxed),
            active_sessions = self.active_sessions.load(Ordering::Relaxed),
        );
        self.render_flow_metrics(&mut output);
        output
    }

    fn render_flow_metrics(&self, output: &mut String) {
        output.push_str(
            "# HELP uncrowned_king_server_flow_open_requests_total UK flow open requests received.\n\
# TYPE uncrowned_king_server_flow_open_requests_total counter\n\
# HELP uncrowned_king_server_flow_open_failures_total UK flow opens rejected or failed.\n\
# TYPE uncrowned_king_server_flow_open_failures_total counter\n\
# HELP uncrowned_king_server_opened_flows_total UK flows opened successfully.\n\
# TYPE uncrowned_king_server_opened_flows_total counter\n\
# HELP uncrowned_king_server_active_flows UK flows currently active.\n\
# TYPE uncrowned_king_server_active_flows gauge\n\
# HELP uncrowned_king_server_relay_bytes_total Payload bytes relayed after a successful socket or carrier write.\n\
# TYPE uncrowned_king_server_relay_bytes_total counter\n",
        );
        for protocol in RelayProtocol::ALL {
            let protocol_index = protocol.index();
            writeln!(
                output,
                "uncrowned_king_server_flow_open_requests_total{{protocol=\"{}\"}} {}",
                protocol.label(),
                self.flow_open_requests_total[protocol_index].load(Ordering::Relaxed)
            )
            .expect("writing metrics to a String cannot fail");
            for failure in FlowOpenFailure::ALL {
                writeln!(
                    output,
                    "uncrowned_king_server_flow_open_failures_total{{protocol=\"{}\",reason=\"{}\"}} {}",
                    protocol.label(),
                    failure.label(),
                    self.flow_open_failures_total[protocol_index][failure.index()]
                        .load(Ordering::Relaxed)
                )
                .expect("writing metrics to a String cannot fail");
            }
            writeln!(
                output,
                "uncrowned_king_server_opened_flows_total{{protocol=\"{}\"}} {}",
                protocol.label(),
                self.opened_flows_total[protocol_index].load(Ordering::Relaxed)
            )
            .expect("writing metrics to a String cannot fail");
            writeln!(
                output,
                "uncrowned_king_server_active_flows{{protocol=\"{}\"}} {}",
                protocol.label(),
                self.active_flows[protocol_index].load(Ordering::Relaxed)
            )
            .expect("writing metrics to a String cannot fail");
            for direction in RelayDirection::ALL {
                writeln!(
                    output,
                    "uncrowned_king_server_relay_bytes_total{{protocol=\"{}\",direction=\"{}\"}} {}",
                    protocol.label(),
                    direction.label(),
                    self.relay_bytes_total[protocol_index][direction.index()]
                        .load(Ordering::Relaxed)
                )
                .expect("writing metrics to a String cannot fail");
            }
        }
    }
}

enum ActiveMetric {
    Handshake,
    Session,
}

pub(super) struct ActiveMetricGuard {
    metrics: Arc<ServerMetrics>,
    metric: ActiveMetric,
}

impl ActiveMetricGuard {
    fn new(metrics: Arc<ServerMetrics>, metric: ActiveMetric) -> Self {
        Self { metrics, metric }
    }
}

impl Drop for ActiveMetricGuard {
    fn drop(&mut self) {
        let gauge = match self.metric {
            ActiveMetric::Handshake => &self.metrics.active_handshakes,
            ActiveMetric::Session => &self.metrics.active_sessions,
        };
        gauge.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub(super) struct ActiveFlowGuard {
    metrics: Arc<ServerMetrics>,
    protocol: RelayProtocol,
}

impl Drop for ActiveFlowGuard {
    fn drop(&mut self) {
        self.metrics.active_flows[self.protocol.index()].fetch_sub(1, Ordering::Relaxed);
    }
}

pub(super) async fn serve(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let listen = match listener.local_addr() {
        Ok(listen) => listen,
        Err(err) => {
            warn!(event = "server.observability.local_addr_error", error = %err);
            return;
        }
    };
    info!(event = "server.observability.listen", listen = %listen);

    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                break;
            }
            accepted = listener.accept() => {
                let (mut stream, peer) = match accepted {
                    Ok(connection) => connection,
                    Err(err) => {
                        warn!(event = "server.observability.accept_error", error = %err);
                        time::sleep(ACCEPT_RETRY_DELAY).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    debug!(event = "server.observability.connection_limit", peer = %peer);
                    let _ = stream.shutdown().await;
                    continue;
                };
                let metrics = Arc::clone(&metrics);
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(err) = serve_connection(&mut stream, &metrics).await {
                        debug!(event = "server.observability.request_error", peer = %peer, error = %err);
                    }
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(err)) = joined {
                    warn!(event = "server.observability.task_error", error = %err);
                }
            }
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
    info!(event = "server.observability.shutdown");
}

async fn serve_connection<S>(stream: &mut S, metrics: &ServerMetrics) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = time::timeout(REQUEST_TIMEOUT, read_request_head(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out"))??;
    let Some((method, path, version)) = parse_request_line(&request) else {
        return write_response(stream, 400, "Bad Request", "text/plain", "bad request\n").await;
    };
    if method != "GET" {
        return write_response(
            stream,
            405,
            "Method Not Allowed",
            "text/plain",
            "method not allowed\n",
        )
        .await;
    }
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return write_response(
            stream,
            505,
            "HTTP Version Not Supported",
            "text/plain",
            "HTTP version not supported\n",
        )
        .await;
    }

    match path {
        "/healthz" => write_response(stream, 200, "OK", "text/plain", "ok\n").await,
        "/readyz" if metrics.is_ready() => {
            write_response(stream, 200, "OK", "text/plain", "ready\n").await
        }
        "/readyz" => {
            write_response(
                stream,
                503,
                "Service Unavailable",
                "text/plain",
                "not ready\n",
            )
            .await
        }
        "/metrics" => {
            let body = metrics.render();
            write_response(
                stream,
                200,
                "OK",
                "text/plain; version=0.0.4; charset=utf-8",
                &body,
            )
            .await
        }
        _ => write_response(stream, 404, "Not Found", "text/plain", "not found\n").await,
    }
}

async fn read_request_head<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut request = Vec::with_capacity(512);
    let mut buffer = [0_u8; 512];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP request closed before headers completed",
            ));
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > MAX_REQUEST_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request headers exceed limit",
            ));
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
        if request.len() == MAX_REQUEST_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request headers exceed limit",
            ));
        }
    }
}

fn parse_request_line(request: &[u8]) -> Option<(&str, &str, &str)> {
    let line_end = request.windows(2).position(|window| window == b"\r\n")?;
    let line = std::str::from_utf8(&request[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || method.is_empty() || path.is_empty() || version.is_empty() {
        return None;
    }
    Some((method, path, version))
}

async fn write_response<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn request(metrics: Arc<ServerMetrics>, request: &[u8]) -> String {
        let (mut client, mut server) = tokio::io::duplex(32 * 1024);
        let request = request.to_vec();
        let server_task = tokio::spawn(async move {
            serve_connection(&mut server, &metrics).await.unwrap();
        });
        client.write_all(&request).await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        server_task.await.unwrap();
        response
    }

    #[tokio::test]
    async fn serves_liveness_and_readiness() {
        let metrics = Arc::new(ServerMetrics::default());

        let health = request(
            Arc::clone(&metrics),
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        let not_ready = request(
            Arc::clone(&metrics),
            b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        metrics.set_ready(true);
        let ready = request(metrics, b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

        assert!(health.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(health.ends_with("ok\n"));
        assert!(not_ready.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(ready.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[tokio::test]
    async fn serves_prometheus_metrics() {
        let metrics = Arc::new(ServerMetrics::default());
        metrics.set_ready(true);
        metrics.set_security_generation(1);
        metrics.record_config_reload_success(2);
        metrics.record_config_reload_failure();
        metrics.record_accepted_connection();
        metrics.record_rejected_handshake();
        metrics.record_failed_handshake();
        let handshake = metrics.begin_handshake();
        let session = metrics.begin_session();
        metrics.record_rejected_session();
        metrics.record_flow_open_request(RelayProtocol::Tcp);
        metrics.record_flow_open_request(RelayProtocol::Udp);
        metrics.record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::TargetUnavailable);
        metrics.record_relay_bytes(RelayProtocol::Tcp, RelayDirection::ClientToTarget, 123);
        let flow = metrics.begin_flow(RelayProtocol::Tcp);

        let response = request(
            Arc::clone(&metrics),
            b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;

        assert!(response.contains("uncrowned_king_server_ready 1\n"));
        assert!(response.contains("uncrowned_king_server_security_generation 2\n"));
        assert!(response.contains("uncrowned_king_server_config_reload_attempts_total 2\n"));
        assert!(response.contains("uncrowned_king_server_config_reload_successes_total 1\n"));
        assert!(response.contains("uncrowned_king_server_config_reload_failures_total 1\n"));
        assert!(response.contains("uncrowned_king_server_accepted_connections_total 1\n"));
        assert!(response.contains("uncrowned_king_server_active_handshakes 1\n"));
        assert!(response.contains("uncrowned_king_server_active_sessions 1\n"));
        assert!(
            response
                .contains("uncrowned_king_server_flow_open_requests_total{protocol=\"tcp\"} 1\n")
        );
        assert!(response.contains(
            "uncrowned_king_server_flow_open_failures_total{protocol=\"tcp\",reason=\"target_unavailable\"} 1\n"
        ));
        assert!(response.contains("uncrowned_king_server_active_flows{protocol=\"tcp\"} 1\n"));
        assert!(response.contains(
            "uncrowned_king_server_relay_bytes_total{protocol=\"tcp\",direction=\"client_to_target\"} 123\n"
        ));

        drop(handshake);
        drop(session);
        drop(flow);
        let response = request(metrics, b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.contains("uncrowned_king_server_active_handshakes 0\n"));
        assert!(response.contains("uncrowned_king_server_active_sessions 0\n"));
        assert!(response.contains("uncrowned_king_server_active_flows{protocol=\"tcp\"} 0\n"));
    }

    #[tokio::test]
    async fn rejects_unsupported_requests() {
        let metrics = Arc::new(ServerMetrics::default());
        let method = request(
            Arc::clone(&metrics),
            b"POST /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        let path = request(metrics, b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

        assert!(method.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(path.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn rejects_malformed_request_lines() {
        assert!(parse_request_line(b"GET  /metrics HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request_line(b"GET /metrics\r\n\r\n").is_none());
        assert!(parse_request_line(b"not-http").is_none());
    }

    #[tokio::test]
    async fn rejects_request_heads_at_the_size_limit() {
        let (mut client, mut server) = tokio::io::duplex(MAX_REQUEST_HEAD_BYTES * 2);
        let request = vec![b'a'; MAX_REQUEST_HEAD_BYTES];
        client.write_all(&request).await.unwrap();

        let error = read_request_head(&mut server).await.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
