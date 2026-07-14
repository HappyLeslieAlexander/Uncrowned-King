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

use crate::session::{EndpointAttemptOutcome, EndpointFailurePhase};

const MAX_CONNECTIONS: usize = 32;
const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const PROTOCOL_COUNT: usize = 2;
const DIRECTION_COUNT: usize = 2;
const ENDPOINT_FAILURE_COUNT: usize = EndpointFailurePhase::ALL.len();

#[derive(Clone, Copy, Debug)]
pub(crate) enum RelayProtocol {
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

#[derive(Clone, Copy, Debug)]
pub(crate) enum RelayDirection {
    LocalToServer,
    ServerToLocal,
}

impl RelayDirection {
    const ALL: [Self; DIRECTION_COUNT] = [Self::LocalToServer, Self::ServerToLocal];

    const fn index(self) -> usize {
        match self {
            Self::LocalToServer => 0,
            Self::ServerToLocal => 1,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::LocalToServer => "local_to_server",
            Self::ServerToLocal => "server_to_local",
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ClientMetrics {
    ready: AtomicBool,
    config_generation: AtomicU64,
    config_reload_attempts_total: AtomicU64,
    config_reload_successes_total: AtomicU64,
    config_reload_failures_total: AtomicU64,
    accepted_socks_connections_total: AtomicU64,
    rejected_socks_connections_total: AtomicU64,
    active_socks_connections: AtomicU64,
    session_connect_attempts_total: AtomicU64,
    session_connect_failures_total: AtomicU64,
    endpoint_attempt_successes_total: AtomicU64,
    endpoint_attempt_failures_total: AtomicU64,
    endpoint_failures_total: [AtomicU64; ENDPOINT_FAILURE_COUNT],
    established_sessions_total: AtomicU64,
    active_sessions: AtomicU64,
    draining_sessions: AtomicU64,
    flow_open_requests_total: [AtomicU64; PROTOCOL_COUNT],
    opened_flows_total: [AtomicU64; PROTOCOL_COUNT],
    active_flows: [AtomicU64; PROTOCOL_COUNT],
    relay_bytes_total: [[AtomicU64; DIRECTION_COUNT]; PROTOCOL_COUNT],
}

impl ClientMetrics {
    pub(crate) fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub(crate) fn set_config_generation(&self, generation: u64) {
        self.config_generation.store(generation, Ordering::Release);
    }

    pub(crate) fn record_reload_success(&self, generation: u64) {
        self.config_reload_attempts_total
            .fetch_add(1, Ordering::Relaxed);
        self.config_reload_successes_total
            .fetch_add(1, Ordering::Relaxed);
        self.set_config_generation(generation);
    }

    pub(crate) fn record_reload_failure(&self) {
        self.config_reload_attempts_total
            .fetch_add(1, Ordering::Relaxed);
        self.config_reload_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_accepted_socks_connection(&self) {
        self.accepted_socks_connections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_rejected_socks_connection(&self) {
        self.rejected_socks_connections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn begin_socks_connection(self: &Arc<Self>) -> ActiveSocksConnectionGuard {
        self.active_socks_connections
            .fetch_add(1, Ordering::Relaxed);
        ActiveSocksConnectionGuard {
            metrics: Arc::clone(self),
        }
    }

    pub(crate) fn record_session_connect_attempt(&self) {
        self.session_connect_attempts_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_session_connect_failure(&self) {
        self.session_connect_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_endpoint_attempt(&self, outcome: EndpointAttemptOutcome) {
        match outcome {
            EndpointAttemptOutcome::Succeeded => {
                self.endpoint_attempt_successes_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            EndpointAttemptOutcome::Failed(phase) => {
                self.endpoint_attempt_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                self.endpoint_failures_total[phase.index()].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn record_session_established(&self) {
        self.established_sessions_total
            .fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_session_closed(&self, was_draining: bool) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
        if was_draining {
            self.draining_sessions.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_session_draining(&self) {
        self.draining_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_flow_open_request(&self, protocol: RelayProtocol) {
        self.flow_open_requests_total[protocol.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn begin_flow(self: &Arc<Self>, protocol: RelayProtocol) -> ActiveFlowGuard {
        self.opened_flows_total[protocol.index()].fetch_add(1, Ordering::Relaxed);
        self.active_flows[protocol.index()].fetch_add(1, Ordering::Relaxed);
        ActiveFlowGuard {
            metrics: Arc::clone(self),
            protocol,
        }
    }

    pub(crate) fn record_relay_bytes(
        &self,
        protocol: RelayProtocol,
        direction: RelayDirection,
        bytes: usize,
    ) {
        self.relay_bytes_total[protocol.index()][direction.index()]
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn render(&self) -> String {
        let ready = u8::from(self.is_ready());
        let mut output = format!(
            concat!(
                "# HELP uncrowned_king_client_ready Whether the SOCKS5 listener is ready.\n",
                "# TYPE uncrowned_king_client_ready gauge\n",
                "uncrowned_king_client_ready {ready}\n",
                "# HELP uncrowned_king_client_config_generation Active client config generation.\n",
                "# TYPE uncrowned_king_client_config_generation gauge\n",
                "uncrowned_king_client_config_generation {config_generation}\n",
                "# HELP uncrowned_king_client_config_reload_attempts_total Config reloads attempted.\n",
                "# TYPE uncrowned_king_client_config_reload_attempts_total counter\n",
                "uncrowned_king_client_config_reload_attempts_total {reload_attempts}\n",
                "# HELP uncrowned_king_client_config_reload_successes_total Config reloads applied atomically.\n",
                "# TYPE uncrowned_king_client_config_reload_successes_total counter\n",
                "uncrowned_king_client_config_reload_successes_total {reload_successes}\n",
                "# HELP uncrowned_king_client_config_reload_failures_total Config reloads rejected.\n",
                "# TYPE uncrowned_king_client_config_reload_failures_total counter\n",
                "uncrowned_king_client_config_reload_failures_total {reload_failures}\n",
                "# HELP uncrowned_king_client_socks_connections_total Accepted SOCKS5 connections.\n",
                "# TYPE uncrowned_king_client_socks_connections_total counter\n",
                "uncrowned_king_client_socks_connections_total {accepted_socks}\n",
                "# HELP uncrowned_king_client_rejected_socks_connections_total SOCKS5 connections rejected by the local limit.\n",
                "# TYPE uncrowned_king_client_rejected_socks_connections_total counter\n",
                "uncrowned_king_client_rejected_socks_connections_total {rejected_socks}\n",
                "# HELP uncrowned_king_client_active_socks_connections Active SOCKS5 connections.\n",
                "# TYPE uncrowned_king_client_active_socks_connections gauge\n",
                "uncrowned_king_client_active_socks_connections {active_socks}\n",
                "# HELP uncrowned_king_client_session_connect_attempts_total UK carrier connection attempts.\n",
                "# TYPE uncrowned_king_client_session_connect_attempts_total counter\n",
                "uncrowned_king_client_session_connect_attempts_total {connect_attempts}\n",
                "# HELP uncrowned_king_client_session_connect_failures_total Failed UK carrier connection attempts.\n",
                "# TYPE uncrowned_king_client_session_connect_failures_total counter\n",
                "uncrowned_king_client_session_connect_failures_total {connect_failures}\n",
                "# HELP uncrowned_king_client_established_sessions_total Authenticated UK carrier sessions established.\n",
                "# TYPE uncrowned_king_client_established_sessions_total counter\n",
                "uncrowned_king_client_established_sessions_total {established_sessions}\n",
                "# HELP uncrowned_king_client_active_sessions Active UK carrier sessions.\n",
                "# TYPE uncrowned_king_client_active_sessions gauge\n",
                "uncrowned_king_client_active_sessions {active_sessions}\n",
                "# HELP uncrowned_king_client_draining_sessions Superseded UK carrier sessions draining flows.\n",
                "# TYPE uncrowned_king_client_draining_sessions gauge\n",
                "uncrowned_king_client_draining_sessions {draining_sessions}\n",
            ),
            ready = ready,
            config_generation = self.config_generation.load(Ordering::Acquire),
            reload_attempts = self.config_reload_attempts_total.load(Ordering::Relaxed),
            reload_successes = self.config_reload_successes_total.load(Ordering::Relaxed),
            reload_failures = self.config_reload_failures_total.load(Ordering::Relaxed),
            accepted_socks = self
                .accepted_socks_connections_total
                .load(Ordering::Relaxed),
            rejected_socks = self
                .rejected_socks_connections_total
                .load(Ordering::Relaxed),
            active_socks = self.active_socks_connections.load(Ordering::Relaxed),
            connect_attempts = self.session_connect_attempts_total.load(Ordering::Relaxed),
            connect_failures = self.session_connect_failures_total.load(Ordering::Relaxed),
            established_sessions = self.established_sessions_total.load(Ordering::Relaxed),
            active_sessions = self.active_sessions.load(Ordering::Relaxed),
            draining_sessions = self.draining_sessions.load(Ordering::Relaxed),
        );
        self.render_endpoint_metrics(&mut output);
        output.push_str("# HELP uncrowned_king_client_flow_open_requests_total UK flow open requests.\n# TYPE uncrowned_king_client_flow_open_requests_total counter\n");
        output.push_str("# HELP uncrowned_king_client_opened_flows_total UK flows opened successfully.\n# TYPE uncrowned_king_client_opened_flows_total counter\n");
        output.push_str("# HELP uncrowned_king_client_active_flows Active UK flows.\n# TYPE uncrowned_king_client_active_flows gauge\n");
        output.push_str("# HELP uncrowned_king_client_relay_bytes_total Payload bytes relayed after a successful write.\n# TYPE uncrowned_king_client_relay_bytes_total counter\n");
        for protocol in RelayProtocol::ALL {
            let index = protocol.index();
            let _ = writeln!(
                output,
                "uncrowned_king_client_flow_open_requests_total{{protocol=\"{}\"}} {}",
                protocol.label(),
                self.flow_open_requests_total[index].load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "uncrowned_king_client_opened_flows_total{{protocol=\"{}\"}} {}",
                protocol.label(),
                self.opened_flows_total[index].load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "uncrowned_king_client_active_flows{{protocol=\"{}\"}} {}",
                protocol.label(),
                self.active_flows[index].load(Ordering::Relaxed)
            );
            for direction in RelayDirection::ALL {
                let _ = writeln!(
                    output,
                    "uncrowned_king_client_relay_bytes_total{{protocol=\"{}\",direction=\"{}\"}} {}",
                    protocol.label(),
                    direction.label(),
                    self.relay_bytes_total[index][direction.index()].load(Ordering::Relaxed)
                );
            }
        }
        output
    }

    fn render_endpoint_metrics(&self, output: &mut String) {
        output.push_str(
            "# HELP uncrowned_king_client_endpoint_attempts_total UK server endpoint connection attempts.\n\
# TYPE uncrowned_king_client_endpoint_attempts_total counter\n\
# HELP uncrowned_king_client_endpoint_failures_total Failed UK server endpoint attempts by bounded phase.\n\
# TYPE uncrowned_king_client_endpoint_failures_total counter\n",
        );
        writeln!(
            output,
            "uncrowned_king_client_endpoint_attempts_total{{outcome=\"success\"}} {}",
            self.endpoint_attempt_successes_total
                .load(Ordering::Relaxed)
        )
        .expect("writing metrics to a String cannot fail");
        writeln!(
            output,
            "uncrowned_king_client_endpoint_attempts_total{{outcome=\"failure\"}} {}",
            self.endpoint_attempt_failures_total.load(Ordering::Relaxed)
        )
        .expect("writing metrics to a String cannot fail");
        for phase in EndpointFailurePhase::ALL {
            writeln!(
                output,
                "uncrowned_king_client_endpoint_failures_total{{phase=\"{}\"}} {}",
                phase.label(),
                self.endpoint_failures_total[phase.index()].load(Ordering::Relaxed)
            )
            .expect("writing metrics to a String cannot fail");
        }
    }
}

pub(crate) struct ActiveSocksConnectionGuard {
    metrics: Arc<ClientMetrics>,
}

impl Drop for ActiveSocksConnectionGuard {
    fn drop(&mut self) {
        self.metrics
            .active_socks_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct ActiveFlowGuard {
    metrics: Arc<ClientMetrics>,
    protocol: RelayProtocol,
}

impl Drop for ActiveFlowGuard {
    fn drop(&mut self) {
        self.metrics.active_flows[self.protocol.index()].fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) async fn serve(
    listener: TcpListener,
    metrics: Arc<ClientMetrics>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let listen = match listener.local_addr() {
        Ok(listen) => listen,
        Err(err) => {
            warn!(event = "client.observability.local_addr_error", error = %err);
            return;
        }
    };
    info!(event = "client.observability.listen", listen = %listen);

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
                        warn!(event = "client.observability.accept_error", error = %err);
                        time::sleep(ACCEPT_RETRY_DELAY).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    debug!(event = "client.observability.connection_limit", peer = %peer);
                    let _ = stream.shutdown().await;
                    continue;
                };
                let metrics = Arc::clone(&metrics);
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(err) = serve_connection(&mut stream, &metrics).await {
                        debug!(event = "client.observability.request_error", peer = %peer, error = %err);
                    }
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(err)) = joined {
                    warn!(event = "client.observability.task_error", error = %err);
                }
            }
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
    info!(event = "client.observability.shutdown");
}

async fn serve_connection<S>(stream: &mut S, metrics: &ClientMetrics) -> io::Result<()>
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

    #[test]
    fn renders_bounded_client_metrics() {
        let metrics = Arc::new(ClientMetrics::default());
        metrics.set_ready(true);
        metrics.record_reload_success(2);
        metrics.record_session_connect_attempt();
        metrics.record_session_connect_failure();
        metrics.record_endpoint_attempt(EndpointAttemptOutcome::Failed(EndpointFailurePhase::Tls));
        metrics.record_endpoint_attempt(EndpointAttemptOutcome::Succeeded);
        metrics.record_session_established();
        metrics.record_session_draining();
        let _flow = metrics.begin_flow(RelayProtocol::Tcp);
        metrics.record_relay_bytes(RelayProtocol::Tcp, RelayDirection::LocalToServer, 42);

        let rendered = metrics.render();
        assert!(rendered.contains("uncrowned_king_client_ready 1\n"));
        assert!(rendered.contains("uncrowned_king_client_config_generation 2\n"));
        assert!(rendered.contains("uncrowned_king_client_session_connect_attempts_total 1\n"));
        assert!(rendered.contains("uncrowned_king_client_session_connect_failures_total 1\n"));
        assert!(
            rendered
                .contains("uncrowned_king_client_endpoint_attempts_total{outcome=\"success\"} 1\n")
        );
        assert!(
            rendered
                .contains("uncrowned_king_client_endpoint_attempts_total{outcome=\"failure\"} 1\n")
        );
        assert!(
            rendered.contains("uncrowned_king_client_endpoint_failures_total{phase=\"tls\"} 1\n")
        );
        assert!(rendered.contains("uncrowned_king_client_active_sessions 1\n"));
        assert!(rendered.contains("uncrowned_king_client_draining_sessions 1\n"));
        assert!(rendered.contains(
            "uncrowned_king_client_relay_bytes_total{protocol=\"tcp\",direction=\"local_to_server\"} 42\n"
        ));
    }

    #[tokio::test]
    async fn serves_health_readiness_and_metrics() {
        let metrics = Arc::new(ClientMetrics::default());
        assert!(request(&metrics, "/healthz").await.contains("200 OK"));
        assert!(
            request(&metrics, "/readyz")
                .await
                .contains("503 Service Unavailable")
        );
        metrics.set_ready(true);
        assert!(request(&metrics, "/readyz").await.contains("200 OK"));
        assert!(
            request(&metrics, "/metrics")
                .await
                .contains("uncrowned_king_client_ready 1\n")
        );
    }

    async fn request(metrics: &Arc<ClientMetrics>, path: &str) -> String {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let metrics = Arc::clone(metrics);
        let task = tokio::spawn(async move { serve_connection(&mut server, &metrics).await });
        client
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        task.await.unwrap().unwrap();
        response
    }
}
