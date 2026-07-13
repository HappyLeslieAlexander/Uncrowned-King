use std::{
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

#[derive(Default)]
pub(super) struct ServerMetrics {
    ready: AtomicBool,
    accepted_connections_total: AtomicU64,
    rejected_handshakes_total: AtomicU64,
    failed_handshakes_total: AtomicU64,
    active_handshakes: AtomicU64,
    authenticated_sessions_total: AtomicU64,
    rejected_sessions_total: AtomicU64,
    active_sessions: AtomicU64,
}

impl ServerMetrics {
    pub(super) fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
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

    fn render(&self) -> String {
        let ready = u8::from(self.is_ready());
        format!(
            concat!(
                "# HELP uncrowned_king_server_ready Whether the relay listener is ready to accept connections.\n",
                "# TYPE uncrowned_king_server_ready gauge\n",
                "uncrowned_king_server_ready {ready}\n",
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
            accepted_connections_total = self.accepted_connections_total.load(Ordering::Relaxed),
            rejected_handshakes_total = self.rejected_handshakes_total.load(Ordering::Relaxed),
            failed_handshakes_total = self.failed_handshakes_total.load(Ordering::Relaxed),
            active_handshakes = self.active_handshakes.load(Ordering::Relaxed),
            authenticated_sessions_total =
                self.authenticated_sessions_total.load(Ordering::Relaxed),
            rejected_sessions_total = self.rejected_sessions_total.load(Ordering::Relaxed),
            active_sessions = self.active_sessions.load(Ordering::Relaxed),
        )
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
        metrics.record_accepted_connection();
        metrics.record_rejected_handshake();
        metrics.record_failed_handshake();
        let handshake = metrics.begin_handshake();
        let session = metrics.begin_session();
        metrics.record_rejected_session();

        let response = request(
            Arc::clone(&metrics),
            b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;

        assert!(response.contains("uncrowned_king_server_ready 1\n"));
        assert!(response.contains("uncrowned_king_server_accepted_connections_total 1\n"));
        assert!(response.contains("uncrowned_king_server_active_handshakes 1\n"));
        assert!(response.contains("uncrowned_king_server_active_sessions 1\n"));

        drop(handshake);
        drop(session);
        let response = request(metrics, b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.contains("uncrowned_king_server_active_handshakes 0\n"));
        assert!(response.contains("uncrowned_king_server_active_sessions 0\n"));
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
