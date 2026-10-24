//! Lightweight HTTP observability probe server helper.
//!
//! Provides common HTTP parsing and response routines used by the
//! UK server and client observability endpoints (`/healthz`, `/readyz`, `/metrics`).

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum size of HTTP request head accepted by probe listeners.
pub const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;
/// Timeout for reading HTTP probe request head.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Delay between accept retry attempts on transient network errors.
pub const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Maximum concurrent connections to the probe listener.
pub const MAX_OBSERVABILITY_CONNECTIONS: usize = 32;

/// Reads the HTTP request header up to `\r\n\r\n` or `MAX_REQUEST_HEAD_BYTES`.
pub async fn read_request_head<S>(stream: &mut S) -> io::Result<Vec<u8>>
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

/// Parses the first line of an HTTP request into `(method, path, version)`.
pub fn parse_request_line(request: &[u8]) -> Option<(&str, &str, &str)> {
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

/// Writes an HTTP response and shuts down the write half.
pub async fn write_response<S>(
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

/// Writes an HTTP response head without body (for HEAD requests) and shuts down.
pub async fn write_response_head_only<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    content_type: &str,
    content_length: usize,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    stream.shutdown().await
}

/// Dispatches a single HTTP probe connection.
pub async fn serve_probe_connection<S, FReady, FRender>(
    stream: &mut S,
    is_ready: FReady,
    render_metrics: FRender,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    FReady: Fn() -> bool,
    FRender: Fn() -> String,
{
    let request = tokio::time::timeout(REQUEST_TIMEOUT, read_request_head(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out"))??;
    let Some((method, raw_path, version)) = parse_request_line(&request) else {
        return write_response(stream, 400, "Bad Request", "text/plain", "bad request\n").await;
    };
    if method != "GET" && method != "HEAD" {
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

    let path = raw_path.split('?').next().unwrap_or(raw_path);
    let is_head = method == "HEAD";

    let (status, reason, content_type, body) = match path {
        "/healthz" => (200, "OK", "text/plain", "ok\n".to_string()),
        "/readyz" if is_ready() => (200, "OK", "text/plain", "ready\n".to_string()),
        "/readyz" => (
            503,
            "Service Unavailable",
            "text/plain",
            "not ready\n".to_string(),
        ),
        "/metrics" => {
            // HEAD must advertise the same Content-Length as GET, so the
            // body is rendered to measure it and dropped right after.
            (
                200,
                "OK",
                "text/plain; version=0.0.4; charset=utf-8",
                render_metrics(),
            )
        }
        _ => (404, "Not Found", "text/plain", "not found\n".to_string()),
    };

    if is_head {
        write_response_head_only(stream, status, reason, content_type, body.len()).await
    } else {
        write_response(stream, status, reason, content_type, &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_request_lines() {
        assert_eq!(
            parse_request_line(b"GET /healthz HTTP/1.1\r\n"),
            Some(("GET", "/healthz", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line(b"HEAD /healthz?verbose=1 HTTP/1.1\r\n"),
            Some(("HEAD", "/healthz?verbose=1", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line(b"GET /metrics HTTP/1.0\r\n"),
            Some(("GET", "/metrics", "HTTP/1.0"))
        );
    }

    #[tokio::test]
    async fn serve_head_request_and_query_params() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            serve_probe_connection(&mut server, || true, || "test_metric 1\n".to_string()).await
        });
        client
            .write_all(b"HEAD /healthz?probe=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        task.await.unwrap().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 3\r\n"));
        assert!(
            response.ends_with("\r\n\r\n"),
            "HEAD request should have no body content"
        );
    }

    #[tokio::test]
    async fn head_metrics_matches_get_content_length() {
        for method in ["GET", "HEAD"] {
            let (mut client, mut server) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move {
                serve_probe_connection(
                    &mut server,
                    || true,
                    || "# HELP demo A demo metric\n# TYPE demo gauge\ndemo 42\n".to_string(),
                )
                .await
            });
            client
                .write_all(format!("{method} /metrics HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            task.await.unwrap().unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{method}");
            assert!(
                response.contains("Content-Length: 52\r\n"),
                "{method} must report the rendered metrics length"
            );
            if method == "HEAD" {
                assert!(response.ends_with("\r\n\r\n"), "HEAD must omit the body");
            } else {
                assert!(response.ends_with("demo 42\n"));
            }
        }
    }

    #[test]
    fn reject_invalid_request_lines() {
        assert!(parse_request_line(b"GET /metrics\r\n").is_none());
        assert!(parse_request_line(b"GET  /metrics HTTP/1.1\r\n").is_none());
        assert!(parse_request_line(b"not-http\r\n").is_none());
    }
}
