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
        "/readyz" if is_ready() => write_response(stream, 200, "OK", "text/plain", "ready\n").await,
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
            let body = render_metrics();
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
            parse_request_line(b"GET /metrics HTTP/1.0\r\n"),
            Some(("GET", "/metrics", "HTTP/1.0"))
        );
    }

    #[test]
    fn reject_invalid_request_lines() {
        assert!(parse_request_line(b"GET /metrics\r\n").is_none());
        assert!(parse_request_line(b"GET  /metrics HTTP/1.1\r\n").is_none());
        assert!(parse_request_line(b"not-http\r\n").is_none());
    }
}
