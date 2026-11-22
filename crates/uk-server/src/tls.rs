//! TLS helpers for the server carrier.

use std::{
    fs,
    io::{self, BufRead as _, IoSlice, Read, Write},
    pin::Pin,
    task::{Context, Poll, ready},
};

use rustls::{
    ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;
use uk_auth::EXPORTER_LABEL;
use uk_proto::ALPN_PROTOCOL;

type TlsError = Box<dyn std::error::Error + Send + Sync>;

/// Builds a TLS 1.3-only server config.
pub fn server_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, TlsError> {
    let (certs, key) = load_identity(cert_path, key_path)?;
    server_config_from_memory(certs, key)
}

/// Loads certificates and private key from disk once into memory.
pub fn load_identity(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    Ok((certs, key))
}

/// Builds a TLS 1.3-only server config from in-memory DER certificates and private key.
pub fn server_config_from_memory(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    config.max_early_data_size = 0;
    Ok(config)
}

/// Verifies that the TLS handshake negotiated the UK ALPN protocol.
pub fn verify_alpn<IO>(stream: &TlsStream<IO>) -> Result<(), TlsError> {
    verify_alpn_connection(stream.get_ref().1)
}

/// Verifies that a [`rustls::ServerConnection`] negotiated the UK ALPN protocol.
pub(crate) fn verify_alpn_connection(conn: &ServerConnection) -> Result<(), TlsError> {
    ensure_alpn(conn.alpn_protocol())
}

/// Exports the UK auth channel binding.
pub fn exporter<IO>(stream: &TlsStream<IO>) -> Result<[u8; 32], TlsError> {
    exporter_connection(stream.get_ref().1)
}

/// Exports the UK auth channel binding from a [`rustls::ServerConnection`].
pub(crate) fn exporter_connection(conn: &ServerConnection) -> Result<[u8; 32], TlsError> {
    let mut out = [0_u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, None)?;
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
enum TlsState {
    Stream,
    ReadShutdown,
    WriteShutdown,
    FullyShutdown,
}

impl TlsState {
    const fn shutdown_read(&mut self) {
        *self = match *self {
            Self::WriteShutdown | Self::FullyShutdown => Self::FullyShutdown,
            Self::Stream | Self::ReadShutdown => Self::ReadShutdown,
        };
    }

    const fn shutdown_write(&mut self) {
        *self = match *self {
            Self::ReadShutdown | Self::FullyShutdown => Self::FullyShutdown,
            Self::Stream | Self::WriteShutdown => Self::WriteShutdown,
        };
    }

    const fn readable(self) -> bool {
        !matches!(self, Self::ReadShutdown | Self::FullyShutdown)
    }

    const fn writeable(self) -> bool {
        !matches!(self, Self::WriteShutdown | Self::FullyShutdown)
    }
}

struct SyncReadAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for SyncReadAdapter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

struct SyncWriteAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<T: Unpin> SyncWriteAdapter<'_, '_, T> {
    fn poll_with<U>(
        &mut self,
        f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<U>>,
    ) -> io::Result<U> {
        match f(Pin::new(self.io), self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.poll_with(|io, cx| io.poll_write(cx, buf))
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.poll_with(|io, cx| io.poll_write_vectored(cx, bufs))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.poll_with(AsyncWrite::poll_flush)
    }
}

fn read_io_silent<IO: AsyncRead + Unpin>(
    io: &mut IO,
    session: &mut ServerConnection,
    cx: &mut Context<'_>,
    alert_suppressed: &mut bool,
) -> Poll<io::Result<usize>> {
    let mut reader = SyncReadAdapter { io, cx };
    let n = match session.read_tls(&mut reader) {
        Ok(n) => n,
        Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
        Err(err) => return Poll::Ready(Err(err)),
    };
    if let Err(err) = session.process_new_packets() {
        *alert_suppressed = true;
        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
    }
    Poll::Ready(Ok(n))
}

fn suppressed_alert_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "tls session failed; alert suppressed",
    )
}

fn write_io<IO: AsyncWrite + Unpin>(
    io: &mut IO,
    session: &mut ServerConnection,
    cx: &mut Context<'_>,
) -> Poll<io::Result<usize>> {
    let mut writer = SyncWriteAdapter { io, cx };
    match session.write_tls(&mut writer) {
        Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        result => Poll::Ready(result),
    }
}

/// Safe async wrapper around a pre-accepted [`rustls::ServerConnection`] for
/// masked TCP carriers. Never writes TLS alert bytes when
/// `process_new_packets` fails.
pub(crate) struct MaskedTlsStream<IO> {
    io: IO,
    session: ServerConnection,
    state: TlsState,
    need_flush: bool,
    alert_suppressed: bool,
    error: Option<io::Error>,
}

impl<IO> MaskedTlsStream<IO> {
    /// Creates a new stream wrapping `io` and an already-constructed `ServerConnection`.
    pub(crate) const fn new(io: IO, session: ServerConnection) -> Self {
        Self {
            io,
            session,
            state: TlsState::Stream,
            need_flush: false,
            alert_suppressed: false,
            error: None,
        }
    }

    /// Returns shared references to the underlying transport and TLS session.
    pub(crate) const fn get_ref(&self) -> (&IO, &ServerConnection) {
        (&self.io, &self.session)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> MaskedTlsStream<IO> {
    /// Drives the remaining TLS server handshake to completion without ever
    /// emitting TLS alert bytes on `process_new_packets` failures.
    pub(crate) async fn handshake(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            if self.alert_suppressed {
                return Poll::Ready(Err(suppressed_alert_error()));
            }
            while self.session.is_handshaking() {
                let mut wrlen = 0_usize;
                let mut rdlen = 0_usize;
                let mut write_would_block = false;
                let mut read_would_block = false;

                while self.session.wants_write() {
                    match write_io(&mut self.io, &mut self.session, cx) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        Poll::Ready(Ok(n)) => {
                            wrlen += n;
                            self.need_flush = true;
                        }
                        Poll::Pending => {
                            write_would_block = true;
                            break;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    }
                }

                if self.need_flush {
                    match Pin::new(&mut self.io).poll_flush(cx) {
                        Poll::Ready(Ok(())) => self.need_flush = false,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => write_would_block = true,
                    }
                }

                while self.state.readable() && self.session.wants_read() {
                    match read_io_silent(
                        &mut self.io,
                        &mut self.session,
                        cx,
                        &mut self.alert_suppressed,
                    ) {
                        Poll::Ready(Ok(0)) => self.state.shutdown_read(),
                        Poll::Ready(Ok(n)) => rdlen += n,
                        Poll::Pending => {
                            read_would_block = true;
                            break;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    }
                }

                if !self.state.readable() && self.session.is_handshaking() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls handshake eof",
                    )));
                }

                if !self.session.is_handshaking() {
                    break;
                }

                if (write_would_block || read_would_block) && rdlen == 0 && wrlen == 0 {
                    return Poll::Pending;
                }
            }

            Pin::new(&mut *self).poll_flush(cx)
        })
        .await
    }

    fn poll_fill_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        if self.alert_suppressed {
            return Poll::Ready(Err(suppressed_alert_error()));
        }
        if !self.state.readable() {
            return Poll::Ready(Ok(&[]));
        }

        let mut io_pending = false;
        while self.session.wants_read() {
            match read_io_silent(
                &mut self.io,
                &mut self.session,
                cx,
                &mut self.alert_suppressed,
            ) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        match self.session.reader().into_first_chunk() {
            Ok(buf) => {
                if buf.is_empty() {
                    self.state.shutdown_read();
                }
                Poll::Ready(Ok(buf))
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if !io_pending {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::ConnectionAborted {
                    self.state.shutdown_read();
                }
                Poll::Ready(Err(err))
            }
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaskedTlsStream<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(err) = self.error.take() {
            return Poll::Ready(Err(err));
        }

        let data = ready!(self.poll_fill_buf(cx))?;
        let len = data.len().min(buf.remaining());
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        buf.put_slice(&data[..len]);
        self.session.reader().consume(len);

        while buf.remaining() > 0 {
            let data = match self.poll_fill_buf(cx) {
                Poll::Ready(Ok([])) | Poll::Pending => break,
                Poll::Ready(Ok(data)) => data,
                Poll::Ready(Err(err)) => {
                    self.error = Some(err);
                    break;
                }
            };
            let len = data.len().min(buf.remaining());
            buf.put_slice(&data[..len]);
            self.session.reader().consume(len);
        }

        Poll::Ready(Ok(()))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaskedTlsStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.alert_suppressed {
            return Poll::Ready(Err(suppressed_alert_error()));
        }
        let mut pos = 0;

        while pos != buf.len() {
            let mut would_block = false;

            match this.session.writer().write(&buf[pos..]) {
                Ok(n) => pos += n,
                Err(err) => return Poll::Ready(Err(err)),
            }

            while this.session.wants_write() {
                match write_io(&mut this.io, &mut this.session, cx) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => {
                        this.need_flush = true;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            return match (pos, would_block) {
                (0, true) => Poll::Pending,
                (n, true) => Poll::Ready(Ok(n)),
                (_, false) => continue,
            };
        }

        Poll::Ready(Ok(pos))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.alert_suppressed {
            return Poll::Ready(Err(suppressed_alert_error()));
        }
        if bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(Ok(0));
        }

        loop {
            let mut would_block = false;
            let written = this.session.writer().write_vectored(bufs)?;

            while this.session.wants_write() {
                match write_io(&mut this.io, &mut this.session, cx) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => {
                        this.need_flush = true;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            return match (written, would_block) {
                (0, true) => Poll::Pending,
                (0, false) => continue,
                (n, _) => Poll::Ready(Ok(n)),
            };
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.alert_suppressed {
            return Poll::Ready(Err(suppressed_alert_error()));
        }
        this.session.writer().flush()?;
        while this.session.wants_write() {
            if ready!(write_io(&mut this.io, &mut this.session, cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            this.need_flush = true;
        }
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        this.need_flush = false;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.alert_suppressed {
            return Poll::Ready(Err(suppressed_alert_error()));
        }
        if this.state.writeable() {
            this.session.send_close_notify();
            this.state.shutdown_write();
        }

        while this.session.wants_write() {
            if ready!(write_io(&mut this.io, &mut this.session, cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(match ready!(Pin::new(&mut this.io).poll_shutdown(cx)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(err) => Err(err),
        })
    }
}

fn ensure_alpn(protocol: Option<&[u8]>) -> Result<(), TlsError> {
    if protocol == Some(ALPN_PROTOCOL) {
        Ok(())
    } else {
        Err("UK ALPN protocol was not negotiated".into())
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let pem =
        fs::read(path).map_err(|err| format!("failed to open certificate chain {path}: {err}"))?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("invalid certificate chain {path}: {err}"))?;
    if certs.is_empty() {
        Err(format!("missing certificate in {path}").into())
    } else {
        Ok(certs)
    }
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let pem = fs::read(path).map_err(|err| format!("failed to open private key {path}: {err}"))?;
    PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|err| format!("invalid private key {path}: {err}").into())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    #[test]
    fn accepts_uk_alpn() {
        assert!(ensure_alpn(Some(ALPN_PROTOCOL)).is_ok());
    }

    #[test]
    fn rejects_missing_alpn() {
        assert!(ensure_alpn(None).is_err());
    }

    #[test]
    fn rejects_wrong_alpn() {
        assert!(ensure_alpn(Some(b"h2")).is_err());
    }

    #[test]
    fn rejects_empty_cert_chain() {
        let path = temp_file("empty-cert", b"");

        assert!(load_certs(&path).is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_empty_private_key_file() {
        let path = temp_file("empty-key", b"");

        assert!(load_private_key(&path).is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn missing_cert_error_includes_path() {
        let path = temp_missing_file("missing-cert");

        let error = load_certs(&path).unwrap_err().to_string();

        assert!(error.contains(&path));
    }

    #[test]
    fn missing_private_key_error_includes_path() {
        let path = temp_missing_file("missing-key");

        let error = load_private_key(&path).unwrap_err().to_string();

        assert!(error.contains(&path));
    }

    fn temp_file(name: &str, contents: &[u8]) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("uk-server-tls-{name}-{now}.pem"));
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn temp_missing_file(name: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("uk-server-tls-{name}-{now}.pem"))
            .to_string_lossy()
            .into_owned()
    }

    const TEST_CERT: &str = r"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUEX51v2igsFngMQTuqhBx+gKL2MswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcwMzEzNTM0MVoXDTM2MDYz
MDEzNTM0MVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAhf3zqFeac7mRJTkyoPMwXUtvgnKcY3ydON4Q3cMrxrd0
qn2leXJObMP846YgGBtKYu3cDo01qK+cN1rY4l/3iNqa4VOYJ3ckmUTEQhmCG78i
XIxR9+488rWsxrhJ4GtGj/jd7UaJM9RMs2bb+7KzSj8t6t+Q1MEKsPeqQZ1wBW9S
wgYLMmrP5eNYFgEgt8KI2r/p+Lf2rbGqu/OdzWkekDbuJq+wqUsEtEnE4x5ELJEE
axEv+savJVWGSvBUkU6sWU8s0iLNiQKMBjAd/vTbqD+NVGihNrE0S0o0S4oxtHhu
wwPbfk3bkGV2Z5QwTMI48AhrcoELMuQjO9wZygLHKQIDAQABo4GSMIGPMB0GA1Ud
DgQWBBT8yAuXKconl4iNVuGmhUJIuVZW5zAfBgNVHSMEGDAWgBT8yAuXKconl4iN
VuGmhUJIuVZW5zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZI
hvcNAQELBQADggEBAESMmK/ln9SXy8uevLxfdf0oKE4UC9CyyMj2FPOWSnpvwLJ4
KI5axpyV3uP4Afd/lH6W47OcvQ9Ah0hSEVY/Xi+sAfLdjPmp3YpTtHP605Bj0y+A
O2F21JkBh/ZVA2SbI9MCg13XBPfrmqarPxIVlye4kxbD4ZDN5Zp0DLjoIIWWGv2n
6MuVnlvftL6nyPvc8EyPLM6wxiisxlB/D7jx9tL+GuLHcvXDuxQIkjB7MMWWfERM
hpwf7QVVYCCnRNdlxk/xa6pr54CMysA75BlDBaVjyqK8Uy74DHL7APCN9opoV5ws
vX1BONgh2gSRGBFiii6imzEAwefkUtYAvAQy1xw=
-----END CERTIFICATE-----
";

    const TEST_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCF/fOoV5pzuZEl
OTKg8zBdS2+CcpxjfJ043hDdwyvGt3SqfaV5ck5sw/zjpiAYG0pi7dwOjTWor5w3
WtjiX/eI2prhU5gndySZRMRCGYIbvyJcjFH37jzytazGuEnga0aP+N3tRokz1Eyz
Ztv7srNKPy3q35DUwQqw96pBnXAFb1LCBgsyas/l41gWASC3wojav+n4t/atsaq7
853NaR6QNu4mr7CpSwS0ScTjHkQskQRrES/6xq8lVYZK8FSRTqxZTyzSIs2JAowG
MB3+9NuoP41UaKE2sTRLSjRLijG0eG7DA9t+TduQZXZnlDBMwjjwCGtygQsy5CM7
3BnKAscpAgMBAAECggEAPjqsP+G3rMlhHJ2M4u0u6BVRy465DQdh6XhQ8v1ixl6L
g2bpRBcPTzpSp9OOkkOSb5Gyott4MUilz5uUoMYbK2cDiWSOhL2ztK8YSu6X25UQ
O1U7+F6f1cUEYiJSxTRtSA4326vnqreNi8BYqHPdCr1+8Nc152lkMr5DR0f8L7lQ
8v7nLryHxGyKZb6Pu75m8Fm8hV4OGG6n1e4jo83+arS3LAppRZVukQkjShHD9+ol
lPKcYsc9hbqojE8gXyOk4xyvlqxdxXuq/tDpfxMxfH5jbsIqnYZ4NDBGOWtT4Hzh
q+pMcRj3iPwbvTybPUTNJHDB8MyqG/hRRvC58NeLpQKBgQC8OV8fG7Za+6FiBQel
2IVYyBEAwpqchyhvKPNUnGz+0h5dJ2q2ANWcLwU56/1U6dpPLNJj42Sjq97fUdX9
156JmFUMT2YKY3ffsR31WFvA91FXRSAkR/g8uXLAEKIr0mYsRB7yopY31f/QWH25
RvD+UTUf1r0g7m+3T7ezyXrrLwKBgQC2PW1MWFhnjPiArJVYXkiC6+3O4nkAPByl
lm7VNw+AKquJu3TgSCHNsuHQXqG2WOisJndfvWyOScOke9W+KvCFNFfo/OV71SW9
Rqn61Cl87p3SOwGF15eR62EPVicaAwBvlnhOX5zA1p5MPs7M/8cqi5ld6gOx8XhW
xF4OOv19JwKBgQCX7idd0NytLBfkKvM1Z0SbmUJAPtTWLDLzJzbiwTEprylbQAne
x2WlID8ztc1S0UCqUB+zCUWe54iK8l+s+nK51gAwY5aWJBwKr8ji1WOaqwc5Tk7X
elBhk7+QUNzWSoq2iHYCnEJs54wJ/KPe/ehhH+Olw4v+HPiIGwzJToSteQKBgFiJ
v3A3+7tTYegh8Ozd4Zy5wu+gV+klS0WnsHEmLwG1uWFREZdldAbbwZnaX/aXe3Mn
vRdmkDcQ31wqTc32TqRoqc0oENX42Dz899hE+2MXCtX4lOTRuXHLSXyJ/rVEgBG2
qPxqt114569jVFWEbt7cs8ZMyz7Icg61mHyRbFZBAoGBAKiV5tDUJewK9oZluSsV
jiIVN0rJ1/EWIoJClBZEQ+uZHiAbwEevcPjJD6Pp9xFjfujebQDLep3RKIMuyi7o
s1BW++ZOOL/nM71C5A1D2kYi9etevjp2qg/P2FOhhKSBAM+oyy6KR2HR3OnRpBfF
VODOlcdwgEkE3j5MxS0brpI9
-----END PRIVATE KEY-----
";

    fn test_server_and_client_configs() -> (
        std::sync::Arc<ServerConfig>,
        std::sync::Arc<rustls::ClientConfig>,
    ) {
        let certs = CertificateDer::pem_slice_iter(TEST_CERT.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(certs.clone());
        let server_cfg = std::sync::Arc::new(server_config_from_memory(certs, key).unwrap());
        let mut client_cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        client_cfg.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        (server_cfg, std::sync::Arc::new(client_cfg))
    }

    fn accept_sync(
        server_cfg: std::sync::Arc<ServerConfig>,
        client_hello_bytes: &[u8],
    ) -> ServerConnection {
        let mut acceptor = rustls::server::Acceptor::default();
        let mut cursor = io::Cursor::new(client_hello_bytes);
        acceptor.read_tls(&mut cursor).unwrap();
        let accepted = acceptor.accept().unwrap().expect("complete ClientHello");
        accepted.into_connection(server_cfg).unwrap()
    }

    #[tokio::test]
    async fn masked_tls_stream_completes_handshake_exporter_and_io() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (server_cfg, client_cfg) = test_server_and_client_configs();
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let client_task = tokio::spawn(async move {
            let mut tls = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    client_io,
                )
                .await
                .unwrap();
            let mut client_exp = [0_u8; 32];
            tls.get_ref()
                .1
                .export_keying_material(&mut client_exp, EXPORTER_LABEL, None)
                .unwrap();
            tls.write_all(b"ping").await.unwrap();
            tls.flush().await.unwrap();
            let mut buf = [0_u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
            tls.shutdown().await.unwrap();
            let mut eof = [0_u8; 1];
            assert_eq!(tls.read(&mut eof).await.unwrap(), 0);
            client_exp
        });

        let mut acceptor = rustls::server::Acceptor::default();
        let mut buf = [0_u8; 4096];
        let accepted = loop {
            let n = server_io.read(&mut buf).await.unwrap();
            assert!(n > 0);
            let mut cursor = io::Cursor::new(&buf[..n]);
            acceptor.read_tls(&mut cursor).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };
        let conn = accepted.into_connection(server_cfg).unwrap();
        let mut tls_stream = MaskedTlsStream::new(server_io, conn);
        tls_stream.handshake().await.unwrap();
        verify_alpn_connection(tls_stream.get_ref().1).unwrap();
        let server_exp = exporter_connection(tls_stream.get_ref().1).unwrap();

        let mut req = [0_u8; 4];
        tls_stream.read_exact(&mut req).await.unwrap();
        assert_eq!(&req, b"ping");
        tls_stream.write_all(b"pong").await.unwrap();
        tls_stream.flush().await.unwrap();
        let mut eof = [0_u8; 1];
        assert_eq!(tls_stream.read(&mut eof).await.unwrap(), 0);
        tls_stream.shutdown().await.unwrap();

        let client_exp = client_task.await.unwrap();
        assert_eq!(server_exp, client_exp);
    }

    #[tokio::test]
    async fn masked_tls_stream_emits_zero_alert_bytes_on_post_accept_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (server_cfg, client_cfg) = test_server_and_client_configs();
        let mut client_conn = rustls::ClientConnection::new(
            client_cfg,
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client_conn.write_tls(&mut hello).unwrap();

        let conn = accept_sync(server_cfg, &hello);
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mut tls_stream = MaskedTlsStream::new(server_io, conn);

        let server_task = tokio::spawn(async move { tls_stream.handshake().await });

        // Drain the server's queued ServerHello flight, then send a corrupt
        // encrypted TLS record to trigger process_new_packets() failure.
        let mut server_flight = vec![0_u8; 8192];
        let n = client_io.read(&mut server_flight).await.unwrap();
        assert!(n > 0);
        // Send a ChangeCipherSpec + malformed encrypted handshake record (invalid MAC).
        client_io
            .write_all(&[0x17, 0x03, 0x03, 0x00, 0x16])
            .await
            .unwrap();
        client_io.write_all(&[0xff_u8; 22]).await.unwrap();
        client_io.flush().await.unwrap();

        let err = server_task.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut trailing = Vec::new();
        let read = client_io.read_to_end(&mut trailing).await.unwrap();
        assert_eq!(
            read, 0,
            "MaskedTlsStream must emit 0 alert bytes on post-accept TLS error"
        );
    }

    #[tokio::test]
    async fn masked_tls_stream_returns_unexpected_eof_on_handshake_eof() {
        use tokio::io::AsyncReadExt;

        let (server_cfg, client_cfg) = test_server_and_client_configs();
        let mut client_conn = rustls::ClientConnection::new(
            client_cfg,
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client_conn.write_tls(&mut hello).unwrap();

        let conn = accept_sync(server_cfg, &hello);
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mut tls_stream = MaskedTlsStream::new(server_io, conn);

        let server_task = tokio::spawn(async move { tls_stream.handshake().await });
        // Read ServerHello flight, then drop client before sending Finished.
        let mut server_flight = vec![0_u8; 8192];
        let n = client_io.read(&mut server_flight).await.unwrap();
        assert!(n > 0);
        drop(client_io);

        let err = server_task.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[derive(Clone, Copy)]
    enum WriteStep {
        Pending,
        Max(usize),
    }

    struct ScriptedTransport<S> {
        inner: S,
        read_chunks: std::collections::VecDeque<Poll<io::Result<Vec<u8>>>>,
        write_steps: std::collections::VecDeque<WriteStep>,
        flush_steps: std::collections::VecDeque<Poll<io::Result<()>>>,
        shutdown_steps: std::collections::VecDeque<Poll<io::Result<()>>>,
        written: Vec<u8>,
        vectored_calls: usize,
    }

    impl<S> ScriptedTransport<S> {
        fn new(inner: S) -> Self {
            Self {
                inner,
                read_chunks: std::collections::VecDeque::new(),
                write_steps: std::collections::VecDeque::new(),
                flush_steps: std::collections::VecDeque::new(),
                shutdown_steps: std::collections::VecDeque::new(),
                written: Vec::new(),
                vectored_calls: 0,
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for ScriptedTransport<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(next) = self.read_chunks.pop_front() {
                return match next {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Ready(Ok(bytes)) => {
                        let take = bytes.len().min(buf.remaining());
                        buf.put_slice(&bytes[..take]);
                        if take < bytes.len() {
                            self.read_chunks
                                .push_front(Poll::Ready(Ok(bytes[take..].to_vec())));
                        }
                        Poll::Ready(Ok(()))
                    }
                };
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ScriptedTransport<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let cap = match self.write_steps.pop_front() {
                Some(WriteStep::Pending) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Some(WriteStep::Max(max)) => buf.len().min(max),
                None => buf.len(),
            };
            let poll = Pin::new(&mut self.inner).poll_write(cx, &buf[..cap]);
            if let Poll::Ready(Ok(n)) = &poll {
                self.written.extend_from_slice(&buf[..*n]);
            }
            poll
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            self.vectored_calls += 1;
            let cap = match self.write_steps.pop_front() {
                Some(WriteStep::Pending) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Some(WriteStep::Max(max)) => max,
                None => usize::MAX,
            };
            let Some(first_non_empty) = bufs.iter().find(|s| !s.is_empty()) else {
                return Poll::Ready(Ok(0));
            };
            let slice = &first_non_empty[..first_non_empty.len().min(cap)];
            let poll = Pin::new(&mut self.inner).poll_write(cx, slice);
            if let Poll::Ready(Ok(n)) = &poll {
                self.written.extend_from_slice(&slice[..*n]);
            }
            poll
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(step) = self.flush_steps.pop_front() {
                if step.is_pending() {
                    cx.waker().wake_by_ref();
                }
                return step;
            }
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(step) = self.shutdown_steps.pop_front() {
                if step.is_pending() {
                    cx.waker().wake_by_ref();
                }
                return step;
            }
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn masked_tls_stream_vectored_and_backpressure_paths_preserve_data() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (server_cfg, client_cfg) = test_server_and_client_configs();
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let client_task = tokio::spawn(async move {
            let mut tls = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    client_io,
                )
                .await
                .unwrap();
            let mut buf = [0_u8; 20];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"firstsecond-vectored");
            let mut eof = [0_u8; 1];
            assert_eq!(tls.read(&mut eof).await.unwrap(), 0);
            tls.shutdown().await.unwrap();
        });

        let mut acceptor = rustls::server::Acceptor::default();
        let mut buf = [0_u8; 4096];
        let accepted = loop {
            let n = server_io.read(&mut buf).await.unwrap();
            assert!(n > 0);
            let mut cursor = io::Cursor::new(&buf[..n]);
            acceptor.read_tls(&mut cursor).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };
        let conn = accepted.into_connection(server_cfg).unwrap();
        let mut transport = ScriptedTransport::new(server_io);
        // Backpressure during handshake().
        transport
            .write_steps
            .extend([WriteStep::Pending, WriteStep::Max(7), WriteStep::Max(11)]);
        transport.flush_steps.push_back(Poll::Pending);

        let mut tls_stream = MaskedTlsStream::new(transport, conn);
        tls_stream.handshake().await.unwrap();
        assert!(tls_stream.is_write_vectored());

        // Empty vectored slice returns Ok(0).
        let empty_n = std::future::poll_fn(|cx| {
            Pin::new(&mut tls_stream).poll_write_vectored(cx, &[IoSlice::new(&[])])
        })
        .await
        .unwrap();
        assert_eq!(empty_n, 0);

        // Backpressure during poll_write.
        tls_stream.io.write_steps.extend([
            WriteStep::Pending,
            WriteStep::Max(3),
            WriteStep::Pending,
        ]);
        tls_stream.write_all(b"first").await.unwrap();

        // Backpressure during poll_write_vectored.
        tls_stream.io.write_steps.extend([
            WriteStep::Pending,
            WriteStep::Max(4),
            WriteStep::Pending,
        ]);
        let slices = [
            IoSlice::new(b"second"),
            IoSlice::new(b"-"),
            IoSlice::new(b"vectored"),
        ];
        let mut offset = 0_usize;
        let combined = b"second-vectored";
        while offset < combined.len() {
            let mut slice_bufs = Vec::new();
            let mut skip = offset;
            for s in &slices {
                if skip >= s.len() {
                    skip -= s.len();
                } else {
                    slice_bufs.push(IoSlice::new(&s[skip..]));
                    skip = 0;
                }
            }
            let n = std::future::poll_fn(|cx| {
                Pin::new(&mut tls_stream).poll_write_vectored(cx, &slice_bufs)
            })
            .await
            .unwrap();
            assert!(n > 0);
            offset += n;
        }
        assert!(tls_stream.io.vectored_calls > 0);

        // Backpressure during poll_flush and poll_shutdown.
        tls_stream.io.flush_steps.push_back(Poll::Pending);
        tls_stream.flush().await.unwrap();

        tls_stream.io.write_steps.push_back(WriteStep::Pending);
        tls_stream.io.write_steps.push_back(WriteStep::Max(4));
        tls_stream.io.shutdown_steps.push_back(Poll::Pending);
        tls_stream.shutdown().await.unwrap();

        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn masked_tls_stream_post_handshake_invalid_data_and_deferred_error_suppress_alerts() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (server_cfg, client_cfg) = test_server_and_client_configs();
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let client_task = tokio::spawn(async move {
            let mut tls = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    client_io,
                )
                .await
                .unwrap();
            tls.write_all(b"warmup").await.unwrap();
            tls.flush().await.unwrap();
            let mut ack = [0_u8; 3];
            tls.read_exact(&mut ack).await.unwrap();
            assert_eq!(&ack, b"ack");
            tls
        });

        let mut acceptor = rustls::server::Acceptor::default();
        let mut buf = [0_u8; 4096];
        let accepted = loop {
            let n = server_io.read(&mut buf).await.unwrap();
            assert!(n > 0);
            let mut cursor = io::Cursor::new(&buf[..n]);
            acceptor.read_tls(&mut cursor).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };
        let conn = accepted.into_connection(server_cfg).unwrap();
        let mut tls_stream = MaskedTlsStream::new(ScriptedTransport::new(server_io), conn);
        tls_stream.handshake().await.unwrap();
        let mut warmup = [0_u8; 6];
        tls_stream.read_exact(&mut warmup).await.unwrap();
        assert_eq!(&warmup, b"warmup");
        tls_stream.write_all(b"ack").await.unwrap();
        tls_stream.flush().await.unwrap();

        let client_tls = client_task.await.unwrap();
        let (mut client_raw, mut client_conn) = client_tls.into_inner();
        client_conn.writer().write_all(b"valid-msg").unwrap();
        let mut valid_record = Vec::new();
        while client_conn.wants_write() {
            client_conn.write_tls(&mut valid_record).unwrap();
        }
        assert!(!valid_record.is_empty());

        // Build a corrupt application record.
        let mut corrupt_record = vec![0x17, 0x03, 0x03, 0x00, 0x16];
        corrupt_record.extend_from_slice(&[0xff_u8; 22]);

        // Script: chunk 1 = valid TLS record (stops poll_fill_buf #1 once plaintext
        // is buffered), chunk 2 = corrupt TLS record (triggers process_new_packets()
        // failure inside poll_read's `while buf.remaining() > 0` loop, deferring to `self.error`).
        tls_stream
            .io
            .read_chunks
            .push_back(Poll::Ready(Ok(valid_record)));
        tls_stream
            .io
            .read_chunks
            .push_back(Poll::Ready(Ok(corrupt_record)));

        let written_before = tls_stream.io.written.len();

        let mut out = [0_u8; 64];
        let n = tls_stream.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"valid-msg");
        assert!(
            tls_stream.io.read_chunks.is_empty(),
            "remaining chunks: {}",
            tls_stream.io.read_chunks.len()
        );
        assert!(tls_stream.error.is_some());
        assert!(tls_stream.alert_suppressed);
        assert!(
            tls_stream.get_ref().1.wants_write(),
            "rustls should have queued an alert that MaskedTlsStream must suppress"
        );

        // Even before reading the deferred error, every write/flush/shutdown
        // path must refuse and emit zero alert bytes.
        let err = tls_stream.write(b"after-alert").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = std::future::poll_fn(|cx| {
            Pin::new(&mut tls_stream).poll_write_vectored(cx, &[IoSlice::new(b"vec")])
        })
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = tls_stream.flush().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = tls_stream.shutdown().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Next read surfaces the deferred `self.error`.
        let err = tls_stream.read(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Subsequent read also fails closed without touching inner IO.
        let err = tls_stream.read(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        assert_eq!(
            tls_stream.io.written.len(),
            written_before,
            "zero alert bytes may be written after post-handshake process_new_packets failure"
        );

        drop(tls_stream);
        let mut trailing = Vec::new();
        assert_eq!(client_raw.read_to_end(&mut trailing).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn masked_tls_stream_direct_post_handshake_invalid_data_suppresses_alerts() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (server_cfg, client_cfg) = test_server_and_client_configs();
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let client_task = tokio::spawn(async move {
            let mut tls = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    client_io,
                )
                .await
                .unwrap();
            tls.write_all(b"warmup").await.unwrap();
            tls.flush().await.unwrap();
            let mut ack = [0_u8; 3];
            tls.read_exact(&mut ack).await.unwrap();
            assert_eq!(&ack, b"ack");
            tls
        });

        let mut acceptor = rustls::server::Acceptor::default();
        let mut buf = [0_u8; 4096];
        let accepted = loop {
            let n = server_io.read(&mut buf).await.unwrap();
            assert!(n > 0);
            let mut cursor = io::Cursor::new(&buf[..n]);
            acceptor.read_tls(&mut cursor).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };
        let conn = accepted.into_connection(server_cfg).unwrap();
        let mut tls_stream = MaskedTlsStream::new(ScriptedTransport::new(server_io), conn);
        tls_stream.handshake().await.unwrap();
        let mut warmup = [0_u8; 6];
        tls_stream.read_exact(&mut warmup).await.unwrap();
        assert_eq!(&warmup, b"warmup");
        tls_stream.write_all(b"ack").await.unwrap();
        tls_stream.flush().await.unwrap();

        let client_tls = client_task.await.unwrap();
        let (mut client_raw, _client_conn) = client_tls.into_inner();
        let written_before = tls_stream.io.written.len();

        // Send a malformed encrypted TLS application record directly over the wire.
        client_raw
            .write_all(&[0x17, 0x03, 0x03, 0x00, 0x16])
            .await
            .unwrap();
        client_raw.write_all(&[0xaa_u8; 22]).await.unwrap();
        client_raw.flush().await.unwrap();

        let mut out = [0_u8; 32];
        let err = tls_stream.read(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(tls_stream.alert_suppressed);
        assert!(tls_stream.get_ref().1.wants_write());

        assert_eq!(
            tls_stream.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            tls_stream.flush().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            tls_stream.shutdown().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(tls_stream.io.written.len(), written_before);

        drop(tls_stream);
        let mut trailing = Vec::new();
        assert_eq!(client_raw.read_to_end(&mut trailing).await.unwrap(), 0);
    }
}
